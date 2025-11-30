use crate::{parse_pmt, parse_pat, ProbeHints, PsiAssembler, TsHeader};
use base64::Engine;
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Duration;

#[derive(Debug)]
pub struct Scte35CueInfo {
    pub pts_90k: u64,
    pub timestamp: Duration,
    pub payload: Vec<u8>,
    pub base64: String,
}

/// List SCTE-35 cues found in the TS file.
pub fn list_scte35_cues(path: &Path, hints: ProbeHints) -> Result<Vec<Scte35CueInfo>> {
    // First pass: find SCTE PID via PAT/PMT unless hinted.
    let scte35_pid = if let Some(pid) = hints.scte35_pid {
        pid
    } else if let Some(pid) = find_scte35_pid(path)? {
        pid
    } else if let Some(pid) = scan_scte35_pid_by_pes(path)? {
        pid
    } else {
        return Err(anyhow!(
            "No SCTE-35 PID found (use --scte35-pid to hint if PMT missing)"
        ));
    };

    // Second pass: extract cues.
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    list_scte35_cues_from_reader(reader, scte35_pid)
}

/// Internal helper for testing; consumes any reader of TS packets.
pub fn list_scte35_cues_from_reader<R: Read>(
    mut reader: R,
    scte35_pid: u16,
) -> Result<Vec<Scte35CueInfo>> {
    let mut buf = [0u8; 188];
    let mut cues = Vec::new();
    let mut current_pes: Option<Vec<u8>> = None;
    let mut section_asm = PsiAssembler::default();

    while reader.read_exact(&mut buf).is_ok() {
        if buf[0] != 0x47 {
            return Err(anyhow!("sync byte missing"));
        }
        let header = TsHeader::parse(&buf)?;
        if header.pid != scte35_pid {
            continue;
        }
        let payload = header
            .payload(&buf)
            .map_err(|e| anyhow!("payload parse failed at pid {}: {}", header.pid, e))?;
        let payload = match payload {
            Some(p) => p,
            None => continue,
        };

        // Section-carried SCTE-35 (table_id 0xFC) via PSI assembly
        if let Some(section) =
            section_asm.push(header.pid, header.payload_unit_start, Some(payload))
            && scte35::parse_splice_info_section(&section).is_ok()
        {
            let base64 = base64::engine::general_purpose::STANDARD.encode(&section);
            cues.push(Scte35CueInfo {
                pts_90k: 0,
                timestamp: Duration::from_secs(0),
                payload: section,
                base64,
            });
            // don't double-count same payload as PES below
            continue;
        }

        if header.payload_unit_start {
            if let Some(prev) = current_pes.take()
                && let Some(cue) = parse_scte35_pes(&prev)?
            {
                cues.push(cue);
            }
            current_pes = Some(Vec::new());
        }
        if let Some(ref mut acc) = current_pes {
            acc.extend_from_slice(payload);
        }
    }
    if let Some(prev) = current_pes.take()
        && let Some(cue) = parse_scte35_pes(&prev)?
    {
        cues.push(cue);
    }
    Ok(cues)
}

fn parse_scte35_pes(pes: &[u8]) -> Result<Option<Scte35CueInfo>> {
    if pes.len() < 9 {
        return Ok(None);
    }
    if pes[0] != 0x00 || pes[1] != 0x00 || pes[2] != 0x01 {
        return Ok(None);
    }
    let stream_id = pes[3];
    if stream_id != 0xFC {
        return Ok(None);
    }
    let flags = pes[7];
    let header_data_len = pes[8] as usize;
    if pes.len() < 9 + header_data_len || pes.len() < 14 {
        return Ok(None);
    }
    let pts = if flags & 0x80 != 0 && header_data_len >= 5 {
        let b = &pes[9..14];
        Some(
            (((b[0] >> 1) as u64) & 0x07) << 30
                | ((b[1] as u64) << 22)
                | (((b[2] >> 1) as u64) << 15)
                | ((b[3] as u64) << 7)
                | ((b[4] >> 1) as u64),
        )
    } else {
        None
    };
    let payload_start = 9 + header_data_len;
    if payload_start >= pes.len() {
        return Ok(None);
    }
    let payload = pes[payload_start..].to_vec();
    let pts_90k = pts.unwrap_or(0);
    let ts = Duration::from_nanos(pts_90k * 1_000_000_000 / 90_000);
    let base64 = base64::engine::general_purpose::STANDARD.encode(&payload);
    Ok(Some(Scte35CueInfo {
        pts_90k,
        timestamp: ts,
        payload,
        base64,
    }))
}

fn find_scte35_pid(path: &Path) -> Result<Option<u16>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 188];
    let mut assembler = super::PsiAssembler::default();
    let mut pmt_pid: Option<u16> = None;
    while reader.read_exact(&mut buf).is_ok() {
        if buf[0] != 0x47 {
            return Err(anyhow!("sync byte missing"));
        }
        let header = TsHeader::parse(&buf)?;
        let payload = header.payload(&buf)?;
        if header.pid == 0x0000
            && let Some(section) = assembler.push(header.pid, header.payload_unit_start, payload)
            && let Some(pid) = parse_pat(&section)?
        {
            pmt_pid = Some(pid);
        } else if Some(header.pid) == pmt_pid
            && let Some(section) = assembler.push(header.pid, header.payload_unit_start, payload)
        {
            let pmt = parse_pmt(&section)?;
            for es in pmt.es_info {
                if es.stream_type == 0x86 {
                    return Ok(Some(es.pid));
                }
            }
        }
        // stop early if found
    }
    Ok(None)
}

/// Fallback scan: look for any PID carrying PES with stream_id 0xFC and valid splice_info_section.
fn scan_scte35_pid_by_pes(path: &Path) -> Result<Option<u16>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = [0u8; 188];
    let mut acc: std::collections::HashMap<u16, Vec<u8>> = std::collections::HashMap::new();

    while reader.read_exact(&mut buf).is_ok() {
        if buf[0] != 0x47 {
            return Err(anyhow!("sync byte missing"));
        }
        let header = TsHeader::parse(&buf)?;
        let payload = match header.payload(&buf)? {
            Some(p) => p,
            None => continue,
        };

        if header.payload_unit_start {
            if let Some(prev) = acc.remove(&header.pid)
                && parse_scte35_pes(&prev)?.is_some()
            {
                return Ok(Some(header.pid));
            }
            acc.insert(header.pid, Vec::new());
        }
        if let Some(entry) = acc.get_mut(&header.pid) {
            entry.extend_from_slice(payload);
            if parse_scte35_pes(entry)?.is_some() {
                return Ok(Some(header.pid));
            }
        }
    }
    Ok(None)
}
