use crate::{parse_pmt, parse_pat, ProbeHints, PsiAssembler, TsHeader};
use base64::Engine;
use anyhow::{anyhow, Result};
use scte35::SpliceCommand;
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
    let meta = crate::probe_ts(path, hints)?;
    let base_pts = meta.timeline.first().map(|p| p.pts_90k);
    let scte35_pid = if let Some(pid) = hints.scte35_pid {
        pid
    } else if let Some(pid) = meta.scte35_pid {
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
    list_scte35_cues_from_reader(reader, scte35_pid, base_pts, Some(&meta.timeline))
}

/// Internal helper for testing; consumes any reader of TS packets.
pub fn list_scte35_cues_from_reader<R: Read>(
    mut reader: R,
    scte35_pid: u16,
    base_pts_90k: Option<u64>,
    timeline: Option<&[crate::PacketPts]>,
) -> Result<Vec<Scte35CueInfo>> {
    let mut buf = [0u8; 188];
    let mut cues = Vec::new(); // temporary with packet index
    let mut current_pes: Option<Vec<u8>> = None;
    let mut section_asm = PsiAssembler::default();
    let mut packet_index: u64 = 0;

    while reader.read_exact(&mut buf).is_ok() {
        let this_index = packet_index;
        packet_index += 1;
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
            let splice = scte35::parse_splice_info_section(&section).unwrap();
            let pts_90k_raw =
                splice_command_pts(&splice.splice_command, splice.pts_adjustment).unwrap_or(0);
            let pts_90k = if let Some(base) = base_pts_90k {
                base + pts_wrap_delta(base, pts_90k_raw)
            } else {
                pts_90k_raw
            };
            let timestamp =
                std::time::Duration::from_nanos(pts_90k.saturating_mul(1_000_000_000) / 90_000);
            let base64 = base64::engine::general_purpose::STANDARD.encode(&section);
            cues.push((this_index, Scte35CueInfo {
                pts_90k,
                timestamp,
                payload: section,
                base64,
            }));
            // don't double-count same payload as PES below
            continue;
        }

        if header.payload_unit_start {
            if let Some(prev) = current_pes.take()
                && let Some(cue) = parse_scte35_pes(&prev)?
            {
                cues.push((this_index.saturating_sub(1), cue));
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
        let mut cue = cue;
        if let Some(base) = base_pts_90k {
            cue.pts_90k = base + pts_wrap_delta(base, cue.pts_90k);
            cue.timestamp =
                Duration::from_nanos(cue.pts_90k.saturating_mul(1_000_000_000) / 90_000);
        }
        cues.push((packet_index, cue));
    }
    // advance packet_index when loop terminates? not needed

    // Rebase PTS using observed timeline if available; prefer timeline mapping over splice payload.
    let mapped = cues
        .into_iter()
        .map(|(idx, mut cue)| {
            if let Some(tl) = timeline
                && !tl.is_empty()
            {
                // choose nearest timeline entry by packet index
                let mut prev = tl[0];
                let mut next: Option<crate::PacketPts> = None;
                for t in tl {
                    if t.packet_index <= idx {
                        prev = *t;
                    } else {
                        next = Some(*t);
                        break;
                    }
                }
                let interp_pts = if let Some(n) = next
                    && n.packet_index > prev.packet_index
                    && n.pts_90k != prev.pts_90k
                {
                    let span_packets = n.packet_index - prev.packet_index;
                    let offset_packets = idx.saturating_sub(prev.packet_index);
                    let span_pts = pts_wrap_delta(prev.pts_90k, n.pts_90k);
                    prev.pts_90k + (span_pts * offset_packets / span_packets)
                } else {
                    prev.pts_90k
                };
                let base = tl[0].pts_90k;
                cue.pts_90k = base + pts_wrap_delta(base, interp_pts);
                cue.timestamp =
                    Duration::from_nanos(cue.pts_90k.saturating_mul(1_000_000_000) / 90_000);
            }
            cue
        })
        .collect();

    Ok(mapped)
}

pub(crate) fn splice_command_pts(cmd: &SpliceCommand, pts_adjustment: u64) -> Option<u64> {
    let raw = match cmd {
        SpliceCommand::TimeSignal(ts) => ts.splice_time.pts_time,
        SpliceCommand::SpliceInsert(si) => si.splice_time.as_ref().and_then(|t| t.pts_time),
        SpliceCommand::SpliceSchedule(_) => None, // schedule carries UTC, not PTS
        _ => None,
    }?;
    // Apply pts_adjustment per SCTE-35 (33-bit wrap)
    let total = (raw + pts_adjustment) & ((1u64 << 33) - 1);
    Some(total)
}

fn pts_wrap_delta(base: u64, target: u64) -> u64 {
    // compute forward delta on 33-bit ring then add to zero to get relative
    let modulus = 1u64 << 33;
    let base_mod = base % modulus;
    let target_mod = target % modulus;
    if target_mod >= base_mod {
        target_mod - base_mod
    } else {
        modulus - base_mod + target_mod
    }
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
