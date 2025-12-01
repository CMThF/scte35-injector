use anyhow::{anyhow, Context, Result};
use base64::Engine;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Duration;

/// In-memory representation of a cue to inject.
#[derive(Debug, Clone, PartialEq)]
pub struct Cue {
    pub timestamp: Duration,
    pub payload: Vec<u8>,
}

const MAX_SECTION_SIZE: usize = 4096;

/// Parse a cue argument of the form `hh:mm:ss.sss=<base64>`.
pub fn parse_cue_arg(raw: &str) -> Result<Cue> {
    let (ts_str, b64_str) = raw
        .split_once('=')
        .ok_or_else(|| anyhow!("cue must look like hh:mm:ss.sss=<base64>"))?;

    let timestamp = parse_timestamp(ts_str)?;

    let payload = base64::engine::general_purpose::STANDARD
        .decode(b64_str)
        .context("base64 decode failed")?;

    if payload.len() > MAX_SECTION_SIZE {
        return Err(anyhow!(
            "SCTE-35 payload too large: {} bytes (max {})",
            payload.len(),
            MAX_SECTION_SIZE
        ));
    }

    // Validate SCTE-35 section structure.
    scte35::parse_splice_info_section(&payload)
        .context("invalid SCTE-35 splice_info_section")?;

    Ok(Cue { timestamp, payload })
}

pub mod inject;
pub mod list;

/// Parse wall-clock timestamp `hh:mm:ss[.sss]` into Duration.
pub fn parse_timestamp(raw: &str) -> Result<Duration> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 3 {
        return Err(anyhow!("timestamp must be hh:mm:ss[.sss]"));
    }
    let hours: u64 = parts[0]
        .parse()
        .context("invalid hours")?;
    let minutes: u64 = parts[1]
        .parse()
        .context("invalid minutes")?;
    if minutes >= 60 {
        return Err(anyhow!("minutes must be < 60"));
    }

    let (secs, millis) = if let Some((s, frac)) = parts[2].split_once('.') {
        (s, Some(frac))
    } else {
        (parts[2], None)
    };

    let seconds: u64 = secs
        .parse()
        .context("invalid seconds")?;
    if seconds >= 60 {
        return Err(anyhow!("seconds must be < 60"));
    }

    let mut duration =
        Duration::from_secs(hours * 3600 + minutes * 60 + seconds);

    if let Some(frac) = millis {
        // Pad / trim to milliseconds precision.
        let frac_trimmed = &frac.chars().take(3).collect::<String>();
        let millis: u64 = frac_trimmed
            .parse()
            .context("invalid fractional seconds")?;
        duration += Duration::from_millis(millis);
    }

    Ok(duration)
}

/// Hints for probing the TS when picking reference PIDs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProbeHints {
    pub scte35_pid: Option<u16>,
    pub pcr_pid: Option<u16>,
    pub video_pid: Option<u16>,
}

/// Basic metadata extracted from an MPEG-TS.
#[derive(Debug)]
pub struct TsMetadata {
    pub pmt_pid: Option<u16>,
    pub pcr_pid: Option<u16>,
    pub scte35_pid: Option<u16>,
    pub video_pid: Option<u16>,
    /// All used PID values found.
    pub used_pids: HashSet<u16>,
    /// PTS timeline for the chosen video_pid (packet index, pts 90kHz).
    pub timeline: Vec<PacketPts>,
    /// First seen PMT section (raw bytes, no pointer_field).
    pub pmt_section: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketPts {
    pub packet_index: u64,
    pub pts_90k: u64,
}

/// Simple continuity counter tracker.
#[derive(Default)]
pub struct Continuity {
    map: HashMap<u16, u8>,
}
impl Continuity {
    pub fn peek(&self, pid: u16) -> Option<u8> {
        self.map.get(&pid).copied()
    }
    pub fn next(&mut self, pid: u16, suggested: Option<u8>) -> u8 {
        let entry = self.map.entry(pid).or_insert_with(|| suggested.unwrap_or(0));
        let current = *entry;
        *entry = (current + 1) & 0x0F;
        current
    }
}

/// Convert wall-clock duration to 90kHz PTS ticks.
pub fn duration_to_pts(duration: Duration) -> Result<u64> {
    let nanos = duration.as_nanos();
    let pts = nanos
        .saturating_mul(90_000)
        .checked_div(1_000_000_000)
        .ok_or_else(|| anyhow!("Duration conversion overflow"))?;
    if pts > u64::MAX as u128 {
        return Err(anyhow!("Duration too large for pts: {:?}", duration));
    }
    Ok(pts as u64)
}

/// Choose insertion packet index at/before the desired PTS.
pub fn choose_insertion_packet(timeline: &[PacketPts], target_pts: u64) -> Option<PacketPts> {
    if timeline.is_empty() {
        return None;
    }
    // Find last point with pts <= target, else first.
    let mut chosen = timeline[0];
    for pt in timeline {
        if pt.pts_90k <= target_pts {
            chosen = *pt;
        } else {
            break;
        }
    }
    Some(chosen)
}

/// Probe a TS file: discover PAT/PMT, PCR, video PID, SCTE-35 PID and gather PTS timeline.
pub fn probe_ts(path: &Path, hints: ProbeHints) -> Result<TsMetadata> {
    let file = File::open(path).with_context(|| format!("open {:?}", path))?;
    let mut reader = BufReader::new(file);

    let mut used_pids = HashSet::new();
    let mut assembler = PsiAssembler::default();

    let mut pmt_pid: Option<u16> = None;
    let mut pcr_pid: Option<u16> = hints.pcr_pid;
    let mut scte35_pid: Option<u16> = hints.scte35_pid;
    let mut video_pid_hint = hints.video_pid;
    let mut stream_types: HashMap<u16, u8> = HashMap::new();
    let mut pts_map: HashMap<u16, Vec<PacketPts>> = HashMap::new();
    let mut pmt_section: Option<Vec<u8>> = None;

    let mut buf = [0u8; 188];
    let mut packet_index: u64 = 0;

    while reader.read_exact(&mut buf).is_ok() {
        if buf[0] != 0x47 {
            return Err(anyhow!("sync byte missing at packet {}", packet_index));
        }
        let header = TsHeader::parse(&buf)?;
        used_pids.insert(header.pid);

        let payload_start = header.payload_unit_start;
        let payload = header.payload(&buf)?;

        // PAT
        if header.pid == 0x0000
            && let Some(section) = assembler.push(header.pid, payload_start, payload)
            && let Some(pmt) = parse_pat(&section)?
        {
            pmt_pid = Some(pmt);
        }
        // PMT
        if let Some(pid) = pmt_pid
            && header.pid == pid
            && let Some(section) = assembler.push(header.pid, payload_start, payload)
        {
            if pmt_section.is_none() {
                pmt_section = Some(section.clone());
            }
            let pmt = parse_pmt(&section)?;
            if pcr_pid.is_none() {
                pcr_pid = pmt.pcr_pid;
            }
            for es in pmt.es_info {
                stream_types.insert(es.pid, es.stream_type);
                if scte35_pid.is_none() && es.stream_type == 0x86 {
                    scte35_pid = Some(es.pid);
                }
                if video_pid_hint.is_none()
                    && matches!(es.stream_type, 0x1B | 0x24 | 0x02)
                {
                    video_pid_hint = Some(es.pid);
                }
            }
        }

        // PTS collection for candidate streams
        if let Some(payload) = payload
            && payload_start
            && let Some(pts) = parse_pes_pts(payload)
        {
            let pid = header.pid;
            pts_map
                .entry(pid)
                .or_default()
                .push(PacketPts { packet_index, pts_90k: pts });
        }

        packet_index += 1;
    }

    let video_pid = video_pid_hint;
    let timeline = video_pid
        .and_then(|pid| pts_map.remove(&pid))
        .unwrap_or_default();

    Ok(TsMetadata {
        pmt_pid,
        pcr_pid,
        scte35_pid,
        video_pid,
        used_pids,
        timeline,
        pmt_section,
    })
}

// --- Minimal MPEG-TS parsing helpers --------------------------------------

#[derive(Debug)]
struct TsHeader {
    pid: u16,
    payload_unit_start: bool,
    adaptation_field_control: u8,
    payload_offset: usize,
}

impl TsHeader {
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() != 188 {
            return Err(anyhow!("TS packet must be 188 bytes"));
        }
        let payload_unit_start = (buf[1] & 0x40) != 0;
        let pid = ((buf[1] & 0x1F) as u16) << 8 | buf[2] as u16;
        let adaptation_field_control = (buf[3] & 0b0011_0000) >> 4;

        let mut offset = 4;
        if adaptation_field_control == 0b10 || adaptation_field_control == 0b11 {
            let af_len = buf[4] as usize;
            offset += 1 + af_len;
        }

        Ok(TsHeader {
            pid,
            payload_unit_start,
            adaptation_field_control,
            payload_offset: offset,
        })
    }

    fn payload<'a>(&self, buf: &'a [u8]) -> Result<Option<&'a [u8]>> {
        if self.adaptation_field_control == 0b01 || self.adaptation_field_control == 0b11 {
            if self.payload_offset > buf.len() {
                return Err(anyhow!("payload offset beyond packet"));
            }
            Ok(Some(&buf[self.payload_offset..]))
        } else {
            Ok(None)
        }
    }
}

#[derive(Default)]
pub(crate) struct PsiAssembler {
    buf: HashMap<u16, Vec<u8>>,
    expected_len: HashMap<u16, usize>,
}

impl PsiAssembler {
    fn push(&mut self, pid: u16, payload_start: bool, payload: Option<&[u8]>) -> Option<Vec<u8>> {
        let payload = payload?;
        let mut idx = 0;
        if payload_start {
            if payload.is_empty() {
                return None;
            }
            let pointer_field = payload[0] as usize;
            idx = 1 + pointer_field;
            if idx > payload.len() {
                return None;
            }
            self.buf.insert(pid, Vec::new());
            self.expected_len.remove(&pid);
        }
        let entry = self.buf.entry(pid).or_default();
        if idx > payload.len() {
            return None;
        }
        entry.extend_from_slice(&payload[idx..]);
        let len = *self.expected_len.entry(pid).or_insert_with(|| {
            if entry.len() >= 3 {
                let section_length =
                    ((entry[1] as usize & 0x0F) << 8) | (entry[2] as usize);
                3 + section_length
            } else {
                usize::MAX
            }
        });
        if entry.len() >= len && len != usize::MAX {
            let full = entry[..len].to_vec();
            self.buf.remove(&pid);
            self.expected_len.remove(&pid);
            Some(full)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct PatProgram {
    pub program_number: u16,
    pub pmt_pid: u16,
}

fn parse_pat(section: &[u8]) -> Result<Option<u16>> {
    if section.len() < 8 {
        return Err(anyhow!("PAT section too short"));
    }
    if section[0] != 0x00 {
        return Err(anyhow!("PAT table_id must be 0x00"));
    }
    let section_length = ((section[1] as usize & 0x0F) << 8) | section[2] as usize;
    if section.len() < section_length + 3 {
        return Err(anyhow!("PAT incomplete"));
    }
    // skip: table_id(1), section_length(2), transport_stream_id(2), flags/version(2), section_number(1), last_section_number(1)
    let mut idx = 8;
    let mut programs = Vec::new();
    while idx + 4 <= 3 + section_length - 4 {
        let program_number = (section[idx] as u16) << 8 | section[idx + 1] as u16;
        let pid = ((section[idx + 2] as u16 & 0x1F) << 8) | section[idx + 3] as u16;
        programs.push(PatProgram {
            program_number,
            pmt_pid: pid,
        });
        idx += 4;
    }
    // choose first non-zero program
    let pmt_pid = programs
        .into_iter()
        .find(|p| p.program_number != 0)
        .map(|p| p.pmt_pid);
    Ok(pmt_pid)
}

#[derive(Debug)]
struct PmtInfo {
    pub pcr_pid: Option<u16>,
    pub es_info: Vec<PmtEsInfo>,
}

#[derive(Debug)]
struct PmtEsInfo {
    pub stream_type: u8,
    pub pid: u16,
}

fn parse_pmt(section: &[u8]) -> Result<PmtInfo> {
    if section.len() < 12 {
        return Err(anyhow!("PMT section too short"));
    }
    if section[0] != 0x02 {
        return Err(anyhow!("PMT table_id must be 0x02"));
    }
    let section_length = ((section[1] as usize & 0x0F) << 8) | section[2] as usize;
    if section.len() < section_length + 3 {
        return Err(anyhow!("PMT incomplete"));
    }
    let pcr_pid = {
        let pid = ((section[8] as u16 & 0x1F) << 8) | section[9] as u16;
        if pid == 0x1FFF {
            None
        } else {
            Some(pid)
        }
    };
    let program_info_length = ((section[10] as usize & 0x0F) << 8) | section[11] as usize;
    let mut idx = 12 + program_info_length;
    let end = 3 + section_length - 4; // exclude CRC
    let mut es_info = Vec::new();
    while idx + 5 <= end {
        let stream_type = section[idx];
        let elementary_pid =
            ((section[idx + 1] as u16 & 0x1F) << 8) | section[idx + 2] as u16;
        let es_info_length = ((section[idx + 3] as usize & 0x0F) << 8) | section[idx + 4] as usize;
        es_info.push(PmtEsInfo {
            stream_type,
            pid: elementary_pid,
        });
        idx += 5 + es_info_length;
    }
    Ok(PmtInfo { pcr_pid, es_info })
}

fn parse_pes_pts(payload: &[u8]) -> Option<u64> {
    if payload.len() < 14 {
        return None;
    }
    if payload[0] != 0x00 || payload[1] != 0x00 || payload[2] != 0x01 {
        return None;
    }
    let flags = payload[7];
    let pts_dts_flags = (flags >> 6) & 0b11;
    let header_data_len = payload[8] as usize;
    if pts_dts_flags & 0b10 == 0 {
        return None;
    }
    if payload.len() < 9 + header_data_len || header_data_len < 5 {
        return None;
    }
    let b = &payload[9..14];
    let pts = (((b[0] >> 1) as u64) & 0x07) << 30
        | ((b[1] as u64) << 22)
        | (((b[2] >> 1) as u64) << 15)
        | ((b[3] as u64) << 7)
        | ((b[4] >> 1) as u64);
    Some(pts)
}

/// Allocate a free PID >= 0x30.
pub fn allocate_pid(used: &HashSet<u16>) -> Result<u16> {
    for pid in 0x30..0x1FFF {
        if !used.contains(&pid) {
            return Ok(pid);
        }
    }
    Err(anyhow!("No available PIDs in range 0x30-0x1FFE"))
}

/// Build a new PMT section by appending SCTE-35 stream_type 0x86 with given PID.
pub fn build_pmt_with_scte35(existing: &[u8], new_pid: u16) -> Result<Vec<u8>> {
    if existing.len() < 12 || existing[0] != 0x02 {
        return Err(anyhow!("invalid PMT section"));
    }
    let section_length = ((existing[1] as usize & 0x0F) << 8) | existing[2] as usize;
    let body_len = section_length + 3; // table_id + length bytes included
    if existing.len() < body_len {
        return Err(anyhow!("PMT section incomplete"));
    }
    let mut base = existing[..body_len - 4].to_vec(); // without CRC
    // bump version_number (byte 5: bits 1..5)
    if base.len() > 5 {
        let ver = (base[5] >> 1) & 0x1F;
        let new_ver = (ver + 1) & 0x1F;
        base[5] = (base[5] & 0b1100_0001) | (new_ver << 1);
    }

    // Program-level registration descriptor "CUEI" (common in the wild).
    let reg_desc: [u8; 6] = [0x05, 0x04, b'C', b'U', b'E', b'I'];
    let prog_info_len = (((base[10] & 0x0F) as usize) << 8) | base[11] as usize;
    let prog_info_start = 12;
    let prog_info_end = prog_info_start + prog_info_len;
    let mut delta_len = 0usize;
    if prog_info_end > base.len() {
        return Err(anyhow!("PMT program_info_length inconsistent"));
    }
    let has_reg = base[prog_info_start..prog_info_end]
        .windows(reg_desc.len())
        .any(|w| w == reg_desc);
    if !has_reg {
        base.splice(prog_info_end..prog_info_end, reg_desc.iter().cloned());
        let new_len = prog_info_len + reg_desc.len();
        base[10] = (base[10] & 0xF0) | ((new_len >> 8) as u8 & 0x0F);
        base[11] = (new_len & 0xFF) as u8;
        delta_len += reg_desc.len();
    }

    // Append new ES entry for SCTE-35. ES info kept empty (descriptor already at program level).
    let es_info_len: u16 = 0;
    base.push(0x86); // stream_type
    base.push(((new_pid >> 8) as u8) | 0xE0);
    base.push((new_pid & 0xFF) as u8);
    base.push(0xF0 | ((es_info_len >> 8) as u8 & 0x0F));
    base.push((es_info_len & 0xFF) as u8);

    // Update section_length (starts at byte 1 bits 0..11)
    let new_section_length = section_length + 5 + delta_len;
    if new_section_length > 0x0FFF {
        return Err(anyhow!("PMT section too large after adding SCTE stream"));
    }
    base[1] = (base[1] & 0xF0) | ((new_section_length >> 8) as u8 & 0x0F);
    base[2] = (new_section_length & 0xFF) as u8;

    // Recompute CRC32 (MPEG-2 polynomial)
    use crc::{Crc, CRC_32_MPEG_2};
    let crc_calc = Crc::<u32>::new(&CRC_32_MPEG_2);
    let crc = crc_calc.checksum(&base);
    let mut full = base;
    full.extend_from_slice(&crc.to_be_bytes());
    Ok(full)
}

/// Packetize a PMT section into TS packets (single section), returns packets.
pub fn packetize_pmt(section: &[u8], pid: u16, cc: &mut Continuity) -> Result<Vec<[u8; 188]>> {
    packetize_section(section, pid, cc)
}

/// Packetize SCTE-35 cue payload into TS packets on given PID at PTS.
pub fn packetize_scte35(
    pid: u16,
    _pts_90k: u64,
    payload: &[u8],
    cc: &mut Continuity,
) -> Result<Vec<[u8; 188]>> {
    // section_length is 12 bits; max section size is 4096 including CRC.
    if payload.len() > 4093 {
        return Err(anyhow!(
            "SCTE-35 section too large: {} bytes (max 4093)",
            payload.len()
        ));
    }
    // Carry SCTE-35 as private section (table_id 0xFC) for better downstream detection.
    packetize_section(payload, pid, cc)
}

fn packetize_section(section: &[u8], pid: u16, cc: &mut Continuity) -> Result<Vec<[u8; 188]>> {
    // PSI requires pointer_field when payload_unit_start_indicator=1
    let mut data = Vec::with_capacity(section.len() + 1);
    data.push(0); // pointer_field = 0
    data.extend_from_slice(section);
    packetize_payload(pid, true, &data, cc)
}

fn packetize_payload(
    pid: u16,
    payload_unit_start: bool,
    payload: &[u8],
    cc: &mut Continuity,
) -> Result<Vec<[u8; 188]>> {
    let mut packets = Vec::new();
    let mut idx = 0usize;
    let mut first = true;
    while idx < payload.len() {
        let remaining = payload.len() - idx;
        let payload_capacity = 184usize;
        let (adaptation, payload_len, afc) = if remaining < payload_capacity {
            // Need stuffing
            let l = 183 - remaining; // adaptation_field_length
        let mut af = Vec::with_capacity(l + 1);
        af.push(l as u8);
        if l > 0 {
            af.push(0x00); // flags
            af.extend(std::iter::repeat_n(0xFF, l - 1));
        }
        (af, remaining, 0b11)
        } else {
            (Vec::new(), payload_capacity, 0b01)
        };

        let mut pkt = Vec::with_capacity(188);
        pkt.push(0x47);
        let b1 = ((payload_unit_start && first) as u8) << 6 | ((pid >> 8) as u8 & 0x1F);
        pkt.push(b1);
        pkt.push((pid & 0xFF) as u8);
        let cc_val = cc.next(pid, None);
        pkt.push((afc << 4) | (cc_val & 0x0F));
        if afc & 0b10 != 0 {
            pkt.extend_from_slice(&adaptation);
        }
        let end = idx + payload_len;
        pkt.extend_from_slice(&payload[idx..end]);
        idx = end;

        // Stuff if somehow short (should not)
        while pkt.len() < 188 {
            pkt.push(0xFF);
        }
        packets.push(pkt.try_into().unwrap());
        first = false;
    }
    Ok(packets)
}


// --- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::io::Cursor;

    #[test]
    fn parse_timestamp_ok() {
        let d = parse_timestamp("01:02:03.450").unwrap();
        assert_eq!(d.as_secs(), 3723);
        assert_eq!(d.subsec_millis(), 450);
    }

    #[test]
    fn parse_timestamp_no_fraction() {
        let d = parse_timestamp("00:00:10").unwrap();
        assert_eq!(d.as_secs(), 10);
    }

    #[test]
    fn parse_timestamp_reject_minutes() {
        assert!(parse_timestamp("00:65:00").is_err());
    }

    #[test]
    fn parse_cue_arg_valid() {
        // Example from crate docs: time_signal with segmentation descriptor
        let b64 = "/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==";
        let cue = parse_cue_arg(&format!("00:00:01.000={}", b64)).unwrap();
        assert_eq!(cue.timestamp, Duration::from_secs(1));
        let decoded_len = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap()
            .len();
        assert_eq!(cue.payload.len(), decoded_len);
    }

    #[test]
    fn parse_cue_arg_invalid_base64() {
        assert!(parse_cue_arg("00:00:01=!!!").is_err());
    }

    #[test]
    fn parse_cue_arg_invalid_timestamp() {
        let b64 = "FC30CgABAAAAAAABf///wAhAA==";
        assert!(parse_cue_arg(&format!("bad={}", b64)).is_err());
    }

    #[test]
    fn parse_pes_pts_bytes() {
        // Build minimal PES header with PTS only.
        let pts_val: u64 = 90_000; // 1s
        let pts_bytes = [
            (0x20 | (((pts_val >> 30) as u8 & 0x07) << 1) | 1),
            ((pts_val >> 22) as u8),
            (((pts_val >> 15) as u8 & 0x7F) << 1) | 1,
            ((pts_val >> 7) as u8),
            (((pts_val & 0x7F) as u8) << 1) | 1,
        ];
        let mut payload = vec![
            0x00, 0x00, 0x01, 0xE0, // start code + stream_id (video)
            0x00, 0x00, // packet length (ignored)
            0x80,       // flags: '10' for pts only
            0x80,       // PTS_DTS_flags=10, rest zero
            0x05,       // header data length
        ];
        payload.extend_from_slice(&pts_bytes);
        let parsed = parse_pes_pts(&payload).expect("pts present");
        assert_eq!(parsed, pts_val);
    }

    #[test]
    fn psi_assembler_reassembles() {
        let mut asm = PsiAssembler::default();
        // Example PAT section split across two payloads.
        let section: Vec<u8> = vec![
            0x00, 0xb0, 0x0d, 0x00, 0x01, 0xc1, 0x00, 0x00, 0x00, 0x01, 0xf0, 0x01, 0x2c, 0xb1,
            0x04, 0xb2,
        ];
        let first = [&[0u8][..], &section[..8]].concat();
        let second = section[8..].to_vec();

        assert!(asm.push(0, true, Some(&first)).is_none());
        let complete = asm.push(0, false, Some(&second)).expect("complete");
        assert_eq!(complete, section);
    }

    #[test]
    fn parse_pmt_basic() {
        // PMT with PCR pid 0x0100 and one H264 stream pid 0x0101
        let section: Vec<u8> = vec![
            0x02, 0xb0, 0x12, 0x00, 0x01, 0xc1, 0x00, 0x00, 0xe1, 0x00, 0xf0, 0x00, 0x1b, 0xe1,
            0x01, 0xf0, 0x00, 0x2a, 0xb1, 0x04, 0xb2,
        ];
        let pmt = parse_pmt(&section).unwrap();
        assert_eq!(pmt.pcr_pid, Some(0x0100));
        assert_eq!(pmt.es_info.len(), 1);
        assert_eq!(pmt.es_info[0].pid, 0x0101);
        assert_eq!(pmt.es_info[0].stream_type, 0x1B);
    }

    #[test]
    fn duration_to_pts_roundtrip() {
        let d = Duration::from_millis(1500);
        let pts = duration_to_pts(d).unwrap();
        assert_eq!(pts, 135_000);
    }

    #[test]
    fn packetize_scte35_basic() {
        let mut cc = Continuity::default();
        let b64 = "/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==";
        let payload = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let packets = packetize_scte35(0x1FFE, 90_000, &payload, &mut cc).unwrap();
        assert!(!packets.is_empty());
        for p in &packets {
            assert_eq!(p.len(), 188);
            assert_eq!(p[0], 0x47);
        }
        // First packet should have PUSI set
        assert_eq!(packets[0][1] & 0x40, 0x40);
    }

    #[test]
    fn choose_insertion_packet_before_target() {
        let timeline = vec![
            PacketPts { packet_index: 10, pts_90k: 90_000 },
            PacketPts { packet_index: 20, pts_90k: 180_000 },
            PacketPts { packet_index: 30, pts_90k: 270_000 },
        ];
        let chosen = choose_insertion_packet(&timeline, 200_000).unwrap();
        assert_eq!(chosen.packet_index, 20);
    }

    #[test]
    fn build_pmt_with_new_scte35() {
        // PMT with PCR pid 0x0100 and one H264 stream pid 0x0101
        let section: Vec<u8> = vec![
            0x02, 0xb0, 0x12, 0x00, 0x01, 0xc1, 0x00, 0x00, 0xe1, 0x00, 0xf0, 0x00, 0x1b, 0xe1,
            0x01, 0xf0, 0x00, 0x2a, 0xb1, 0x04, 0xb2,
        ];
        let new_sec = build_pmt_with_scte35(&section, 0x1FFE).unwrap();
        let old_len = ((section[1] as usize & 0x0F) << 8) | section[2] as usize;
        let new_len = ((new_sec[1] as usize & 0x0F) << 8) | new_sec[2] as usize;
        // added ES info is 5 bytes + 6-byte reg descriptor = 11 bytes
        assert_eq!(new_len, old_len + 11);
        assert_eq!(new_sec.len(), 3 + new_len);
        // Program-level reg descriptor added
        let prog_info_len = ((new_sec[10] as usize & 0x0F) << 8) | new_sec[11] as usize;
        let prog_info = &new_sec[12..12 + prog_info_len];
        assert!(
            prog_info.windows(6).any(|w| w == b"\x05\x04CUEI"),
            "registration descriptor missing"
        );
        // ES entry present with stream_type and PID (last entry)
        let es_pos = new_sec.len() - 4 - 5;
        assert_eq!(new_sec[es_pos], 0x86);
        let pid = ((new_sec[es_pos + 1] as u16 & 0x1F) << 8) | new_sec[es_pos + 2] as u16;
        assert_eq!(pid, 0x1FFE);
    }

    #[test]
    fn list_cues_from_generated_packets() {
        // Build TS packets with a single SCTE-35 cue at 1s.
        let mut cc = Continuity::default();
        let payload = base64::engine::general_purpose::STANDARD
            .decode("/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==")
            .unwrap();
        let splice = scte35::parse_splice_info_section(&payload).unwrap();
        let expected_pts =
            crate::list::splice_command_pts(&splice.splice_command, splice.pts_adjustment)
                .unwrap_or(0);
        let packets = packetize_scte35(0x30, 90_000, &payload, &mut cc).unwrap();
        let mut bytes = Vec::new();
        for p in packets {
            bytes.extend_from_slice(&p);
        }
        let cues = crate::list::list_scte35_cues_from_reader(
            Cursor::new(bytes),
            0x30,
            Some(0),
            None
        ).unwrap();
        assert_eq!(cues.len(), 1);
        assert_eq!(cues[0].pts_90k, expected_pts);
        assert_eq!(cues[0].payload, payload);
    }

    #[test]
    fn probe_on_fixture_if_present() {
        // todo: pull from remote
        let path = PathBuf::from("../test-assets/tears_of_steel_1080p.ts");
        if !path.exists() {
            eprintln!("fixture missing, skipping");
            return;
        }
        let meta = probe_ts(&path, ProbeHints::default()).expect("probe ok");
        assert!(meta.pmt_pid.is_some());
        // We expect to discover at least one video PID and some timeline entries.
        assert!(meta.video_pid.is_some());
        assert!(!meta.timeline.is_empty());
    }
}
