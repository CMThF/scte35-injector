//! Deterministic synthetic MPEG-TS fixture builder for fast CI tests.
//!
//! Produces small single- or multi-program transport streams with a valid
//! PAT, one PMT per program, video PES packets carrying monotonic PTS, and
//! optional null packets. Everything is byte-deterministic so outputs can be
//! pinned with golden hashes.

use crc::{CRC_32_MPEG_2, Crc};
use scte35_injector::{Continuity, packetize_pmt};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const NULL_PID: u16 = 0x1FFF;

/// One program in the synthetic mux.
#[derive(Debug, Clone, Copy)]
pub struct ProgramSpec {
    pub program_number: u16,
    pub pmt_pid: u16,
    pub video_pid: u16,
}

/// Shape of the synthetic stream.
#[derive(Debug, Clone)]
pub struct SyntheticSpec {
    pub programs: Vec<ProgramSpec>,
    /// Video frames per program.
    pub frames: u32,
    /// Null packets appended after each frame group.
    pub nulls_per_frame: u32,
    /// Re-emit PAT + PMTs every this many frames.
    pub psi_every_frames: u32,
    /// Emit an adaptation-field-only PCR packet on each video PID per frame
    /// (continuity counter repeats, per ISO 13818-1).
    pub pcr_packets: bool,
    /// Bump the PMT version to 1 for PSI emissions from this frame onward.
    pub bump_pmt_version_at_frame: Option<u32>,
}

impl Default for SyntheticSpec {
    fn default() -> Self {
        SyntheticSpec {
            programs: vec![ProgramSpec {
                program_number: 1,
                pmt_pid: 0x0100,
                video_pid: 0x0101,
            }],
            frames: 100,
            nulls_per_frame: 0,
            psi_every_frames: 25,
            pcr_packets: false,
            bump_pmt_version_at_frame: None,
        }
    }
}

/// First video PTS in the fixture (1s) and per-frame increment (25 fps).
pub const BASE_PTS: u64 = 90_000;
pub const FRAME_TICKS: u64 = 3_600;

/// Build the synthetic TS as raw bytes.
pub fn build_synthetic_ts(spec: &SyntheticSpec) -> Vec<u8> {
    let mut cc = Continuity::default();
    let mut out = Vec::new();

    let pat = build_pat_section(&spec.programs);

    let emit_psi = |out: &mut Vec<u8>, cc: &mut Continuity, version: u8| {
        for pkt in packetize_pmt(&pat, 0x0000, cc).expect("packetize PAT") {
            out.extend_from_slice(&pkt);
        }
        for program in &spec.programs {
            let section = build_pmt_section(program, version);
            for pkt in packetize_pmt(&section, program.pmt_pid, cc).expect("packetize PMT") {
                out.extend_from_slice(&pkt);
            }
        }
    };

    for frame in 0..spec.frames {
        if frame % spec.psi_every_frames == 0 {
            let version = match spec.bump_pmt_version_at_frame {
                Some(bump) if frame >= bump => 1,
                _ => 0,
            };
            emit_psi(&mut out, &mut cc, version);
        }
        let pts = BASE_PTS + u64::from(frame) * FRAME_TICKS;
        for program in &spec.programs {
            let pes = build_video_pes(pts, 16, (program.video_pid & 0xFF) as u8);
            for pkt in scte35_injector::packetize_payload(program.video_pid, true, &pes, &mut cc)
                .expect("packetize PES")
            {
                out.extend_from_slice(&pkt);
            }
            if spec.pcr_packets {
                let last_cc = cc.last_emitted(program.video_pid).unwrap_or(0);
                out.extend_from_slice(&adaptation_only_pcr_packet(
                    program.video_pid,
                    last_cc,
                    pts.saturating_sub(FRAME_TICKS),
                ));
            }
        }
        for _ in 0..spec.nulls_per_frame {
            out.extend_from_slice(&null_packet());
        }
    }
    out
}

/// Adaptation-field-only packet carrying a PCR. The continuity counter is not
/// incremented on payload-less packets, so `cc` must repeat the last value.
fn adaptation_only_pcr_packet(pid: u16, cc: u8, pcr_base: u64) -> [u8; 188] {
    let mut pkt = [0xFFu8; 188];
    pkt[0] = 0x47;
    pkt[1] = (pid >> 8) as u8 & 0x1F;
    pkt[2] = (pid & 0xFF) as u8;
    pkt[3] = 0x20 | (cc & 0x0F); // adaptation field only, no payload
    pkt[4] = 183; // adaptation_field_length fills the packet
    pkt[5] = 0x10; // PCR flag
    let base = pcr_base & ((1u64 << 33) - 1);
    pkt[6] = (base >> 25) as u8;
    pkt[7] = (base >> 17) as u8;
    pkt[8] = (base >> 9) as u8;
    pkt[9] = (base >> 1) as u8;
    pkt[10] = (((base & 1) as u8) << 7) | 0x7E; // reserved bits set, ext = 0
    pkt[11] = 0x00;
    pkt
}

/// Build the fixture and write it to a unique temp file; returns the path.
pub fn write_synthetic_ts(spec: &SyntheticSpec, name: &str) -> PathBuf {
    let bytes = build_synthetic_ts(spec);
    let path = tmp_path(name);
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

fn build_pat_section(programs: &[ProgramSpec]) -> Vec<u8> {
    // table_id, section_length placeholder, transport_stream_id=1,
    // version 0 / current_next=1, section_number 0, last_section_number 0.
    let mut sec = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0xC1, 0x00, 0x00];
    for p in programs {
        sec.push((p.program_number >> 8) as u8);
        sec.push((p.program_number & 0xFF) as u8);
        sec.push(0xE0 | ((p.pmt_pid >> 8) as u8 & 0x1F));
        sec.push((p.pmt_pid & 0xFF) as u8);
    }
    finish_section(sec)
}

fn build_pmt_section(program: &ProgramSpec, version: u8) -> Vec<u8> {
    let mut sec = vec![
        0x02,
        0x00,
        0x00,
        (program.program_number >> 8) as u8,
        (program.program_number & 0xFF) as u8,
        0xC1 | ((version & 0x1F) << 1),
        0x00,
        0x00,
        0xE0 | ((program.video_pid >> 8) as u8 & 0x1F), // PCR PID = video PID
        (program.video_pid & 0xFF) as u8,
        0xF0,
        0x00, // program_info_length = 0
    ];
    // Single H.264 elementary stream.
    sec.push(0x1B);
    sec.push(0xE0 | ((program.video_pid >> 8) as u8 & 0x1F));
    sec.push((program.video_pid & 0xFF) as u8);
    sec.push(0xF0);
    sec.push(0x00);
    finish_section(sec)
}

/// Fill in section_length (reserving 4 CRC bytes) and append the CRC.
fn finish_section(mut sec: Vec<u8>) -> Vec<u8> {
    let section_length = sec.len() - 3 + 4;
    sec[1] = 0xB0 | ((section_length >> 8) as u8 & 0x0F);
    sec[2] = (section_length & 0xFF) as u8;
    let crc = Crc::<u32>::new(&CRC_32_MPEG_2).checksum(&sec);
    sec.extend_from_slice(&crc.to_be_bytes());
    sec
}

fn build_video_pes(pts: u64, payload_len: usize, seed: u8) -> Vec<u8> {
    let mut pes = vec![0x00, 0x00, 0x01, 0xE0];
    // Bytes after PES_packet_length: flags(2) + header_len(1) + PTS(5) + payload.
    let pes_len = 3 + 5 + payload_len;
    pes.push((pes_len >> 8) as u8);
    pes.push((pes_len & 0xFF) as u8);
    pes.push(0x80); // marker bits
    pes.push(0x80); // PTS_DTS_flags = '10'
    pes.push(0x05); // header data length
    pes.push(0x20 | (((pts >> 30) as u8 & 0x07) << 1) | 1);
    pes.push((pts >> 22) as u8);
    pes.push((((pts >> 15) as u8 & 0x7F) << 1) | 1);
    pes.push((pts >> 7) as u8);
    pes.push((((pts & 0x7F) as u8) << 1) | 1);
    pes.extend((0..payload_len).map(|i| seed.wrapping_add(i as u8)));
    pes
}

pub fn null_packet() -> [u8; 188] {
    let mut pkt = [0xFFu8; 188];
    pkt[0] = 0x47;
    pkt[1] = 0x1F;
    pkt[2] = 0xFF;
    pkt[3] = 0x10;
    pkt
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn sha256_file_hex(path: &std::path::Path) -> String {
    sha256_hex(&std::fs::read(path).expect("read file for hashing"))
}

pub fn count_pid_packets(bytes: &[u8], pid: u16) -> u64 {
    bytes
        .chunks_exact(188)
        .filter(|pkt| pkt[0] == 0x47 && (((pkt[1] & 0x1F) as u16) << 8 | pkt[2] as u16) == pid)
        .count() as u64
}

/// Packet index of the first packet on the given PID, if any.
pub fn first_pid_packet_index(bytes: &[u8], pid: u16) -> Option<u64> {
    bytes
        .chunks_exact(188)
        .position(|pkt| pkt[0] == 0x47 && (((pkt[1] & 0x1F) as u16) << 8 | pkt[2] as u16) == pid)
        .map(|i| i as u64)
}

pub fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("{}_{}", nanos, name));
    p
}
