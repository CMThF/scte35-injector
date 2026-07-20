use std::io::Cursor;
use std::time::Duration;

use base64::Engine;
use scte35_injector::{
    build_pmt_with_scte35, duration_to_pts, list::list_scte35_cues_from_reader, packetize_scte35,
    parse_cue_arg, parse_timestamp, rewrite_splice_time,
};

#[test]
fn parse_timestamp_invalid_format() {
    assert!(parse_timestamp("not-a-time").is_err());
    assert!(parse_timestamp("00:00").is_err());
}

#[test]
fn parse_cue_arg_oversize_rejected() {
    let big = vec![0u8; 4097];
    let b64 = base64::engine::general_purpose::STANDARD.encode(&big);
    assert!(parse_cue_arg(&format!("00:00:00.000={}", b64)).is_err());
}

#[test]
fn packetize_scte35_payload_too_large() {
    let mut cc = scte35_injector::Continuity::default();
    let huge = vec![0u8; u16::MAX as usize];
    let err = packetize_scte35(0x30, 0, &huge, &mut cc).unwrap_err();
    assert!(err.to_string().contains("too large"));
}

#[test]
fn build_pmt_with_scte35_too_large_section() {
    // section_length at max (0x0FFF) so adding 5 bytes should fail
    let section_length = 0x0FFFusize;
    let mut sec = vec![
        0x02,
        0xF0 | ((section_length >> 8) as u8 & 0x0F),
        (section_length & 0xFF) as u8,
    ];
    sec.resize(3 + section_length, 0);
    assert!(build_pmt_with_scte35(&sec, 0x30).is_err());
}

#[test]
fn list_cues_from_reader_bad_stream_id_yields_none() {
    // Build a fake PES with stream_id 0xBD (not SCTE-35)
    let pes = vec![
        0x00, 0x00, 0x01, 0xBD, // start code + stream_id
        0x00, 0x00, // length
        0x80, 0x80, 0x05, // flags + header len
        0, 0, 0, 0, 0, // fake PTS bytes
        0xAA, 0xBB, 0xCC,
    ];
    // Wrap into one TS packet manually (pid 0x30)
    let mut pkt = vec![0x47, 0x40, 0x30, 0x10]; // PUSI=1, PID=0x30, afc=1, cc=0
    let mut payload = vec![0]; // pointer_field=0
    payload.extend_from_slice(&pes);
    payload.resize(184, 0xFF);
    pkt.extend_from_slice(&payload);
    let cues = list_scte35_cues_from_reader(Cursor::new(pkt), 0x30, Some(0), None).unwrap();
    assert!(cues.is_empty());
}

#[test]
fn duration_to_pts_large_does_not_panic() {
    // very large duration should not panic; value will saturate in u128 math then cast
    let d = Duration::from_secs(10_000_000);
    let _ = scte35_injector::duration_to_pts(d).unwrap();
}

// Real broadcast sections with splice_command_length == 0xFFF (legacy "not
// specified" sentinel), taken from issue #2. CRC-valid, unencrypted.
const B64_NULL_FFF: &str = "/DARAAAAAAAAAP///wAAAE8lM5Y=";
const B64_INSERT_OUT_FFF: &str =
    "/DAvAAAAAAAAAP///wUAAAKWf+//4WoauH4BTFYgAAEAAAAKAAhDVUVJAAAAABD6TZ4=";
const B64_INSERT_IN_FFF: &str = "/DAqAAAAAAAAAP///wUAAAKWf0//4rZw2AABAAAACgAIQ1VFSQAAAABuMzIe";

fn b64_decode(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
}

#[test]
fn parse_tolerates_unspecified_command_length() {
    let null = scte35_injector::parse_splice_info_section_tolerant(&b64_decode(B64_NULL_FFF))
        .expect("splice_null with cmd_len 0xFFF should parse");
    assert!(matches!(
        null.splice_command,
        scte35::SpliceCommand::SpliceNull
    ));
    assert_eq!(null.splice_command_length, 0xFFF);

    let payload = b64_decode(B64_INSERT_OUT_FFF);
    let out = scte35_injector::parse_splice_info_section_tolerant(&payload)
        .expect("splice_insert OUT with cmd_len 0xFFF should parse");
    assert_eq!(out.splice_command_length, 0xFFF);
    // On-wire CRC must be reported, not the normalized copy's CRC.
    assert_eq!(
        out.crc_32,
        u32::from_be_bytes(payload[payload.len() - 4..].try_into().unwrap())
    );
    let si = match out.splice_command {
        scte35::SpliceCommand::SpliceInsert(si) => si,
        other => panic!("expected SpliceInsert, got {:?}", other),
    };
    assert_eq!(si.out_of_network_indicator, 1);
    assert!(si.splice_time.and_then(|t| t.pts_time).is_some());
    assert!(si.break_duration.is_some());

    let inn = scte35_injector::parse_splice_info_section_tolerant(&b64_decode(B64_INSERT_IN_FFF))
        .expect("splice_insert IN with cmd_len 0xFFF should parse");
    let si = match inn.splice_command {
        scte35::SpliceCommand::SpliceInsert(si) => si,
        other => panic!("expected SpliceInsert, got {:?}", other),
    };
    assert_eq!(si.out_of_network_indicator, 0);
}

#[test]
fn list_cues_finds_sections_with_unspecified_command_length() {
    let mut cc = scte35_injector::Continuity::default();
    let payload = b64_decode(B64_INSERT_OUT_FFF);
    let packets = packetize_scte35(0x30, 90_000, &payload, &mut cc).unwrap();
    let mut bytes = Vec::new();
    for p in packets {
        bytes.extend_from_slice(&p);
    }
    let cues = list_scte35_cues_from_reader(Cursor::new(bytes), 0x30, Some(0), None).unwrap();
    assert_eq!(cues.len(), 1);
    // The original on-wire bytes must be reported, not a normalized copy.
    assert_eq!(cues[0].payload, payload);
}

#[test]
fn rewrite_splice_time_updates_pts() {
    let b64 = "/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==";
    let payload = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap();
    let new_pts = duration_to_pts(Duration::from_secs(30)).unwrap();
    let rewritten = rewrite_splice_time(&payload, new_pts).unwrap();
    let parsed = scte35::parse_splice_info_section(&rewritten).unwrap();
    assert_eq!(parsed.pts_adjustment, 0);
    let pts = match parsed.splice_command {
        scte35::SpliceCommand::TimeSignal(ts) => ts.splice_time.pts_time,
        _ => None,
    };
    assert_eq!(pts, Some(new_pts & ((1u64 << 33) - 1)));
}
