use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use scte35_injector::{ProbeHints, inject::inject_file, parse_cue_arg, probe_ts};

// End-to-end on provided fixture. Skips if fixture missing.
#[test]
fn injects_cue_and_finds_scte35_pid() {
    // todo: pull from remote
    let fixture = PathBuf::from("../test-assets/tears_of_steel_1080p.ts");
    if !fixture.exists() {
        eprintln!("fixture missing, skipping");
        return;
    }

    let out = tmp_path("out_inject.ts");

    let cue =
        parse_cue_arg("00:00:10.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==").expect("cue parse");

    inject_file(&fixture, &out, &[cue], ProbeHints::default()).expect("inject ok");

    let meta_out = probe_ts(&out, ProbeHints::default()).expect("probe out");
    let scte35_pid = meta_out
        .scte35_pid
        .expect("SCTE-35 PID should exist after injection");

    // PMT should list stream_type 0x86 for that PID.
    let pmt_section = meta_out.pmt_section.expect("pmt present");
    assert!(
        pmt_section
            .windows(5)
            .any(|w| w[0] == 0x86 && (((w[1] as u16 & 0x1F) << 8) | w[2] as u16) == scte35_pid),
        "PMT lacks SCTE-35 entry"
    );

    let scte_packets = count_pid_packets(&out, scte35_pid);
    assert!(scte_packets > 0, "expected SCTE-35 PID packets in output");

    // Output should be larger or equal than input (insertion adds packets).
    let in_size = fs::metadata(&fixture).unwrap().len();
    let out_size = fs::metadata(&out).unwrap().len();
    assert!(out_size >= in_size);

    // Cleanup
    let _ = fs::remove_file(&out);
}

// Second end-to-end: two cues at different times.
#[test]
fn injects_multiple_cues() {
    let fixture = PathBuf::from("../test-assets/tears_of_steel_1080p.ts");
    if !fixture.exists() {
        eprintln!("fixture missing, skipping");
        return;
    }

    let out = tmp_path("out_inject_multi.ts");

    let c1 = parse_cue_arg("00:00:05.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==").unwrap();
    let c2 = parse_cue_arg("00:00:15.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==").unwrap();
    let c3 =
        parse_cue_arg("00:00:25.000@00:00:30.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==").unwrap();
    inject_file(&fixture, &out, &[c1, c2], ProbeHints::default()).expect("inject ok");
    inject_file(&out, &out, &[c3], ProbeHints::default()).expect("inject ok");

    let meta_out = probe_ts(&out, ProbeHints::default()).expect("probe out");
    let scte35_pid = meta_out.scte35_pid.expect("SCTE-35 PID present");
    let scte35_packets = count_pid_packets(&out, scte35_pid);
    assert!(
        scte35_packets >= 3,
        "expected multiple SCTE-35 packets, got {scte35_packets}"
    );

    let _ = fs::remove_file(&out);
}

// Ensure we preserve existing SCTE-35 streams and append new cues.
#[test]
fn preserves_existing_scte35_and_adds_new() {
    let fixture = PathBuf::from("../test-assets/scte35_splice_inserts_with_auto_return.ts");
    if !fixture.exists() {
        eprintln!("fixture missing, skipping");
        return;
    }

    let out = tmp_path("out_inject_existing_scte.ts");
    let c_new = parse_cue_arg("00:00:05.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==").unwrap();
    inject_file(&fixture, &out, &[c_new], ProbeHints::default()).expect("inject ok");

    // Probe original and output to compare SCTE PID and cue count
    let meta_in = probe_ts(&fixture, ProbeHints::default()).expect("probe in");
    let meta_out = probe_ts(&out, ProbeHints::default()).expect("probe out");

    let pid_in = meta_in.scte35_pid.expect("input SCTE pid");
    let pid_out = meta_out.scte35_pid.expect("output SCTE pid");
    assert_eq!(pid_in, pid_out, "should reuse existing SCTE PID");

    // List cues before and after
    let cues_in =
        scte35_injector::list::list_scte35_cues(&fixture, ProbeHints::default()).expect("list in");
    let cues_out =
        scte35_injector::list::list_scte35_cues(&out, ProbeHints::default()).expect("list out");
    assert!(
        cues_out.len() >= cues_in.len() + 1,
        "expected at least one extra cue: in={}, out={}",
        cues_in.len(),
        cues_out.len()
    );

    let _ = fs::remove_file(&out);
}

fn count_pid_packets(path: &PathBuf, pid: u16) -> u64 {
    let mut rdr = BufReader::new(File::open(path).unwrap());
    let mut buf = [0u8; 188];
    let mut count = 0u64;
    while let Ok(_) = rdr.read_exact(&mut buf) {
        if buf[0] != 0x47 {
            continue;
        }
        let p = (((buf[1] & 0x1F) as u16) << 8) | buf[2] as u16;
        if p == pid {
            count += 1;
        }
    }
    count
}

fn tmp_path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("{}_{}", nanos, name));
    p
}
