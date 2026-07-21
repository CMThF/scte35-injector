//! Fast CI tests on small synthetic fixtures with golden hashes.
//! These do not depend on the large assets in `test-assets/`.

mod common;

use common::{
    NULL_PID, ProgramSpec, SyntheticSpec, build_synthetic_ts, count_pid_packets,
    first_pid_packet_index, sha256_file_hex, sha256_hex, tmp_path, write_synthetic_ts,
};
use scte35_injector::{
    InsertPolicy, ProbeHints,
    inject::{InjectOptions, inject_file_with_options},
    list::list_scte35_cues,
    parse_cue_arg, probe_ts,
};
use std::fs;

const CUE_B64: &str = "/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==";

// Golden hashes pin the deterministic fixture builder and injector output.
// If a deliberate format change occurs, regenerate with:
//   cargo test --test synthetic_golden -- --nocapture
// and update the constants from the assertion output.
const GOLDEN_FIXTURE_SHA256: &str =
    "e337ef1b3f389883f4bed6386cc961cfa045dd45ad4322b92aee979cc97b2fd4";
const GOLDEN_INJECT_SHA256: &str =
    "af5fa83fb4d6ebcf64df078e74e6f5c3ce247f89948e851062589e98c6df3d90";

fn default_options() -> InjectOptions {
    InjectOptions::default()
}

#[test]
fn synthetic_fixture_matches_golden_hash() {
    let bytes = build_synthetic_ts(&SyntheticSpec::default());
    assert_eq!(bytes.len() % 188, 0, "fixture must be whole packets");
    assert_eq!(sha256_hex(&bytes), GOLDEN_FIXTURE_SHA256);
}

#[test]
fn inject_into_synthetic_matches_golden_hash() {
    let input = write_synthetic_ts(&SyntheticSpec::default(), "synth_golden_in.ts");
    let output = tmp_path("synth_golden_out.ts");

    let cue = parse_cue_arg(&format!("00:00:02.000={}", CUE_B64)).unwrap();
    inject_file_with_options(
        &input,
        &output,
        &[cue],
        ProbeHints::default(),
        None,
        default_options(),
    )
    .expect("inject ok");

    assert_eq!(sha256_file_hex(&output), GOLDEN_INJECT_SHA256);

    // Semantic checks besides the byte-exact pin.
    let meta = probe_ts(&output, ProbeHints::default()).expect("probe out");
    let scte35_pid = meta.scte35_pid.expect("SCTE-35 PID after injection");
    let out_bytes = fs::read(&output).unwrap();
    assert_eq!(count_pid_packets(&out_bytes, scte35_pid), 1);
    let cues = list_scte35_cues(&output, ProbeHints::default()).expect("list out");
    assert_eq!(cues.len(), 1);

    let _ = fs::remove_file(&input);
    let _ = fs::remove_file(&output);
}

#[test]
fn insert_policy_after_places_cue_later() {
    let input = write_synthetic_ts(&SyntheticSpec::default(), "synth_policy_in.ts");
    // 2.010s sits between the frames at 2.000s and 2.040s.
    let cue_spec = format!("00:00:02.010={}", CUE_B64);

    let mut positions = Vec::new();
    for policy in [InsertPolicy::Before, InsertPolicy::After] {
        let output = tmp_path("synth_policy_out.ts");
        let cue = parse_cue_arg(&cue_spec).unwrap();
        inject_file_with_options(
            &input,
            &output,
            &[cue],
            ProbeHints::default(),
            None,
            InjectOptions {
                policy,
                ..Default::default()
            },
        )
        .expect("inject ok");
        let bytes = fs::read(&output).unwrap();
        let scte35_pid = probe_ts(&output, ProbeHints::default())
            .unwrap()
            .scte35_pid
            .expect("SCTE-35 PID");
        positions.push(first_pid_packet_index(&bytes, scte35_pid).expect("cue packet present"));
        let _ = fs::remove_file(&output);
    }

    assert!(
        positions[1] > positions[0],
        "after-policy cue ({}) should land later than before-policy cue ({})",
        positions[1],
        positions[0]
    );
    let _ = fs::remove_file(&input);
}

#[test]
fn pad_nulls_preserves_packet_count() {
    let spec = SyntheticSpec {
        nulls_per_frame: 2,
        ..Default::default()
    };
    let input = write_synthetic_ts(&spec, "synth_nulls_in.ts");
    let in_len = fs::metadata(&input).unwrap().len();

    // Without padding the output grows by the inserted cue packet.
    let out_plain = tmp_path("synth_nulls_plain.ts");
    let cue = parse_cue_arg(&format!("00:00:02.000={}", CUE_B64)).unwrap();
    inject_file_with_options(
        &input,
        &out_plain,
        std::slice::from_ref(&cue),
        ProbeHints::default(),
        None,
        default_options(),
    )
    .expect("inject ok");
    assert_eq!(fs::metadata(&out_plain).unwrap().len(), in_len + 188);

    // With padding, one null packet is dropped per inserted packet.
    let out_padded = tmp_path("synth_nulls_padded.ts");
    inject_file_with_options(
        &input,
        &out_padded,
        &[cue],
        ProbeHints::default(),
        None,
        InjectOptions {
            pad_nulls: true,
            ..Default::default()
        },
    )
    .expect("inject ok");
    assert_eq!(fs::metadata(&out_padded).unwrap().len(), in_len);

    let padded = fs::read(&out_padded).unwrap();
    let plain = fs::read(&out_plain).unwrap();
    assert_eq!(
        count_pid_packets(&padded, NULL_PID) + 1,
        count_pid_packets(&plain, NULL_PID),
        "exactly one null packet should be dropped"
    );
    let cues = list_scte35_cues(&out_padded, ProbeHints::default()).expect("list padded");
    assert_eq!(cues.len(), 1);

    let _ = fs::remove_file(&input);
    let _ = fs::remove_file(&out_plain);
    let _ = fs::remove_file(&out_padded);
}

#[test]
fn pmt_interval_repeats_pmt() {
    let spec = SyntheticSpec::default();
    let pmt_pid = spec.programs[0].pmt_pid;
    let input = write_synthetic_ts(&spec, "synth_pmt_in.ts");
    let in_pmt_count = count_pid_packets(&fs::read(&input).unwrap(), pmt_pid);

    let output = tmp_path("synth_pmt_out.ts");
    let cue = parse_cue_arg(&format!("00:00:02.000={}", CUE_B64)).unwrap();
    inject_file_with_options(
        &input,
        &output,
        &[cue],
        ProbeHints::default(),
        None,
        InjectOptions {
            pmt_interval_ms: Some(100),
            ..Default::default()
        },
    )
    .expect("inject ok");

    let out_bytes = fs::read(&output).unwrap();
    let out_pmt_count = count_pid_packets(&out_bytes, pmt_pid);
    assert!(
        out_pmt_count > in_pmt_count * 2,
        "expected many repeated PMTs: in={in_pmt_count}, out={out_pmt_count}"
    );

    // Repeated PMTs must carry the SCTE-35 entry and keep continuity intact.
    assert_continuity_monotonic(&out_bytes, pmt_pid);
    let meta = probe_ts(&output, ProbeHints::default()).expect("probe out");
    assert!(meta.scte35_pid.is_some());
    let cues = list_scte35_cues(&output, ProbeHints::default()).expect("list out");
    assert_eq!(cues.len(), 1);

    let _ = fs::remove_file(&input);
    let _ = fs::remove_file(&output);
}

#[test]
fn multi_program_injects_into_selected_program() {
    let spec = SyntheticSpec {
        programs: vec![
            ProgramSpec {
                program_number: 1,
                pmt_pid: 0x0100,
                video_pid: 0x0101,
            },
            ProgramSpec {
                program_number: 2,
                pmt_pid: 0x0200,
                video_pid: 0x0201,
            },
        ],
        ..Default::default()
    };
    let input = write_synthetic_ts(&spec, "synth_multi_in.ts");
    let output = tmp_path("synth_multi_out.ts");

    let cue = parse_cue_arg(&format!("00:00:02.000={}", CUE_B64)).unwrap();
    let hints = ProbeHints {
        program: Some(2),
        ..Default::default()
    };
    inject_file_with_options(&input, &output, &[cue], hints, None, default_options())
        .expect("inject ok");

    // Program 2 gained an SCTE-35 stream.
    let meta_p2 = probe_ts(&output, hints).expect("probe p2");
    assert_eq!(meta_p2.pmt_pid, Some(0x0200));
    assert!(
        meta_p2.scte35_pid.is_some(),
        "program 2 should carry SCTE-35"
    );

    // Program 1's PMT is untouched.
    let hints_p1 = ProbeHints {
        program: Some(1),
        ..Default::default()
    };
    let meta_p1 = probe_ts(&output, hints_p1).expect("probe p1");
    assert_eq!(meta_p1.pmt_pid, Some(0x0100));
    assert!(
        meta_p1.scte35_pid.is_none(),
        "program 1 must stay untouched"
    );

    // PAT still lists both programs; listing without a hint finds the cue
    // via the multi-program PMT scan.
    assert_eq!(meta_p1.programs.len(), 2);
    let cues = list_scte35_cues(&output, ProbeHints::default()).expect("list out");
    assert_eq!(cues.len(), 1);

    // An unknown program is rejected.
    let bad = ProbeHints {
        program: Some(9),
        ..Default::default()
    };
    assert!(probe_ts(&output, bad).is_err());

    let _ = fs::remove_file(&input);
    let _ = fs::remove_file(&output);
}

#[test]
fn ref_pid_hint_drives_timeline() {
    let spec = SyntheticSpec {
        programs: vec![
            ProgramSpec {
                program_number: 1,
                pmt_pid: 0x0100,
                video_pid: 0x0101,
            },
            ProgramSpec {
                program_number: 2,
                pmt_pid: 0x0200,
                video_pid: 0x0201,
            },
        ],
        ..Default::default()
    };
    let input = write_synthetic_ts(&spec, "synth_refpid_in.ts");

    // Reference PID from program 2 while targeting program 1: the timeline
    // must come from the hinted PID even though it is not the selected video.
    let hints = ProbeHints {
        ref_pid: Some(0x0201),
        ..Default::default()
    };
    let meta = probe_ts(&input, hints).expect("probe");
    assert_eq!(meta.video_pid, Some(0x0101));
    assert!(!meta.timeline.is_empty());
    // Program 2's PES packets follow program 1's within each frame group.
    let bytes = fs::read(&input).unwrap();
    let first_p1 = first_pid_packet_index(&bytes, 0x0101).unwrap();
    let first_ref = meta.timeline.first().unwrap().packet_index;
    assert!(first_ref > first_p1, "timeline should track PID 0x0201");

    let _ = fs::remove_file(&input);
}

#[test]
fn adaptation_only_packets_keep_continuity() {
    let spec = SyntheticSpec {
        pcr_packets: true,
        ..Default::default()
    };
    let video_pid = spec.programs[0].video_pid;
    let input = write_synthetic_ts(&spec, "synth_pcr_in.ts");
    // The fixture itself must obey the spec.
    assert_continuity_spec_conform(&fs::read(&input).unwrap(), video_pid);

    let output = tmp_path("synth_pcr_out.ts");
    let cue = parse_cue_arg(&format!("00:00:02.000={}", CUE_B64)).unwrap();
    inject_file_with_options(
        &input,
        &output,
        &[cue],
        ProbeHints::default(),
        None,
        default_options(),
    )
    .expect("inject ok");

    // Injection must not introduce continuity errors around PCR-only packets.
    assert_continuity_spec_conform(&fs::read(&output).unwrap(), video_pid);

    let _ = fs::remove_file(&input);
    let _ = fs::remove_file(&output);
}

#[test]
fn pmt_interval_repeats_latest_pmt_version() {
    // PMT version bumps to 1 at frame 50; periodic repetition must follow.
    let spec = SyntheticSpec {
        bump_pmt_version_at_frame: Some(50),
        ..Default::default()
    };
    let pmt_pid = spec.programs[0].pmt_pid;
    let input = write_synthetic_ts(&spec, "synth_pmtver_in.ts");

    let output = tmp_path("synth_pmtver_out.ts");
    // No cues: the original sections are repeated, tracked from the wire.
    inject_file_with_options(
        &input,
        &output,
        &[],
        ProbeHints::default(),
        None,
        InjectOptions {
            pmt_interval_ms: Some(100),
            ..Default::default()
        },
    )
    .expect("inject ok");

    let versions = pmt_versions(&fs::read(&output).unwrap(), pmt_pid);
    assert!(versions.contains(&0) && versions.contains(&1));
    let first_v1 = versions.iter().position(|&v| v == 1).unwrap();
    assert!(
        versions[first_v1..].iter().all(|&v| v == 1),
        "stale PMT version repeated after the version bump: {versions:?}"
    );

    let _ = fs::remove_file(&input);
    let _ = fs::remove_file(&output);
}

/// Extract the version_number of every PMT section start on the given PID.
fn pmt_versions(bytes: &[u8], pmt_pid: u16) -> Vec<u8> {
    let mut versions = Vec::new();
    for pkt in bytes.chunks_exact(188) {
        let pid = ((pkt[1] & 0x1F) as u16) << 8 | pkt[2] as u16;
        let pusi = pkt[1] & 0x40 != 0;
        if pid != pmt_pid || !pusi {
            continue;
        }
        let afc = (pkt[3] >> 4) & 0x03;
        let mut offset = if afc == 0b10 || afc == 0b11 {
            5 + pkt[4] as usize
        } else {
            4
        };
        if offset >= 188 {
            continue;
        }
        offset += 1 + pkt[offset] as usize; // pointer_field
        // table_id at offset, version_number at offset + 5
        if offset + 5 < 188 && pkt[offset] == 0x02 {
            versions.push((pkt[offset + 5] >> 1) & 0x1F);
        }
    }
    versions
}

/// Assert ISO 13818-1 continuity: +1 on payload packets, unchanged on
/// adaptation-field-only packets.
fn assert_continuity_spec_conform(bytes: &[u8], pid: u16) {
    let mut prev: Option<u8> = None;
    for pkt in bytes.chunks_exact(188) {
        let p = ((pkt[1] & 0x1F) as u16) << 8 | pkt[2] as u16;
        if p != pid {
            continue;
        }
        let cur = pkt[3] & 0x0F;
        let has_payload = pkt[3] & 0x10 != 0;
        if let Some(prev) = prev {
            let expected = if has_payload { (prev + 1) & 0x0F } else { prev };
            assert_eq!(cur, expected, "continuity violation on PID {pid:#x}");
        }
        prev = Some(cur);
    }
    assert!(prev.is_some(), "no packets on PID {pid:#x}");
}

/// Assert the continuity counter increments by exactly one per packet on a PID.
fn assert_continuity_monotonic(bytes: &[u8], pid: u16) {
    let mut prev: Option<u8> = None;
    for pkt in bytes.chunks_exact(188) {
        let p = ((pkt[1] & 0x1F) as u16) << 8 | pkt[2] as u16;
        if p != pid {
            continue;
        }
        let cur = pkt[3] & 0x0F;
        if let Some(prev) = prev {
            assert_eq!(cur, (prev + 1) & 0x0F, "continuity break on PID {pid:#x}");
        }
        prev = Some(cur);
    }
    assert!(prev.is_some(), "no packets on PID {pid:#x}");
}
