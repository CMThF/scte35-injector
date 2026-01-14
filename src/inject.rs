use crate::{
    Continuity, Cue, PesAccumulator, ProbeHints, allocate_pid, build_pmt_with_scte35,
    choose_insertion_packet, duration_to_pts, packetize_payload, packetize_pmt, packetize_scte35,
    pes_h264_payload, probe_ts, rebuild_pes_with_payload,
};
use crate::h264::{PicTimingState, contains_idr, inject_sei_into_access_unit};
use anyhow::{Context, Result, anyhow};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tracing::{debug, info, warn};

/// High-level injection: read TS, inject cues, update PMT if needed, write out.
pub fn inject_file(input: &Path, output: &Path, cues: &[Cue], hints: ProbeHints) -> Result<()> {
    inject_file_with_pic_timing(input, output, cues, hints, None)
}

/// Inject with optional Picture Timing SEI injection on keyframes.
pub fn inject_file_with_pic_timing(
    input: &Path,
    output: &Path,
    cues: &[Cue],
    hints: ProbeHints,
    mut pic_timing: Option<PicTimingState>,
) -> Result<()> {
    let meta = probe_ts(input, hints)?;
    let scte35_pid = if let Some(pid) = meta.scte35_pid {
        pid
    } else if !cues.is_empty() {
        allocate_pid(&meta.used_pids)?
    } else {
        0 // No SCTE-35 needed
    };

    let mut cc = Continuity::default();

    // PMT update section to be packetized when first PMT packet is seen (for continuity alignment).
    let new_pmt_section: Option<Vec<u8>> = if meta.scte35_pid.is_none() && !cues.is_empty() {
        let section = meta
            .pmt_section
            .as_ref()
            .ok_or_else(|| anyhow!("PMT section not captured"))?;
        Some(build_pmt_with_scte35(section, scte35_pid)?)
    } else {
        None
    };

    // Plan cue insertions: for each cue, map to packet index and packetize.
    let mut insertions: Vec<(u64, Vec<[u8; 188]>)> = Vec::new();
    for cue in cues {
        let target_pts = duration_to_pts(cue.placement)?;
        let ref_pts = choose_insertion_packet(&meta.timeline, target_pts)
            .ok_or_else(|| anyhow!("No timeline entries to place cue at {:?}", cue.placement))?;

        let payload = if let Some(splice_ts) = cue.splice_time {
            let splice_pts = duration_to_pts(splice_ts)?;
            crate::rewrite_splice_time(&cue.payload, splice_pts)?
        } else {
            cue.payload.clone()
        };

        let pkts = packetize_scte35(scte35_pid, target_pts, &payload, &mut cc)?;
        insertions.push((ref_pts.packet_index, pkts));
    }
    insertions.sort_by_key(|(idx, _)| *idx);

    // Stream copy with injections.
    let mut reader = BufReader::new(
        File::open(input).with_context(|| format!("failed to open input {:?}", input))?,
    );
    let mut writer = BufWriter::new(
        File::create(output).with_context(|| format!("failed to create output {:?}", output))?,
    );
    let mut buf = [0u8; 188];
    let mut packet_index: u64 = 0;
    let mut ins_cursor = 0usize;
    // If we had to add an SCTE-35 stream, rewrite every PMT packet with the
    // updated section to avoid later PMT versions removing the new stream.
    let rewrite_pmt = meta.scte35_pid.is_none() && !cues.is_empty();

    // Video PES accumulator for SEI injection
    let video_pid = meta.video_pid;
    let mut video_pes = PesAccumulator::default();
    let mut sei_injection_count = 0u64;

    while reader.read_exact(&mut buf).is_ok() {
        // Inject cues scheduled before current packet_index
        while ins_cursor < insertions.len() && insertions[ins_cursor].0 == packet_index {
            for pkt in &insertions[ins_cursor].1 {
                writer.write_all(pkt)?;
            }
            ins_cursor += 1;
        }

        let pid = ((buf[1] as u16 & 0x1F) << 8) | buf[2] as u16;
        let pusi = (buf[1] & 0x40) != 0;
        let afc = (buf[3] >> 4) & 0x03;
        let orig_cc = buf[3] & 0x0F;

        // If we added SCTE-35, replace EVERY PMT packet with the updated section.
        if rewrite_pmt
            && let (Some(pmt_pid), Some(section)) = (meta.pmt_pid, new_pmt_section.as_ref())
            && pmt_pid == pid
        {
            // Start continuity from the incoming cc so the sequence remains monotonic.
            let mut local_cc = Continuity::default();
            local_cc.map.insert(pmt_pid, orig_cc);
            let pmt_packets = packetize_pmt(section, pmt_pid, &mut local_cc)?;
            let final_cc = local_cc.peek(pmt_pid).unwrap_or(orig_cc);
            cc.map.insert(pmt_pid, final_cc);
            for pkt in &pmt_packets {
                writer.write_all(pkt)?;
            }
            packet_index += 1;
            continue;
        }

        // Handle video packets for SEI injection
        if pic_timing.is_some() && Some(pid) == video_pid {
            let payload_offset = if afc == 0b10 || afc == 0b11 {
                5 + buf[4] as usize
            } else {
                4
            };
            let payload = if afc == 0b01 || afc == 0b11 {
                &buf[payload_offset..]
            } else {
                &[]
            };

            // Accumulate video PES
            if let Some((pes_data, pes_pts)) = video_pes.push(pusi, payload) {
                // Process completed PES - inject SEI if keyframe
                if let Some(modified_pes) =
                    process_video_pes_for_sei(&pes_data, pes_pts, pic_timing.as_mut().unwrap())
                {
                    // Output the modified PES as TS packets
                    let packets = packetize_payload(pid, true, &modified_pes, &mut cc)?;
                    for pkt in &packets {
                        writer.write_all(pkt)?;
                    }
                    sei_injection_count += 1;
                    debug!("Injected SEI at PTS {:?}", pes_pts);
                } else {
                    // No modification needed, re-packetize original
                    let packets = packetize_payload(pid, true, &pes_data, &mut cc)?;
                    for pkt in &packets {
                        writer.write_all(pkt)?;
                    }
                }
            }
            packet_index += 1;
            continue;
        }

        // Normal packet: bump continuity and forward.
        let cc_val = cc.next(pid, Some(orig_cc));
        buf[3] = (buf[3] & 0xF0) | cc_val;
        writer.write_all(&buf)?;
        packet_index += 1;
    }

    // Flush remaining video PES if any
    if pic_timing.is_some() && let Some(video_pid) = video_pid {
        if let Some((pes_data, pes_pts)) = video_pes.flush() {
            if let Some(modified_pes) =
                process_video_pes_for_sei(&pes_data, pes_pts, pic_timing.as_mut().unwrap())
            {
                let packets = packetize_payload(video_pid, true, &modified_pes, &mut cc)?;
                for pkt in &packets {
                    writer.write_all(pkt)?;
                }
                sei_injection_count += 1;
            } else {
                let packets = packetize_payload(video_pid, true, &pes_data, &mut cc)?;
                for pkt in &packets {
                    writer.write_all(pkt)?;
                }
            }
        }
    }

    // If some insertions were beyond the end, warn.
    if ins_cursor < insertions.len() {
        warn!(
            "Some cues were not inserted (packet index beyond file): {} remaining",
            insertions.len() - ins_cursor
        );
    }

    if sei_injection_count > 0 {
        info!("Injected Picture Timing SEI into {} keyframes", sei_injection_count);
    }

    writer.flush()?;
    Ok(())
}

/// Process a video PES packet, injecting SEI if it's a keyframe.
/// Returns the modified PES if SEI was injected, None otherwise.
fn process_video_pes_for_sei(
    pes_data: &[u8],
    pes_pts: Option<u64>,
    state: &mut PicTimingState,
) -> Option<Vec<u8>> {
    let h264_payload = pes_h264_payload(pes_data)?;

    // Try to extract VUI from SPS if present
    state.try_extract_vui(h264_payload);

    // Only inject SEI on keyframes (IDR)
    if !contains_idr(h264_payload) {
        return None;
    }

    let pts = pes_pts?;

    // Build SEI NAL unit
    let sei_nal = state.build_sei_for_pts(pts);

    // Inject SEI into access unit
    let modified_h264 = inject_sei_into_access_unit(h264_payload, &sei_nal)?;

    // Rebuild PES with modified payload
    rebuild_pes_with_payload(pes_data, &modified_h264)
}
