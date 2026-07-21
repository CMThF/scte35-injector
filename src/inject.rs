use crate::h264::{PicTimingState, contains_idr, inject_sei_into_access_unit};
use crate::{
    Continuity, Cue, InsertPolicy, PacketPts, PesAccumulator, ProbeHints, allocate_pid,
    build_pmt_with_scte35, choose_insertion_packet_with_policy, duration_to_pts, packetize_payload,
    packetize_pmt, packetize_scte35, pes_h264_payload, probe_ts, rebuild_pes_with_payload,
};
use anyhow::{Context, Result, anyhow};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tracing::{debug, info, warn};

const NULL_PID: u16 = 0x1FFF;

/// Optional behaviors of the injection pipeline.
#[derive(Debug, Default, Clone, Copy)]
pub struct InjectOptions {
    /// Where to anchor cue packets relative to the target PTS.
    pub policy: InsertPolicy,
    /// Repeat the PMT at least every this many milliseconds (estimated from
    /// the reference timeline). Applies to the updated PMT when an SCTE-35
    /// PID was added, otherwise to the latest section seen on the wire.
    pub pmt_interval_ms: Option<u64>,
    /// Drop one null packet (PID 0x1FFF) for every packet inserted, keeping
    /// the total packet count, mux bitrate, and PCR spacing intact.
    pub pad_nulls: bool,
}

/// High-level injection: read TS, inject cues, update PMT if needed, write out.
pub fn inject_file(input: &Path, output: &Path, cues: &[Cue], hints: ProbeHints) -> Result<()> {
    inject_file_with_options(input, output, cues, hints, None, InjectOptions::default())
}

/// Inject with optional Picture Timing SEI injection on keyframes.
pub fn inject_file_with_pic_timing(
    input: &Path,
    output: &Path,
    cues: &[Cue],
    hints: ProbeHints,
    pic_timing: Option<PicTimingState>,
) -> Result<()> {
    inject_file_with_options(
        input,
        output,
        cues,
        hints,
        pic_timing,
        InjectOptions::default(),
    )
}

/// Full-control injection entry point.
pub fn inject_file_with_options(
    input: &Path,
    output: &Path,
    cues: &[Cue],
    hints: ProbeHints,
    mut pic_timing: Option<PicTimingState>,
    options: InjectOptions,
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

    // Plan cue insertions: map each cue to a packet index. Packetization is
    // deferred to the copy loop so the continuity counter continues from any
    // traffic already present on the SCTE-35 PID.
    let mut insertions: Vec<(u64, Vec<u8>)> = Vec::new();
    for cue in cues {
        let target_pts = duration_to_pts(cue.placement)?;
        let ref_pts =
            choose_insertion_packet_with_policy(&meta.timeline, target_pts, options.policy)
                .ok_or_else(|| {
                    anyhow!("No timeline entries to place cue at {:?}", cue.placement)
                })?;

        let payload = if let Some(splice_ts) = cue.splice_time {
            let splice_pts = duration_to_pts(splice_ts)?;
            crate::rewrite_splice_time(&cue.payload, splice_pts)?
        } else {
            cue.payload.clone()
        };
        if payload.len() > 4093 {
            return Err(anyhow!(
                "SCTE-35 section too large: {} bytes (max 4093)",
                payload.len()
            ));
        }

        insertions.push((ref_pts.packet_index, payload));
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
    if rewrite_pmt
        && let Some(pmt_pid) = meta.pmt_pid
        && meta
            .programs
            .iter()
            .filter(|p| p.pmt_pid == pmt_pid)
            .count()
            > 1
    {
        return Err(anyhow!(
            "multiple programs share PMT PID {:#x}; PMT rewrite would clobber the other programs' sections",
            pmt_pid
        ));
    }

    // Periodic PMT repetition: emit the PMT section again whenever more than
    // `interval` packets passed without a PMT packet. Uses the updated section
    // when rewriting; otherwise tracks the latest section seen on the wire so
    // mid-stream PMT version changes are repeated faithfully.
    let pmt_repeat_interval: Option<u64> = if let Some(interval_ms) = options.pmt_interval_ms {
        match (
            pmt_interval_packets(&meta.timeline, interval_ms),
            meta.pmt_pid,
        ) {
            (Some(interval), Some(_)) => Some(interval),
            _ => {
                warn!(
                    "--pmt-interval-ms requested but PMT or reference timeline unavailable; skipping periodic PMT repetition"
                );
                None
            }
        }
    } else {
        None
    };
    let mut pmt_repeat_section: Option<Vec<u8>> = if pmt_repeat_interval.is_some() {
        new_pmt_section.clone().or_else(|| meta.pmt_section.clone())
    } else {
        None
    };
    let mut pmt_asm = crate::PsiAssembler::default();
    let selected_program =
        crate::select_program(&meta.programs, hints.program).map(|p| p.program_number);
    let mut packets_since_pmt: u64 = 0;

    // Packets we inserted but have not yet compensated for by dropping nulls.
    let mut null_debt: u64 = 0;

    // Video PES accumulator for SEI injection
    let video_pid = meta.video_pid;
    let mut video_pes = PesAccumulator::default();
    let mut sei_injection_count = 0u64;

    while reader.read_exact(&mut buf).is_ok() {
        // Inject cues scheduled before current packet_index
        while ins_cursor < insertions.len() && insertions[ins_cursor].0 == packet_index {
            let pkts = packetize_scte35(scte35_pid, 0, &insertions[ins_cursor].1, &mut cc)?;
            for pkt in &pkts {
                writer.write_all(pkt)?;
            }
            null_debt += pkts.len() as u64;
            packets_since_pmt += pkts.len() as u64;
            ins_cursor += 1;
        }

        let pid = ((buf[1] as u16 & 0x1F) << 8) | buf[2] as u16;
        let pusi = (buf[1] & 0x40) != 0;
        let afc = (buf[3] >> 4) & 0x03;
        let orig_cc = buf[3] & 0x0F;

        // Repay insertion debt by dropping null packets to keep the mux rate.
        if options.pad_nulls && pid == NULL_PID && null_debt > 0 {
            null_debt -= 1;
            packet_index += 1;
            continue;
        }

        if Some(pid) == meta.pmt_pid {
            packets_since_pmt = 0;
            // Track the latest complete PMT section of the selected program so
            // periodic repetition follows mid-stream PMT changes. When
            // rewriting, the updated section is authoritative instead.
            if !rewrite_pmt && pmt_repeat_interval.is_some() {
                let header = crate::TsHeader::parse(&buf)?;
                if let Some(section) = pmt_asm.push(pid, pusi, header.payload(&buf)?)
                    && section.first() == Some(&0x02)
                    && section.len() >= 5
                    && selected_program
                        .is_none_or(|n| ((section[3] as u16) << 8 | section[4] as u16) == n)
                {
                    pmt_repeat_section = Some(section);
                }
            }
        } else {
            if let (Some(section), Some(interval)) = (&pmt_repeat_section, pmt_repeat_interval)
                && packets_since_pmt >= interval
                && let Some(pmt_pid) = meta.pmt_pid
            {
                let pmt_packets = packetize_pmt(section, pmt_pid, &mut cc)?;
                for pkt in &pmt_packets {
                    writer.write_all(pkt)?;
                }
                null_debt += pmt_packets.len() as u64;
                packets_since_pmt = 0;
            }
            packets_since_pmt += 1;
        }

        // If we added SCTE-35, replace EVERY PMT packet with the updated section.
        if rewrite_pmt
            && let (Some(pmt_pid), Some(section)) = (meta.pmt_pid, new_pmt_section.as_ref())
            && pmt_pid == pid
        {
            // Seed continuity from the incoming cc so the sequence stays
            // monotonic across rewrites and periodic repetitions.
            cc.seed(pmt_pid, orig_cc);
            let pmt_packets = packetize_pmt(section, pmt_pid, &mut cc)?;
            for pkt in &pmt_packets {
                writer.write_all(pkt)?;
            }
            // A rewritten section larger than the original packet still counts
            // as inserted data for null compensation.
            null_debt += (pmt_packets.len() as u64).saturating_sub(1);
            packet_index += 1;
            continue;
        }

        // Handle video packets for SEI injection
        if let Some(ref mut pt) = pic_timing
            && Some(pid) == video_pid
        {
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
                if let Some(modified_pes) = process_video_pes_for_sei(&pes_data, pes_pts, pt) {
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

        // Normal packet: bump continuity and forward. Per ISO 13818-1 the
        // counter must not increment on packets without payload
        // (adaptation-field-only), so those repeat the last emitted value.
        let cc_val = if afc & 0b01 != 0 {
            cc.next(pid, Some(orig_cc))
        } else {
            cc.last_emitted(pid).unwrap_or(orig_cc)
        };
        buf[3] = (buf[3] & 0xF0) | cc_val;
        writer.write_all(&buf)?;
        packet_index += 1;
    }

    // Flush remaining video PES if any
    if let (Some(pt), Some(video_pid)) = (&mut pic_timing, video_pid)
        && let Some((pes_data, pes_pts)) = video_pes.flush()
    {
        if let Some(modified_pes) = process_video_pes_for_sei(&pes_data, pes_pts, pt) {
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

    if options.pad_nulls && null_debt > 0 {
        info!(
            "{} inserted packet(s) could not be compensated (not enough null packets)",
            null_debt
        );
    }

    // If some insertions were beyond the end, warn.
    if ins_cursor < insertions.len() {
        warn!(
            "Some cues were not inserted (packet index beyond file): {} remaining",
            insertions.len() - ins_cursor
        );
    }

    if sei_injection_count > 0 {
        info!(
            "Injected Picture Timing SEI into {} keyframes",
            sei_injection_count
        );
    }

    writer.flush()?;
    Ok(())
}

/// Convert a repetition interval in milliseconds to a packet count using the
/// average packet rate observed on the reference timeline.
fn pmt_interval_packets(timeline: &[PacketPts], interval_ms: u64) -> Option<u64> {
    let first = timeline.first()?;
    let last = timeline.last()?;
    let delta_packets = last.packet_index.checked_sub(first.packet_index)?;
    let delta_ticks = last.pts_90k.saturating_sub(first.pts_90k);
    if delta_packets == 0 || delta_ticks == 0 {
        return None;
    }
    let ticks = interval_ms.saturating_mul(90);
    Some(std::cmp::max(
        1,
        (ticks as u128 * delta_packets as u128 / delta_ticks as u128) as u64,
    ))
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
