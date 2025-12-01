use crate::{
    Continuity, Cue, ProbeHints, allocate_pid, build_pmt_with_scte35, choose_insertion_packet,
    duration_to_pts, packetize_pmt, packetize_scte35, probe_ts,
};
use anyhow::{Context, Result, anyhow};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tracing::warn;

/// High-level injection: read TS, inject cues, update PMT if needed, write out.
pub fn inject_file(input: &Path, output: &Path, cues: &[Cue], hints: ProbeHints) -> Result<()> {
    let meta = probe_ts(input, hints)?;
    let scte35_pid = if let Some(pid) = meta.scte35_pid {
        pid
    } else {
        allocate_pid(&meta.used_pids)?
    };

    let mut cc = Continuity::default();

    // PMT update section to be packetized when first PMT packet is seen (for continuity alignment).
    let new_pmt_section: Option<Vec<u8>> = if meta.scte35_pid.is_none() {
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
        let target_pts = duration_to_pts(cue.timestamp)?;
        let ref_pts = choose_insertion_packet(&meta.timeline, target_pts)
            .ok_or_else(|| anyhow!("No timeline entries to place cue at {:?}", cue.timestamp))?;
        let pkts = packetize_scte35(scte35_pid, target_pts, &cue.payload, &mut cc)?;
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
    let rewrite_pmt = meta.scte35_pid.is_none();

    while reader.read_exact(&mut buf).is_ok() {
        // Inject cues scheduled before current packet_index
        while ins_cursor < insertions.len() && insertions[ins_cursor].0 == packet_index {
            for pkt in &insertions[ins_cursor].1 {
                writer.write_all(pkt)?;
            }
            ins_cursor += 1;
        }

        let pid = ((buf[1] as u16 & 0x1F) << 8) | buf[2] as u16;
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

        // Normal packet: bump continuity and forward.
        let cc_val = cc.next(pid, Some(orig_cc));
        buf[3] = (buf[3] & 0xF0) | cc_val;
        writer.write_all(&buf)?;
        packet_index += 1;
    }

    // If some insertions were beyond the end, warn.
    if ins_cursor < insertions.len() {
        warn!(
            "Some cues were not inserted (packet index beyond file): {} remaining",
            insertions.len() - ins_cursor
        );
    }

    writer.flush()?;
    Ok(())
}
