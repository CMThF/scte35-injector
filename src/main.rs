use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use tracing::{info, warn};

use scte35_injector::{
    Cue, InsertPolicy, ProbeHints,
    h264::{ClockTimestamp, PicTimingState},
    inject::{InjectOptions, inject_file_with_options},
    list::list_scte35_cues,
    parse_cue_arg,
};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CliInsertPolicy {
    /// Anchor cue packets at the last reference packet with PTS at or before the target (default).
    #[default]
    Before,
    /// Anchor cue packets at the first reference packet with PTS at or after the target.
    After,
}

impl From<CliInsertPolicy> for InsertPolicy {
    fn from(value: CliInsertPolicy) -> Self {
        match value {
            CliInsertPolicy::Before => InsertPolicy::Before,
            CliInsertPolicy::After => InsertPolicy::After,
        }
    }
}

/// Inject SCTE-35 cues into an MPEG-TS file.
#[derive(Debug, Parser)]
#[command(author, version, about = "SCTE-35 injector for MPEG-TS", long_about = None)]
struct Cli {
    /// Input MPEG-TS file path
    #[arg(long, short = 'i')]
    input: PathBuf,

    /// Output MPEG-TS file path
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Cue specification: placement[@splice]=<base64 scte35 section>. Can be repeated.
    /// Example: 00:00:25.000@00:00:30.000=BASE64 sets packet placement at 25s and splice_time to 30s.
    #[arg(long = "cue")]
    cues: Vec<String>,

    /// Optional SCTE-35 PID hint (hex or decimal).
    #[arg(long = "scte35-pid")]
    scte35_pid: Option<u16>,

    /// Optional PCR PID hint.
    #[arg(long = "pcr-pid")]
    pcr_pid: Option<u16>,

    /// Optional video PID hint (used for timing).
    #[arg(long = "video-pid")]
    video_pid: Option<u16>,

    /// Explicit timeline reference PID for cue placement (overrides the video PID).
    #[arg(long = "ref-pid")]
    ref_pid: Option<u16>,

    /// Program number to target in a multi-program TS (defaults to the first program in the PAT).
    #[arg(long = "program")]
    program: Option<u16>,

    /// Insertion policy: anchor cue packets before or after the target PTS.
    #[arg(long = "insert-policy", value_enum, default_value_t = CliInsertPolicy::Before)]
    insert_policy: CliInsertPolicy,

    /// Repeat the PMT at least every N milliseconds (useful after adding an SCTE-35 PID
    /// so decoders joining mid-stream pick it up quickly).
    #[arg(long = "pmt-interval-ms", value_parser = clap::value_parser!(u64).range(1..))]
    pmt_interval_ms: Option<u64>,

    /// Drop one null packet per inserted packet to keep the mux bitrate and PCR spacing.
    #[arg(long = "pad-nulls")]
    pad_nulls: bool,

    /// List SCTE-35 cues found in the input and exit (no injection).
    #[arg(long = "list-cues")]
    list_cues: bool,

    /// Start time for Picture Timing SEI injection (format: HH:MM:SS.mmm).
    /// When set, injects Picture Timing SEI on video keyframes with incrementing timestamps.
    #[arg(long = "pic-timing-start")]
    pic_timing_start: Option<String>,
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .ok()
                .unwrap_or_else(|| "info,scte35_injector=debug".to_string()),
        )
        .try_init();
}

fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    let hints = ProbeHints {
        scte35_pid: cli.scte35_pid,
        pcr_pid: cli.pcr_pid,
        video_pid: cli.video_pid,
        program: cli.program,
        ref_pid: cli.ref_pid,
    };

    if cli.list_cues {
        let cues = list_scte35_cues(&cli.input, hints)?;
        if cues.is_empty() {
            println!("No SCTE-35 cues found.");
        } else {
            for cue in cues {
                println!(
                    "PTS={} ({}.{:03}s) size={}B base64={}",
                    cue.pts_90k,
                    cue.timestamp.as_secs(),
                    cue.timestamp.subsec_millis(),
                    cue.payload.len(),
                    cue.base64
                );
            }
        }
        return Ok(());
    }

    if cli.cues.is_empty() && cli.pic_timing_start.is_none() && cli.pmt_interval_ms.is_none() {
        warn!(
            "No cues, pic-timing-start, or pmt-interval-ms provided; output will be a copy with normalized continuity counters."
        );
    }

    let parsed_cues: Vec<Cue> = cli
        .cues
        .iter()
        .map(|c| parse_cue_arg(c))
        .collect::<Result<Vec<_>>>()?;

    // Parse Picture Timing start time if provided
    let pic_timing = if let Some(ref time_str) = cli.pic_timing_start {
        // Use a default frame rate; will be updated from SPS if available
        let default_frame_rate = 29.97;
        let start_ts = ClockTimestamp::from_time_str(time_str, default_frame_rate)
            .map_err(|e| anyhow::anyhow!("Invalid pic-timing-start: {}", e))?;
        info!(
            "Picture Timing SEI injection enabled, start time: {}",
            time_str
        );
        Some(PicTimingState::new(start_ts))
    } else {
        None
    };

    let output = cli
        .output
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("--output is required for injection"))?;

    info!(
        "Parsed {} cue(s); input={}, output={}",
        parsed_cues.len(),
        cli.input.display(),
        output.display()
    );

    let options = InjectOptions {
        policy: cli.insert_policy.into(),
        pmt_interval_ms: cli.pmt_interval_ms,
        pad_nulls: cli.pad_nulls,
    };

    inject_file_with_options(&cli.input, output, &parsed_cues, hints, pic_timing, options)?;
    info!("Finished writing {}", output.display());

    Ok(())
}
