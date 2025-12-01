use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{info, warn};

use scte35_injector::{
    Cue, ProbeHints, inject::inject_file, list::list_scte35_cues, parse_cue_arg,
};

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

    /// Cue specification: hh:mm:ss.sss=<base64 scte35 section>. Can be repeated.
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

    /// List SCTE-35 cues found in the input and exit (no injection).
    #[arg(long = "list-cues")]
    list_cues: bool,
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

    if cli.cues.is_empty() {
        warn!("No cues provided; the tool will exit without modifications.");
    }

    let parsed_cues: Vec<Cue> = cli
        .cues
        .iter()
        .map(|c| parse_cue_arg(c))
        .collect::<Result<Vec<_>>>()?;

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

    inject_file(&cli.input, output, &parsed_cues, hints)?;
    info!("Finished writing {}", output.display());

    Ok(())
}
