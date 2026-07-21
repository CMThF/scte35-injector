# scte35-injector

[![CI](https://github.com/CMThF/scte35-injector/actions/workflows/ci.yml/badge.svg)](https://github.com/CMThF/scte35-injector/actions/workflows/ci.yml)
[![Release](https://github.com/CMThF/scte35-injector/actions/workflows/release.yml/badge.svg)](https://github.com/CMThF/scte35-injector/actions/workflows/release.yml)

MPEG-TS CLI tool to detect, insert, and list SCTE-35 cues. Think of it as a lightweight shorthand alternative to common TSDuck workflows for SCTE-35.

## Disclaimer

- Written with excessive use of GenAI Agents.

## Features

- **Inject cues**: Add base64-encoded SCTE-35 `splice_info_section` messages.
- **Dual timestamps**: `placement@splice=` — control where packets are placed *and* the internal `splice_time` carried in the cue.
- **Auto-add SCTE-35 PID**: If none exists, allocate one, rewrite PMT (CRC-correct, with CUEI reg descriptor), and update continuity.
- **Periodic PMT repetition**: `--pmt-interval-ms` re-emits the (updated) PMT at a minimum cadence so decoders joining mid-stream pick up the SCTE-35 PID quickly.
- **Bitrate-safe padding**: `--pad-nulls` drops one null packet per inserted packet, keeping the mux bitrate and PCR spacing intact.
- **Multi-program TS**: `--program` selects the program to target; PAT parsing, PMT rewrite, and cue listing are program-aware.
- **Insertion policy**: `--insert-policy before|after` anchors cue packets at the last frame at/before or the first frame at/after the target PTS; `--ref-pid` selects an explicit timeline reference PID.
- **Continuity-safe**: Maintains continuity counters for all PIDs it touches.
- **List cues**: Finds cues via PMT, PSI sections (`table_id 0xFC`), or PES (`stream_id 0xFC`); reports PTS and base64.
- **Picture Timing SEI**: Inject H.264 Picture Timing SEI messages on video keyframes with incrementing timestamps.
- **Streaming**: Processes TS incrementally; no full-file buffering.
- **Well-tested**: Unit, edge, and end-to-end tests (fixtures in `test-assets/`).

## Quickstart

```bash
scte35-injector --input test-assets/tears_of_steel_1080p.ts \
  --output /tmp/out.ts \
  --cue "00:00:25.000@00:00:30.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A=="
```
Places packets at 25s and rewrites `splice_time` to 30s inside the cue. Omit `@...` to keep the original splice time.

Inject Picture Timing SEI on all keyframes starting at 18:00:00:

```bash
scte35-injector --input test-assets/tears_of_steel_1080p.ts \
  --output /tmp/out.ts \
  --pic-timing-start "18:00:00.000"
```

List cues in a stream:

```bash
scte35-injector --input test-assets/scte35_splice_inserts_with_auto_return.ts --list-cues
```

## CLI

```
scte35-injector [OPTIONS] --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>           Input MPEG-TS file path
  -o, --output <OUTPUT>         Output MPEG-TS file path (required for injection; ignored in list mode)
      --cue <CUES>              Repeatable: placement[@splice]=<base64 splice_info_section>, placement/splice in HH:MM:SS[.mmm] format
                                 Example: 00:00:10=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==
      --scte35-pid <SCTE_PID>   Optional SCTE-35 PID hint (hex or decimal)
      --pcr-pid <PCR_PID>       Optional PCR PID hint
      --video-pid <VIDEO_PID>   Optional video PID hint (timing reference)
      --ref-pid <REF_PID>       Explicit timeline reference PID for cue placement (overrides the video PID)
      --program <PROGRAM>       Program number to target in a multi-program TS (defaults to first program in PAT)
      --insert-policy <POLICY>  Anchor cue packets before or after the target PTS [default: before] [possible values: before, after]
      --pmt-interval-ms <MS>    Repeat the PMT at least every N milliseconds
      --pad-nulls               Drop one null packet per inserted packet to keep bitrate and PCR spacing
      --list-cues               List SCTE-35 cues present in the input, then exit
      --pic-timing-start <TIME> Start time for Picture Timing SEI injection (HH:MM:SS.mmm)
  -h, --help                    Print help
  -V, --version                 Print version
```

## Input cue format

- `placement`: `HH:MM:SS[.mmm]` — where to insert packets on the TS timeline.
- Optional `@splice`: `HH:MM:SS[.mmm]` — value to write into the SCTE-35 `splice_time` (time_signal or splice_insert). If omitted, the payload’s existing splice_time is preserved.
- `=<base64>`: complete SCTE-35 `splice_info_section` (CRC included).

On inject:
- Payload is validated; if `@splice` is provided, the cue is re-encoded with the new `splice_time` (33-bit wrap respected).
- Packets are placed at the nearest reference packet at/before the target PTS (default), or at/after it with `--insert-policy after`. The reference timeline comes from `--ref-pid` if given, otherwise the detected or hinted video PID.

## Picture Timing SEI

The `--pic-timing-start` option injects H.264 Picture Timing SEI messages (ITU-T H.264 Annex D.2.2) into the video stream:

- **When**: SEI is injected on every video keyframe (IDR NAL unit).
- **Format**: `HH:MM:SS.mmm` — hours, minutes, seconds, milliseconds.
- **Timing**: The start time is used for the first keyframe. Subsequent keyframes receive timestamps incremented based on PTS delta from the first keyframe.
- **VUI extraction**: If the video SPS contains VUI timing parameters (`time_scale`, `num_units_in_tick`), they are used for accurate frame rate calculation. Otherwise defaults to 29.97fps.
- **Milliseconds to frames**: Milliseconds are converted to `n_frames` based on the detected or default frame rate.

Example combining SCTE-35 cues with Picture Timing SEI:

```bash
scte35-injector --input input.ts --output output.ts \
  --pic-timing-start "18:00:00.000" \
  --cue "00:00:10.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A=="
```

## Behavior and assumptions

- Multi-program TS supported: `--program` selects the target program; without it the first program listed in the PAT is used. Only the selected program's PMT is rewritten.
- If no SCTE-35 PID exists, a free PID ≥ 0x30 is allocated and every PMT packet of the selected program is rewritten to include it (version bump, CRC).
- Bitrate: inserted packets grow the file by default. `--pad-nulls` compensates by dropping one null packet (PID 0x1FFF) per inserted packet, preserving mux bitrate and PCR spacing; if the stream carries too few nulls, the remainder is reported.
- PMT cadence: `--pmt-interval-ms` re-emits the PMT whenever more packets than the estimated interval passed without one (interval derived from the reference timeline's average packet rate). Uses the updated PMT when an SCTE-35 PID was added, otherwise the latest section seen on the wire (mid-stream PMT changes are followed). Only the PMT is repeated; the PAT is expected to repeat at its native cadence.
- Timing reference: `--ref-pid` if given, else the first detected video PID or the `--video-pid` hint. PCR PID is discovered or hinted.
- Listing: supports PSI (`table_id 0xFC`) and PES (`stream_id 0xFC`), with PMT discovery across all programs or heuristic PID scan.
- Streaming: no full-file buffering; timeline collection grows with duration.

## Project layout

- `src/main.rs`          CLI entry.
- `src/lib.rs`           Core parsing, packetization, PID allocation, timing helpers, PES handling.
- `src/inject.rs`        Injection pipeline (probe → plan → packetize → write).
- `src/list.rs`          Cue listing pipeline.
- `src/h264.rs`          H.264 NAL parsing, Picture Timing SEI encoding, VUI extraction.
- `test-assets/`         Sample TS fixtures.
- `tests/common/`        Deterministic synthetic TS fixture builder for fast CI tests.

## Testing

```bash
cargo test           # unit + integration
cargo test --test synthetic_golden   # fast synthetic fixtures with golden hashes (no large assets needed)
cargo run -- --input test-assets/... --list-cues   # manual validation
```

The `synthetic_golden` tests build small single- and multi-program TS fixtures in memory and pin both the fixture bytes and the injector output with SHA-256 golden hashes, so format regressions are caught without the large `test-assets/` files.

## Roadmap / TODO

- More source formats: read SCTE-35 cues from sidecar JSON/base64 lists.
- Additional validators: integrate `tsp -P analyze` summaries into CI.

## Safety notes

- Designed for offline processing; no network or FFmpeg runtime dependencies.
- Assumes input TS is well-formed (188-byte packets). Errors if sync byte missing.
