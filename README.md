# scte35-injector

MPEG-TS CLI tool to detect, insert, and list SCTE-35 cues.

## Disclaimer

- Written with excessive use of GenAI Agents.

## Features

- **Inject cues**: Add base64-encoded SCTE-35 `splice_info_section` messages at wall-clock offsets.
- **Auto-add SCTE PID**: If no SCTE-35 PID exists, it allocates one and updates the PMT (CRC-correct).
- **Continuity-safe**: Maintains continuity counters for all PIDs it touches.
- **List cues**: Read SCTE-35 cues already present in a TS (PES or PSI-carried, PMT or heuristic PID discovery).
- **Streaming**: Reads and writes TS incrementally; no full-file buffering.
- **Tests**: Unit, integration, and end-to-end tests (fixtures in `test/`).

## Quickstart

```bash
cargo run -- --input test-assets/tears_of_steel_1080p.ts \
  --output /tmp/out.ts \
  --cue "00:10:00.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A=="
```

List cues in a stream:

```bash
cargo run -- --input test-assets/scte35_splice_inserts_with_auto_return.ts --list-cues
```

## CLI

```
scte35-injector [OPTIONS] --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>           Input MPEG-TS file path
  -o, --output <OUTPUT>         Output MPEG-TS file path (required for injection; ignored in list mode)
      --cue <CUES>              Repeatable: hh:mm:ss.sss=<base64 splice_info_section>
      --scte35-pid <SCTE_PID>   Optional SCTE-35 PID hint (hex or decimal)
      --pcr-pid <PCR_PID>       Optional PCR PID hint
      --video-pid <VIDEO_PID>   Optional video PID hint (timing reference)
      --list-cues               List SCTE-35 cues present in the input, then exit
  -h, --help                    Print help
  -V, --version                 Print version
```

## Input cue format

`--cue "HH:MM:SS.mmm=<base64>"` where base64 is a complete SCTE-35 `splice_info_section` (CRC included). The tool:
- Parses and validates the section,
- Converts the wall-clock timestamp to 90 kHz PTS using the reference video timeline,
- Inserts at the nearest packet at/before the target PTS.

## Behavior and assumptions

- Single-program TS expected. PMT rewrite handles one PMT; multi-PMT not yet supported.
- If no SCTE PID exists, a free PID ≥ 0x30 is allocated and appended to the PMT once (periodic repetition TODO).
- Bitrate preservation is best-effort; currently we insert packets (not rate-shaped). For strict CBR, add null stuffing after injection (future work).
- Reference timing comes from the first detected video PID (or `--video-pid` hint). PCR PID is discovered from PMT unless hinted.
- Listing mode can find cues in:
  - PES with `stream_id 0xFC` (standard SCTE-35),
  - PSI sections with `table_id 0xFC`,
  - Even when PMT lacks SCTE, via heuristic PID scan.
- Processing is streaming; the tool does not load the entire TS into memory. Memory scales with PSI assemblies and the PTS timeline (one Vec of packet index/PTS). Probe stops early after 200k packets once metadata is found; timeline is otherwise unbounded (future: sampling/capping).

## Project layout

- `src/main.rs`          CLI entry.
- `src/lib.rs`           Core parsing, packetization, PID allocation, timing helpers.
- `src/inject.rs`        Injection pipeline (probe → plan → packetize → write).
- `src/list.rs`          Cue listing pipeline.
- `test/`                Sample TS assets (large).

## Testing

```bash
cargo test           # unit + integration
cargo run -- --input test-assets/... --list-cues   # manual validation
```

## Roadmap / TODO

- Periodic PMT repetition after adding SCTE PID.
- Optional null-packet padding to maintain bitrate and PCR spacing.
- Multi-program TS support.
- Configurable insertion policy (before/after target PTS) and explicit reference PID selection.
- Additional small synthetic fixtures with golden hashes for faster CI.

## Safety notes

- Designed for offline processing; no network or FFmpeg runtime dependencies.
- Assumes input TS is well-formed (188-byte packets). Errors if sync byte missing.

