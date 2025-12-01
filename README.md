# scte35-injector

MPEG-TS CLI tool to detect, insert, and list SCTE-35 cues. Think of it as a lightweight shorthand alternative to common TSDuck workflows for SCTE-35.

## Disclaimer

- Written with excessive use of GenAI Agents.

## Features

- **Inject cues**: Add base64-encoded SCTE-35 `splice_info_section` messages.
- **Dual timestamps**: `placement@splice=` — control where packets are placed *and* the internal `splice_time` carried in the cue.
- **Auto-add SCTE-35 PID**: If none exists, allocate one, rewrite PMT (CRC-correct, with CUEI reg descriptor), and update continuity.
- **Continuity-safe**: Maintains continuity counters for all PIDs it touches.
- **List cues**: Finds cues via PMT, PSI sections (`table_id 0xFC`), or PES (`stream_id 0xFC`); reports PTS and base64.
- **Streaming**: Processes TS incrementally; no full-file buffering.
- **Well-tested**: Unit, edge, and end-to-end tests (fixtures in `test-assets/`).

## Quickstart

```bash
cargo run -- --input test-assets/tears_of_steel_1080p.ts \
  --output /tmp/out.ts \
  --cue "00:00:25.000@00:00:30.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A=="
```
Places packets at 25s and rewrites `splice_time` to 30s inside the cue. Omit `@...` to keep the original splice time.

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
      --cue <CUES>              Repeatable: placement[@splice]=<base64 splice_info_section>, placement/splice in HH:MM:SS[.mmm] format
                                 Example: 00:00:10=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==
      --scte35-pid <SCTE_PID>   Optional SCTE-35 PID hint (hex or decimal)
      --pcr-pid <PCR_PID>       Optional PCR PID hint
      --video-pid <VIDEO_PID>   Optional video PID hint (timing reference)
      --list-cues               List SCTE-35 cues present in the input, then exit
  -h, --help                    Print help
  -V, --version                 Print version
```

## Input cue format

- `placement`: `HH:MM:SS[.mmm]` — where to insert packets on the TS timeline.
- Optional `@splice`: `HH:MM:SS[.mmm]` — value to write into the SCTE-35 `splice_time` (time_signal or splice_insert). If omitted, the payload’s existing splice_time is preserved.
- `=<base64>`: complete SCTE-35 `splice_info_section` (CRC included).

On inject:
- Payload is validated; if `@splice` is provided, the cue is re-encoded with the new `splice_time` (33-bit wrap respected).
- Packets are placed at the nearest packet at/before the target PTS derived from the reference timeline.

## Behavior and assumptions

- Single-program TS expected. PMT rewrite handles one PMT; multi-PMT not yet supported.
- If no SCTE PID exists, a free PID ≥ 0x30 is allocated and every PMT packet is rewritten to include it (version bump, CRC).
- Bitrate: we insert packets; not currently doing CBR shaping. Add nulls after if you need strict rate.
- Timing reference: first detected video PID unless `--video-pid` hint is given. PCR PID is discovered or hinted.
- Listing: supports PSI (`table_id 0xFC`) and PES (`stream_id 0xFC`), with PMT discovery or heuristic PID scan.
- Streaming: no full-file buffering. Probe caps metadata search to ~200k packets; timeline collection otherwise grows with duration.

## Project layout

- `src/main.rs`          CLI entry.
- `src/lib.rs`           Core parsing, packetization, PID allocation, timing helpers.
- `src/inject.rs`        Injection pipeline (probe → plan → packetize → write).
- `src/list.rs`          Cue listing pipeline.
- `test-assets/`         Sample TS fixtures.

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
