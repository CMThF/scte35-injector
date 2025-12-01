# AGENTS GUIDE

This note is for anyone picking up work on `scte35-injector` and needing the quickest path to understand the code, common workflows, and validation tools.

## Project At A Glance
- Goal: inject SCTE-35 cues into MPEG-TS files or list existing cues, while keeping PMT/PTS correct so downstream tools (ffprobe, mediainfo, splicemonitor) recognize the data stream.
- Languages/stack: Rust 1.80+, workspace is a single crate (`src/`), CLI built with `clap`, logging via `tracing`.
- Key modules:
  - `src/main.rs`: CLI argument parsing (`--cue`, `--list-cues`, PID hints).
  - `src/inject.rs`: high-level inject pipeline, PMT rewrite, continuity management, packet output.
  - `src/list.rs`: cue discovery (PAT/PMT scan, PSI section parsing, PES fallback), timeline-aware PTS calculation.
  - `src/lib.rs`: parsing utilities (PAT/PMT/PES), packetization helpers, PTS math, probe (`probe_ts`), PID allocation.
- Fixtures: `test-assets/tears_of_steel_1080p.ts` (main e2e), `test-assets/scte35_splice_inserts_with_auto_return.ts` (ground-truth SCTE stream).
- Output defaults: continuity counters are re-generated; PMT is rewritten on every PMT packet when we add SCTE to keep version consistent.

## How To Run
- Build: `cargo build`
- Tests: `cargo test` (unit + e2e). Clippy: `cargo clippy -- -D warnings` (currently clean).
- Inject cue example:
  ```
  target/debug/scte35-injector \
    -i test-assets/tears_of_steel_1080p.ts \
    -o tmp/out.ts \
    --cue 00:00:05=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A==
  ```
- List cues:
  ```
  target/debug/scte35-injector -i tmp/out.ts --list-cues
  ```

## Tools (runtime + validation)
- `cargo test` / `cargo clippy` – primary CI-level checks.
- `ffprobe` – verify PMT and stream tagging; examples:
  - `ffprobe -hide_banner tmp/out.ts`
  - `ffprobe -v trace -show_programs -show_streams tmp/out.ts`
- `tsp` (TS duck / TSDuck) – spot-check cue timing with splicemonitor:
  - `tsp -I file tmp/out.ts -P splicemonitor -O drop`
- Optional sanity:
  - `mediainfo tmp/out.ts` to ensure data stream shows up as `scte_35` (not required but useful).

## Current Behavior & Decisions
- SCTE is carried as PSI section (`table_id 0xFC`) not PES for better tool recognition.
- PMT rewrite: adds stream_type `0x86`, program-level registration descriptor `CUEI`; version bumps and CRC recomputed; all PMT packets are replaced when adding SCTE so later PMT versions don’t erase the stream.
- PTS math: `list-cues` applies `pts_adjustment`, re-bases against earliest timeline PTS, and interpolates between nearby timeline entries to report human-readable timestamps.
- Memory: current pipeline streams packets; does not load full TS into RAM.

## Common Gotchas
- If `--cue` is omitted, injection exits with a warning (no-op).
- For files lacking PMT or PCR discovery within the first ~200k packets, probe will error (safety bound).
- Large SCTE sections (>4093 bytes) are rejected during packetization.
- Timeline hints: for atypical streams you can pass `--video-pid`, `--pcr-pid`, or `--scte35-pid` to speed probing or disambiguate.

## Where To Extend Next
- More source formats: allow reading SCTE cues from sidecar JSON/b64 lists.
- Seekless injection: consider sparse rewrites or chunked output for very large assets.
- Additional validators: integrate `tsp -P analyze` summaries into tests, if available in CI image.

## Quick File Map
- `src/inject.rs` — PMT rewrite & packet injection.
- `src/list.rs` — cue discovery + PTS/timestamp calculation.
- `src/lib.rs` — shared parsing/packet helpers, probe.
- `tests/e2e_asset_test.rs` — end-to-end coverage for inject + detect.
- `tests/unit_edges.rs` — edge conditions (oversize, bad formats).
- `test-assets/` — sample TS inputs.

That’s the minimal context to get productive quickly. If you change PMT logic or cue timing, re-run `cargo test` and validate with `ffprobe` and `tsp splicemonitor` as above. Good hunting.
