# H.264 Picture Timing SEI Research

This document outlines research for implementing H.264 Picture Timing SEI injection on video keyframes.

## What is SEI?

**Supplemental Enhancement Information (SEI)** is additional data inserted into H.264/H.265 bitstreams to convey extra information synchronized with audio/video content. SEI messages are a type of NAL (Network Abstraction Layer) unit with `nal_unit_type = 6`.

### Key Characteristics

- **Optional for decoders**: Decoders are not required to process SEI messages; they may be discarded
- **Does not affect core decoding**: SEI messages don't affect the decoding process but indicate how video should be post-processed or displayed
- **In-band metadata**: SEI metadata is injected into encoded frame NAL units, becoming part of the same stream
- **Various payload types**: Can contain timing info, closed captions, copyright info, camera parameters, user-defined data, etc.

### SEI NAL Unit Structure

```
[Start Code] [NAL Header] [SEI Payload Type] [SEI Payload Size] [SEI Payload Data]
   3-4 bytes    1 byte       variable           variable           variable
```

**NAL Header byte:**
- Bit 0: `forbidden_zero_bit` (always 0)
- Bits 1-2: `nal_ref_idc` (reference importance, typically 0 for SEI)
- Bits 3-7: `nal_unit_type` (6 for SEI)

**References:**
- [Magewell: Introduction to SEI](https://magewell.com/blog/82/detail)
- [SVTA Wiki: SEI](https://wiki.svta.org/supplemental-enhancement-information/)
- [Membrane: H.264 NAL Units](https://membrane.stream/learn/h264/3)

---

## What is Picture Timing SEI?

The **Picture Timing SEI** message (payload type 1) carries timing information for individual pictures, including:

1. **CPB/DPB delays**: Buffer timing for HRD (Hypothetical Reference Decoder) conformance
2. **pic_struct**: Picture structure (frame, field, interlaced patterns)
3. **Clock timestamps**: Up to 3 timecodes per picture

This is defined in **ITU-T H.264 Annex D.2.2** (also ISO/IEC 14496-10).

### When to Use Picture Timing SEI

- Carrying precise timestamps synchronized with video frames
- Enabling 3:2 pulldown control with multiple timestamps per picture
- Embedding timecodes (hours:minutes:seconds:frames) in the bitstream
- Providing timing references independent of container-level timestamps

**Note**: H.264 streams rarely include timestamps internally; when present, they are in Picture Timing SEI messages.

**References:**
- [FFmpeg H264SEIPictureTiming](https://ffmpeg.org/doxygen/trunk/structH264SEIPictureTiming.html)
- [CODE Sequoia: H.264 Time Code](https://codesequoia.wordpress.com/2011/01/30/understand-h-264-time-code/)
- [NVIDIA Forums: H264 Pic_Timing SEI](https://forums.developer.nvidia.com/t/h264-pic-timing-sei-message/71188)

---

## Picture Timing SEI Structure

### Dependencies on SPS/VUI

The Picture Timing SEI syntax depends on parameters from the **Sequence Parameter Set (SPS)** VUI (Video Usability Information):

| SPS/VUI Parameter | Purpose |
|-------------------|---------|
| `CpbDpbDelaysPresentFlag` | Enables cpb_removal_delay and dpb_output_delay fields |
| `cpb_removal_delay_length_minus1` | Bit length of cpb_removal_delay (length = value + 1) |
| `dpb_output_delay_length_minus1` | Bit length of dpb_output_delay (length = value + 1) |
| `pic_struct_present_flag` | Enables pic_struct and clock timestamp fields |
| `time_offset_length` | Bit length of time_offset field in clock timestamps |
| `time_scale` | Time scale in Hz (e.g., 60000 for 29.97fps) |
| `num_units_in_tick` | Tick units (e.g., 1001 for 29.97fps) |

### Binary Format (D.2.2 syntax)

```
pic_timing( payloadSize ) {
    if( CpbDpbDelaysPresentFlag ) {
        cpb_removal_delay     // u(cpb_removal_delay_length)
        dpb_output_delay      // u(dpb_output_delay_length)
    }
    if( pic_struct_present_flag ) {
        pic_struct            // u(4)
        for( i = 0; i < NumClockTS; i++ ) {
            clock_timestamp_flag[i]  // u(1)
            if( clock_timestamp_flag[i] ) {
                ct_type                    // u(2)
                nuit_field_based_flag      // u(1)
                counting_type              // u(5)
                full_timestamp_flag        // u(1)
                discontinuity_flag         // u(1)
                cnt_dropped_flag           // u(1)
                n_frames                   // u(8)
                if( full_timestamp_flag ) {
                    seconds_value          // u(6)  range 0-59
                    minutes_value          // u(6)  range 0-59
                    hours_value            // u(5)  range 0-23
                } else {
                    seconds_flag           // u(1)
                    if( seconds_flag ) {
                        seconds_value      // u(6)
                        minutes_flag       // u(1)
                        if( minutes_flag ) {
                            minutes_value  // u(6)
                            hours_flag     // u(1)
                            if( hours_flag ) {
                                hours_value // u(5)
                            }
                        }
                    }
                }
                if( time_offset_length > 0 )
                    time_offset            // i(time_offset_length)
            }
        }
    }
}
```

### pic_struct Values

| Value | Meaning | NumClockTS |
|-------|---------|------------|
| 0 | Frame | 1 |
| 1 | Top field | 1 |
| 2 | Bottom field | 1 |
| 3 | Top field, bottom field (interlaced) | 2 |
| 4 | Bottom field, top field (interlaced) | 2 |
| 5 | Top, bottom, top repeated | 3 |
| 6 | Bottom, top, bottom repeated | 3 |
| 7 | Frame doubling | 2 |
| 8 | Frame tripling | 3 |

### Clock Timestamp Calculation

The `clockTimestamp` is a tick count in `time_scale` Hz:

```
clockTimestamp = ((hH × 60 + mM) × 60 + sS) × time_scale
               + nFrames × (num_units_in_tick × 2)
               + tOffset
```

For example, with `time_scale = 60000` and `num_units_in_tick = 1001` (29.97fps):
- Field rate = 60000 / 1001 ≈ 59.94 fields/sec
- Frame rate = 29.97 fps

---

## RBSP and Emulation Prevention

### Raw Byte Sequence Payload (RBSP)

SEI data must be converted to RBSP format with **emulation prevention bytes** to avoid conflicts with start codes:

| Original Sequence | Escaped Sequence |
|-------------------|------------------|
| `0x000000` | `0x00000300` |
| `0x000001` | `0x00000301` |
| `0x000002` | `0x00000302` |
| `0x000003` | `0x00000303` |

When encoding SEI:
1. Build the SEI payload (SODB - String of Data Bits)
2. Add RBSP trailing bits (1 bit = 1, then 0s to byte-align)
3. Insert emulation prevention bytes where needed (RBSP to NAL)

When decoding SEI:
1. Remove emulation prevention bytes (NAL to RBSP)
2. Parse the RBSP data

---

## Rust Implementation

### Reading: h264-reader

- **Crate**: [h264-reader](https://crates.io/crates/h264-reader)
- **Docs**: [docs.rs/h264-reader](https://docs.rs/h264-reader)
- **Features**:
  - Supports `pic_timing()` SEI parsing
  - Handles both Annex B and AVCC formats
  - Lazy parsing for efficiency
  - RBSP decoding built-in

### Writing: Custom Implementation

The Rust ecosystem lacks a mature crate for writing H.264 SEI messages. Given the project already implements custom TS packet handling, a custom Picture Timing SEI encoder is the right approach:

```rust
// Pseudocode structure
struct PicTimingSei {
    cpb_removal_delay: Option<u32>,
    dpb_output_delay: Option<u32>,
    pic_struct: Option<PicStruct>,
    clock_timestamps: Vec<ClockTimestamp>,
}

struct ClockTimestamp {
    ct_type: u8,           // 2 bits
    counting_type: u8,     // 5 bits
    full_timestamp: bool,
    discontinuity: bool,
    cnt_dropped: bool,
    n_frames: u8,
    seconds: u8,           // 0-59
    minutes: u8,           // 0-59
    hours: u8,             // 0-23
    time_offset: i32,
}

impl PicTimingSei {
    fn encode(&self, sps_vui: &VuiParams) -> Vec<u8> {
        let mut bits = BitWriter::new();

        if sps_vui.cpb_dpb_delays_present {
            bits.write_bits(self.cpb_removal_delay, sps_vui.cpb_removal_delay_length);
            bits.write_bits(self.dpb_output_delay, sps_vui.dpb_output_delay_length);
        }

        if sps_vui.pic_struct_present {
            bits.write_bits(self.pic_struct as u8, 4);
            for ts in &self.clock_timestamps {
                ts.encode(&mut bits, sps_vui.time_offset_length);
            }
        }

        // Add RBSP trailing bits
        bits.write_bit(1);
        bits.byte_align();

        // Build NAL unit with emulation prevention
        build_sei_nal(SEI_TYPE_PIC_TIMING, bits.to_bytes())
    }
}
```

---

## Proposed Feature Implementation

### Feature: Set Picture Timing SEI on Keyframes

**Option**: `--pic-timing-start <time>`

**Input Format**: ISO-8601 time with milliseconds
- Format: `HH:MM:SS.mmm`
- Example: `18:00:00.000`
- Milliseconds are converted to frame count based on stream's frame rate (`time_scale / num_units_in_tick / 2`)

**Behavior**:
1. Parse the start time from CLI argument
2. On the **first video keyframe** (IDR NAL unit), inject Picture Timing SEI with the start time
3. On **subsequent keyframes**, calculate the new timestamp:
   ```
   new_time = start_time + (current_pts - first_keyframe_pts)
   ```
4. The time increment should respect the stream's `time_scale` and `num_units_in_tick`

### Implementation Steps

1. **Parse SPS to extract VUI timing parameters**
   - Use h264-reader to parse SPS NAL units
   - Extract `time_scale`, `num_units_in_tick`, `cpb_removal_delay_length_minus1`, etc.

2. **Detect keyframes (IDR NAL units)**
   - NAL unit type 5 (IDR slice) indicates a keyframe
   - May need to handle NAL unit type 19 (IDR with prefix) for some streams

3. **Build Picture Timing SEI NAL unit**
   - Construct the binary payload per D.2.2 syntax
   - Add RBSP trailing bits
   - Insert emulation prevention bytes
   - Prepend start code and NAL header

4. **Inject SEI before keyframe**
   - SEI NAL units should precede the slice NAL units they describe
   - Insert in the PES payload, after AUD (if present) but before slice

5. **Track timing for incremental updates**
   - Store the first keyframe's PTS and clock timestamp
   - Calculate delta for subsequent keyframes

### Handling PES Payload Modification

Since PES packets have a fixed structure, modifying H.264 payload requires:

1. Parse existing PES header to get payload offset
2. Insert SEI NAL unit at appropriate position in payload
3. Update `PES_packet_length` if specified (or use unbounded: 0x0000)
4. Re-packetize into TS packets with proper continuity counters

### Example Timeline

Given `--pic-timing-start "18:00:00.000"` with 29.97fps stream:

```
Keyframe 0 (PTS=0):      pic_timing = 18:00:00 n_frames=0
Keyframe 1 (PTS=90000):  pic_timing = 18:00:01 n_frames=0   (1 second at 90kHz)
Keyframe 2 (PTS=180000): pic_timing = 18:00:02 n_frames=0   (2 seconds)
...
```

### Milliseconds to Frame Count Conversion

```
frame_rate = time_scale / num_units_in_tick / 2
n_frames = floor(milliseconds * frame_rate / 1000)
```

Example at 29.97fps (`time_scale=60000`, `num_units_in_tick=1001`):
- `18:00:00.500` → 18:00:00 n_frames=14 (500ms × 29.97fps / 1000 ≈ 14.98 → 14)

---

## References

### Standards
- ITU-T H.264 / ISO/IEC 14496-10 (AVC specification)
  - Annex D: SEI messages
  - Annex C: HRD timing
  - Section E.1.1: VUI parameters

### Code References
- [FFmpeg h264_sei.h](https://github.com/FFmpeg/FFmpeg/blob/master/libavcodec/h264_sei.h)
- [FFmpeg h264_sei.c](https://github.com/FFmpeg/FFmpeg/blob/master/libavcodec/h264_sei.c)
- [h264-reader (Rust)](https://github.com/dholroyd/h264-reader)
- [h264bitstream (C)](https://github.com/aizvorski/h264bitstream)

### Articles
- [CODE Sequoia: Understanding H.264 Time Code](https://codesequoia.wordpress.com/2011/01/30/understand-h-264-time-code/)
- [Membrane: H.264 NAL Unit Format](https://membrane.stream/learn/h264/3)

---

## Implementation Status

### Completed

**Core H.264 module (`src/h264.rs`):**

1. **BitWriter** - Bit-level encoding for SEI payload construction
2. **RBSP handling** - Emulation prevention byte insertion/removal
3. **Picture Timing SEI encoder** - Full D.2.2 syntax implementation
4. **NAL unit detection** - Start code parsing, type identification, keyframe detection
5. **SPS/VUI extraction** - Using h264-reader to extract timing parameters
6. **CLI parameter** - `--pic-timing-start HH:MM:SS.mmm`
7. **Time arithmetic** - Milliseconds to frame count, PTS delta calculation
8. **SEI injection helpers** - `inject_sei_into_access_unit()`, `PicTimingState`

**TS Pipeline Integration (`src/lib.rs`, `src/inject.rs`):**

1. **PES reassembly** - `PesAccumulator` accumulates video TS packets into complete PES
2. **Access unit detection** - PES boundaries serve as access unit boundaries
3. **Keyframe-triggered injection** - `process_video_pes_for_sei()` processes IDR frames
4. **PES re-packetization** - `packetize_payload()` splits modified payload back into TS packets

**Testing:**

- 50+ unit tests for H.264 module
- End-to-end test verifying SEI injection (53 keyframes in sample asset)

### Usage (CLI)

```bash
# Inject Picture Timing SEI starting at 18:00:00.000 on all keyframes
scte35-injector -i input.ts -o output.ts --pic-timing-start "18:00:00.000"

# Combine with SCTE-35 cue injection
scte35-injector -i input.ts -o output.ts \
    --pic-timing-start "18:00:00.000" \
    --cue "00:00:10.000=/DAWAAAAAAAAAP/wBQb+Qjo1vQAAuwxz9A=="
```

### Usage (Rust API)

```rust
use scte35_injector::h264::{ClockTimestamp, PicTimingState, contains_idr, inject_sei_into_access_unit};

// Parse start time from CLI
let start_ts = ClockTimestamp::from_time_str("18:00:00.000", 29.97)?;
let mut state = PicTimingState::new(start_ts);

// When processing a video access unit:
state.try_extract_vui(&access_unit_data);  // Extract VUI from SPS if present

if contains_idr(&access_unit_data) {
    let sei_nal = state.build_sei_for_pts(current_pts);
    if let Some(modified) = inject_sei_into_access_unit(&access_unit_data, &sei_nal) {
        // Use modified access unit
    }
}
```
