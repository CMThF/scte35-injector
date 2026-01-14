//! H.264 utilities for Picture Timing SEI injection.
//!
//! This module provides:
//! - Bit-level writing for SEI encoding
//! - RBSP emulation prevention byte handling
//! - Picture Timing SEI structure and encoding

/// A bit-level writer for constructing H.264 NAL unit payloads.
///
/// Writes bits MSB-first (most significant bit first) as required by H.264.
#[derive(Debug, Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    bit_position: u8, // 0-7, number of bits written to current_byte
}

impl BitWriter {
    /// Create a new empty BitWriter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a single bit (0 or 1).
    pub fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1 << (7 - self.bit_position);
        }
        self.bit_position += 1;
        if self.bit_position == 8 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.bit_position = 0;
        }
    }

    /// Write multiple bits from a value (MSB first).
    ///
    /// `num_bits` must be <= 32.
    pub fn write_bits(&mut self, value: u32, num_bits: u8) {
        debug_assert!(num_bits <= 32);
        for i in (0..num_bits).rev() {
            self.write_bit((value >> i) & 1 != 0);
        }
    }

    /// Byte-align by padding with zero bits.
    pub fn byte_align(&mut self) {
        if self.bit_position > 0 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.bit_position = 0;
        }
    }

    /// Get the number of bits written so far.
    pub fn bit_count(&self) -> usize {
        self.bytes.len() * 8 + self.bit_position as usize
    }

    /// Consume the writer and return the byte buffer.
    ///
    /// If not byte-aligned, the final partial byte is included with zero padding.
    pub fn into_bytes(mut self) -> Vec<u8> {
        self.byte_align();
        self.bytes
    }
}

/// Insert emulation prevention bytes into RBSP data to create NAL unit payload.
///
/// H.264 requires that byte sequences 0x000000, 0x000001, 0x000002, and 0x000003
/// be escaped by inserting 0x03 after the two 0x00 bytes:
/// - 0x00 0x00 0x00 -> 0x00 0x00 0x03 0x00
/// - 0x00 0x00 0x01 -> 0x00 0x00 0x03 0x01
/// - 0x00 0x00 0x02 -> 0x00 0x00 0x03 0x02
/// - 0x00 0x00 0x03 -> 0x00 0x00 0x03 0x03
pub fn rbsp_to_nal(rbsp: &[u8]) -> Vec<u8> {
    let mut nal = Vec::with_capacity(rbsp.len() + rbsp.len() / 256);
    let mut zero_count = 0;

    for &byte in rbsp {
        if zero_count >= 2 && byte <= 0x03 {
            // Insert emulation prevention byte
            nal.push(0x03);
            zero_count = 0;
        }
        nal.push(byte);
        if byte == 0x00 {
            zero_count += 1;
        } else {
            zero_count = 0;
        }
    }

    nal
}

/// Remove emulation prevention bytes from NAL unit payload to get RBSP data.
///
/// This reverses the transformation done by `rbsp_to_nal`.
pub fn nal_to_rbsp(nal: &[u8]) -> Vec<u8> {
    let mut rbsp = Vec::with_capacity(nal.len());
    let mut i = 0;

    while i < nal.len() {
        if i + 2 < nal.len() && nal[i] == 0x00 && nal[i + 1] == 0x00 && nal[i + 2] == 0x03 {
            // Found emulation prevention byte sequence
            rbsp.push(0x00);
            rbsp.push(0x00);
            i += 3; // Skip the 0x03 emulation prevention byte
        } else {
            rbsp.push(nal[i]);
            i += 1;
        }
    }

    rbsp
}

// NAL unit types
pub const NAL_TYPE_SEI: u8 = 6;

// SEI payload types
pub const SEI_TYPE_PIC_TIMING: u8 = 1;

/// Picture structure values for pic_timing SEI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum PicStruct {
    /// Progressive frame
    #[default]
    Frame = 0,
    /// Top field
    TopField = 1,
    /// Bottom field
    BottomField = 2,
    /// Top field, bottom field, in that order (interlaced)
    TopBottomField = 3,
    /// Bottom field, top field, in that order (interlaced)
    BottomTopField = 4,
    /// Top, bottom, top repeated (3:2 pulldown)
    TopBottomTop = 5,
    /// Bottom, top, bottom repeated (3:2 pulldown)
    BottomTopBottom = 6,
    /// Frame doubling
    FrameDoubling = 7,
    /// Frame tripling
    FrameTripling = 8,
}

impl PicStruct {
    /// Number of clock timestamps for this pic_struct value.
    pub fn num_clock_ts(self) -> u8 {
        match self {
            PicStruct::Frame | PicStruct::TopField | PicStruct::BottomField => 1,
            PicStruct::TopBottomField
            | PicStruct::BottomTopField
            | PicStruct::FrameDoubling => 2,
            PicStruct::TopBottomTop | PicStruct::BottomTopBottom | PicStruct::FrameTripling => 3,
        }
    }
}

/// Clock timestamp for Picture Timing SEI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockTimestamp {
    /// Clock type: 0=progressive, 1=interlaced, 2=unknown, 3=reserved
    pub ct_type: u8,
    /// Counting type (0-6 typically)
    pub counting_type: u8,
    /// True if this is a discontinuity point
    pub discontinuity_flag: bool,
    /// True if frames were dropped (for drop-frame timecode)
    pub cnt_dropped_flag: bool,
    /// Frame count within the second (0 to fps-1)
    pub n_frames: u8,
    /// Seconds (0-59)
    pub seconds: u8,
    /// Minutes (0-59)
    pub minutes: u8,
    /// Hours (0-23)
    pub hours: u8,
    /// Time offset in clock ticks (can be negative)
    pub time_offset: i32,
}

impl Default for ClockTimestamp {
    fn default() -> Self {
        Self {
            ct_type: 0,       // progressive
            counting_type: 0, // unknown
            discontinuity_flag: false,
            cnt_dropped_flag: false,
            n_frames: 0,
            seconds: 0,
            minutes: 0,
            hours: 0,
            time_offset: 0,
        }
    }
}

impl ClockTimestamp {
    /// Create a clock timestamp from hours, minutes, seconds, and frame count.
    pub fn new(hours: u8, minutes: u8, seconds: u8, n_frames: u8) -> Self {
        Self {
            hours,
            minutes,
            seconds,
            n_frames,
            ..Default::default()
        }
    }

    /// Encode clock timestamp to bit stream.
    fn encode(&self, bits: &mut BitWriter, time_offset_length: u8) {
        bits.write_bits(self.ct_type as u32, 2);
        bits.write_bit(false); // nuit_field_based_flag
        bits.write_bits(self.counting_type as u32, 5);
        bits.write_bit(true); // full_timestamp_flag (always use full timestamp)
        bits.write_bit(self.discontinuity_flag);
        bits.write_bit(self.cnt_dropped_flag);
        bits.write_bits(self.n_frames as u32, 8);
        // Full timestamp: seconds, minutes, hours
        bits.write_bits(self.seconds as u32, 6);
        bits.write_bits(self.minutes as u32, 6);
        bits.write_bits(self.hours as u32, 5);
        // Time offset (signed, but we write as unsigned bits)
        if time_offset_length > 0 {
            bits.write_bits(self.time_offset as u32, time_offset_length);
        }
    }
}

/// VUI timing parameters needed to encode Picture Timing SEI.
#[derive(Debug, Clone)]
pub struct VuiTimingParams {
    /// True if CPB/DPB delays are present
    pub cpb_dpb_delays_present: bool,
    /// Bit length of cpb_removal_delay field
    pub cpb_removal_delay_length: u8,
    /// Bit length of dpb_output_delay field
    pub dpb_output_delay_length: u8,
    /// True if pic_struct is present
    pub pic_struct_present: bool,
    /// Bit length of time_offset field
    pub time_offset_length: u8,
    /// Time scale (e.g., 60000 for 29.97fps)
    pub time_scale: u32,
    /// Number of units in tick (e.g., 1001 for 29.97fps)
    pub num_units_in_tick: u32,
}

impl Default for VuiTimingParams {
    fn default() -> Self {
        Self {
            cpb_dpb_delays_present: false,
            cpb_removal_delay_length: 24,
            dpb_output_delay_length: 24,
            pic_struct_present: true,
            time_offset_length: 0,
            time_scale: 60000,      // 29.97fps default
            num_units_in_tick: 1001,
        }
    }
}

impl VuiTimingParams {
    /// Calculate frame rate from VUI parameters.
    pub fn frame_rate(&self) -> f64 {
        if self.num_units_in_tick == 0 {
            return 0.0;
        }
        // time_scale / num_units_in_tick gives field rate
        // Divide by 2 for frame rate (assuming field_pic_flag = 0)
        self.time_scale as f64 / self.num_units_in_tick as f64 / 2.0
    }
}

/// Picture Timing SEI message.
#[derive(Debug, Clone, Default)]
pub struct PicTimingSei {
    /// CPB removal delay (present if cpb_dpb_delays_present)
    pub cpb_removal_delay: u32,
    /// DPB output delay (present if cpb_dpb_delays_present)
    pub dpb_output_delay: u32,
    /// Picture structure
    pub pic_struct: PicStruct,
    /// Clock timestamps (up to NumClockTS based on pic_struct)
    pub clock_timestamps: Vec<Option<ClockTimestamp>>,
}

impl PicTimingSei {
    /// Create a new Picture Timing SEI with a single clock timestamp.
    pub fn new(timestamp: ClockTimestamp) -> Self {
        Self {
            pic_struct: PicStruct::Frame,
            clock_timestamps: vec![Some(timestamp)],
            ..Default::default()
        }
    }

    /// Encode the Picture Timing SEI payload (RBSP, without NAL header).
    pub fn encode_payload(&self, vui: &VuiTimingParams) -> Vec<u8> {
        let mut bits = BitWriter::new();

        // CPB/DPB delays
        if vui.cpb_dpb_delays_present {
            bits.write_bits(self.cpb_removal_delay, vui.cpb_removal_delay_length);
            bits.write_bits(self.dpb_output_delay, vui.dpb_output_delay_length);
        }

        // pic_struct and clock timestamps
        if vui.pic_struct_present {
            bits.write_bits(self.pic_struct as u32, 4);

            let num_clock_ts = self.pic_struct.num_clock_ts();
            for i in 0..num_clock_ts as usize {
                let has_timestamp = self.clock_timestamps.get(i).and_then(|t| t.as_ref());
                bits.write_bit(has_timestamp.is_some());
                if let Some(ts) = has_timestamp {
                    ts.encode(&mut bits, vui.time_offset_length);
                }
            }
        }

        // RBSP trailing bits: 1 followed by zeros to byte align
        bits.write_bit(true);
        bits.byte_align();

        bits.into_bytes()
    }

    /// Build a complete SEI NAL unit containing this Picture Timing message.
    pub fn build_sei_nal(&self, vui: &VuiTimingParams) -> Vec<u8> {
        let payload = self.encode_payload(vui);
        let payload_with_epb = rbsp_to_nal(&payload);

        // Build SEI NAL unit
        let mut nal = Vec::with_capacity(4 + 2 + payload_with_epb.len());

        // Start code (4 bytes)
        nal.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        // NAL header: forbidden_zero_bit=0, nal_ref_idc=0, nal_unit_type=6 (SEI)
        nal.push(NAL_TYPE_SEI);

        // SEI payload type (pic_timing = 1)
        nal.push(SEI_TYPE_PIC_TIMING);

        // SEI payload size (may need multiple bytes if size >= 255)
        let size = payload_with_epb.len();
        if size < 255 {
            nal.push(size as u8);
        } else {
            // For sizes >= 255, write 0xFF bytes then remainder
            let full_bytes = size / 255;
            let remainder = size % 255;
            for _ in 0..full_bytes {
                nal.push(0xFF);
            }
            nal.push(remainder as u8);
        }

        // SEI payload data
        nal.extend_from_slice(&payload_with_epb);

        // RBSP trailing bits for the SEI NAL unit itself
        nal.push(0x80); // 1 bit followed by 7 zeros

        nal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitwriter_single_bits() {
        let mut bw = BitWriter::new();
        bw.write_bit(true);
        bw.write_bit(false);
        bw.write_bit(true);
        bw.write_bit(false);
        bw.write_bit(true);
        bw.write_bit(false);
        bw.write_bit(true);
        bw.write_bit(false);
        assert_eq!(bw.into_bytes(), vec![0b10101010]);
    }

    #[test]
    fn test_bitwriter_write_bits() {
        let mut bw = BitWriter::new();
        bw.write_bits(0b1010, 4);
        bw.write_bits(0b1100, 4);
        assert_eq!(bw.into_bytes(), vec![0b10101100]);
    }

    #[test]
    fn test_bitwriter_cross_byte_boundary() {
        let mut bw = BitWriter::new();
        bw.write_bits(0b101, 3);
        bw.write_bits(0b11001100, 8);
        bw.write_bits(0b10101, 5);
        // 101 11001 | 100 10101
        // 0xB9      | 0x95
        assert_eq!(bw.into_bytes(), vec![0b10111001, 0b10010101]);
    }

    #[test]
    fn test_bitwriter_partial_byte() {
        let mut bw = BitWriter::new();
        bw.write_bits(0b101, 3);
        // Should pad with zeros: 101 00000 = 0xA0
        assert_eq!(bw.into_bytes(), vec![0b10100000]);
    }

    #[test]
    fn test_bitwriter_bit_count() {
        let mut bw = BitWriter::new();
        assert_eq!(bw.bit_count(), 0);
        bw.write_bits(0xFF, 8);
        assert_eq!(bw.bit_count(), 8);
        bw.write_bits(0b101, 3);
        assert_eq!(bw.bit_count(), 11);
    }

    #[test]
    fn test_bitwriter_empty() {
        let bw = BitWriter::new();
        assert_eq!(bw.into_bytes(), vec![]);
    }

    #[test]
    fn test_rbsp_to_nal_no_escape_needed() {
        let rbsp = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(rbsp_to_nal(&rbsp), rbsp);
    }

    #[test]
    fn test_rbsp_to_nal_escape_000000() {
        let rbsp = vec![0x00, 0x00, 0x00];
        assert_eq!(rbsp_to_nal(&rbsp), vec![0x00, 0x00, 0x03, 0x00]);
    }

    #[test]
    fn test_rbsp_to_nal_escape_000001() {
        let rbsp = vec![0x00, 0x00, 0x01];
        assert_eq!(rbsp_to_nal(&rbsp), vec![0x00, 0x00, 0x03, 0x01]);
    }

    #[test]
    fn test_rbsp_to_nal_escape_000002() {
        let rbsp = vec![0x00, 0x00, 0x02];
        assert_eq!(rbsp_to_nal(&rbsp), vec![0x00, 0x00, 0x03, 0x02]);
    }

    #[test]
    fn test_rbsp_to_nal_escape_000003() {
        let rbsp = vec![0x00, 0x00, 0x03];
        assert_eq!(rbsp_to_nal(&rbsp), vec![0x00, 0x00, 0x03, 0x03]);
    }

    #[test]
    fn test_rbsp_to_nal_multiple_escapes() {
        let rbsp = vec![0x00, 0x00, 0x00, 0x00, 0x01];
        // First 0x00 0x00 0x00 -> 0x00 0x00 0x03 0x00
        // Then 0x00 0x01 (not escaped, only one zero before)
        assert_eq!(rbsp_to_nal(&rbsp), vec![0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x01]);
    }

    #[test]
    fn test_rbsp_to_nal_no_escape_at_04() {
        let rbsp = vec![0x00, 0x00, 0x04];
        // 0x04 is not escaped
        assert_eq!(rbsp_to_nal(&rbsp), vec![0x00, 0x00, 0x04]);
    }

    #[test]
    fn test_nal_to_rbsp_no_escape() {
        let nal = vec![0x01, 0x02, 0x03, 0x04];
        assert_eq!(nal_to_rbsp(&nal), nal);
    }

    #[test]
    fn test_nal_to_rbsp_removes_emulation_prevention() {
        let nal = vec![0x00, 0x00, 0x03, 0x00];
        assert_eq!(nal_to_rbsp(&nal), vec![0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_rbsp_nal_roundtrip() {
        let original = vec![0x00, 0x00, 0x01, 0x67, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02];
        let nal = rbsp_to_nal(&original);
        let rbsp = nal_to_rbsp(&nal);
        assert_eq!(rbsp, original);
    }

    #[test]
    fn test_pic_struct_num_clock_ts() {
        assert_eq!(PicStruct::Frame.num_clock_ts(), 1);
        assert_eq!(PicStruct::TopField.num_clock_ts(), 1);
        assert_eq!(PicStruct::BottomField.num_clock_ts(), 1);
        assert_eq!(PicStruct::TopBottomField.num_clock_ts(), 2);
        assert_eq!(PicStruct::BottomTopField.num_clock_ts(), 2);
        assert_eq!(PicStruct::TopBottomTop.num_clock_ts(), 3);
        assert_eq!(PicStruct::BottomTopBottom.num_clock_ts(), 3);
        assert_eq!(PicStruct::FrameDoubling.num_clock_ts(), 2);
        assert_eq!(PicStruct::FrameTripling.num_clock_ts(), 3);
    }

    #[test]
    fn test_clock_timestamp_new() {
        let ts = ClockTimestamp::new(12, 34, 56, 15);
        assert_eq!(ts.hours, 12);
        assert_eq!(ts.minutes, 34);
        assert_eq!(ts.seconds, 56);
        assert_eq!(ts.n_frames, 15);
        assert_eq!(ts.ct_type, 0);
        assert_eq!(ts.discontinuity_flag, false);
    }

    #[test]
    fn test_vui_frame_rate_29_97() {
        let vui = VuiTimingParams {
            time_scale: 60000,
            num_units_in_tick: 1001,
            ..Default::default()
        };
        let fps = vui.frame_rate();
        assert!((fps - 29.97).abs() < 0.01);
    }

    #[test]
    fn test_vui_frame_rate_25() {
        let vui = VuiTimingParams {
            time_scale: 50,
            num_units_in_tick: 1,
            ..Default::default()
        };
        let fps = vui.frame_rate();
        assert!((fps - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_pic_timing_sei_encode_simple() {
        // Simple case: pic_struct=0 (frame), one clock timestamp
        let ts = ClockTimestamp::new(1, 2, 3, 4);
        let sei = PicTimingSei::new(ts);
        let vui = VuiTimingParams {
            cpb_dpb_delays_present: false,
            pic_struct_present: true,
            time_offset_length: 0,
            ..Default::default()
        };

        let payload = sei.encode_payload(&vui);

        // Verify the payload is non-empty and properly terminated
        assert!(!payload.is_empty());
        // Last byte should contain RBSP trailing bits
        assert!(payload.last().unwrap() & 0x80 != 0);
    }

    #[test]
    fn test_pic_timing_sei_build_nal() {
        let ts = ClockTimestamp::new(18, 0, 0, 0);
        let sei = PicTimingSei::new(ts);
        let vui = VuiTimingParams::default();

        let nal = sei.build_sei_nal(&vui);

        // Verify NAL structure
        assert!(nal.len() >= 8);
        // Start code
        assert_eq!(&nal[0..4], &[0x00, 0x00, 0x00, 0x01]);
        // NAL type = 6 (SEI)
        assert_eq!(nal[4], NAL_TYPE_SEI);
        // Payload type = 1 (pic_timing)
        assert_eq!(nal[5], SEI_TYPE_PIC_TIMING);
        // Payload size follows
        assert!(nal[6] > 0);
    }

    #[test]
    fn test_pic_timing_sei_with_cpb_dpb_delays() {
        let ts = ClockTimestamp::new(0, 0, 0, 0);
        let sei = PicTimingSei {
            cpb_removal_delay: 1000,
            dpb_output_delay: 500,
            pic_struct: PicStruct::Frame,
            clock_timestamps: vec![Some(ts)],
        };
        let vui = VuiTimingParams {
            cpb_dpb_delays_present: true,
            cpb_removal_delay_length: 24,
            dpb_output_delay_length: 24,
            pic_struct_present: true,
            time_offset_length: 0,
            ..Default::default()
        };

        let payload = sei.encode_payload(&vui);
        // With 24+24 bits for delays, payload should be larger
        // 48 bits = 6 bytes for delays + pic_struct + clock_timestamp + trailing
        assert!(payload.len() >= 6);
    }

    #[test]
    fn test_pic_timing_sei_no_clock_timestamp() {
        // Test with clock_timestamp_flag = 0
        let sei = PicTimingSei {
            pic_struct: PicStruct::Frame,
            clock_timestamps: vec![None],
            ..Default::default()
        };
        let vui = VuiTimingParams::default();

        let payload = sei.encode_payload(&vui);
        // Minimal payload: 4 bits pic_struct + 1 bit flag + 1 bit trailing + padding
        assert!(!payload.is_empty());
    }
}
