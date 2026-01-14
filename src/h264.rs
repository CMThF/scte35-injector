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
}
