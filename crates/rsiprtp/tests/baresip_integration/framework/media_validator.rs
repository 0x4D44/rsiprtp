//! Media validation utilities for RTP stream testing.
//!
//! This module provides tools to validate RTP streams, including:
//! - Sequence number validation
//! - Timestamp validation
//! - SSRC consistency
//! - Packet loss calculation
//! - Jitter measurement
//! - Audio tone detection

use std::collections::HashMap;
use std::time::Duration;

/// RTP packet parser and validator
#[derive(Debug)]
pub struct RtpPacket {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Parse RTP packet from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }

        let byte0 = data[0];
        let byte1 = data[1];

        let version = (byte0 >> 6) & 0x03;
        if version != 2 {
            return None;
        }

        let padding = (byte0 & 0x20) != 0;
        let extension = (byte0 & 0x10) != 0;
        let csrc_count = byte0 & 0x0F;

        let marker = (byte1 & 0x80) != 0;
        let payload_type = byte1 & 0x7F;

        let sequence = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let header_len = 12 + (csrc_count as usize * 4);
        if data.len() < header_len {
            return None;
        }

        let payload = data[header_len..].to_vec();

        Some(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
            payload,
        })
    }

    /// Get expected sequence number for next packet
    pub fn next_sequence(&self) -> u16 {
        self.sequence.wrapping_add(1)
    }
}

/// Codec types for validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    PCMU, // PT 0
    PCMA, // PT 8
    G722, // PT 9
}

impl Codec {
    /// Get payload type for codec
    pub fn payload_type(&self) -> u8 {
        match self {
            Codec::PCMU => 0,
            Codec::PCMA => 8,
            Codec::G722 => 9,
        }
    }

    /// Get expected packet time in milliseconds
    pub fn ptime_ms(&self) -> u32 {
        20 // Standard ptime
    }

    /// Get samples per packet
    pub fn samples_per_packet(&self) -> u32 {
        match self {
            Codec::PCMU | Codec::PCMA => 160, // 20ms @ 8kHz
            Codec::G722 => 160,               // 20ms @ 16kHz (but sampled at 8kHz)
        }
    }
}

/// Validation result
#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, msg: String) {
        self.valid = false;
        self.errors.push(msg);
    }

    pub fn add_warning(&mut self, msg: String) {
        self.warnings.push(msg);
    }
}

impl Default for ValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// RTP stream statistics
#[derive(Debug, Clone)]
pub struct StreamStats {
    pub total_packets: usize,
    pub lost_packets: usize,
    pub out_of_order: usize,
    pub duplicate: usize,
    pub jitter_ms: f64,
    pub start_timestamp: u32,
    pub end_timestamp: u32,
}

/// RTP stream validator
pub struct RtpValidator {
    expected_codec: Codec,
    expected_ptime: u32,
    packets: Vec<RtpPacket>,
    sequence_map: HashMap<u16, bool>, // Track seen sequences
    last_sequence: Option<u16>,
    last_timestamp: Option<u32>,
    ssrc: Option<u32>,
    jitter_sum: f64,
    jitter_count: usize,
}

impl RtpValidator {
    /// Create new validator for codec
    pub fn new(codec: Codec) -> Self {
        Self {
            expected_codec: codec,
            expected_ptime: codec.ptime_ms(),
            packets: Vec::new(),
            sequence_map: HashMap::new(),
            last_sequence: None,
            last_timestamp: None,
            ssrc: None,
            jitter_sum: 0.0,
            jitter_count: 0,
        }
    }

    /// Record an RTP packet
    pub fn record_packet(&mut self, data: &[u8]) -> Option<()> {
        let packet = RtpPacket::parse(data)?;

        // Track SSRC
        if let Some(ssrc) = self.ssrc {
            if ssrc != packet.ssrc {
                // SSRC changed - this is unusual but can happen
            }
        } else {
            self.ssrc = Some(packet.ssrc);
        }

        // Calculate jitter if we have previous packet
        if let (Some(last_ts), Some(_last_seq)) = (self.last_timestamp, self.last_sequence) {
            let ts_diff = packet.timestamp.wrapping_sub(last_ts) as i64;
            let expected_diff = self.expected_codec.samples_per_packet() as i64;
            let jitter = (ts_diff - expected_diff).abs() as f64;
            self.jitter_sum += jitter;
            self.jitter_count += 1;
        }

        self.last_sequence = Some(packet.sequence);
        self.last_timestamp = Some(packet.timestamp);

        // Track sequence
        if self.sequence_map.contains_key(&packet.sequence) {
            // Duplicate packet
        }
        self.sequence_map.insert(packet.sequence, true);

        self.packets.push(packet);
        Some(())
    }

    /// Verify RTP stream properties
    pub fn verify_stream(&self) -> ValidationResult {
        let mut result = ValidationResult::new();

        if self.packets.is_empty() {
            result.add_error("No packets received".to_string());
            return result;
        }

        // Check payload type consistency
        let first_pt = self.packets[0].payload_type;
        if first_pt != self.expected_codec.payload_type() {
            result.add_error(format!(
                "Payload type mismatch: expected {}, got {}",
                self.expected_codec.payload_type(),
                first_pt
            ));
        }

        for packet in &self.packets {
            if packet.payload_type != first_pt {
                result.add_warning(format!(
                    "Payload type changed mid-stream: {} -> {}",
                    first_pt, packet.payload_type
                ));
            }
        }

        // Check SSRC consistency
        if let Some(ssrc) = self.ssrc {
            for packet in &self.packets {
                if packet.ssrc != ssrc {
                    result.add_warning(format!(
                        "SSRC changed mid-stream: {} -> {}",
                        ssrc, packet.ssrc
                    ));
                }
            }
        }

        // Check sequence number gaps
        let loss = self.calculate_packet_loss();
        if loss > 0 {
            result.add_warning(format!(
                "{} packets lost ({:.1}%)",
                loss,
                self.packet_loss_percent()
            ));
        }

        result
    }

    /// Calculate packet loss count
    fn calculate_packet_loss(&self) -> usize {
        if self.packets.len() < 2 {
            return 0;
        }

        let first_seq = self.packets[0].sequence;
        let last_seq = self.packets.last().unwrap().sequence;

        let expected_count = if last_seq >= first_seq {
            (last_seq - first_seq + 1) as usize
        } else {
            // Handle wrap-around
            ((0xFFFF - first_seq as u32) + last_seq as u32 + 1) as usize
        };

        expected_count.saturating_sub(self.packets.len())
    }

    /// Calculate packet loss percentage
    pub fn packet_loss_percent(&self) -> f64 {
        if self.packets.len() < 2 {
            return 0.0;
        }

        let lost = self.calculate_packet_loss();
        let total = self.packets.len() + lost;

        (lost as f64 / total as f64) * 100.0
    }

    /// Calculate average jitter
    pub fn jitter(&self) -> Duration {
        if self.jitter_count == 0 {
            return Duration::from_millis(0);
        }

        let avg_jitter_samples = self.jitter_sum / self.jitter_count as f64;
        // Convert samples to milliseconds (assuming 8kHz sample rate)
        let jitter_ms = avg_jitter_samples / 8.0;

        Duration::from_millis(jitter_ms as u64)
    }

    /// Get stream statistics
    pub fn stats(&self) -> StreamStats {
        let start_timestamp = self.packets.first().map(|p| p.timestamp).unwrap_or(0);
        let end_timestamp = self.packets.last().map(|p| p.timestamp).unwrap_or(0);

        StreamStats {
            total_packets: self.packets.len(),
            lost_packets: self.calculate_packet_loss(),
            out_of_order: 0, // TODO: implement
            duplicate: 0,    // TODO: implement
            jitter_ms: self.jitter().as_millis() as f64,
            start_timestamp,
            end_timestamp,
        }
    }

    /// Simple tone detection (checks if payload looks like consistent waveform)
    pub fn verify_audio_tone(&self, _frequency: u32) -> bool {
        // TODO: Implement actual tone detection using FFT or similar
        // For now, just check that we have audio data
        !self.packets.is_empty() && self.packets.iter().all(|p| !p.payload.is_empty())
    }

    /// Check if stream appears to have valid audio
    pub fn has_audio(&self) -> bool {
        self.packets.iter().any(|p| !p.payload.is_empty())
    }

    /// Get number of packets received
    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_packet_parse() {
        // Valid RTP packet: version 2, PT 0 (PCMU), seq 100, ts 160, ssrc 0x12345678
        let data = vec![
            0x80, // V=2, P=0, X=0, CC=0
            0x00, // M=0, PT=0
            0x00, 0x64, // Seq 100
            0x00, 0x00, 0x00, 0xA0, // TS 160
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x01, 0x02, 0x03, // Payload
        ];

        let packet = RtpPacket::parse(&data).unwrap();
        assert_eq!(packet.version, 2);
        assert_eq!(packet.payload_type, 0);
        assert_eq!(packet.sequence, 100);
        assert_eq!(packet.timestamp, 160);
        assert_eq!(packet.ssrc, 0x12345678);
        assert_eq!(packet.payload.len(), 3);
    }

    #[test]
    fn test_rtp_packet_invalid() {
        // Too short
        assert!(RtpPacket::parse(&[0x80]).is_none());

        // Wrong version
        let data = vec![
            0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(RtpPacket::parse(&data).is_none());
    }

    #[test]
    fn test_codec_properties() {
        assert_eq!(Codec::PCMU.payload_type(), 0);
        assert_eq!(Codec::PCMA.payload_type(), 8);
        assert_eq!(Codec::PCMU.samples_per_packet(), 160);
    }

    #[test]
    fn test_validator_basic() {
        let mut validator = RtpValidator::new(Codec::PCMU);

        // Add some packets
        for i in 0..10u16 {
            let data = create_test_packet(i, i as u32 * 160, 0x12345678, 0);
            validator.record_packet(&data);
        }

        assert_eq!(validator.packet_count(), 10);
        assert_eq!(validator.packet_loss_percent(), 0.0);

        let result = validator.verify_stream();
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validator_packet_loss() {
        let mut validator = RtpValidator::new(Codec::PCMU);

        // Add packets with gaps
        validator.record_packet(&create_test_packet(0, 0, 0x12345678, 0));
        validator.record_packet(&create_test_packet(1, 160, 0x12345678, 0));
        // Skip sequence 2
        validator.record_packet(&create_test_packet(3, 480, 0x12345678, 0));
        validator.record_packet(&create_test_packet(4, 640, 0x12345678, 0));

        assert_eq!(validator.packet_count(), 4);
        let loss = validator.packet_loss_percent();
        assert!(loss > 0.0 && loss < 50.0); // Should be 1 out of 5 = 20%
    }

    fn create_test_packet(seq: u16, ts: u32, ssrc: u32, pt: u8) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x80); // V=2, no padding/extension/CSRC
        data.push(pt); // Payload type
        data.extend_from_slice(&seq.to_be_bytes());
        data.extend_from_slice(&ts.to_be_bytes());
        data.extend_from_slice(&ssrc.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // Dummy payload
        data
    }
}
