//! DTMF telephone event handling (RFC 4733).
//!
//! Provides encoding and decoding of DTMF digits as RTP telephone events.

use bytes::{BufMut, BytesMut};

/// DTMF digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DtmfDigit {
    Zero,
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Star,
    Pound,
    A,
    B,
    C,
    D,
}

impl DtmfDigit {
    /// Get the RFC 4733 event code for this digit.
    pub fn event_code(&self) -> u8 {
        match self {
            DtmfDigit::Zero => 0,
            DtmfDigit::One => 1,
            DtmfDigit::Two => 2,
            DtmfDigit::Three => 3,
            DtmfDigit::Four => 4,
            DtmfDigit::Five => 5,
            DtmfDigit::Six => 6,
            DtmfDigit::Seven => 7,
            DtmfDigit::Eight => 8,
            DtmfDigit::Nine => 9,
            DtmfDigit::Star => 10,
            DtmfDigit::Pound => 11,
            DtmfDigit::A => 12,
            DtmfDigit::B => 13,
            DtmfDigit::C => 14,
            DtmfDigit::D => 15,
        }
    }

    /// Parse from RFC 4733 event code.
    pub fn from_event_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(DtmfDigit::Zero),
            1 => Some(DtmfDigit::One),
            2 => Some(DtmfDigit::Two),
            3 => Some(DtmfDigit::Three),
            4 => Some(DtmfDigit::Four),
            5 => Some(DtmfDigit::Five),
            6 => Some(DtmfDigit::Six),
            7 => Some(DtmfDigit::Seven),
            8 => Some(DtmfDigit::Eight),
            9 => Some(DtmfDigit::Nine),
            10 => Some(DtmfDigit::Star),
            11 => Some(DtmfDigit::Pound),
            12 => Some(DtmfDigit::A),
            13 => Some(DtmfDigit::B),
            14 => Some(DtmfDigit::C),
            15 => Some(DtmfDigit::D),
            _ => None,
        }
    }

    /// Parse from character.
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            '0' => Some(DtmfDigit::Zero),
            '1' => Some(DtmfDigit::One),
            '2' => Some(DtmfDigit::Two),
            '3' => Some(DtmfDigit::Three),
            '4' => Some(DtmfDigit::Four),
            '5' => Some(DtmfDigit::Five),
            '6' => Some(DtmfDigit::Six),
            '7' => Some(DtmfDigit::Seven),
            '8' => Some(DtmfDigit::Eight),
            '9' => Some(DtmfDigit::Nine),
            '*' => Some(DtmfDigit::Star),
            '#' => Some(DtmfDigit::Pound),
            'A' | 'a' => Some(DtmfDigit::A),
            'B' | 'b' => Some(DtmfDigit::B),
            'C' | 'c' => Some(DtmfDigit::C),
            'D' | 'd' => Some(DtmfDigit::D),
            _ => None,
        }
    }

    /// Get the character representation.
    pub fn as_char(&self) -> char {
        match self {
            DtmfDigit::Zero => '0',
            DtmfDigit::One => '1',
            DtmfDigit::Two => '2',
            DtmfDigit::Three => '3',
            DtmfDigit::Four => '4',
            DtmfDigit::Five => '5',
            DtmfDigit::Six => '6',
            DtmfDigit::Seven => '7',
            DtmfDigit::Eight => '8',
            DtmfDigit::Nine => '9',
            DtmfDigit::Star => '*',
            DtmfDigit::Pound => '#',
            DtmfDigit::A => 'A',
            DtmfDigit::B => 'B',
            DtmfDigit::C => 'C',
            DtmfDigit::D => 'D',
        }
    }
}

impl std::fmt::Display for DtmfDigit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_char())
    }
}

/// RFC 4733 telephone event payload.
///
/// Format (4 bytes):
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfEvent {
    /// DTMF digit (event code 0-15).
    pub digit: DtmfDigit,
    /// End of event flag.
    pub end: bool,
    /// Volume (0-63, 0 is loudest).
    pub volume: u8,
    /// Duration in timestamp units.
    pub duration: u16,
}

impl DtmfEvent {
    /// Create a new DTMF event.
    pub fn new(digit: DtmfDigit, duration: u16) -> Self {
        Self {
            digit,
            end: false,
            volume: 10, // Default volume
            duration,
        }
    }

    /// Create with end flag set.
    pub fn with_end(mut self) -> Self {
        self.end = true;
        self
    }

    /// Create with specific volume.
    pub fn with_volume(mut self, volume: u8) -> Self {
        self.volume = volume.min(63);
        self
    }

    /// Encode to bytes.
    pub fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0] = self.digit.event_code();
        buf[1] = if self.end { 0x80 } else { 0x00 } | (self.volume & 0x3F);
        buf[2] = (self.duration >> 8) as u8;
        buf[3] = (self.duration & 0xFF) as u8;
        buf
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let event_code = data[0];
        let digit = DtmfDigit::from_event_code(event_code)?;
        let end = (data[1] & 0x80) != 0;
        let volume = data[1] & 0x3F;
        let duration = u16::from_be_bytes([data[2], data[3]]);

        Some(Self {
            digit,
            end,
            volume,
            duration,
        })
    }
}

/// DTMF sender for generating telephone event RTP packets.
pub struct DtmfSender {
    /// Payload type for telephone events.
    payload_type: u8,
    /// SSRC.
    ssrc: u32,
    /// Current sequence number.
    sequence: u16,
    /// Sample rate (8000 for narrowband).
    sample_rate: u32,
}

impl DtmfSender {
    /// Create a new DTMF sender.
    pub fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            sequence: rand::random(),
            sample_rate: 8000,
        }
    }

    /// Set the sample rate (default 8000).
    pub fn set_sample_rate(&mut self, rate: u32) {
        self.sample_rate = rate;
    }

    /// Generate RTP packets for a DTMF digit.
    ///
    /// Returns a series of RTP packets to send. Per RFC 4733, we send:
    /// - Initial packet (may be repeated for reliability)
    /// - Update packets every 50ms
    /// - End packets (with E bit set, repeated 3 times)
    pub fn generate_packets(
        &mut self,
        digit: DtmfDigit,
        duration_ms: u32,
        timestamp: u32,
    ) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let samples_per_packet = self.sample_rate / 20; // 50ms intervals
        let total_samples = (duration_ms * self.sample_rate) / 1000;
        let packet_count = (total_samples / samples_per_packet).max(1);

        for i in 0..packet_count {
            let is_last = i == packet_count - 1;
            let current_duration = (i + 1) * samples_per_packet;

            let event = if is_last {
                DtmfEvent::new(digit, current_duration.min(0xFFFF) as u16).with_end()
            } else {
                DtmfEvent::new(digit, current_duration.min(0xFFFF) as u16)
            };

            // Build RTP packet
            let packet = self.build_rtp_packet(&event, timestamp, i == 0);
            packets.push(packet);

            // Send end packet 3 times for reliability
            if is_last {
                for _ in 0..2 {
                    self.sequence = self.sequence.wrapping_add(1);
                    let end_packet = self.build_rtp_packet(&event, timestamp, false);
                    packets.push(end_packet);
                }
            }

            self.sequence = self.sequence.wrapping_add(1);
        }

        packets
    }

    /// Build a single RTP packet with DTMF event payload.
    fn build_rtp_packet(&self, event: &DtmfEvent, timestamp: u32, marker: bool) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(16);

        // RTP header
        // V=2, P=0, X=0, CC=0
        buf.put_u8(0x80);
        // M bit + payload type
        buf.put_u8(if marker { 0x80 } else { 0x00 } | self.payload_type);
        // Sequence number
        buf.put_u16(self.sequence);
        // Timestamp
        buf.put_u32(timestamp);
        // SSRC
        buf.put_u32(self.ssrc);

        // DTMF event payload
        buf.put_slice(&event.encode());

        buf.to_vec()
    }
}

/// DTMF receiver for parsing telephone event RTP packets.
pub struct DtmfReceiver {
    /// Payload type for telephone events.
    payload_type: u8,
    /// Current event being received.
    current_event: Option<(DtmfDigit, u32)>, // (digit, start_timestamp)
    /// Last completed event.
    last_event: Option<DtmfDigit>,
}

impl DtmfReceiver {
    /// Create a new DTMF receiver.
    pub fn new(payload_type: u8) -> Self {
        Self {
            payload_type,
            current_event: None,
            last_event: None,
        }
    }

    /// Process an RTP packet and return any completed DTMF digit.
    ///
    /// Returns Some(digit) when an event with the E bit is received.
    pub fn process_packet(&mut self, payload_type: u8, payload: &[u8]) -> Option<DtmfDigit> {
        if payload_type != self.payload_type {
            return None;
        }

        let event = DtmfEvent::decode(payload)?;

        if event.end {
            // Event completed
            let digit = event.digit;
            self.current_event = None;

            // Avoid duplicates from repeated end packets
            if self.last_event != Some(digit) {
                self.last_event = Some(digit);
                return Some(digit);
            }
        } else {
            // Event in progress
            self.current_event = Some((event.digit, 0));
            self.last_event = None;
        }

        None
    }

    /// Get the currently active event (if any).
    pub fn current_digit(&self) -> Option<DtmfDigit> {
        self.current_event.map(|(d, _)| d)
    }

    /// Clear receiver state.
    pub fn reset(&mut self) {
        self.current_event = None;
        self.last_event = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digit_event_codes() {
        assert_eq!(DtmfDigit::Zero.event_code(), 0);
        assert_eq!(DtmfDigit::Nine.event_code(), 9);
        assert_eq!(DtmfDigit::Star.event_code(), 10);
        assert_eq!(DtmfDigit::Pound.event_code(), 11);
        assert_eq!(DtmfDigit::D.event_code(), 15);
    }

    #[test]
    fn test_digit_from_char() {
        assert_eq!(DtmfDigit::from_char('0'), Some(DtmfDigit::Zero));
        assert_eq!(DtmfDigit::from_char('*'), Some(DtmfDigit::Star));
        assert_eq!(DtmfDigit::from_char('#'), Some(DtmfDigit::Pound));
        assert_eq!(DtmfDigit::from_char('A'), Some(DtmfDigit::A));
        assert_eq!(DtmfDigit::from_char('a'), Some(DtmfDigit::A));
        assert_eq!(DtmfDigit::from_char('x'), None);
    }

    #[test]
    fn test_digit_roundtrip() {
        for code in 0..=15 {
            let digit = DtmfDigit::from_event_code(code).unwrap();
            assert_eq!(digit.event_code(), code);
        }
    }

    #[test]
    fn test_event_encode_decode() {
        let event = DtmfEvent::new(DtmfDigit::Five, 1000)
            .with_volume(20)
            .with_end();

        let encoded = event.encode();
        let decoded = DtmfEvent::decode(&encoded).unwrap();

        assert_eq!(decoded.digit, DtmfDigit::Five);
        assert_eq!(decoded.duration, 1000);
        assert_eq!(decoded.volume, 20);
        assert!(decoded.end);
    }

    #[test]
    fn test_event_format() {
        let event = DtmfEvent::new(DtmfDigit::One, 0x1234).with_end();
        let encoded = event.encode();

        assert_eq!(encoded[0], 1); // Event code for '1'
        assert_eq!(encoded[1] & 0x80, 0x80); // End bit set
        assert_eq!(encoded[2], 0x12); // Duration high byte
        assert_eq!(encoded[3], 0x34); // Duration low byte
    }

    #[test]
    fn test_sender_generate_packets() {
        let mut sender = DtmfSender::new(101, 0x12345678);
        let packets = sender.generate_packets(DtmfDigit::One, 100, 1000);

        // Should have at least 1 packet + 2 end repeats
        assert!(packets.len() >= 3);

        // Check first packet has marker bit
        assert_eq!(packets[0][1] & 0x80, 0x80);

        // Check SSRC in all packets
        for packet in &packets {
            let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
            assert_eq!(ssrc, 0x12345678);
        }
    }

    #[test]
    fn test_receiver_process() {
        let mut receiver = DtmfReceiver::new(101);

        // Start event (no end bit)
        let start_event = DtmfEvent::new(DtmfDigit::Seven, 100);
        let result = receiver.process_packet(101, &start_event.encode());
        assert!(result.is_none()); // Not complete yet
        assert_eq!(receiver.current_digit(), Some(DtmfDigit::Seven));

        // End event
        let end_event = DtmfEvent::new(DtmfDigit::Seven, 500).with_end();
        let result = receiver.process_packet(101, &end_event.encode());
        assert_eq!(result, Some(DtmfDigit::Seven));
    }

    #[test]
    fn test_receiver_duplicate_end() {
        let mut receiver = DtmfReceiver::new(101);

        let end_event = DtmfEvent::new(DtmfDigit::Star, 500).with_end();

        // First end packet returns digit
        let result = receiver.process_packet(101, &end_event.encode());
        assert_eq!(result, Some(DtmfDigit::Star));

        // Duplicate end packets (for reliability) should not return digit again
        let result = receiver.process_packet(101, &end_event.encode());
        assert!(result.is_none());
    }

    #[test]
    fn test_receiver_wrong_payload_type() {
        let mut receiver = DtmfReceiver::new(101);
        let event = DtmfEvent::new(DtmfDigit::One, 100).with_end();

        // Wrong payload type
        let result = receiver.process_packet(102, &event.encode());
        assert!(result.is_none());
    }
}
