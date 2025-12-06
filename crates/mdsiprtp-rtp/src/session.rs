//! RTP session management.
//!
//! Manages RTP packet sending and receiving for a media stream.

use crate::packet::{RtpPacket, sequence_diff};
use mdsiprtp_core::{random_u16, random_u32};
use std::time::{Duration, Instant};

/// RTP session for managing a media stream.
#[derive(Debug)]
pub struct RtpSession {
    /// Local SSRC.
    ssrc: u32,
    /// Payload type.
    payload_type: u8,
    /// Clock rate (samples per second).
    clock_rate: u32,
    /// Next sequence number to send.
    next_seq: u16,
    /// Current timestamp.
    current_timestamp: u32,
    /// Packets sent.
    packets_sent: u64,
    /// Octets sent.
    octets_sent: u64,
    /// Start time for timestamp calculation.
    start_time: Instant,
    /// Receiver state for statistics.
    receiver_state: ReceiverState,
}

/// Receiver state for RTCP statistics.
#[derive(Debug, Default)]
pub struct ReceiverState {
    /// Highest sequence number received.
    pub max_seq: u16,
    /// Sequence number of first packet.
    pub base_seq: u16,
    /// Whether we've received any packets.
    pub initialized: bool,
    /// Packets received.
    pub packets_received: u64,
    /// Packets lost.
    pub packets_lost: u64,
    /// Expected packets (for loss calculation).
    pub expected_packets: u64,
    /// Last received timestamp.
    pub last_timestamp: u32,
    /// Jitter estimate (in timestamp units).
    pub jitter: u32,
    /// Last arrival time.
    pub last_arrival: Option<Instant>,
}

impl RtpSession {
    /// Create a new RTP session.
    pub fn new(ssrc: u32, payload_type: u8, clock_rate: u32) -> Self {
        // Start with random sequence number (per RFC 3550)
        let initial_seq = random_u16();
        let initial_ts = random_u32();

        Self {
            ssrc,
            payload_type,
            clock_rate,
            next_seq: initial_seq,
            current_timestamp: initial_ts,
            packets_sent: 0,
            octets_sent: 0,
            start_time: Instant::now(),
            receiver_state: ReceiverState::default(),
        }
    }

    /// Get the SSRC.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Get the payload type.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Get the clock rate.
    pub fn clock_rate(&self) -> u32 {
        self.clock_rate
    }

    /// Get packets sent count.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Get octets sent count.
    pub fn octets_sent(&self) -> u64 {
        self.octets_sent
    }

    /// Create an RTP packet for sending.
    ///
    /// `samples` is the number of samples in the payload (for timestamp calculation).
    /// `marker` indicates the start of a talkspurt.
    pub fn create_packet(&mut self, payload: Vec<u8>, samples: u32, marker: bool) -> RtpPacket {
        let seq = self.next_seq;
        let timestamp = self.current_timestamp;

        self.next_seq = self.next_seq.wrapping_add(1);
        self.current_timestamp = self.current_timestamp.wrapping_add(samples);
        self.packets_sent += 1;
        self.octets_sent += payload.len() as u64;

        RtpPacket::new(self.payload_type, seq, timestamp, self.ssrc)
            .with_marker(marker)
            .with_payload(payload)
    }

    /// Create a packet with specific timestamp (for silence suppression).
    pub fn create_packet_at(&mut self, payload: Vec<u8>, timestamp: u32, marker: bool) -> RtpPacket {
        let seq = self.next_seq;

        self.next_seq = self.next_seq.wrapping_add(1);
        self.current_timestamp = timestamp;
        self.packets_sent += 1;
        self.octets_sent += payload.len() as u64;

        RtpPacket::new(self.payload_type, seq, timestamp, self.ssrc)
            .with_marker(marker)
            .with_payload(payload)
    }

    /// Update timestamp based on elapsed time.
    ///
    /// Call this periodically to keep timestamp in sync with real time.
    pub fn update_timestamp(&mut self) {
        let elapsed = self.start_time.elapsed();
        let samples = (elapsed.as_secs_f64() * self.clock_rate as f64) as u32;
        self.current_timestamp = self.current_timestamp.wrapping_add(samples);
        self.start_time = Instant::now();
    }

    /// Process a received RTP packet and update statistics.
    pub fn receive_packet(&mut self, packet: &RtpPacket) {
        let now = Instant::now();

        if !self.receiver_state.initialized {
            self.receiver_state.base_seq = packet.sequence_number;
            self.receiver_state.max_seq = packet.sequence_number;
            self.receiver_state.initialized = true;
            self.receiver_state.last_timestamp = packet.timestamp;
            self.receiver_state.last_arrival = Some(now);
            self.receiver_state.packets_received = 1;
            self.receiver_state.expected_packets = 1;
            return;
        }

        self.receiver_state.packets_received += 1;

        // Update max sequence number
        let seq_diff = sequence_diff(packet.sequence_number, self.receiver_state.max_seq);
        if seq_diff > 0 {
            // Calculate expected packets
            let expected_increase = seq_diff as u64;
            self.receiver_state.expected_packets += expected_increase;

            // Calculate lost packets
            if expected_increase > 1 {
                self.receiver_state.packets_lost += expected_increase - 1;
            }

            self.receiver_state.max_seq = packet.sequence_number;
        }

        // Update jitter estimate (RFC 3550 A.8)
        if let Some(last_arrival) = self.receiver_state.last_arrival {
            let arrival_diff = now.duration_since(last_arrival);
            let arrival_samples = (arrival_diff.as_secs_f64() * self.clock_rate as f64) as i32;

            let ts_diff = packet.timestamp.wrapping_sub(self.receiver_state.last_timestamp) as i32;
            let d = (arrival_samples - ts_diff).unsigned_abs();

            // J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
            // Use saturating arithmetic to handle negative adjustments safely
            let adjustment = (d as i32 - self.receiver_state.jitter as i32) >> 4;
            if adjustment >= 0 {
                self.receiver_state.jitter = self.receiver_state.jitter.saturating_add(adjustment as u32);
            } else {
                self.receiver_state.jitter = self.receiver_state.jitter.saturating_sub((-adjustment) as u32);
            }
        }

        self.receiver_state.last_timestamp = packet.timestamp;
        self.receiver_state.last_arrival = Some(now);
    }

    /// Get receiver statistics.
    pub fn receiver_stats(&self) -> &ReceiverState {
        &self.receiver_state
    }

    /// Calculate packet loss percentage.
    pub fn packet_loss_percent(&self) -> f64 {
        let state = &self.receiver_state;
        if state.expected_packets == 0 {
            return 0.0;
        }
        (state.packets_lost as f64 / state.expected_packets as f64) * 100.0
    }

    /// Get jitter in milliseconds.
    pub fn jitter_ms(&self) -> f64 {
        let jitter_samples = self.receiver_state.jitter as f64;
        (jitter_samples / self.clock_rate as f64) * 1000.0
    }

    /// Calculate timestamp for a given duration from session start.
    pub fn timestamp_for_duration(&self, duration: Duration) -> u32 {
        let samples = (duration.as_secs_f64() * self.clock_rate as f64) as u32;
        self.current_timestamp.wrapping_add(samples)
    }

    /// Generate a Sender Report for this session.
    ///
    /// Call this periodically (typically every 5 seconds) when sending media.
    pub fn create_sender_report(&self) -> crate::rtcp::SenderReport {
        use crate::rtcp::{NtpTimestamp, ReportBlock, SenderReport};

        let mut report_blocks = Vec::new();

        // If we're also receiving, add a report block for the remote
        if self.receiver_state.initialized {
            let state = &self.receiver_state;

            // Calculate fraction lost (8-bit value, 0-255)
            let fraction_lost = if state.expected_packets > 0 {
                let loss_fraction = state.packets_lost as f64 / state.expected_packets as f64;
                (loss_fraction * 256.0).min(255.0) as u8
            } else {
                0
            };

            // Extended highest sequence number (32-bit)
            // Combine cycles with max_seq
            let extended_seq = state.max_seq as u32;

            report_blocks.push(ReportBlock {
                ssrc: 0, // Would be remote SSRC, set by caller
                fraction_lost,
                cumulative_lost: state.packets_lost.min(0x7FFFFF) as i32,
                extended_seq,
                jitter: state.jitter,
                last_sr: 0, // Would be set from received SR
                delay_since_sr: 0,
            });
        }

        SenderReport {
            ssrc: self.ssrc,
            ntp_timestamp: NtpTimestamp::now(),
            rtp_timestamp: self.current_timestamp,
            sender_packet_count: self.packets_sent as u32,
            sender_octet_count: self.octets_sent as u32,
            report_blocks,
        }
    }

    /// Generate a Receiver Report for this session.
    ///
    /// Call this periodically (typically every 5 seconds) when only receiving.
    pub fn create_receiver_report(&self, remote_ssrc: u32) -> crate::rtcp::ReceiverReport {
        use crate::rtcp::{ReceiverReport, ReportBlock};

        let mut report_blocks = Vec::new();

        if self.receiver_state.initialized {
            let state = &self.receiver_state;

            let fraction_lost = if state.expected_packets > 0 {
                let loss_fraction = state.packets_lost as f64 / state.expected_packets as f64;
                (loss_fraction * 256.0).min(255.0) as u8
            } else {
                0
            };

            let extended_seq = state.max_seq as u32;

            report_blocks.push(ReportBlock {
                ssrc: remote_ssrc,
                fraction_lost,
                cumulative_lost: state.packets_lost.min(0x7FFFFF) as i32,
                extended_seq,
                jitter: state.jitter,
                last_sr: 0,
                delay_since_sr: 0,
            });
        }

        ReceiverReport {
            ssrc: self.ssrc,
            report_blocks,
        }
    }

    /// Create an RTCP compound packet (SR + SDES or RR + SDES).
    pub fn create_rtcp_compound(&self, cname: &str, is_sender: bool) -> crate::rtcp::RtcpCompound {
        use crate::rtcp::RtcpCompound;

        if is_sender {
            let sr = self.create_sender_report();
            RtcpCompound::sender_compound(sr, cname)
        } else {
            let rr = self.create_receiver_report(0);
            RtcpCompound::receiver_compound(rr, cname)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_create_session() {
        let session = RtpSession::new(12345, 0, 8000);
        assert_eq!(session.ssrc(), 12345);
        assert_eq!(session.payload_type(), 0);
        assert_eq!(session.clock_rate(), 8000);
    }

    #[test]
    fn test_create_packet() {
        let mut session = RtpSession::new(12345, 0, 8000);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        let pkt1 = session.create_packet(payload.clone(), 160, true);
        assert!(pkt1.marker);
        assert_eq!(pkt1.payload_type, 0);
        assert_eq!(pkt1.ssrc, 12345);

        let pkt2 = session.create_packet(payload, 160, false);
        assert!(!pkt2.marker);
        // Sequence number should increment
        assert_eq!(
            pkt2.sequence_number,
            pkt1.sequence_number.wrapping_add(1)
        );
        // Timestamp should increment by 160
        assert_eq!(pkt2.timestamp, pkt1.timestamp.wrapping_add(160));
    }

    #[test]
    fn test_packets_sent() {
        let mut session = RtpSession::new(12345, 0, 8000);

        session.create_packet(vec![0; 160], 160, false);
        session.create_packet(vec![0; 160], 160, false);
        session.create_packet(vec![0; 160], 160, false);

        assert_eq!(session.packets_sent(), 3);
        assert_eq!(session.octets_sent(), 480);
    }

    #[test]
    fn test_receive_packet() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Simulate receiving packets
        let pkt1 = RtpPacket::new(0, 100, 0, 99999)
            .with_payload(Bytes::from_static(&[0; 160]));
        session.receive_packet(&pkt1);

        assert_eq!(session.receiver_stats().packets_received, 1);
        assert!(session.receiver_stats().initialized);

        let pkt2 = RtpPacket::new(0, 101, 160, 99999)
            .with_payload(Bytes::from_static(&[0; 160]));
        session.receive_packet(&pkt2);

        assert_eq!(session.receiver_stats().packets_received, 2);
        assert_eq!(session.receiver_stats().max_seq, 101);
    }

    #[test]
    fn test_packet_loss_detection() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Receive packet 100
        let pkt1 = RtpPacket::new(0, 100, 0, 99999);
        session.receive_packet(&pkt1);

        // Skip packet 101, receive 102
        let pkt3 = RtpPacket::new(0, 102, 320, 99999);
        session.receive_packet(&pkt3);

        // Should detect 1 lost packet
        assert_eq!(session.receiver_stats().packets_lost, 1);
        assert_eq!(session.receiver_stats().expected_packets, 3);
    }
}
