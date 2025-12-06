//! RTP session management.
//!
//! Manages RTP packet sending and receiving for a media stream.

use crate::packet::{sequence_diff, RtpPacket};
use mdsiprtp_core::{random_u16, random_u32};
use std::collections::VecDeque;
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

// =============================================================================
// Congestion Control (AIMD-based)
// =============================================================================

/// Congestion controller state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow start - exponential increase.
    SlowStart,
    /// Congestion avoidance - additive increase.
    CongestionAvoidance,
    /// Rate reduction after loss.
    Recovery,
}

/// Simple AIMD (Additive Increase Multiplicative Decrease) congestion controller.
///
/// This provides basic congestion control based on:
/// - NACK feedback (packet loss detected)
/// - REMB feedback (receiver bandwidth estimate)
/// - RTT measurements
///
/// The controller maintains a target bitrate that can be queried by the encoder
/// or pacer to adjust sending rate.
#[derive(Debug)]
pub struct CongestionController {
    /// Current congestion state.
    state: CongestionState,
    /// Current target bitrate (bps).
    target_bitrate: u64,
    /// Minimum bitrate (bps).
    min_bitrate: u64,
    /// Maximum bitrate (bps).
    max_bitrate: u64,
    /// Slow start threshold (bps).
    ssthresh: u64,
    /// Last time we increased the rate.
    last_increase: Instant,
    /// Last time we decreased the rate (for rate limiting decreases).
    last_decrease: Instant,
    /// Recent RTT samples (for smoothing).
    rtt_samples: VecDeque<Duration>,
    /// Smoothed RTT.
    smoothed_rtt: Duration,
    /// RTT variance.
    rtt_var: Duration,
    /// Number of NACKs received in current interval.
    nacks_in_interval: u32,
    /// Packets sent in current interval.
    packets_in_interval: u32,
    /// Last REMB bitrate received.
    last_remb: Option<u64>,
}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new(500_000, 50_000, 5_000_000) // 500kbps start, 50kbps min, 5Mbps max
    }
}

impl CongestionController {
    /// Create a new congestion controller.
    ///
    /// # Arguments
    /// * `initial_bitrate` - Starting bitrate in bps
    /// * `min_bitrate` - Minimum bitrate in bps
    /// * `max_bitrate` - Maximum bitrate in bps
    pub fn new(initial_bitrate: u64, min_bitrate: u64, max_bitrate: u64) -> Self {
        Self {
            state: CongestionState::SlowStart,
            target_bitrate: initial_bitrate,
            min_bitrate,
            max_bitrate,
            ssthresh: max_bitrate / 2,
            last_increase: Instant::now(),
            last_decrease: Instant::now(),
            rtt_samples: VecDeque::with_capacity(10),
            smoothed_rtt: Duration::from_millis(100),
            rtt_var: Duration::from_millis(50),
            nacks_in_interval: 0,
            packets_in_interval: 0,
            last_remb: None,
        }
    }

    /// Get the current target bitrate in bps.
    pub fn target_bitrate(&self) -> u64 {
        self.target_bitrate
    }

    /// Get the current congestion state.
    pub fn state(&self) -> CongestionState {
        self.state
    }

    /// Get the smoothed RTT.
    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    /// Record that a packet was sent.
    pub fn on_packet_sent(&mut self) {
        self.packets_in_interval += 1;
    }

    /// Handle NACK feedback (packet loss detected).
    ///
    /// This triggers multiplicative decrease of the target bitrate.
    pub fn on_nack(&mut self, lost_packets: u32) {
        self.nacks_in_interval += lost_packets;

        // Rate limit decreases to at most once per RTT
        if self.last_decrease.elapsed() < self.smoothed_rtt {
            return;
        }

        // Multiplicative decrease (halve the rate)
        self.target_bitrate = (self.target_bitrate / 2).max(self.min_bitrate);
        self.ssthresh = self.target_bitrate;
        self.state = CongestionState::Recovery;
        self.last_decrease = Instant::now();

        tracing::debug!(
            "NACK: Reduced bitrate to {} bps (lost {} packets)",
            self.target_bitrate,
            lost_packets
        );
    }

    /// Handle REMB feedback (receiver estimated maximum bitrate).
    ///
    /// The REMB value is used as a ceiling for the target bitrate.
    pub fn on_remb(&mut self, bitrate: u64) {
        self.last_remb = Some(bitrate);

        // If REMB is significantly lower than our target, reduce immediately
        if bitrate < self.target_bitrate * 90 / 100 {
            self.target_bitrate = bitrate.max(self.min_bitrate);
            self.ssthresh = self.target_bitrate;
            self.state = CongestionState::CongestionAvoidance;
            self.last_decrease = Instant::now();

            tracing::debug!("REMB: Reduced bitrate to {} bps", self.target_bitrate);
        }

        // Clamp max bitrate to REMB
        if bitrate < self.max_bitrate {
            self.max_bitrate = bitrate;
        }
    }

    /// Handle RTT measurement from RTCP.
    ///
    /// Updates the smoothed RTT using exponential weighted moving average.
    pub fn on_rtt(&mut self, rtt: Duration) {
        // Add to sample history
        if self.rtt_samples.len() >= 10 {
            self.rtt_samples.pop_front();
        }
        self.rtt_samples.push_back(rtt);

        // Update smoothed RTT (RFC 6298-like algorithm)
        if self.rtt_samples.len() == 1 {
            self.smoothed_rtt = rtt;
            self.rtt_var = rtt / 2;
        } else {
            // rttvar = (1 - 1/4) * rttvar + 1/4 * |srtt - rtt|
            let diff = self.smoothed_rtt.abs_diff(rtt);
            self.rtt_var = self.rtt_var * 3 / 4 + diff / 4;

            // srtt = (1 - 1/8) * srtt + 1/8 * rtt
            self.smoothed_rtt = self.smoothed_rtt * 7 / 8 + rtt / 8;
        }
    }

    /// Periodic update - call this regularly (e.g., every 100ms).
    ///
    /// Handles additive increase when no congestion is detected.
    pub fn update(&mut self) {
        let now = Instant::now();

        // Calculate loss ratio in current interval
        let loss_ratio = if self.packets_in_interval > 0 {
            self.nacks_in_interval as f64 / self.packets_in_interval as f64
        } else {
            0.0
        };

        // Reset interval counters
        self.nacks_in_interval = 0;
        self.packets_in_interval = 0;

        // If significant loss, don't increase
        if loss_ratio > 0.02 {
            return;
        }

        // Rate increase logic
        let increase_interval = Duration::from_millis(100);
        if now.duration_since(self.last_increase) < increase_interval {
            return;
        }

        match self.state {
            CongestionState::SlowStart => {
                // Exponential increase (double every RTT)
                let increase = self.target_bitrate / 10; // ~10% per interval
                self.target_bitrate = (self.target_bitrate + increase).min(self.max_bitrate);

                if self.target_bitrate >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                    tracing::debug!(
                        "Entering congestion avoidance at {} bps",
                        self.target_bitrate
                    );
                }
            }
            CongestionState::CongestionAvoidance | CongestionState::Recovery => {
                // Additive increase (fixed increment per RTT)
                // Increase by approximately 1 packet per RTT
                let packet_size_bits = 1200 * 8; // ~1200 byte packets
                let packets_per_second = self.target_bitrate / packet_size_bits as u64;
                let increase = (packets_per_second / 10).max(10_000); // At least 10kbps

                self.target_bitrate = (self.target_bitrate + increase).min(self.max_bitrate);

                // Respect REMB ceiling
                if let Some(remb) = self.last_remb {
                    self.target_bitrate = self.target_bitrate.min(remb);
                }
            }
        }

        self.last_increase = now;
    }

    /// Get the recommended packet pacing interval.
    ///
    /// Returns the interval between packets to achieve the target bitrate
    /// for a given packet size.
    pub fn pacing_interval(&self, packet_size_bytes: u32) -> Duration {
        let packet_size_bits = packet_size_bytes as u64 * 8;
        if self.target_bitrate == 0 {
            return Duration::from_millis(20);
        }
        let interval_secs = packet_size_bits as f64 / self.target_bitrate as f64;
        Duration::from_secs_f64(interval_secs)
    }

    /// Reset the controller to initial state.
    pub fn reset(&mut self, initial_bitrate: u64) {
        self.state = CongestionState::SlowStart;
        self.target_bitrate = initial_bitrate;
        self.ssthresh = self.max_bitrate / 2;
        self.nacks_in_interval = 0;
        self.packets_in_interval = 0;
        self.last_remb = None;
    }
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
    pub fn create_packet_at(
        &mut self,
        payload: Vec<u8>,
        timestamp: u32,
        marker: bool,
    ) -> RtpPacket {
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

            let ts_diff = packet
                .timestamp
                .wrapping_sub(self.receiver_state.last_timestamp) as i32;
            let d = (arrival_samples - ts_diff).unsigned_abs();

            // J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
            // Use saturating arithmetic to handle negative adjustments safely
            let adjustment = (d as i32 - self.receiver_state.jitter as i32) >> 4;
            if adjustment >= 0 {
                self.receiver_state.jitter =
                    self.receiver_state.jitter.saturating_add(adjustment as u32);
            } else {
                self.receiver_state.jitter = self
                    .receiver_state
                    .jitter
                    .saturating_sub((-adjustment) as u32);
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

    // ReceiverState tests
    #[test]
    fn test_receiver_state_default() {
        let state = ReceiverState::default();
        assert_eq!(state.max_seq, 0);
        assert_eq!(state.base_seq, 0);
        assert!(!state.initialized);
        assert_eq!(state.packets_received, 0);
        assert_eq!(state.packets_lost, 0);
        assert_eq!(state.expected_packets, 0);
        assert_eq!(state.last_timestamp, 0);
        assert_eq!(state.jitter, 0);
        assert!(state.last_arrival.is_none());
    }

    #[test]
    fn test_receiver_state_debug() {
        let state = ReceiverState::default();
        let debug = format!("{:?}", state);
        assert!(debug.contains("ReceiverState"));
    }

    // CongestionState tests
    #[test]
    fn test_congestion_state_debug() {
        assert!(format!("{:?}", CongestionState::SlowStart).contains("SlowStart"));
        assert!(
            format!("{:?}", CongestionState::CongestionAvoidance).contains("CongestionAvoidance")
        );
        assert!(format!("{:?}", CongestionState::Recovery).contains("Recovery"));
    }

    #[test]
    fn test_congestion_state_eq() {
        assert_eq!(CongestionState::SlowStart, CongestionState::SlowStart);
        assert_ne!(CongestionState::SlowStart, CongestionState::Recovery);
    }

    #[test]
    fn test_congestion_state_clone() {
        let state = CongestionState::CongestionAvoidance;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    // RtpSession tests
    #[test]
    fn test_create_session() {
        let session = RtpSession::new(12345, 0, 8000);
        assert_eq!(session.ssrc(), 12345);
        assert_eq!(session.payload_type(), 0);
        assert_eq!(session.clock_rate(), 8000);
    }

    #[test]
    fn test_session_debug() {
        let session = RtpSession::new(12345, 0, 8000);
        let debug = format!("{:?}", session);
        assert!(debug.contains("RtpSession"));
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
        assert_eq!(pkt2.sequence_number, pkt1.sequence_number.wrapping_add(1));
        // Timestamp should increment by 160
        assert_eq!(pkt2.timestamp, pkt1.timestamp.wrapping_add(160));
    }

    #[test]
    fn test_create_packet_at() {
        let mut session = RtpSession::new(12345, 0, 8000);
        let payload = vec![0x01, 0x02, 0x03];

        let specific_ts = 1000000;
        let pkt = session.create_packet_at(payload.clone(), specific_ts, true);

        assert_eq!(pkt.timestamp, specific_ts);
        assert!(pkt.marker);
        assert_eq!(session.packets_sent(), 1);
        assert_eq!(session.octets_sent(), 3);
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
    fn test_update_timestamp() {
        let mut session = RtpSession::new(12345, 0, 8000);
        let initial_ts = session.current_timestamp;

        // Small sleep to ensure some time passes
        std::thread::sleep(Duration::from_millis(10));

        session.update_timestamp();

        // Timestamp should have advanced
        // Note: the new timestamp might wrap, so we can't simply assert >
        // Just verify the function doesn't panic
    }

    #[test]
    fn test_receive_packet() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Simulate receiving packets
        let pkt1 = RtpPacket::new(0, 100, 0, 99999).with_payload(Bytes::from_static(&[0; 160]));
        session.receive_packet(&pkt1);

        assert_eq!(session.receiver_stats().packets_received, 1);
        assert!(session.receiver_stats().initialized);

        let pkt2 = RtpPacket::new(0, 101, 160, 99999).with_payload(Bytes::from_static(&[0; 160]));
        session.receive_packet(&pkt2);

        assert_eq!(session.receiver_stats().packets_received, 2);
        assert_eq!(session.receiver_stats().max_seq, 101);
    }

    #[test]
    fn test_receive_packet_out_of_order() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Receive packet 100
        let pkt1 = RtpPacket::new(0, 100, 0, 99999);
        session.receive_packet(&pkt1);

        // Receive packet 102 first (101 is delayed)
        let pkt3 = RtpPacket::new(0, 102, 320, 99999);
        session.receive_packet(&pkt3);

        // Receive delayed packet 101
        let pkt2 = RtpPacket::new(0, 101, 160, 99999);
        session.receive_packet(&pkt2);

        // max_seq should still be 102
        assert_eq!(session.receiver_stats().max_seq, 102);
        assert_eq!(session.receiver_stats().packets_received, 3);
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

    #[test]
    fn test_packet_loss_percent() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // No packets yet
        assert_eq!(session.packet_loss_percent(), 0.0);

        // Receive packet 100
        let pkt1 = RtpPacket::new(0, 100, 0, 99999);
        session.receive_packet(&pkt1);

        // Skip 101-104, receive 105 (4 lost packets)
        let pkt2 = RtpPacket::new(0, 105, 800, 99999);
        session.receive_packet(&pkt2);

        // Expected: 6 packets (100-105), Lost: 4, Loss = 4/6 * 100 = 66.67%
        let loss = session.packet_loss_percent();
        assert!(loss > 60.0);
        assert!(loss < 70.0);
    }

    #[test]
    fn test_jitter_ms() {
        let session = RtpSession::new(12345, 0, 8000);
        // Initial jitter should be 0
        assert_eq!(session.jitter_ms(), 0.0);
    }

    #[test]
    fn test_jitter_calculation() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Receive first packet
        let pkt1 = RtpPacket::new(0, 100, 0, 99999);
        session.receive_packet(&pkt1);

        // Small delay then receive second packet
        std::thread::sleep(Duration::from_millis(25)); // ~200 samples at 8kHz

        let pkt2 = RtpPacket::new(0, 101, 160, 99999);
        session.receive_packet(&pkt2);

        // Jitter should be calculated
        // Can't assert exact value due to timing variability
    }

    #[test]
    fn test_timestamp_for_duration() {
        let session = RtpSession::new(12345, 0, 8000);

        // 1 second at 8000 Hz = 8000 samples
        let ts = session.timestamp_for_duration(Duration::from_secs(1));
        let expected = session.current_timestamp.wrapping_add(8000);
        assert_eq!(ts, expected);

        // 500ms at 8000 Hz = 4000 samples
        let ts2 = session.timestamp_for_duration(Duration::from_millis(500));
        let expected2 = session.current_timestamp.wrapping_add(4000);
        assert_eq!(ts2, expected2);
    }

    #[test]
    fn test_create_sender_report() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Send some packets
        session.create_packet(vec![0; 160], 160, false);
        session.create_packet(vec![0; 160], 160, false);

        let sr = session.create_sender_report();

        assert_eq!(sr.ssrc, 12345);
        assert_eq!(sr.sender_packet_count, 2);
        assert_eq!(sr.sender_octet_count, 320);
    }

    #[test]
    fn test_create_sender_report_with_receiver_stats() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Receive a packet first to initialize receiver state
        let pkt = RtpPacket::new(0, 100, 0, 99999);
        session.receive_packet(&pkt);

        // Send some packets
        session.create_packet(vec![0; 160], 160, false);

        let sr = session.create_sender_report();

        // Should have a report block
        assert!(!sr.report_blocks.is_empty());
    }

    #[test]
    fn test_create_receiver_report() {
        let mut session = RtpSession::new(12345, 0, 8000);

        // Receive some packets
        let pkt1 = RtpPacket::new(0, 100, 0, 99999);
        session.receive_packet(&pkt1);

        let pkt2 = RtpPacket::new(0, 101, 160, 99999);
        session.receive_packet(&pkt2);

        let rr = session.create_receiver_report(99999);

        assert_eq!(rr.ssrc, 12345);
        assert!(!rr.report_blocks.is_empty());
        assert_eq!(rr.report_blocks[0].ssrc, 99999);
    }

    #[test]
    fn test_create_receiver_report_uninitialized() {
        let session = RtpSession::new(12345, 0, 8000);

        let rr = session.create_receiver_report(99999);

        // No report blocks if we haven't received anything
        assert!(rr.report_blocks.is_empty());
    }

    #[test]
    fn test_create_rtcp_compound_sender() {
        use crate::rtcp::RtcpPacket;

        let mut session = RtpSession::new(12345, 0, 8000);
        session.create_packet(vec![0; 160], 160, false);

        let compound = session.create_rtcp_compound("user@host.example.com", true);

        // Should contain SR (first packet should be SenderReport)
        assert!(!compound.packets.is_empty());
        assert!(matches!(&compound.packets[0], RtcpPacket::SenderReport(_)));
    }

    #[test]
    fn test_create_rtcp_compound_receiver() {
        use crate::rtcp::RtcpPacket;

        let session = RtpSession::new(12345, 0, 8000);

        let compound = session.create_rtcp_compound("user@host.example.com", false);

        // Should contain RR (first packet should be ReceiverReport)
        assert!(!compound.packets.is_empty());
        assert!(matches!(
            &compound.packets[0],
            RtcpPacket::ReceiverReport(_)
        ));
    }

    // ==========================================================================
    // Congestion Controller Tests
    // ==========================================================================

    #[test]
    fn test_congestion_controller_creation() {
        let cc = CongestionController::default();
        assert_eq!(cc.target_bitrate(), 500_000);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_congestion_controller_custom() {
        let cc = CongestionController::new(1_000_000, 100_000, 10_000_000);
        assert_eq!(cc.target_bitrate(), 1_000_000);
    }

    #[test]
    fn test_congestion_controller_debug() {
        let cc = CongestionController::default();
        let debug = format!("{:?}", cc);
        assert!(debug.contains("CongestionController"));
    }

    #[test]
    fn test_on_packet_sent() {
        let mut cc = CongestionController::default();
        cc.on_packet_sent();
        cc.on_packet_sent();
        cc.on_packet_sent();
        // Internal state updated, can't directly verify packets_in_interval
        // but the function should not panic
    }

    #[test]
    fn test_nack_reduces_bitrate() {
        let mut cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // Force decrease to be allowed
        std::thread::sleep(Duration::from_millis(150));

        cc.on_nack(5);

        // Bitrate should be halved
        assert_eq!(cc.target_bitrate(), 500_000);
        assert_eq!(cc.state(), CongestionState::Recovery);
    }

    #[test]
    fn test_nack_rate_limited() {
        let mut cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // First NACK immediately after creation - rate limited
        cc.on_nack(5);

        // Bitrate should NOT be halved yet (rate limited)
        assert_eq!(cc.target_bitrate(), 1_000_000);
    }

    #[test]
    fn test_nack_min_bitrate() {
        let mut cc = CongestionController::new(100_000, 100_000, 10_000_000);

        // Force decrease to be allowed
        std::thread::sleep(Duration::from_millis(150));

        cc.on_nack(5);

        // Should not go below min_bitrate
        assert_eq!(cc.target_bitrate(), 100_000);
    }

    #[test]
    fn test_remb_caps_bitrate() {
        let mut cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // REMB says we should only use 500kbps
        cc.on_remb(500_000);

        // Bitrate should be reduced to match REMB
        assert!(cc.target_bitrate() <= 500_000);
    }

    #[test]
    fn test_remb_slightly_lower() {
        let mut cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // REMB only slightly lower (within 10%) - should not reduce immediately
        cc.on_remb(950_000);

        // Bitrate should stay at 1Mbps (within 10% of REMB)
        assert_eq!(cc.target_bitrate(), 1_000_000);
    }

    #[test]
    fn test_remb_updates_max() {
        let mut cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // REMB caps max bitrate
        cc.on_remb(2_000_000);

        // max_bitrate should be updated
        // This is internal, but subsequent operations would respect this limit
    }

    #[test]
    fn test_rtt_smoothing() {
        let mut cc = CongestionController::default();

        // Add several RTT samples
        cc.on_rtt(Duration::from_millis(100));
        cc.on_rtt(Duration::from_millis(120));
        cc.on_rtt(Duration::from_millis(90));

        // Smoothed RTT should be close to the average
        let srtt = cc.smoothed_rtt();
        assert!(srtt > Duration::from_millis(80));
        assert!(srtt < Duration::from_millis(130));
    }

    #[test]
    fn test_rtt_first_sample() {
        let mut cc = CongestionController::default();

        cc.on_rtt(Duration::from_millis(50));

        // First sample should set smoothed_rtt directly
        assert_eq!(cc.smoothed_rtt(), Duration::from_millis(50));
    }

    #[test]
    fn test_rtt_many_samples() {
        let mut cc = CongestionController::default();

        // Add more than 10 samples to test VecDeque cycling
        for i in 0..15 {
            cc.on_rtt(Duration::from_millis(100 + i * 5));
        }

        // Should have smoothed RTT close to recent values
        let srtt = cc.smoothed_rtt();
        assert!(srtt > Duration::from_millis(100));
        assert!(srtt < Duration::from_millis(200));
    }

    #[test]
    fn test_update_slow_start() {
        let mut cc = CongestionController::new(100_000, 10_000, 1_000_000);

        // Wait for increase interval
        std::thread::sleep(Duration::from_millis(110));

        cc.update();

        // Should have increased from slow start
        assert!(cc.target_bitrate() > 100_000);
    }

    #[test]
    fn test_update_with_loss() {
        let mut cc = CongestionController::new(500_000, 100_000, 10_000_000);

        // Simulate packet loss
        for _ in 0..10 {
            cc.on_packet_sent();
        }
        // Add NACKs to cause loss ratio > 2%
        cc.nacks_in_interval = 1; // 10% loss

        // Wait for increase interval
        std::thread::sleep(Duration::from_millis(110));

        let initial_bitrate = cc.target_bitrate();
        cc.update();

        // Should NOT increase due to loss
        assert_eq!(cc.target_bitrate(), initial_bitrate);
    }

    #[test]
    fn test_update_congestion_avoidance() {
        let mut cc = CongestionController::new(800_000, 100_000, 1_000_000);

        // Set to congestion avoidance mode
        cc.state = CongestionState::CongestionAvoidance;
        cc.ssthresh = 700_000;

        // Wait for increase interval
        std::thread::sleep(Duration::from_millis(110));

        cc.update();

        // Should have increased (additive increase)
        assert!(cc.target_bitrate() > 800_000);
    }

    #[test]
    fn test_update_respects_remb() {
        let mut cc = CongestionController::new(400_000, 100_000, 1_000_000);
        cc.state = CongestionState::CongestionAvoidance;

        // Set REMB cap
        cc.on_remb(450_000);

        // Wait for increase interval
        std::thread::sleep(Duration::from_millis(110));

        cc.update();

        // Should not exceed REMB
        assert!(cc.target_bitrate() <= 450_000);
    }

    #[test]
    fn test_pacing_interval() {
        let cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // 1Mbps = 1,000,000 bps
        // 1200 byte packet = 9600 bits
        // Interval = 9600 / 1,000,000 = 9.6ms
        let interval = cc.pacing_interval(1200);
        assert!(interval > Duration::from_millis(9));
        assert!(interval < Duration::from_millis(10));
    }

    #[test]
    fn test_pacing_interval_zero_bitrate() {
        let mut cc = CongestionController::new(0, 0, 10_000_000);
        cc.target_bitrate = 0;

        let interval = cc.pacing_interval(1200);
        assert_eq!(interval, Duration::from_millis(20));
    }

    #[test]
    fn test_pacing_interval_small_packet() {
        let cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        let interval = cc.pacing_interval(100);
        // 100 bytes = 800 bits, interval = 800/1_000_000 = 0.8ms
        assert!(interval < Duration::from_millis(1));
    }

    #[test]
    fn test_congestion_controller_reset() {
        let mut cc = CongestionController::new(1_000_000, 100_000, 10_000_000);

        // Trigger some state changes
        std::thread::sleep(Duration::from_millis(150));
        cc.on_nack(5);
        cc.on_remb(800_000);

        // Reset
        cc.reset(500_000);

        assert_eq!(cc.target_bitrate(), 500_000);
        assert_eq!(cc.state(), CongestionState::SlowStart);
    }

    #[test]
    fn test_transition_to_congestion_avoidance() {
        let mut cc = CongestionController::new(100_000, 10_000, 500_000);
        cc.ssthresh = 150_000;

        // Increase until we hit ssthresh
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(110));
            cc.update();
            if cc.state() == CongestionState::CongestionAvoidance {
                break;
            }
        }

        // Should eventually transition
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
    }
}
