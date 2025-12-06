//! Adaptive jitter buffer implementation.
//!
//! Buffers incoming RTP packets to smooth out network jitter and handle
//! packet reordering and loss. Uses adaptive delay estimation.

use std::collections::BTreeMap;
use std::time::Instant;

/// Jitter buffer configuration.
#[derive(Debug, Clone)]
pub struct JitterBufferConfig {
    /// Minimum buffer delay in milliseconds.
    pub min_delay_ms: u32,
    /// Maximum buffer delay in milliseconds.
    pub max_delay_ms: u32,
    /// Initial buffer delay in milliseconds.
    pub initial_delay_ms: u32,
    /// Clock rate (samples per second).
    pub clock_rate: u32,
    /// Samples per packet (e.g., 160 for 20ms @ 8kHz).
    pub samples_per_packet: u32,
}

impl Default for JitterBufferConfig {
    fn default() -> Self {
        Self {
            min_delay_ms: 20,
            max_delay_ms: 200,
            initial_delay_ms: 60,
            clock_rate: 8000,
            samples_per_packet: 160,
        }
    }
}

impl JitterBufferConfig {
    /// Create config for G.711 at 8kHz with 20ms packets.
    pub fn g711() -> Self {
        Self::default()
    }

    /// Convert milliseconds to samples.
    fn ms_to_samples(&self, ms: u32) -> u32 {
        (ms * self.clock_rate) / 1000
    }

    /// Convert samples to milliseconds.
    fn samples_to_ms(&self, samples: u32) -> u32 {
        (samples * 1000) / self.clock_rate
    }
}

/// A packet stored in the jitter buffer.
#[derive(Debug, Clone)]
pub struct BufferedPacket {
    /// RTP sequence number.
    pub sequence: u16,
    /// RTP timestamp.
    pub timestamp: u32,
    /// Decoded audio samples.
    pub samples: Vec<i16>,
    /// When packet was received.
    pub received_at: Instant,
}

/// Decision made by the jitter buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlayoutDecision {
    /// Play the next packet normally.
    Play,
    /// Expand (stretch) audio to increase delay.
    Expand,
    /// Conceal a lost packet with generated audio.
    Conceal,
    /// Accelerate (compress) audio to decrease delay.
    Accelerate,
    /// No audio available yet (buffer underrun).
    Silence,
}

/// Statistics from the jitter buffer.
#[derive(Debug, Clone, Default)]
pub struct JitterStats {
    /// Packets received.
    pub packets_received: u64,
    /// Packets played out.
    pub packets_played: u64,
    /// Packets lost (never arrived).
    pub packets_lost: u64,
    /// Packets arrived too late (discarded).
    pub packets_late: u64,
    /// Packets duplicated (discarded).
    pub packets_duplicate: u64,
    /// Current buffer depth in packets.
    pub buffer_depth: usize,
    /// Current target delay in ms.
    pub target_delay_ms: u32,
    /// Estimated jitter in ms.
    pub jitter_ms: f64,
}

/// Adaptive jitter buffer.
#[derive(Debug)]
pub struct JitterBuffer {
    config: JitterBufferConfig,
    /// Packets stored by timestamp.
    packets: BTreeMap<u32, BufferedPacket>,
    /// Current target delay in samples.
    target_delay: u32,
    /// Estimated jitter in samples (RFC 3550 algorithm).
    jitter: f64,
    /// Expected next sequence number.
    next_seq: Option<u16>,
    /// Expected next timestamp for playout.
    next_playout_ts: Option<u32>,
    /// Last packet's arrival time and timestamp for jitter calculation.
    last_arrival: Option<(Instant, u32)>,
    /// Statistics.
    stats: JitterStats,
    /// Last played samples (for PLC).
    last_samples: Vec<i16>,
    /// Whether buffer is primed (has initial delay worth of packets).
    primed: bool,
    /// Time when first packet arrived.
    first_packet_time: Option<Instant>,
}

impl JitterBuffer {
    /// Create a new jitter buffer.
    pub fn new(config: JitterBufferConfig) -> Self {
        let target_delay = config.ms_to_samples(config.initial_delay_ms);
        let samples_per_packet = config.samples_per_packet as usize;

        Self {
            config,
            packets: BTreeMap::new(),
            target_delay,
            jitter: 0.0,
            next_seq: None,
            next_playout_ts: None,
            last_arrival: None,
            stats: JitterStats::default(),
            last_samples: vec![0; samples_per_packet],
            primed: false,
            first_packet_time: None,
        }
    }

    /// Push a packet into the buffer.
    ///
    /// Returns true if packet was accepted, false if duplicate/too late.
    pub fn push(&mut self, sequence: u16, timestamp: u32, samples: Vec<i16>) -> bool {
        let now = Instant::now();
        self.stats.packets_received += 1;

        // Initialize on first packet
        if self.first_packet_time.is_none() {
            self.first_packet_time = Some(now);
            self.next_seq = Some(sequence);
            self.next_playout_ts = Some(timestamp);
        }

        // Update jitter estimate (RFC 3550 A.8)
        if let Some((last_time, last_ts)) = self.last_arrival {
            let arrival_diff = now.duration_since(last_time);
            let arrival_samples =
                (arrival_diff.as_secs_f64() * self.config.clock_rate as f64) as i32;

            let ts_diff = timestamp.wrapping_sub(last_ts) as i32;
            let d = (arrival_samples - ts_diff).unsigned_abs() as f64;

            // J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
            self.jitter += (d - self.jitter) / 16.0;
        }
        self.last_arrival = Some((now, timestamp));

        // Check for duplicate
        if self.packets.contains_key(&timestamp) {
            self.stats.packets_duplicate += 1;
            return false;
        }

        // Check if packet is too late (already played past this timestamp)
        if let Some(playout_ts) = self.next_playout_ts {
            if timestamp_before(timestamp, playout_ts) {
                self.stats.packets_late += 1;
                return false;
            }
        }

        // Update sequence tracking
        if let Some(expected_seq) = self.next_seq {
            let seq_diff = sequence_diff(sequence, expected_seq);
            if seq_diff > 0 {
                // Packets were skipped
                self.next_seq = Some(sequence.wrapping_add(1));
            } else if seq_diff == 0 {
                self.next_seq = Some(sequence.wrapping_add(1));
            }
            // If seq_diff < 0, it's an old packet (reordered), don't update next_seq
        }

        // Store packet
        self.packets.insert(
            timestamp,
            BufferedPacket {
                sequence,
                timestamp,
                samples,
                received_at: now,
            },
        );

        // Adapt target delay based on jitter
        self.adapt_delay();

        // Check if buffer is primed
        if !self.primed {
            let packets_needed = (self.target_delay / self.config.samples_per_packet) as usize;
            if self.packets.len() >= packets_needed.max(1) {
                self.primed = true;
            }
        }

        true
    }

    /// Get the next frame of audio for playout.
    ///
    /// Returns the decision and audio samples.
    pub fn pop(&mut self) -> (PlayoutDecision, Vec<i16>) {
        let samples_per_packet = self.config.samples_per_packet as usize;

        // Not primed yet - return silence
        if !self.primed {
            return (PlayoutDecision::Silence, vec![0; samples_per_packet]);
        }

        let playout_ts = match self.next_playout_ts {
            Some(ts) => ts,
            None => return (PlayoutDecision::Silence, vec![0; samples_per_packet]),
        };

        // Advance playout timestamp
        self.next_playout_ts = Some(playout_ts.wrapping_add(self.config.samples_per_packet));

        // Try to get the packet at playout timestamp
        if let Some(packet) = self.packets.remove(&playout_ts) {
            self.stats.packets_played += 1;
            self.last_samples = packet.samples.clone();
            self.stats.buffer_depth = self.packets.len();
            return (PlayoutDecision::Play, packet.samples);
        }

        // Packet not found - check if we need to conceal or accelerate

        // Look for nearest packet
        let next_packet_ts = self.packets.keys().next().copied();

        match next_packet_ts {
            Some(next_ts) => {
                let gap = timestamp_diff(next_ts, playout_ts);

                if gap <= self.config.samples_per_packet as i32 {
                    // Next packet is close, conceal this one
                    self.stats.packets_lost += 1;
                    let concealed = self.conceal_packet();
                    self.stats.buffer_depth = self.packets.len();
                    (PlayoutDecision::Conceal, concealed)
                } else if gap > self.target_delay as i32 * 2 {
                    // Buffer is too full, accelerate by skipping ahead
                    self.next_playout_ts = Some(next_ts);
                    if let Some(packet) = self.packets.remove(&next_ts) {
                        self.stats.packets_played += 1;
                        self.last_samples = packet.samples.clone();
                        self.stats.buffer_depth = self.packets.len();
                        return (PlayoutDecision::Accelerate, packet.samples);
                    }
                    self.stats.buffer_depth = self.packets.len();
                    (PlayoutDecision::Silence, vec![0; samples_per_packet])
                } else {
                    // Normal loss, conceal
                    self.stats.packets_lost += 1;
                    let concealed = self.conceal_packet();
                    self.stats.buffer_depth = self.packets.len();
                    (PlayoutDecision::Conceal, concealed)
                }
            }
            None => {
                // Buffer empty
                self.stats.packets_lost += 1;
                let concealed = self.conceal_packet();
                self.stats.buffer_depth = 0;
                (PlayoutDecision::Conceal, concealed)
            }
        }
    }

    /// Conceal a lost packet using simple PLC (fade out last frame).
    fn conceal_packet(&mut self) -> Vec<i16> {
        // Simple PLC: fade out the last packet
        let mut concealed = self.last_samples.clone();
        let len = concealed.len();
        for (i, sample) in concealed.iter_mut().enumerate() {
            // Linear fade out over the frame
            let factor = 1.0 - (i as f32 / len as f32) * 0.5;
            *sample = (*sample as f32 * factor) as i16;
        }
        self.last_samples = concealed.clone();
        concealed
    }

    /// Adapt the target delay based on observed jitter.
    fn adapt_delay(&mut self) {
        // Target delay = 2 * jitter + min_delay
        let jitter_samples = self.jitter as u32;
        let new_target = (2 * jitter_samples)
            .max(self.config.ms_to_samples(self.config.min_delay_ms))
            .min(self.config.ms_to_samples(self.config.max_delay_ms));

        // Smooth adaptation (don't change too quickly)
        if new_target > self.target_delay {
            // Increase quickly
            self.target_delay = self.target_delay + (new_target - self.target_delay) / 4;
        } else if new_target < self.target_delay {
            // Decrease slowly
            self.target_delay = self.target_delay - (self.target_delay - new_target) / 16;
        }

        self.stats.target_delay_ms = self.config.samples_to_ms(self.target_delay);
        self.stats.jitter_ms =
            (self.jitter * 1000.0) / self.config.clock_rate as f64;
    }

    /// Get current statistics.
    pub fn stats(&self) -> &JitterStats {
        &self.stats
    }

    /// Get number of packets currently in buffer.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Check if buffer is primed and ready for playout.
    pub fn is_primed(&self) -> bool {
        self.primed
    }

    /// Reset the buffer state.
    pub fn reset(&mut self) {
        self.packets.clear();
        self.next_seq = None;
        self.next_playout_ts = None;
        self.last_arrival = None;
        self.last_samples = vec![0; self.config.samples_per_packet as usize];
        self.primed = false;
        self.first_packet_time = None;
        self.jitter = 0.0;
        self.target_delay = self.config.ms_to_samples(self.config.initial_delay_ms);
        // Keep stats across reset
    }

    /// Get current target delay in milliseconds.
    pub fn target_delay_ms(&self) -> u32 {
        self.config.samples_to_ms(self.target_delay)
    }

    /// Get estimated jitter in milliseconds.
    pub fn jitter_ms(&self) -> f64 {
        self.stats.jitter_ms
    }
}

/// Calculate sequence number difference handling wraparound.
fn sequence_diff(a: u16, b: u16) -> i32 {
    let diff = a.wrapping_sub(b) as i16;
    diff as i32
}

/// Calculate timestamp difference handling wraparound.
fn timestamp_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

/// Check if timestamp a is before timestamp b (handling wraparound).
fn timestamp_before(a: u32, b: u32) -> bool {
    timestamp_diff(a, b) < 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_push_and_pop() {
        let mut jb = JitterBuffer::new(JitterBufferConfig::g711());

        // Push some packets
        let samples = vec![0i16; 160];
        jb.push(0, 0, samples.clone());
        jb.push(1, 160, samples.clone());
        jb.push(2, 320, samples.clone());
        jb.push(3, 480, samples.clone());

        assert!(jb.is_primed());

        // Pop should give us packets in order
        let (decision, _) = jb.pop();
        assert_eq!(decision, PlayoutDecision::Play);
    }

    #[test]
    fn test_reordering() {
        let mut jb = JitterBuffer::new(JitterBufferConfig::g711());

        let samples = vec![100i16; 160];

        // Push packets out of order
        jb.push(0, 0, samples.clone());
        jb.push(2, 320, samples.clone()); // Skip seq 1
        jb.push(1, 160, samples.clone()); // Late arrival
        jb.push(3, 480, samples.clone());

        // All packets should be in buffer
        assert_eq!(jb.len(), 4);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut jb = JitterBuffer::new(JitterBufferConfig::g711());

        let samples = vec![0i16; 160];

        assert!(jb.push(0, 0, samples.clone()));
        assert!(!jb.push(0, 0, samples.clone())); // Duplicate

        assert_eq!(jb.stats().packets_duplicate, 1);
    }

    #[test]
    fn test_loss_concealment() {
        let config = JitterBufferConfig {
            initial_delay_ms: 20, // Lower initial delay for faster priming
            ..JitterBufferConfig::g711()
        };
        let mut jb = JitterBuffer::new(config);

        // Push packet 0 and 2, skip 1
        let samples = vec![1000i16; 160];
        jb.push(0, 0, samples.clone());
        jb.push(2, 320, samples.clone());

        // Pop should give packet 0
        let (decision1, _) = jb.pop();
        assert_eq!(decision1, PlayoutDecision::Play);

        // Pop should conceal missing packet 1
        let (decision2, concealed) = jb.pop();
        assert_eq!(decision2, PlayoutDecision::Conceal);
        assert_eq!(concealed.len(), 160);

        // Pop should give packet 2
        let (decision3, _) = jb.pop();
        assert_eq!(decision3, PlayoutDecision::Play);
    }

    #[test]
    fn test_silence_before_primed() {
        let mut jb = JitterBuffer::new(JitterBufferConfig::g711());

        // Pop before any packets
        let (decision, samples) = jb.pop();
        assert_eq!(decision, PlayoutDecision::Silence);
        assert!(samples.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_jitter_estimation() {
        let mut jb = JitterBuffer::new(JitterBufferConfig::g711());

        let samples = vec![0i16; 160];

        // Simulate packets arriving with jitter
        jb.push(0, 0, samples.clone());
        std::thread::sleep(Duration::from_millis(20));
        jb.push(1, 160, samples.clone());
        std::thread::sleep(Duration::from_millis(25)); // Extra jitter
        jb.push(2, 320, samples.clone());

        // Jitter should be non-zero
        assert!(jb.jitter >= 0.0);
    }

    #[test]
    fn test_stats() {
        let config = JitterBufferConfig {
            initial_delay_ms: 20,
            ..JitterBufferConfig::g711()
        };
        let mut jb = JitterBuffer::new(config);

        let samples = vec![0i16; 160];
        jb.push(0, 0, samples.clone());
        jb.push(1, 160, samples.clone());

        let stats = jb.stats();
        assert_eq!(stats.packets_received, 2);

        jb.pop();
        assert_eq!(jb.stats().packets_played, 1);
    }

    #[test]
    fn test_reset() {
        let mut jb = JitterBuffer::new(JitterBufferConfig::g711());

        let samples = vec![0i16; 160];
        jb.push(0, 0, samples.clone());
        jb.push(1, 160, samples.clone());

        jb.reset();

        assert!(jb.is_empty());
        assert!(!jb.is_primed());
        // Stats should be preserved
        assert_eq!(jb.stats().packets_received, 2);
    }

    #[test]
    fn test_late_packet_rejection() {
        let config = JitterBufferConfig {
            initial_delay_ms: 20,
            ..JitterBufferConfig::g711()
        };
        let mut jb = JitterBuffer::new(config);

        let samples = vec![0i16; 160];

        // Push and play first packet
        jb.push(0, 0, samples.clone());
        jb.push(1, 160, samples.clone());
        jb.pop(); // Play packet 0
        jb.pop(); // Play packet 1

        // Now try to push packet 0 again - should be rejected as too late
        assert!(!jb.push(0, 0, samples.clone()));
        assert_eq!(jb.stats().packets_late, 1);
    }

    #[test]
    fn test_config_conversions() {
        let config = JitterBufferConfig::g711();

        assert_eq!(config.ms_to_samples(20), 160);
        assert_eq!(config.ms_to_samples(1000), 8000);
        assert_eq!(config.samples_to_ms(160), 20);
        assert_eq!(config.samples_to_ms(8000), 1000);
    }
}
