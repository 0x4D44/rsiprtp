//! AI Agent Bridge Example
//!
//! Demonstrates how to build a call bridge between a SIP caller and an AI agent
//! with audio mixing capabilities.
//!
//! Features:
//! - Accept incoming SIP calls
//! - Bridge audio to/from AI agent (via audio stream)
//! - Conference mode: multiple callers talking to same AI
//! - Active speaker detection
//! - DTMF passthrough to AI
//!
//! Usage:
//! ```bash
//! cargo run --example ai_bridge -- --sip-port 5060 --ai-endpoint ws://localhost:8080/audio
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// AI Bridge call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeState {
    /// Connecting to AI.
    Connecting,
    /// Active conversation.
    Active,
    /// AI is speaking.
    AiSpeaking,
    /// User is speaking.
    UserSpeaking,
    /// Call ending.
    Ending,
}

/// Configuration for the AI bridge.
#[derive(Debug, Clone)]
pub struct AiBridgeConfig {
    /// Local SIP address.
    pub sip_addr: SocketAddr,
    /// AI agent endpoint (e.g., WebSocket URL).
    pub ai_endpoint: String,
    /// Sample rate for AI audio.
    pub sample_rate: u32,
    /// Enable conference mode (multiple callers to one AI).
    pub conference_mode: bool,
    /// Maximum participants in conference.
    pub max_participants: usize,
    /// VAD (Voice Activity Detection) threshold.
    pub vad_threshold: f32,
    /// Interrupt AI when user speaks.
    pub allow_interrupt: bool,
}

impl Default for AiBridgeConfig {
    fn default() -> Self {
        Self {
            sip_addr: "0.0.0.0:5060".parse().unwrap(),
            ai_endpoint: "ws://localhost:8080/audio".to_string(),
            sample_rate: 16000, // Common for AI
            conference_mode: false,
            max_participants: 5,
            vad_threshold: 0.02,
            allow_interrupt: true,
        }
    }
}

/// A participant in the bridge.
pub struct Participant {
    /// SIP call ID.
    pub call_id: String,
    /// Caller identifier.
    pub caller: String,
    /// SSRC for RTP.
    pub ssrc: u32,
    /// Current speaking state.
    pub is_speaking: bool,
    /// Join time.
    pub joined_at: Instant,
}

/// AI audio session.
pub struct AiSession {
    /// Session ID.
    pub id: String,
    /// AI speaking state.
    pub ai_speaking: bool,
    /// Pending AI audio samples.
    pub pending_audio: Vec<i16>,
    /// Last AI response time.
    pub last_response: Instant,
}

/// Audio mixer for conference.
pub struct ConferenceMixer {
    /// Source audio buffers (SSRC -> samples).
    sources: HashMap<u32, Vec<i16>>,
}

impl ConferenceMixer {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
        }
    }

    /// Add audio from a source.
    pub fn add_audio(&mut self, ssrc: u32, samples: &[i16]) {
        self.sources.insert(ssrc, samples.to_vec());
    }

    /// Mix all sources except one (for conference).
    pub fn mix_except(&self, exclude_ssrc: u32, num_samples: usize) -> Vec<i16> {
        let mut mixed = vec![0i32; num_samples];

        for (&ssrc, samples) in &self.sources {
            if ssrc == exclude_ssrc {
                continue;
            }

            for (i, &sample) in samples.iter().take(num_samples).enumerate() {
                mixed[i] += sample as i32;
            }
        }

        // Clamp to i16
        mixed
            .iter()
            .map(|&s| s.clamp(i16::MIN as i32, i16::MAX as i32) as i16)
            .collect()
    }

    /// Mix all sources (for AI input).
    pub fn mix_all(&self, num_samples: usize) -> Vec<i16> {
        let mut mixed = vec![0i32; num_samples];

        for samples in self.sources.values() {
            for (i, &sample) in samples.iter().take(num_samples).enumerate() {
                mixed[i] += sample as i32;
            }
        }

        mixed
            .iter()
            .map(|&s| s.clamp(i16::MIN as i32, i16::MAX as i32) as i16)
            .collect()
    }

    pub fn clear(&mut self) {
        self.sources.clear();
    }
}

impl Default for ConferenceMixer {
    fn default() -> Self {
        Self::new()
    }
}

/// Active speaker detector.
pub struct SpeakerDetector {
    /// Energy levels per SSRC.
    energy: HashMap<u32, f32>,
    /// Threshold for speech.
    threshold: f32,
}

impl SpeakerDetector {
    pub fn new(threshold: f32) -> Self {
        Self {
            energy: HashMap::new(),
            threshold,
        }
    }

    /// Update with audio from a source.
    pub fn update(&mut self, ssrc: u32, samples: &[i16]) -> bool {
        let energy = calculate_rms(samples);
        self.energy.insert(ssrc, energy);
        energy > self.threshold
    }

    /// Get the loudest speaker.
    pub fn get_active_speaker(&self) -> Option<u32> {
        self.energy
            .iter()
            .filter(|(_, &e)| e > self.threshold)
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(&ssrc, _)| ssrc)
    }
}

fn calculate_rms(samples: &[i16]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum: f64 = samples.iter().map(|&s| (s as f64) * (s as f64)).sum();
    ((sum / samples.len() as f64).sqrt() / i16::MAX as f64) as f32
}

/// AI Bridge server.
pub struct AiBridge {
    /// Configuration.
    pub config: AiBridgeConfig,
    /// Active participants.
    pub participants: Arc<RwLock<HashMap<String, Participant>>>,
    /// AI session.
    pub ai_session: Arc<RwLock<Option<AiSession>>>,
    /// Audio mixer.
    pub mixer: Arc<RwLock<ConferenceMixer>>,
    /// Speaker detector.
    pub speaker_detector: Arc<RwLock<SpeakerDetector>>,
}

impl AiBridge {
    /// Create a new AI bridge.
    pub fn new(config: AiBridgeConfig) -> Self {
        let threshold = config.vad_threshold;
        Self {
            config,
            participants: Arc::new(RwLock::new(HashMap::new())),
            ai_session: Arc::new(RwLock::new(None)),
            mixer: Arc::new(RwLock::new(ConferenceMixer::new())),
            speaker_detector: Arc::new(RwLock::new(SpeakerDetector::new(threshold))),
        }
    }

    /// Handle new incoming call.
    pub async fn handle_incoming_call(&self, call_id: &str, caller: &str, ssrc: u32) -> bool {
        let mut participants = self.participants.write().await;

        if !self.config.conference_mode && !participants.is_empty() {
            println!("Rejecting call {} - not in conference mode", call_id);
            return false;
        }

        if participants.len() >= self.config.max_participants {
            println!("Rejecting call {} - max participants reached", call_id);
            return false;
        }

        let participant = Participant {
            call_id: call_id.to_string(),
            caller: caller.to_string(),
            ssrc,
            is_speaking: false,
            joined_at: Instant::now(),
        };

        participants.insert(call_id.to_string(), participant);
        println!("Participant {} joined from {}", call_id, caller);

        // Initialize AI session if first participant
        if participants.len() == 1 {
            let mut ai = self.ai_session.write().await;
            *ai = Some(AiSession {
                id: format!("ai-{}", call_id),
                ai_speaking: false,
                pending_audio: Vec::new(),
                last_response: Instant::now(),
            });
            println!("Started AI session");
        }

        true
    }

    /// Handle call ending.
    pub async fn handle_call_end(&self, call_id: &str) {
        let mut participants = self.participants.write().await;
        if participants.remove(call_id).is_some() {
            println!("Participant {} left", call_id);
        }

        if participants.is_empty() {
            let mut ai = self.ai_session.write().await;
            *ai = None;
            println!("Ended AI session");
        }
    }

    /// Process incoming audio from a participant.
    pub async fn process_participant_audio(&self, call_id: &str, samples: &[i16]) {
        let participants = self.participants.read().await;
        let participant = match participants.get(call_id) {
            Some(p) => p,
            None => return,
        };
        let ssrc = participant.ssrc;
        drop(participants);

        // Update speaker detector
        let is_speaking = self.speaker_detector.write().await.update(ssrc, samples);

        // Update participant speaking state
        {
            let mut participants = self.participants.write().await;
            if let Some(p) = participants.get_mut(call_id) {
                p.is_speaking = is_speaking;
            }
        }

        // Add to mixer
        self.mixer.write().await.add_audio(ssrc, samples);

        // Check if user interrupt
        if is_speaking && self.config.allow_interrupt {
            let mut ai = self.ai_session.write().await;
            if let Some(session) = ai.as_mut() {
                if session.ai_speaking {
                    println!("User interrupt detected");
                    session.ai_speaking = false;
                    session.pending_audio.clear();
                }
            }
        }

        // In real implementation:
        // 1. Resample if needed
        // 2. Mix all participants
        // 3. Send to AI endpoint
    }

    /// Process audio from AI.
    pub async fn process_ai_audio(&self, samples: &[i16]) {
        {
            let mut ai = self.ai_session.write().await;
            if let Some(session) = ai.as_mut() {
                session.ai_speaking = !samples.iter().all(|&s| s.abs() < 100);
                session.last_response = Instant::now();
            }
        }

        // In real implementation:
        // 1. Resample if needed
        // 2. Send to all participants via RTP
    }

    /// Handle DTMF from participant.
    pub async fn handle_dtmf(&self, call_id: &str, digit: char) {
        println!("DTMF {} from {}", digit, call_id);

        // In real implementation:
        // 1. Convert to text or action
        // 2. Send to AI
    }

    /// Get mixed audio for a participant (excludes their own audio).
    pub async fn get_audio_for_participant(&self, call_id: &str, num_samples: usize) -> Vec<i16> {
        let participants = self.participants.read().await;
        let participant = match participants.get(call_id) {
            Some(p) => p,
            None => return vec![0; num_samples],
        };
        let ssrc = participant.ssrc;
        drop(participants);

        // Mix other participants
        let mixer = self.mixer.read().await;
        let mut mixed = mixer.mix_except(ssrc, num_samples);

        // Add AI audio
        let ai = self.ai_session.read().await;
        if let Some(session) = ai.as_ref() {
            for (i, &sample) in session.pending_audio.iter().take(num_samples).enumerate() {
                let sum = mixed[i] as i32 + sample as i32;
                mixed[i] = sum.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            }
        }

        mixed
    }

    /// Get number of active participants.
    pub async fn participant_count(&self) -> usize {
        self.participants.read().await.len()
    }
}

/// Example main function.
#[tokio::main]
async fn main() {
    println!("=== rsiprtp AI Bridge Example ===\n");

    let config = AiBridgeConfig {
        conference_mode: true,
        max_participants: 3,
        ..Default::default()
    };

    println!("Configuration:");
    println!("  SIP address: {}", config.sip_addr);
    println!("  AI endpoint: {}", config.ai_endpoint);
    println!("  Sample rate: {} Hz", config.sample_rate);
    println!("  Conference mode: {}", config.conference_mode);
    println!("  Max participants: {}", config.max_participants);
    println!("  Allow interrupt: {}", config.allow_interrupt);

    let bridge = AiBridge::new(config);

    // Simulate calls
    println!("\n--- Simulating conference call ---");

    // First caller joins
    let accepted = bridge
        .handle_incoming_call("call-1", "alice@example.com", 1001)
        .await;
    assert!(accepted);

    // Second caller joins
    let accepted = bridge
        .handle_incoming_call("call-2", "bob@example.com", 1002)
        .await;
    assert!(accepted);

    println!("Participants: {}", bridge.participant_count().await);

    // Simulate audio exchange
    println!("\n--- Simulating audio exchange ---");

    let alice_audio: Vec<i16> = vec![5000; 160];
    let bob_audio: Vec<i16> = vec![3000; 160];
    let ai_response: Vec<i16> = vec![4000; 160];

    bridge
        .process_participant_audio("call-1", &alice_audio)
        .await;
    bridge.process_participant_audio("call-2", &bob_audio).await;
    bridge.process_ai_audio(&ai_response).await;

    // Get mixed audio for each participant
    let for_alice = bridge.get_audio_for_participant("call-1", 160).await;
    let for_bob = bridge.get_audio_for_participant("call-2", 160).await;

    println!("Audio for Alice (first sample): {}", for_alice[0]);
    println!("Audio for Bob (first sample): {}", for_bob[0]);

    // DTMF
    println!("\n--- DTMF handling ---");
    bridge.handle_dtmf("call-1", '5').await;

    // End calls
    println!("\n--- Ending calls ---");
    bridge.handle_call_end("call-2").await;
    bridge.handle_call_end("call-1").await;

    println!("\n=== AI Bridge Example Complete ===");

    // In a real implementation, this would:
    // 1. Parse command line arguments
    // 2. Create SIP transport
    // 3. Connect to AI endpoint (WebSocket, gRPC, etc.)
    // 4. Handle incoming INVITE
    // 5. Bridge audio in real-time
    // 6. Handle DTMF and events
    // 7. Clean shutdown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = AiBridgeConfig::default();
        assert_eq!(config.sample_rate, 16000);
        assert!(!config.conference_mode);
    }

    #[test]
    fn test_mixer() {
        let mut mixer = ConferenceMixer::new();

        mixer.add_audio(1, &[100, 200, 300]);
        mixer.add_audio(2, &[50, 100, 150]);

        let mixed = mixer.mix_all(3);
        assert_eq!(mixed, vec![150, 300, 450]);

        let except_1 = mixer.mix_except(1, 3);
        assert_eq!(except_1, vec![50, 100, 150]);
    }

    #[test]
    fn test_speaker_detector() {
        let mut detector = SpeakerDetector::new(0.02);

        let loud: Vec<i16> = vec![10000; 100];
        let quiet: Vec<i16> = vec![10; 100];

        assert!(detector.update(1, &loud));
        assert!(!detector.update(2, &quiet));

        assert_eq!(detector.get_active_speaker(), Some(1));
    }

    #[tokio::test]
    async fn test_bridge_flow() {
        let config = AiBridgeConfig {
            conference_mode: true,
            ..Default::default()
        };
        let bridge = AiBridge::new(config);

        // Join
        assert!(bridge.handle_incoming_call("c1", "user1", 1001).await);
        assert!(bridge.handle_incoming_call("c2", "user2", 1002).await);
        assert_eq!(bridge.participant_count().await, 2);

        // Leave
        bridge.handle_call_end("c1").await;
        assert_eq!(bridge.participant_count().await, 1);

        bridge.handle_call_end("c2").await;
        assert_eq!(bridge.participant_count().await, 0);
    }

    #[tokio::test]
    async fn test_single_call_mode() {
        let config = AiBridgeConfig::default(); // conference_mode = false
        let bridge = AiBridge::new(config);

        assert!(bridge.handle_incoming_call("c1", "user1", 1001).await);
        // Second call should be rejected
        assert!(!bridge.handle_incoming_call("c2", "user2", 1002).await);
    }
}
