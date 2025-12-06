//! Voicemail Application Example
//!
//! Demonstrates how to build a simple voicemail system using mdsiprtp.
//!
//! Features:
//! - Answer incoming calls
//! - Play greeting message
//! - Record caller's message to WAV file
//! - DTMF detection for menu navigation
//! - Configurable max recording duration
//!
//! Usage:
//! ```bash
//! cargo run --example voicemail -- --port 5060 --greeting greeting.wav --output /tmp/messages
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// These would be imported from mdsiprtp crates
// For demonstration, we define the key structures

/// Voicemail call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoicemailState {
    /// Playing greeting message.
    PlayingGreeting,
    /// Recording message.
    Recording,
    /// Playing back recorded message.
    Playback,
    /// Call ending.
    Ending,
}

/// Configuration for the voicemail system.
#[derive(Debug, Clone)]
pub struct VoicemailConfig {
    /// Local SIP address to listen on.
    pub listen_addr: SocketAddr,
    /// Path to greeting WAV file.
    pub greeting_path: PathBuf,
    /// Directory to save recorded messages.
    pub output_dir: PathBuf,
    /// Maximum recording duration in seconds.
    pub max_record_duration: u32,
    /// Beep tone frequency for "record after the beep".
    pub beep_frequency: f64,
    /// Beep duration in milliseconds.
    pub beep_duration_ms: u32,
    /// Silence threshold for detecting end of message.
    pub silence_threshold: f32,
    /// Seconds of silence to end recording.
    pub silence_duration_secs: u32,
}

impl Default for VoicemailConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:5060".parse().unwrap(),
            greeting_path: PathBuf::from("greeting.wav"),
            output_dir: PathBuf::from("/tmp/voicemail"),
            max_record_duration: 120,
            beep_frequency: 1000.0,
            beep_duration_ms: 500,
            silence_threshold: 0.01,
            silence_duration_secs: 3,
        }
    }
}

/// Active voicemail call.
pub struct VoicemailCall {
    /// Call ID.
    pub call_id: String,
    /// Caller info.
    pub caller: String,
    /// Current state.
    pub state: VoicemailState,
    /// Recording start time.
    pub record_start: Option<Instant>,
    /// Output file path.
    pub output_path: Option<PathBuf>,
    /// Consecutive silence duration.
    pub silence_duration: Duration,
    /// Last audio timestamp.
    pub last_audio: Instant,
}

/// Voicemail server.
pub struct VoicemailServer {
    /// Configuration.
    pub config: VoicemailConfig,
    /// Active calls.
    pub calls: Arc<RwLock<HashMap<String, VoicemailCall>>>,
}

impl VoicemailServer {
    /// Create a new voicemail server.
    pub fn new(config: VoicemailConfig) -> Self {
        Self {
            config,
            calls: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Handle an incoming call.
    pub async fn handle_incoming_call(&self, call_id: &str, caller: &str) {
        println!("Incoming call from {} ({})", caller, call_id);

        let call = VoicemailCall {
            call_id: call_id.to_string(),
            caller: caller.to_string(),
            state: VoicemailState::PlayingGreeting,
            record_start: None,
            output_path: None,
            silence_duration: Duration::ZERO,
            last_audio: Instant::now(),
        };

        self.calls.write().await.insert(call_id.to_string(), call);

        // In real implementation:
        // 1. Send 200 OK
        // 2. Start media session
        // 3. Play greeting WAV file
        // 4. After greeting, transition to Recording state
    }

    /// Process audio frame from caller.
    pub async fn process_audio(&self, call_id: &str, samples: &[i16]) {
        let mut calls = self.calls.write().await;
        let call = match calls.get_mut(call_id) {
            Some(c) => c,
            None => return,
        };

        match call.state {
            VoicemailState::Recording => {
                // Check for silence
                let is_silent = is_silence(samples, self.config.silence_threshold);

                if is_silent {
                    call.silence_duration += Duration::from_millis(20); // Assuming 20ms frames

                    if call.silence_duration.as_secs() >= self.config.silence_duration_secs as u64 {
                        println!("Silence detected, ending recording for {}", call_id);
                        call.state = VoicemailState::Ending;
                    }
                } else {
                    call.silence_duration = Duration::ZERO;
                }

                // Check max duration
                if let Some(start) = call.record_start {
                    if start.elapsed().as_secs() >= self.config.max_record_duration as u64 {
                        println!("Max duration reached for {}", call_id);
                        call.state = VoicemailState::Ending;
                    }
                }

                // In real implementation: write samples to WAV file
            }
            _ => {}
        }

        call.last_audio = Instant::now();
    }

    /// Handle DTMF digit from caller.
    pub async fn handle_dtmf(&self, call_id: &str, digit: char) {
        let mut calls = self.calls.write().await;
        let call = match calls.get_mut(call_id) {
            Some(c) => c,
            None => return,
        };

        println!("DTMF {} received for {}", digit, call_id);

        match digit {
            '#' => {
                // End recording
                call.state = VoicemailState::Ending;
            }
            '*' => {
                // Restart recording
                call.state = VoicemailState::PlayingGreeting;
                call.record_start = None;
            }
            '1' => {
                // Play back recording
                if call.state == VoicemailState::Recording || call.state == VoicemailState::Ending {
                    call.state = VoicemailState::Playback;
                }
            }
            _ => {}
        }
    }

    /// Transition call to recording state.
    pub async fn start_recording(&self, call_id: &str) {
        let mut calls = self.calls.write().await;
        if let Some(call) = calls.get_mut(call_id) {
            let filename = format!(
                "msg_{}_{}.wav",
                call.caller.replace(['@', '.', ':'], "_"),
                chrono_lite_timestamp()
            );
            let path = self.config.output_dir.join(&filename);

            call.state = VoicemailState::Recording;
            call.record_start = Some(Instant::now());
            call.output_path = Some(path.clone());
            call.silence_duration = Duration::ZERO;

            println!("Recording to {:?}", path);

            // In real implementation:
            // 1. Play beep
            // 2. Create WavWriter
            // 3. Start writing audio frames
        }
    }

    /// End a call.
    pub async fn end_call(&self, call_id: &str) {
        if let Some(call) = self.calls.write().await.remove(call_id) {
            if let Some(path) = call.output_path {
                println!("Call {} ended. Message saved to {:?}", call_id, path);
            } else {
                println!("Call {} ended. No message recorded.", call_id);
            }

            // In real implementation:
            // 1. Close WAV file
            // 2. Send BYE
        }
    }
}

/// Simple silence detection.
fn is_silence(samples: &[i16], threshold: f32) -> bool {
    if samples.is_empty() {
        return true;
    }

    let sum_squares: i64 = samples.iter().map(|&s| (s as i64) * (s as i64)).sum();

    let rms = ((sum_squares as f64) / (samples.len() as f64)).sqrt();
    let normalized = rms / (i16::MAX as f64);

    normalized < threshold as f64
}

/// Generate a simple timestamp string.
fn chrono_lite_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// Example main function (not actually runnable without full implementation).
#[tokio::main]
async fn main() {
    println!("=== mdsiprtp Voicemail Example ===\n");

    let config = VoicemailConfig::default();
    println!("Configuration:");
    println!("  Listen address: {}", config.listen_addr);
    println!("  Greeting file: {:?}", config.greeting_path);
    println!("  Output directory: {:?}", config.output_dir);
    println!("  Max record duration: {}s", config.max_record_duration);
    println!("  Silence threshold: {}", config.silence_threshold);
    println!(
        "  Silence duration to end: {}s",
        config.silence_duration_secs
    );

    let server = VoicemailServer::new(config);

    // Simulate a call
    println!("\n--- Simulating incoming call ---");
    server
        .handle_incoming_call("call-123", "alice@example.com")
        .await;

    // Simulate greeting playback complete
    println!("\n--- Starting recording ---");
    server.start_recording("call-123").await;

    // Simulate some audio frames
    let loud_audio: Vec<i16> = vec![5000; 160];
    let _silent_audio: Vec<i16> = vec![10; 160];

    for _ in 0..10 {
        server.process_audio("call-123", &loud_audio).await;
    }
    println!("Received 10 frames of audio");

    // Simulate DTMF
    println!("\n--- DTMF # received (end recording) ---");
    server.handle_dtmf("call-123", '#').await;

    // End call
    server.end_call("call-123").await;

    println!("\n=== Voicemail Example Complete ===");

    // In a real implementation, this would:
    // 1. Parse command line arguments
    // 2. Create SIP transport
    // 3. Register with SIP registrar (optional)
    // 4. Listen for incoming INVITE
    // 5. Handle calls in event loop
    // 6. Clean shutdown on SIGINT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_silence() {
        let loud: Vec<i16> = vec![10000; 100];
        let quiet: Vec<i16> = vec![10; 100];

        assert!(!is_silence(&loud, 0.01));
        assert!(is_silence(&quiet, 0.01));
    }

    #[test]
    fn test_config_default() {
        let config = VoicemailConfig::default();
        assert_eq!(config.max_record_duration, 120);
        assert_eq!(config.silence_duration_secs, 3);
    }

    #[tokio::test]
    async fn test_voicemail_flow() {
        let config = VoicemailConfig::default();
        let server = VoicemailServer::new(config);

        // Handle call
        server.handle_incoming_call("test-1", "bob@test.com").await;

        // Check state
        let calls = server.calls.read().await;
        assert!(calls.contains_key("test-1"));
        assert_eq!(
            calls.get("test-1").unwrap().state,
            VoicemailState::PlayingGreeting
        );
        drop(calls);

        // Start recording
        server.start_recording("test-1").await;

        let calls = server.calls.read().await;
        assert_eq!(
            calls.get("test-1").unwrap().state,
            VoicemailState::Recording
        );
        drop(calls);

        // DTMF to end
        server.handle_dtmf("test-1", '#').await;

        let calls = server.calls.read().await;
        assert_eq!(calls.get("test-1").unwrap().state, VoicemailState::Ending);
    }
}
