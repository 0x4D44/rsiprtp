//! Call handler for voice conversations.
//!
//! Manages a single call's audio pipeline: RTP -> STT -> LLM -> TTS -> RTP.

use crate::audio::Resampler;
use crate::config::GabbyConfig;
use crate::pipeline::{OllamaClient, SttProcessor, TtsProcessor, VadDecision, VadState};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use vosk::Model as VoskModel;

/// RTP constants
const RTP_HEADER_SIZE: usize = 12;
const SAMPLES_PER_FRAME: usize = 160; // 20ms at 8kHz
const PCMU_PAYLOAD_TYPE: u8 = 0;

/// Buffer limits to prevent unbounded growth
const MAX_OUTPUT_BUFFER_SAMPLES: usize = 8000 * 30; // 30 seconds at 8kHz
const MAX_STT_BUFFER_SAMPLES: usize = 16000 * 10; // 10 seconds at 16kHz
const MAX_VAD_BUFFER_SAMPLES: usize = 8000 * 10; // 10 seconds at 8kHz

/// Default call timeout in seconds (if not configured)
const DEFAULT_CALL_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Call handler managing a single voice conversation.
pub struct CallHandler {
    call_id: String,
    #[allow(dead_code)] // May be used for future call-specific settings
    config: GabbyConfig,

    // RTP
    rtp_socket: UdpSocket,
    remote_rtp_addr: SocketAddr,
    rtp_sequence: u16,
    rtp_timestamp: u32,
    rtp_ssrc: u32,

    // SIP (for future BYE implementation)
    #[allow(dead_code)]
    sip_socket: Arc<UdpSocket>,
    #[allow(dead_code)]
    sip_source: SocketAddr,
    #[allow(dead_code)]
    local_sip_addr: SocketAddr,
    #[allow(dead_code)]
    to_tag: String,
    #[allow(dead_code)]
    from_tag: String,
    #[allow(dead_code)]
    cseq: u32,

    // Pipeline components
    stt: SttProcessor,
    vad: VadState,
    llm: OllamaClient,
    tts: Option<TtsProcessor>,

    // Audio processing
    input_resampler: Resampler,
    output_resampler: Option<Resampler>,
    output_buffer: VecDeque<i16>,
    stt_buffer: Vec<i16>,
    vad_buffer: Vec<i16>, // Aligned with STT processing

    // Call state
    greeted: bool,
    last_activity: Instant,
    call_timeout: Duration,

    // Shutdown signal
    shutdown_rx: mpsc::Receiver<()>,
}

impl CallHandler {
    /// Create a new call handler.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        call_id: String,
        config: GabbyConfig,
        vosk_model: Arc<VoskModel>,
        rtp_port: u16,
        remote_rtp_addr: SocketAddr,
        sip_source: SocketAddr,
        sip_socket: Arc<UdpSocket>,
        local_sip_addr: SocketAddr,
        to_tag: String,
        from_tag: String,
        cseq: u32,
        shutdown_rx: mpsc::Receiver<()>,
    ) -> Result<Self, CallError> {
        // Bind RTP socket
        let rtp_socket = UdpSocket::bind(format!("0.0.0.0:{}", rtp_port)).await?;
        tracing::info!("RTP socket bound to port {}", rtp_port);

        // Create STT processor
        let stt = SttProcessor::from_config(&config.stt, &vosk_model)?;

        // Create VAD
        let vad = VadState::new(&config.vad);

        // Create LLM client
        let llm = OllamaClient::new(&config.llm);

        // Create TTS processor (optional - may not be installed)
        let tts = crate::pipeline::tts::try_create_tts(&config.tts);
        if tts.is_none() {
            tracing::warn!("TTS not available - responses will be text only");
        }

        // Create resamplers
        let input_resampler = Resampler::rtp_to_vosk()?;
        let output_resampler = if tts.is_some() {
            Some(Resampler::piper_to_rtp()?)
        } else {
            None
        };

        // Get call timeout from config (or use default)
        let call_timeout = Duration::from_secs(
            config
                .server
                .call_timeout_secs
                .unwrap_or(DEFAULT_CALL_TIMEOUT_SECS),
        );

        Ok(Self {
            call_id,
            config,
            rtp_socket,
            remote_rtp_addr,
            rtp_sequence: 0,
            rtp_timestamp: 0,
            rtp_ssrc: rand::random(),
            sip_socket,
            sip_source,
            local_sip_addr,
            to_tag,
            from_tag,
            cseq,
            stt,
            vad,
            llm,
            tts,
            input_resampler,
            output_resampler,
            output_buffer: VecDeque::new(),
            stt_buffer: Vec::new(),
            vad_buffer: Vec::new(),
            greeted: false,
            last_activity: Instant::now(),
            call_timeout,
            shutdown_rx,
        })
    }

    /// Run the call handler main loop.
    pub async fn run(mut self) -> Result<(), CallError> {
        tracing::info!("Call {} started", self.call_id);

        let mut buf = vec![0u8; 2048];
        let mut send_interval = tokio::time::interval(Duration::from_millis(20));

        loop {
            tokio::select! {
                // Receive RTP
                result = self.rtp_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, _source)) => {
                            self.last_activity = Instant::now();

                            // Send greeting on first audio packet (call is established)
                            if !self.greeted {
                                self.greeted = true;
                                self.send_greeting().await;
                            }

                            if len > RTP_HEADER_SIZE {
                                self.handle_rtp_packet(&buf[..len]).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("RTP receive error: {}", e);
                        }
                    }
                }

                // Send RTP at regular intervals
                _ = send_interval.tick() => {
                    // Check for call timeout
                    if self.last_activity.elapsed() > self.call_timeout {
                        tracing::info!(
                            "Call {} timed out after {:?} of inactivity",
                            self.call_id,
                            self.call_timeout
                        );
                        break;
                    }

                    self.send_rtp_frame().await;
                }

                // Shutdown signal
                _ = self.shutdown_rx.recv() => {
                    tracing::info!("Call {} received shutdown signal", self.call_id);
                    break;
                }
            }
        }

        tracing::info!("Call {} ended", self.call_id);
        Ok(())
    }

    /// Handle an incoming RTP packet.
    async fn handle_rtp_packet(&mut self, data: &[u8]) {
        // Extract payload (skip RTP header)
        let payload = &data[RTP_HEADER_SIZE..];

        // Decode G.711 mu-law to PCM
        let samples: Vec<i16> = payload.iter().map(|&b| decode_ulaw(b)).collect();

        // Resample 8kHz -> 16kHz for Vosk
        let resampled = self.input_resampler.process(&samples);
        self.stt_buffer.extend(&resampled);

        // Buffer original samples for VAD (to align with STT processing)
        self.vad_buffer.extend(&samples);

        // Limit buffer sizes to prevent unbounded growth
        if self.stt_buffer.len() > MAX_STT_BUFFER_SAMPLES {
            let excess = self.stt_buffer.len() - MAX_STT_BUFFER_SAMPLES;
            self.stt_buffer.drain(0..excess);
            tracing::warn!("STT buffer overflow, dropped {} samples", excess);
        }
        if self.vad_buffer.len() > MAX_VAD_BUFFER_SAMPLES {
            let excess = self.vad_buffer.len() - MAX_VAD_BUFFER_SAMPLES;
            self.vad_buffer.drain(0..excess);
        }

        // Process STT in chunks (200ms = 3200 samples at 16kHz)
        // Corresponding VAD samples: 200ms = 1600 samples at 8kHz
        while self.stt_buffer.len() >= 3200 && self.vad_buffer.len() >= 1600 {
            let stt_chunk: Vec<i16> = self.stt_buffer.drain(..3200).collect();
            let vad_chunk: Vec<i16> = self.vad_buffer.drain(..1600).collect();

            let partial = self.stt.accept_waveform(&stt_chunk);

            // Run VAD on aligned 8kHz samples (same temporal window as STT)
            let decision = self.vad.process(&vad_chunk, partial.as_deref());

            match decision {
                VadDecision::SpeechStart => {
                    tracing::debug!("Speech started");
                }
                VadDecision::SpeechEnd => {
                    // Get final transcription
                    let transcript = self.stt.final_result();
                    if !transcript.trim().is_empty() {
                        tracing::info!("User said: {}", transcript);
                        self.process_user_turn(&transcript).await;
                    }
                    self.stt.reset();
                    self.vad.reset();
                }
                _ => {}
            }
        }
    }

    /// Process a user turn and generate response.
    async fn process_user_turn(&mut self, transcript: &str) {
        // Get LLM response (non-streaming for simplicity)
        let response = self.llm.chat_complete(transcript).await;

        tracing::info!("Gabby said: {}", response);

        // Synthesize and queue for playback
        self.synthesize_and_queue(&response).await;
    }

    /// Synthesize text and queue for playback.
    async fn synthesize_and_queue(&mut self, text: &str) {
        if let Some(tts) = &self.tts {
            match tts.synthesize(text).await {
                Ok(samples) => {
                    // Resample 22kHz -> 8kHz
                    if let Some(resampler) = &mut self.output_resampler {
                        let resampled = resampler.process(&samples);
                        self.output_buffer.extend(resampled);

                        // Limit output buffer size
                        if self.output_buffer.len() > MAX_OUTPUT_BUFFER_SAMPLES {
                            let excess = self.output_buffer.len() - MAX_OUTPUT_BUFFER_SAMPLES;
                            self.output_buffer.drain(0..excess);
                            tracing::warn!("Output buffer overflow, dropped {} samples", excess);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("TTS synthesis failed: {}", e);
                }
            }
        }
    }

    /// Send greeting when call starts.
    async fn send_greeting(&mut self) {
        let greeting = "Hello! I'm Gabby, your voice AI assistant. How can I help you today?";
        tracing::info!("Sending greeting: {}", greeting);

        self.synthesize_and_queue(greeting).await;

        // Also add to LLM history as if assistant said it
        self.llm.add_assistant_response(greeting);
    }

    /// Send an RTP frame from the output buffer.
    async fn send_rtp_frame(&mut self) {
        let samples: Vec<i16> = if self.output_buffer.len() >= SAMPLES_PER_FRAME {
            self.output_buffer.drain(..SAMPLES_PER_FRAME).collect()
        } else {
            // Send silence if no audio available
            vec![0i16; SAMPLES_PER_FRAME]
        };

        // Encode to G.711 mu-law
        let payload: Vec<u8> = samples.iter().map(|&s| encode_ulaw(s)).collect();

        // Build RTP packet
        let mut packet = Vec::with_capacity(RTP_HEADER_SIZE + payload.len());

        // RTP header
        packet.push(0x80); // Version 2, no padding, no extension, no CSRC
        packet.push(PCMU_PAYLOAD_TYPE); // Payload type 0 (PCMU), no marker

        // Sequence number (big-endian)
        packet.extend_from_slice(&self.rtp_sequence.to_be_bytes());
        self.rtp_sequence = self.rtp_sequence.wrapping_add(1);

        // Timestamp (big-endian)
        packet.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        self.rtp_timestamp = self.rtp_timestamp.wrapping_add(SAMPLES_PER_FRAME as u32);

        // SSRC (big-endian)
        packet.extend_from_slice(&self.rtp_ssrc.to_be_bytes());

        // Payload
        packet.extend_from_slice(&payload);

        // Send
        if let Err(e) = self.rtp_socket.send_to(&packet, self.remote_rtp_addr).await {
            tracing::warn!("Failed to send RTP: {}", e);
        }
    }
}

/// G.711 mu-law decoding table (ITU-T G.711)
fn decode_ulaw(compressed: u8) -> i16 {
    const ULAW_TABLE: [i16; 256] = [
        -32124, -31100, -30076, -29052, -28028, -27004, -25980, -24956, -23932, -22908, -21884,
        -20860, -19836, -18812, -17788, -16764, -15996, -15484, -14972, -14460, -13948, -13436,
        -12924, -12412, -11900, -11388, -10876, -10364, -9852, -9340, -8828, -8316, -7932, -7676,
        -7420, -7164, -6908, -6652, -6396, -6140, -5884, -5628, -5372, -5116, -4860, -4604, -4348,
        -4092, -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004, -2876, -2748, -2620, -2492,
        -2364, -2236, -2108, -1980, -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436, -1372,
        -1308, -1244, -1180, -1116, -1052, -988, -924, -876, -844, -812, -780, -748, -716, -684,
        -652, -620, -588, -556, -524, -492, -460, -428, -396, -372, -356, -340, -324, -308, -292,
        -276, -260, -244, -228, -212, -196, -180, -164, -148, -132, -120, -112, -104, -96, -88,
        -80, -72, -64, -56, -48, -40, -32, -24, -16, -8, 0, 32124, 31100, 30076, 29052, 28028,
        27004, 25980, 24956, 23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764, 15996, 15484,
        14972, 14460, 13948, 13436, 12924, 12412, 11900, 11388, 10876, 10364, 9852, 9340, 8828,
        8316, 7932, 7676, 7420, 7164, 6908, 6652, 6396, 6140, 5884, 5628, 5372, 5116, 4860, 4604,
        4348, 4092, 3900, 3772, 3644, 3516, 3388, 3260, 3132, 3004, 2876, 2748, 2620, 2492, 2364,
        2236, 2108, 1980, 1884, 1820, 1756, 1692, 1628, 1564, 1500, 1436, 1372, 1308, 1244, 1180,
        1116, 1052, 988, 924, 876, 844, 812, 780, 748, 716, 684, 652, 620, 588, 556, 524, 492, 460,
        428, 396, 372, 356, 340, 324, 308, 292, 276, 260, 244, 228, 212, 196, 180, 164, 148, 132,
        120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8, 0,
    ];
    ULAW_TABLE[compressed as usize]
}

/// G.711 mu-law encoding (ITU-T G.711 standard algorithm)
fn encode_ulaw(sample: i16) -> u8 {
    const BIAS: i16 = 0x84; // 132
    const CLIP: i16 = 32635;

    // Get sign and magnitude
    let sign: u8;
    let mut sample = sample;

    if sample < 0 {
        sign = 0x80;
        sample = sample.saturating_neg();
    } else {
        sign = 0x00;
    }

    // Clip
    if sample > CLIP {
        sample = CLIP;
    }

    // Add bias
    sample = sample.saturating_add(BIAS);

    // Find the segment (exponent)
    let exponent = match sample {
        0..=0xFF => 0,
        0x100..=0x1FF => 1,
        0x200..=0x3FF => 2,
        0x400..=0x7FF => 3,
        0x800..=0xFFF => 4,
        0x1000..=0x1FFF => 5,
        0x2000..=0x3FFF => 6,
        _ => 7,
    };

    // Extract mantissa
    let mantissa = ((sample >> (exponent + 3)) & 0x0F) as u8;

    // Combine and invert
    !(sign | (exponent << 4) | mantissa)
}

/// Call handler errors.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("STT: {0}")]
    Stt(#[from] crate::pipeline::stt::SttError),

    #[error("Resampler: {0}")]
    Resampler(#[from] crate::audio::ResamplerError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ulaw_roundtrip() {
        // Test that encode/decode roundtrip is approximately correct
        let test_values: [i16; 5] = [0, 1000, -1000, 16000, -16000];

        for &original in &test_values {
            let encoded = encode_ulaw(original);
            let decoded = decode_ulaw(encoded);

            // G.711 is lossy, but should be within ~1% for larger values
            let error = (original as i32 - decoded as i32).abs();
            let tolerance = if original.abs() > 100 {
                (original.abs() as i32) / 50 // ~2% tolerance
            } else {
                10 // Small values have fixed tolerance
            };

            assert!(
                error <= tolerance,
                "Roundtrip error too large for {}: got {}, error {}",
                original,
                decoded,
                error
            );
        }
    }

    #[test]
    fn test_ulaw_silence() {
        // Silence (0) should encode to 0xFF
        let encoded = encode_ulaw(0);
        assert_eq!(encoded, 0xFF, "Silence should encode to 0xFF");
    }
}
