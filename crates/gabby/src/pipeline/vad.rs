//! Voice Activity Detection (VAD).
//!
//! Detects when the user has stopped speaking to trigger LLM response.

use crate::audio::calculate_rms;
use crate::config::VadConfig;
use std::time::{Duration, Instant};

/// Voice activity detection state machine.
pub struct VadState {
    /// RMS energy threshold for silence detection.
    silence_threshold: f32,
    /// Duration of silence to consider end of utterance.
    silence_duration: Duration,
    /// Minimum utterance duration before accepting.
    min_utterance_duration: Duration,
    /// Time of last detected speech.
    last_speech_time: Instant,
    /// Time speech started (if in utterance).
    speech_start: Option<Instant>,
    /// Whether we're currently in an utterance.
    in_utterance: bool,
    /// Previous partial text for stability detection.
    last_partial: Option<String>,
    /// Count of consecutive stable partials.
    stable_count: u32,
}

/// VAD decision for the current audio frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadDecision {
    /// No speech detected, silence.
    Silence,
    /// Speech just started.
    SpeechStart,
    /// Speech is continuing.
    SpeechContinue,
    /// Speech ended (silence threshold reached).
    SpeechEnd,
}

impl VadState {
    /// Create a new VAD state from configuration.
    pub fn new(config: &VadConfig) -> Self {
        Self {
            silence_threshold: config.silence_threshold,
            silence_duration: Duration::from_millis(config.silence_duration_ms),
            min_utterance_duration: Duration::from_millis(config.min_utterance_ms),
            last_speech_time: Instant::now(),
            speech_start: None,
            in_utterance: false,
            last_partial: None,
            stable_count: 0,
        }
    }

    /// Process audio samples and STT partial result.
    ///
    /// Returns the VAD decision for this frame.
    pub fn process(&mut self, samples: &[i16], partial_text: Option<&str>) -> VadDecision {
        let energy = calculate_rms(samples);
        let is_speech = energy > self.silence_threshold;

        // Track partial text stability
        let text_changed = if let Some(text) = partial_text {
            let changed = self.last_partial.as_deref() != Some(text);
            if changed {
                self.last_partial = Some(text.to_string());
                self.stable_count = 0;
            } else {
                self.stable_count += 1;
            }
            changed
        } else {
            false
        };

        let now = Instant::now();

        // State machine transitions
        match (self.in_utterance, is_speech, text_changed) {
            // Not in utterance, detected speech -> start
            (false, true, _) => {
                self.in_utterance = true;
                self.speech_start = Some(now);
                self.last_speech_time = now;
                self.last_partial = None;
                self.stable_count = 0;
                VadDecision::SpeechStart
            }

            // In utterance, speech continues (energy or text changing)
            (true, true, _) | (true, _, true) => {
                self.last_speech_time = now;
                VadDecision::SpeechContinue
            }

            // In utterance, silence detected, check if long enough
            (true, false, false) => {
                let silence_elapsed = now.duration_since(self.last_speech_time);
                let utterance_duration = self
                    .speech_start
                    .map(|s| now.duration_since(s))
                    .unwrap_or(Duration::ZERO);

                // Use stable_count for faster end detection when text stabilizes
                let stability_bonus = if self.stable_count > 3 {
                    Duration::from_millis(200) // Reduce required silence if text is stable
                } else {
                    Duration::ZERO
                };
                let effective_silence_threshold =
                    self.silence_duration.saturating_sub(stability_bonus);

                if silence_elapsed >= effective_silence_threshold
                    && utterance_duration >= self.min_utterance_duration
                {
                    // End of speech
                    self.in_utterance = false;
                    self.speech_start = None;
                    self.last_partial = None;
                    self.stable_count = 0;
                    VadDecision::SpeechEnd
                } else {
                    // Brief pause within utterance
                    VadDecision::SpeechContinue
                }
            }

            // Not in utterance, no speech
            (false, false, _) => VadDecision::Silence,
        }
    }

    /// Check if currently in an utterance.
    #[allow(dead_code)] // API for callers that need state info
    pub fn is_in_utterance(&self) -> bool {
        self.in_utterance
    }

    /// Reset VAD state for a new conversation turn.
    pub fn reset(&mut self) {
        self.in_utterance = false;
        self.speech_start = None;
        self.last_partial = None;
        self.stable_count = 0;
        self.last_speech_time = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::calculate_rms as audio_rms;

    #[test]
    fn test_calculate_rms_silence() {
        let silence = vec![0i16; 160];
        let rms = audio_rms(&silence);
        assert!(rms < 0.001);
    }

    #[test]
    fn test_calculate_rms_loud() {
        let loud: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 16000 } else { -16000 })
            .collect();
        let rms = audio_rms(&loud);
        assert!(rms > 0.4);
    }

    #[test]
    fn test_vad_silence_to_speech() {
        let config = VadConfig::default();
        let mut vad = VadState::new(&config);

        // Silence
        let silence = vec![0i16; 160];
        assert_eq!(vad.process(&silence, None), VadDecision::Silence);

        // Speech starts
        let speech: Vec<i16> = (0..160)
            .map(|i| ((i as f32 * 0.1).sin() * 5000.0) as i16)
            .collect();
        assert_eq!(
            vad.process(&speech, Some("hello")),
            VadDecision::SpeechStart
        );
    }
}
