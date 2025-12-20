//! Speech-to-Text processor using Vosk.

use crate::config::SttConfig;
use std::path::Path;
use std::sync::Arc;
use vosk::{Model, Recognizer};

/// Speech-to-Text processor wrapping Vosk.
pub struct SttProcessor {
    recognizer: Recognizer,
}

impl SttProcessor {
    /// Create a new STT processor with the given model.
    pub fn new(model: &Arc<Model>, sample_rate: f32) -> Result<Self, SttError> {
        let recognizer =
            Recognizer::new(model, sample_rate).ok_or(SttError::RecognizerCreationFailed)?;

        Ok(Self { recognizer })
    }

    /// Create a new STT processor from configuration.
    pub fn from_config(config: &SttConfig, model: &Arc<Model>) -> Result<Self, SttError> {
        Self::new(model, config.sample_rate as f32)
    }

    /// Feed audio samples and get partial transcription result.
    ///
    /// Returns the partial text if speech is being recognized.
    pub fn accept_waveform(&mut self, samples: &[i16]) -> Option<String> {
        let state = self.recognizer.accept_waveform(samples);

        match state {
            Ok(vosk::DecodingState::Running) => {
                let partial = self.recognizer.partial_result();
                let text = partial.partial;
                if text.is_empty() {
                    None
                } else {
                    Some(text.to_string())
                }
            }
            Ok(vosk::DecodingState::Finalized) => {
                // Will call final_result() separately
                None
            }
            Ok(vosk::DecodingState::Failed) | Err(_) => None,
        }
    }

    /// Get the final transcription result and reset the recognizer.
    pub fn final_result(&mut self) -> String {
        let result = self.recognizer.final_result();
        match result {
            vosk::CompleteResult::Single(r) => r.text.to_string(),
            vosk::CompleteResult::Multiple(r) => r
                .alternatives
                .first()
                .map(|a| a.text.to_string())
                .unwrap_or_default(),
        }
    }

    /// Reset the recognizer for a new utterance.
    pub fn reset(&mut self) {
        self.recognizer.reset();
    }
}

/// Load a Vosk model from disk.
pub fn load_model(path: &Path) -> Result<Arc<Model>, SttError> {
    let path_str = path
        .to_str()
        .ok_or_else(|| SttError::InvalidPath(path.to_path_buf()))?;

    Model::new(path_str)
        .map(Arc::new)
        .ok_or_else(|| SttError::ModelLoadFailed(path.to_path_buf()))
}

/// STT-related errors.
#[derive(Debug, thiserror::Error)]
pub enum SttError {
    #[error("Failed to load Vosk model from {0}")]
    ModelLoadFailed(std::path::PathBuf),

    #[error("Invalid model path: {0}")]
    InvalidPath(std::path::PathBuf),

    #[error("Failed to create Vosk recognizer")]
    RecognizerCreationFailed,
}
