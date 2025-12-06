//! Audio mixer for conference bridges.
//!
//! Provides N-way audio mixing with CSRC list tracking per RFC 3550.

use std::collections::HashMap;

/// Audio mixer for combining multiple audio streams.
///
/// Implements RFC 3550 mixing semantics:
/// - Sums audio samples from multiple sources
/// - Tracks contributing sources (CSRC list)
/// - Provides N-1 mixing (each participant hears others, not themselves)
pub struct AudioMixer {
    /// Active sources and their latest audio.
    sources: HashMap<u32, SourceState>,
    /// Maximum number of sources to mix.
    max_sources: usize,
    /// Output buffer.
    output_buffer: Vec<i16>,
}

/// State for a single audio source.
struct SourceState {
    /// Current audio samples.
    samples: Vec<i16>,
    /// Whether source is currently active.
    active: bool,
    /// Number of consecutive silent frames.
    silent_frames: u32,
}

impl AudioMixer {
    /// Create a new mixer with default settings.
    pub fn new(_sample_rate: u32) -> Self {
        Self {
            sources: HashMap::new(),
            max_sources: 15, // RFC 3550 limits CSRC list to 15
            output_buffer: Vec::new(),
        }
    }

    /// Set the maximum number of sources to mix.
    pub fn set_max_sources(&mut self, max: usize) {
        self.max_sources = max.min(15);
    }

    /// Add or update audio from a source.
    ///
    /// # Arguments
    /// * `ssrc` - Source identifier
    /// * `samples` - Audio samples (16-bit signed PCM)
    pub fn add_source(&mut self, ssrc: u32, samples: &[i16]) {
        if self.sources.len() >= self.max_sources && !self.sources.contains_key(&ssrc) {
            // Remove oldest inactive source if at capacity
            let inactive = self
                .sources
                .iter()
                .filter(|(_, s)| !s.active)
                .max_by_key(|(_, s)| s.silent_frames)
                .map(|(ssrc, _)| *ssrc);

            if let Some(old_ssrc) = inactive {
                self.sources.remove(&old_ssrc);
            } else {
                return; // Can't add more sources
            }
        }

        let source = self.sources.entry(ssrc).or_insert_with(|| SourceState {
            samples: Vec::new(),
            active: true,
            silent_frames: 0,
        });

        source.samples = samples.to_vec();
        source.active = true;
        source.silent_frames = 0;
    }

    /// Mark a source as having no current audio.
    pub fn mark_silent(&mut self, ssrc: u32) {
        if let Some(source) = self.sources.get_mut(&ssrc) {
            source.active = false;
            source.silent_frames += 1;
        }
    }

    /// Remove a source from the mixer.
    pub fn remove_source(&mut self, ssrc: u32) {
        self.sources.remove(&ssrc);
    }

    /// Mix all sources and return combined audio.
    ///
    /// # Arguments
    /// * `num_samples` - Number of samples to produce
    ///
    /// # Returns
    /// Tuple of (mixed audio samples, contributing SSRC list)
    pub fn mix(&mut self, num_samples: usize) -> (Vec<i16>, Vec<u32>) {
        self.mix_except(num_samples, None)
    }

    /// Mix all sources except one (N-1 mixing for conferences).
    ///
    /// # Arguments
    /// * `num_samples` - Number of samples to produce
    /// * `exclude_ssrc` - SSRC to exclude from mix (typically the receiving participant)
    ///
    /// # Returns
    /// Tuple of (mixed audio samples, contributing SSRC list)
    pub fn mix_except(
        &mut self,
        num_samples: usize,
        exclude_ssrc: Option<u32>,
    ) -> (Vec<i16>, Vec<u32>) {
        self.output_buffer.clear();
        self.output_buffer.resize(num_samples, 0);

        let mut csrc_list = Vec::new();

        for (&ssrc, source) in &self.sources {
            // Skip excluded source
            if exclude_ssrc == Some(ssrc) {
                continue;
            }

            // Skip inactive sources
            if !source.active || source.samples.is_empty() {
                continue;
            }

            // Track this source
            if csrc_list.len() < 15 {
                csrc_list.push(ssrc);
            }

            // Mix samples using i32 accumulator to avoid overflow
            let mix_len = num_samples.min(source.samples.len());
            for i in 0..mix_len {
                let mixed = self.output_buffer[i] as i32 + source.samples[i] as i32;
                // Clamp to i16 range
                self.output_buffer[i] = mixed.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            }
        }

        (self.output_buffer.clone(), csrc_list)
    }

    /// Get the number of active sources.
    pub fn active_source_count(&self) -> usize {
        self.sources.values().filter(|s| s.active).count()
    }

    /// Get the list of all source SSRCs.
    pub fn source_ssrcs(&self) -> Vec<u32> {
        self.sources.keys().copied().collect()
    }

    /// Clear all sources.
    pub fn clear(&mut self) {
        self.sources.clear();
    }
}

/// Conference mixer that manages multiple participants.
///
/// Provides higher-level mixing with per-participant output.
pub struct ConferenceMixer {
    /// Underlying audio mixer.
    mixer: AudioMixer,
    /// Number of samples per frame.
    frame_size: usize,
}

impl ConferenceMixer {
    /// Create a new conference mixer.
    ///
    /// # Arguments
    /// * `sample_rate` - Audio sample rate (e.g., 8000)
    /// * `frame_duration_ms` - Frame duration in milliseconds (e.g., 20)
    pub fn new(sample_rate: u32, frame_duration_ms: u32) -> Self {
        let frame_size = (sample_rate * frame_duration_ms / 1000) as usize;
        Self {
            mixer: AudioMixer::new(sample_rate),
            frame_size,
        }
    }

    /// Submit audio from a participant.
    ///
    /// # Arguments
    /// * `ssrc` - Participant identifier
    /// * `samples` - Audio samples
    pub fn submit_audio(&mut self, ssrc: u32, samples: &[i16]) {
        self.mixer.add_source(ssrc, samples);
    }

    /// Mark a participant as silent for this frame.
    pub fn mark_silent(&mut self, ssrc: u32) {
        self.mixer.mark_silent(ssrc);
    }

    /// Remove a participant from the conference.
    pub fn remove_participant(&mut self, ssrc: u32) {
        self.mixer.remove_source(ssrc);
    }

    /// Get the mixed audio for a specific participant.
    ///
    /// Returns the mix of all other participants' audio (N-1 mixing).
    ///
    /// # Arguments
    /// * `ssrc` - Participant to get audio for (will be excluded from mix)
    ///
    /// # Returns
    /// Tuple of (mixed audio, contributing SSRC list)
    pub fn get_mix_for(&mut self, ssrc: u32) -> (Vec<i16>, Vec<u32>) {
        self.mixer.mix_except(self.frame_size, Some(ssrc))
    }

    /// Get the number of active participants.
    pub fn participant_count(&self) -> usize {
        self.mixer.active_source_count()
    }
}

/// Active speaker detector.
///
/// Tracks audio energy levels to determine the current active speaker(s).
pub struct ActiveSpeakerDetector {
    /// Energy history per source (SSRC -> recent energy levels).
    energy_history: HashMap<u32, Vec<f32>>,
    /// History length for smoothing.
    history_len: usize,
    /// Energy threshold for speech detection.
    speech_threshold: f32,
}

impl ActiveSpeakerDetector {
    /// Create a new active speaker detector.
    pub fn new() -> Self {
        Self {
            energy_history: HashMap::new(),
            history_len: 10, // ~200ms at 20ms frames
            speech_threshold: 0.02,
        }
    }

    /// Set the speech detection threshold (0.0 to 1.0).
    pub fn set_threshold(&mut self, threshold: f32) {
        self.speech_threshold = threshold;
    }

    /// Update with new audio samples from a source.
    ///
    /// # Arguments
    /// * `ssrc` - Source identifier
    /// * `samples` - Audio samples
    ///
    /// # Returns
    /// The normalized energy level (0.0 to 1.0)
    pub fn update(&mut self, ssrc: u32, samples: &[i16]) -> f32 {
        let energy = calculate_rms_energy(samples);

        let history = self.energy_history.entry(ssrc).or_default();
        history.push(energy);

        // Keep history bounded
        while history.len() > self.history_len {
            history.remove(0);
        }

        energy
    }

    /// Check if a source is currently speaking.
    pub fn is_speaking(&self, ssrc: u32) -> bool {
        self.get_smoothed_energy(ssrc) > self.speech_threshold
    }

    /// Get the smoothed energy level for a source.
    pub fn get_smoothed_energy(&self, ssrc: u32) -> f32 {
        self.energy_history
            .get(&ssrc)
            .map(|history| {
                if history.is_empty() {
                    0.0
                } else {
                    history.iter().sum::<f32>() / history.len() as f32
                }
            })
            .unwrap_or(0.0)
    }

    /// Get the current active speaker (highest energy above threshold).
    ///
    /// Returns None if no one is speaking.
    pub fn get_active_speaker(&self) -> Option<u32> {
        self.energy_history
            .iter()
            .filter(|(_, history)| !history.is_empty())
            .map(|(&ssrc, history)| {
                let avg = history.iter().sum::<f32>() / history.len() as f32;
                (ssrc, avg)
            })
            .filter(|(_, energy)| *energy > self.speech_threshold)
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .map(|(ssrc, _)| ssrc)
    }

    /// Get all active speakers sorted by energy (highest first).
    pub fn get_active_speakers(&self) -> Vec<(u32, f32)> {
        let mut speakers: Vec<_> = self
            .energy_history
            .iter()
            .filter(|(_, history)| !history.is_empty())
            .map(|(&ssrc, history)| {
                let avg = history.iter().sum::<f32>() / history.len() as f32;
                (ssrc, avg)
            })
            .filter(|(_, energy)| *energy > self.speech_threshold)
            .collect();

        speakers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        speakers
    }

    /// Remove a source from tracking.
    pub fn remove(&mut self, ssrc: u32) {
        self.energy_history.remove(&ssrc);
    }

    /// Clear all sources.
    pub fn clear(&mut self) {
        self.energy_history.clear();
    }
}

impl Default for ActiveSpeakerDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate RMS energy of audio samples (normalized 0.0 to 1.0).
fn calculate_rms_energy(samples: &[i16]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }

    let sum_squares: i64 = samples.iter().map(|&s| (s as i64) * (s as i64)).sum();

    let rms = ((sum_squares as f64) / (samples.len() as f64)).sqrt();
    (rms / i16::MAX as f64) as f32
}

/// Detect silence in audio samples.
///
/// # Arguments
/// * `samples` - Audio samples to analyze
/// * `threshold` - Energy threshold (0.0 to 1.0)
///
/// # Returns
/// True if the audio is below the silence threshold
pub fn is_silence(samples: &[i16], threshold: f32) -> bool {
    if samples.is_empty() {
        return true;
    }

    // Calculate RMS energy
    let sum_squares: i64 = samples.iter().map(|&s| (s as i64) * (s as i64)).sum();

    let rms = ((sum_squares as f64) / (samples.len() as f64)).sqrt();
    let normalized = rms / (i16::MAX as f64);

    normalized < threshold as f64
}

/// Simple automatic gain control.
///
/// # Arguments
/// * `samples` - Audio samples to process (modified in place)
/// * `target_level` - Target peak level (0.0 to 1.0)
/// * `max_gain` - Maximum gain to apply
pub fn auto_gain_control(samples: &mut [i16], target_level: f32, max_gain: f32) {
    if samples.is_empty() {
        return;
    }

    // Find peak
    let peak = samples.iter().map(|&s| s.abs() as i32).max().unwrap_or(0);

    if peak == 0 {
        return;
    }

    // Calculate gain needed
    let target_peak = (target_level * i16::MAX as f32) as i32;
    let gain = (target_peak as f32 / peak as f32).min(max_gain);

    if (gain - 1.0).abs() < 0.01 {
        return; // No significant adjustment needed
    }

    // Apply gain
    for sample in samples.iter_mut() {
        let adjusted = (*sample as f32 * gain) as i32;
        *sample = adjusted.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixer_single_source() {
        let mut mixer = AudioMixer::new(8000);

        let samples: Vec<i16> = vec![100, 200, 300, -100, -200];
        mixer.add_source(1, &samples);

        let (mixed, csrc) = mixer.mix(5);

        assert_eq!(mixed, samples);
        assert_eq!(csrc, vec![1]);
    }

    #[test]
    fn test_mixer_two_sources() {
        let mut mixer = AudioMixer::new(8000);

        let samples1: Vec<i16> = vec![100, 200, 300];
        let samples2: Vec<i16> = vec![50, 100, 150];

        mixer.add_source(1, &samples1);
        mixer.add_source(2, &samples2);

        let (mixed, csrc) = mixer.mix(3);

        assert_eq!(mixed, vec![150, 300, 450]);
        assert!(csrc.contains(&1));
        assert!(csrc.contains(&2));
    }

    #[test]
    fn test_mixer_overflow_clamp() {
        let mut mixer = AudioMixer::new(8000);

        // Values that would overflow when summed
        let samples1: Vec<i16> = vec![i16::MAX, i16::MAX];
        let samples2: Vec<i16> = vec![i16::MAX, 1000];

        mixer.add_source(1, &samples1);
        mixer.add_source(2, &samples2);

        let (mixed, _) = mixer.mix(2);

        // Should be clamped to i16::MAX
        assert_eq!(mixed[0], i16::MAX);
        assert_eq!(mixed[1], i16::MAX);
    }

    #[test]
    fn test_mixer_n_minus_1() {
        let mut mixer = AudioMixer::new(8000);

        let samples1: Vec<i16> = vec![100];
        let samples2: Vec<i16> = vec![200];
        let samples3: Vec<i16> = vec![300];

        mixer.add_source(1, &samples1);
        mixer.add_source(2, &samples2);
        mixer.add_source(3, &samples3);

        // Mix excluding source 1
        let (mixed, csrc) = mixer.mix_except(1, Some(1));

        assert_eq!(mixed, vec![500]); // 200 + 300
        assert!(!csrc.contains(&1));
        assert!(csrc.contains(&2));
        assert!(csrc.contains(&3));
    }

    #[test]
    fn test_mixer_inactive_source() {
        let mut mixer = AudioMixer::new(8000);

        mixer.add_source(1, &[100, 200]);
        mixer.add_source(2, &[50, 100]);
        mixer.mark_silent(2);

        let (mixed, csrc) = mixer.mix(2);

        // Only source 1 should be in the mix
        assert_eq!(mixed, vec![100, 200]);
        assert!(csrc.contains(&1));
        assert!(!csrc.contains(&2));
    }

    #[test]
    fn test_conference_mixer() {
        let mut conf = ConferenceMixer::new(8000, 20);

        // 20ms at 8kHz = 160 samples
        let audio1: Vec<i16> = vec![100; 160];
        let audio2: Vec<i16> = vec![50; 160];

        conf.submit_audio(1, &audio1);
        conf.submit_audio(2, &audio2);

        // Participant 1 should hear participant 2
        let (mix1, _) = conf.get_mix_for(1);
        assert_eq!(mix1.len(), 160);
        assert_eq!(mix1[0], 50);

        // Participant 2 should hear participant 1
        let (mix2, _) = conf.get_mix_for(2);
        assert_eq!(mix2[0], 100);
    }

    #[test]
    fn test_is_silence() {
        let loud: Vec<i16> = vec![10000, -10000, 10000];
        let quiet: Vec<i16> = vec![10, -10, 5];
        let empty: Vec<i16> = vec![];

        assert!(!is_silence(&loud, 0.01));
        assert!(is_silence(&quiet, 0.01));
        assert!(is_silence(&empty, 0.01));
    }

    #[test]
    fn test_auto_gain_control() {
        let mut samples: Vec<i16> = vec![1000, -1000, 500, -500];
        auto_gain_control(&mut samples, 0.5, 20.0);

        // Peak should be closer to target (0.5 * i16::MAX)
        let peak = samples.iter().map(|s| s.abs()).max().unwrap();
        // Original peak was 1000, target is ~16383, so gain is ~16x
        assert!(peak > 10000); // Should be amplified significantly
    }

    #[test]
    fn test_mixer_max_sources() {
        let mut mixer = AudioMixer::new(8000);
        mixer.set_max_sources(3);

        // Add 4 sources - should only keep 3
        for i in 1..=4 {
            mixer.add_source(i, &[100]);
        }

        assert!(mixer.active_source_count() <= 3);
    }

    #[test]
    fn test_active_speaker_detector() {
        let mut detector = ActiveSpeakerDetector::new();

        // Loud source
        let loud: Vec<i16> = vec![10000, -10000, 8000, -8000];
        detector.update(1, &loud);

        // Quiet source
        let quiet: Vec<i16> = vec![100, -100, 50, -50];
        detector.update(2, &quiet);

        assert!(detector.is_speaking(1));
        assert!(!detector.is_speaking(2));

        // Active speaker should be the loud one
        assert_eq!(detector.get_active_speaker(), Some(1));
    }

    #[test]
    fn test_active_speaker_smoothing() {
        let mut detector = ActiveSpeakerDetector::new();

        // Send several frames of audio
        let loud: Vec<i16> = vec![5000; 160];
        for _ in 0..5 {
            detector.update(1, &loud);
        }

        let energy = detector.get_smoothed_energy(1);
        assert!(energy > 0.1); // Should have significant energy
    }

    #[test]
    fn test_active_speakers_sorted() {
        let mut detector = ActiveSpeakerDetector::new();

        detector.update(1, &vec![10000i16; 100]);
        detector.update(2, &vec![5000i16; 100]);
        detector.update(3, &vec![7500i16; 100]);

        let speakers = detector.get_active_speakers();

        // Should be sorted by energy (highest first)
        assert!(!speakers.is_empty());
        if speakers.len() >= 2 {
            assert!(speakers[0].1 >= speakers[1].1);
        }
    }

    #[test]
    fn test_rms_energy() {
        let silence: Vec<i16> = vec![0; 100];
        assert_eq!(calculate_rms_energy(&silence), 0.0);

        let max: Vec<i16> = vec![i16::MAX; 100];
        let energy = calculate_rms_energy(&max);
        assert!((energy - 1.0).abs() < 0.01);
    }
}
