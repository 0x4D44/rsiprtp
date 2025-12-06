//! Opus codec implementation.
//!
//! Opus is a versatile audio codec for interactive speech and music.
//! - Variable bitrate (6-510 kbps)
//! - Sample rates: 8, 12, 16, 24, 48 kHz
//! - Frame sizes: 2.5, 5, 10, 20, 40, 60 ms
//! - RTP payload type: dynamic (typically 111)
//!
//! This implementation uses libopus via the audiopus crate.

use audiopus::{
    coder::{Decoder, Encoder},
    Application, Channels, SampleRate,
};

/// Default Opus sample rate (48 kHz).
pub const OPUS_SAMPLE_RATE: u32 = 48000;

/// Default frame size in ms.
pub const OPUS_FRAME_MS: usize = 20;

/// Samples per 20ms frame at 48kHz.
pub const OPUS_SAMPLES_PER_FRAME: usize = 960; // 48000 * 0.020

/// Maximum Opus packet size.
pub const OPUS_MAX_PACKET_SIZE: usize = 4000;

/// Opus encoder/decoder configuration.
#[derive(Debug, Clone)]
pub struct OpusConfig {
    /// Sample rate in Hz (8000, 12000, 16000, 24000, or 48000).
    pub sample_rate: u32,
    /// Number of channels (1 for mono, 2 for stereo).
    pub channels: u8,
    /// Bitrate in bits per second.
    pub bitrate: u32,
    /// Frame size in milliseconds (2.5, 5, 10, 20, 40, or 60).
    pub frame_ms: f32,
}

impl Default for OpusConfig {
    fn default() -> Self {
        Self {
            sample_rate: OPUS_SAMPLE_RATE,
            channels: 1,
            bitrate: 32000, // 32 kbps for speech
            frame_ms: 20.0,
        }
    }
}

impl OpusConfig {
    /// Create config for wideband speech (16 kHz mono).
    pub fn wideband_speech() -> Self {
        Self {
            sample_rate: 16000,
            channels: 1,
            bitrate: 24000,
            frame_ms: 20.0,
        }
    }

    /// Create config for fullband speech (48 kHz mono).
    pub fn fullband_speech() -> Self {
        Self {
            sample_rate: 48000,
            channels: 1,
            bitrate: 32000,
            frame_ms: 20.0,
        }
    }

    /// Create config for music (48 kHz stereo).
    pub fn music() -> Self {
        Self {
            sample_rate: 48000,
            channels: 2,
            bitrate: 96000,
            frame_ms: 20.0,
        }
    }

    /// Get samples per frame.
    pub fn samples_per_frame(&self) -> usize {
        (self.sample_rate as f32 * self.frame_ms / 1000.0) as usize
    }

    fn to_sample_rate(&self) -> SampleRate {
        match self.sample_rate {
            8000 => SampleRate::Hz8000,
            12000 => SampleRate::Hz12000,
            16000 => SampleRate::Hz16000,
            24000 => SampleRate::Hz24000,
            _ => SampleRate::Hz48000,
        }
    }

    fn to_channels(&self) -> Channels {
        if self.channels >= 2 {
            Channels::Stereo
        } else {
            Channels::Mono
        }
    }
}

/// Opus encoder/decoder.
pub struct OpusCodec {
    encoder: Encoder,
    decoder: Decoder,
    config: OpusConfig,
    encode_buffer: Vec<u8>,
}

impl OpusCodec {
    /// Create a new Opus codec with default configuration.
    pub fn new() -> Result<Self, String> {
        Self::with_config(OpusConfig::default())
    }

    /// Create a new Opus codec with custom configuration.
    pub fn with_config(config: OpusConfig) -> Result<Self, String> {
        let sample_rate = config.to_sample_rate();
        let channels = config.to_channels();

        let encoder = Encoder::new(sample_rate, channels, Application::Voip)
            .map_err(|e| format!("Failed to create Opus encoder: {}", e))?;

        let decoder = Decoder::new(sample_rate, channels)
            .map_err(|e| format!("Failed to create Opus decoder: {}", e))?;

        Ok(Self {
            encoder,
            decoder,
            config,
            encode_buffer: vec![0u8; OPUS_MAX_PACKET_SIZE],
        })
    }

    /// Get the codec name.
    pub fn name(&self) -> &'static str {
        "opus"
    }

    /// Get the sample rate.
    pub fn sample_rate(&self) -> u32 {
        self.config.sample_rate
    }

    /// Get number of channels.
    pub fn channels(&self) -> u8 {
        self.config.channels
    }

    /// Get samples per frame.
    pub fn samples_per_frame(&self) -> usize {
        self.config.samples_per_frame()
    }

    /// Encode 16-bit PCM samples to Opus.
    ///
    /// Input: 16-bit signed linear PCM samples
    /// Output: Opus encoded bytes
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, String> {
        let len = self.encoder
            .encode(pcm, &mut self.encode_buffer)
            .map_err(|e| format!("Opus encode error: {}", e))?;

        Ok(self.encode_buffer[..len].to_vec())
    }

    /// Decode Opus to 16-bit PCM samples.
    ///
    /// Input: Opus encoded bytes
    /// Output: 16-bit signed linear PCM samples
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, String> {
        let frame_size = self.samples_per_frame() * self.channels() as usize;
        let mut decoded = vec![0i16; frame_size];

        let samples = self.decoder
            .decode(Some(data), &mut decoded, false)
            .map_err(|e| format!("Opus decode error: {}", e))?;

        decoded.truncate(samples * self.channels() as usize);
        Ok(decoded)
    }

    /// Decode with packet loss concealment.
    ///
    /// Call this when a packet is lost to generate concealment audio.
    pub fn decode_plc(&mut self) -> Result<Vec<i16>, String> {
        let frame_size = self.samples_per_frame() * self.channels() as usize;
        let mut decoded = vec![0i16; frame_size];

        let samples = self.decoder
            .decode(None, &mut decoded, false)
            .map_err(|e| format!("Opus PLC error: {}", e))?;

        decoded.truncate(samples * self.channels() as usize);
        Ok(decoded)
    }

    /// Set the encoder bitrate.
    pub fn set_bitrate(&mut self, bitrate: u32) -> Result<(), String> {
        self.encoder
            .set_bitrate(audiopus::Bitrate::BitsPerSecond(bitrate as i32))
            .map_err(|e| format!("Failed to set bitrate: {}", e))
    }

    /// Enable or disable FEC (Forward Error Correction).
    pub fn set_fec(&mut self, enabled: bool) -> Result<(), String> {
        self.encoder
            .set_inband_fec(enabled)
            .map_err(|e| format!("Failed to set FEC: {}", e))
    }

    /// Set expected packet loss percentage (0-100).
    ///
    /// This helps Opus optimize for lossy networks.
    pub fn set_packet_loss(&mut self, percent: u8) -> Result<(), String> {
        self.encoder
            .set_packet_loss_perc(percent as i32)
            .map_err(|e| format!("Failed to set packet loss: {}", e))
    }

    /// Enable or disable DTX (Discontinuous Transmission).
    ///
    /// When enabled, Opus will not transmit during silence.
    pub fn set_dtx(&mut self, enabled: bool) -> Result<(), String> {
        self.encoder
            .set_dtx(enabled)
            .map_err(|e| format!("Failed to set DTX: {}", e))
    }
}

impl Default for OpusCodec {
    fn default() -> Self {
        Self::new().expect("Failed to create default Opus codec")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_codec() {
        let codec = OpusCodec::new();
        assert!(codec.is_ok());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut codec = OpusCodec::new().unwrap();

        // Create a test signal (sine wave)
        let samples: Vec<i16> = (0..codec.samples_per_frame())
            .map(|i| ((i as f32 * 0.1).sin() * 16000.0) as i16)
            .collect();

        // Encode
        let encoded = codec.encode(&samples).unwrap();
        assert!(!encoded.is_empty());
        assert!(encoded.len() < samples.len() * 2); // Should compress

        // Decode
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), samples.len());
    }

    #[test]
    fn test_wideband_config() {
        let config = OpusConfig::wideband_speech();
        assert_eq!(config.sample_rate, 16000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.samples_per_frame(), 320);
    }

    #[test]
    fn test_fullband_config() {
        let config = OpusConfig::fullband_speech();
        assert_eq!(config.sample_rate, 48000);
        assert_eq!(config.samples_per_frame(), 960);
    }

    #[test]
    fn test_plc() {
        let mut codec = OpusCodec::new().unwrap();

        // First, encode and decode a real frame to prime the decoder
        let samples: Vec<i16> = (0..codec.samples_per_frame())
            .map(|i| ((i as f32 * 0.1).sin() * 8000.0) as i16)
            .collect();
        let encoded = codec.encode(&samples).unwrap();
        let _ = codec.decode(&encoded).unwrap();

        // Now test PLC
        let plc = codec.decode_plc();
        assert!(plc.is_ok());
        let plc_samples = plc.unwrap();
        assert_eq!(plc_samples.len(), codec.samples_per_frame());
    }

    #[test]
    fn test_set_bitrate() {
        let mut codec = OpusCodec::new().unwrap();
        assert!(codec.set_bitrate(24000).is_ok());
        assert!(codec.set_bitrate(64000).is_ok());
    }

    #[test]
    fn test_set_fec() {
        let mut codec = OpusCodec::new().unwrap();
        assert!(codec.set_fec(true).is_ok());
        assert!(codec.set_fec(false).is_ok());
    }

    #[test]
    fn test_set_packet_loss() {
        let mut codec = OpusCodec::new().unwrap();
        assert!(codec.set_packet_loss(10).is_ok());
    }

    #[test]
    fn test_set_dtx() {
        let mut codec = OpusCodec::new().unwrap();
        assert!(codec.set_dtx(true).is_ok());
    }

    #[test]
    fn test_name() {
        let codec = OpusCodec::new().unwrap();
        assert_eq!(codec.name(), "opus");
    }
}
