//! G.722 (Wideband) codec implementation.
//!
//! G.722 is a wideband audio codec standardized by ITU-T.
//! - 7 kHz audio bandwidth (wideband)
//! - 16 kHz sample rate input
//! - 64 kbps bitrate
//! - RTP payload type 9
//! - Uses Sub-band ADPCM encoding
//!
//! Note: RTP for G.722 uses a timestamp rate of 8000 Hz despite
//! the 16 kHz sample rate (RFC 3551).

use ezk_g722::libg722::{decoder::Decoder, encoder::Encoder, Bitrate};

/// RTP payload type for G.722.
pub const G722_PAYLOAD_TYPE: u8 = 9;

/// Sample rate for G.722 (16 kHz input/output).
pub const G722_SAMPLE_RATE: u32 = 16000;

/// RTP timestamp rate for G.722 (8 kHz per RFC 3551).
pub const G722_RTP_RATE: u32 = 8000;

/// G.722 encoder/decoder.
pub struct G722Codec {
    encoder: Encoder,
    decoder: Decoder,
}

impl G722Codec {
    /// Create a new G.722 codec at 64kbps.
    pub fn new() -> Self {
        Self {
            // rate=64kbps, eight_k=false (16kHz samples), packed=false
            encoder: Encoder::new(Bitrate::Mode1_64000, false, false),
            decoder: Decoder::new(Bitrate::Mode1_64000, false, false),
        }
    }

    /// Get the RTP payload type (9).
    pub fn payload_type(&self) -> u8 {
        G722_PAYLOAD_TYPE
    }

    /// Get the codec name.
    pub fn name(&self) -> &'static str {
        "G722"
    }

    /// Get the sample rate (16000 Hz).
    pub fn sample_rate(&self) -> u32 {
        G722_SAMPLE_RATE
    }

    /// Get the RTP timestamp rate (8000 Hz per RFC 3551).
    pub fn rtp_rate(&self) -> u32 {
        G722_RTP_RATE
    }

    /// Get samples per 20ms frame (320 at 16kHz).
    pub fn samples_per_frame(&self) -> usize {
        320 // 16000 Hz * 0.020s
    }

    /// Get bytes per 20ms frame (160).
    ///
    /// G.722 compresses 16kHz to 64kbps, so 320 samples -> 160 bytes.
    pub fn bytes_per_frame(&self) -> usize {
        160 // 64000 bps * 0.020s / 8
    }

    /// Encode 16-bit PCM samples to G.722.
    ///
    /// Input: 16-bit signed linear PCM samples at 16 kHz
    /// Output: G.722 encoded bytes
    ///
    /// Note: For best results, input should be a multiple of 2 samples.
    pub fn encode(&mut self, pcm: &[i16]) -> Vec<u8> {
        self.encoder.encode(pcm)
    }

    /// Decode G.722 to 16-bit PCM samples.
    ///
    /// Input: G.722 encoded bytes
    /// Output: 16-bit signed linear PCM samples at 16 kHz
    pub fn decode(&mut self, data: &[u8]) -> Vec<i16> {
        self.decoder.decode(data)
    }

    /// Reset the encoder/decoder state.
    pub fn reset(&mut self) {
        self.encoder = Encoder::new(Bitrate::Mode1_64000, false, false);
        self.decoder = Decoder::new(Bitrate::Mode1_64000, false, false);
    }
}

impl Default for G722Codec {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a silence frame for G.722.
///
/// Returns 160 bytes (20ms at 64kbps).
pub fn silence_frame() -> Vec<u8> {
    // G.722 silence is approximately 0x00 bytes
    vec![0u8; 160]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut codec = G722Codec::new();

        // Create a test signal (sine wave at ~1kHz)
        let samples: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.1).sin() * 16000.0) as i16)
            .collect();

        // Encode
        let encoded = codec.encode(&samples);
        assert_eq!(encoded.len(), 160);

        // Decode
        let decoded = codec.decode(&encoded);
        assert_eq!(decoded.len(), 320);

        // G.722 is lossy but should preserve general signal shape
        // Check that the decoded signal isn't all zeros
        let non_zero = decoded.iter().filter(|&&s| s != 0).count();
        assert!(non_zero > decoded.len() / 2);
    }

    #[test]
    fn test_frame_sizes() {
        let codec = G722Codec::new();
        assert_eq!(codec.sample_rate(), 16000);
        assert_eq!(codec.rtp_rate(), 8000);
        assert_eq!(codec.samples_per_frame(), 320);
        assert_eq!(codec.bytes_per_frame(), 160);
    }

    #[test]
    fn test_payload_type() {
        let codec = G722Codec::new();
        assert_eq!(codec.payload_type(), 9);
    }

    #[test]
    fn test_name() {
        let codec = G722Codec::new();
        assert_eq!(codec.name(), "G722");
    }

    #[test]
    fn test_reset() {
        let mut codec = G722Codec::new();

        // Encode something
        let samples = vec![1000i16; 320];
        let _ = codec.encode(&samples);

        // Reset
        codec.reset();

        // Should still work
        let encoded = codec.encode(&samples);
        assert_eq!(encoded.len(), 160);
    }

    #[test]
    fn test_silence_frame() {
        let frame = silence_frame();
        assert_eq!(frame.len(), 160);
    }

    #[test]
    fn test_default() {
        let codec = G722Codec::default();
        assert_eq!(codec.payload_type(), 9);
    }
}
