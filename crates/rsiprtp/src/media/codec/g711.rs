//! G.711 (PCMU/PCMA) codec implementation.
//!
//! G.711 is the standard telephone audio codec with two variants:
//! - PCMU (mu-law): RTP payload type 0, used in North America/Japan
//! - PCMA (A-law): RTP payload type 8, used in Europe and rest of world
//!
//! Both operate at 8kHz sample rate, 8 bits per sample, resulting in
//! 64 kbit/s bitrate (8000 samples/sec * 8 bits).

use audio_codec_algorithms::{decode_alaw, decode_ulaw, encode_alaw, encode_ulaw};

/// G.711 codec variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G711Variant {
    /// Mu-law (PCMU), RTP payload type 0.
    MuLaw,
    /// A-law (PCMA), RTP payload type 8.
    ALaw,
}

impl G711Variant {
    /// Get the RTP payload type for this variant.
    pub fn payload_type(&self) -> u8 {
        match self {
            G711Variant::MuLaw => 0,
            G711Variant::ALaw => 8,
        }
    }

    /// Get the codec name.
    pub fn name(&self) -> &'static str {
        match self {
            G711Variant::MuLaw => "PCMU",
            G711Variant::ALaw => "PCMA",
        }
    }
}

/// G.711 encoder/decoder.
#[derive(Debug, Clone)]
pub struct G711Codec {
    variant: G711Variant,
}

impl G711Codec {
    /// Create a new G.711 codec.
    pub fn new(variant: G711Variant) -> Self {
        Self { variant }
    }

    /// Create a PCMU (mu-law) codec.
    pub fn pcmu() -> Self {
        Self::new(G711Variant::MuLaw)
    }

    /// Create a PCMA (A-law) codec.
    pub fn pcma() -> Self {
        Self::new(G711Variant::ALaw)
    }

    /// Get the codec variant.
    pub fn variant(&self) -> G711Variant {
        self.variant
    }

    /// Get the sample rate (always 8000 Hz).
    pub fn sample_rate(&self) -> u32 {
        8000
    }

    /// Get samples per 20ms frame (160).
    pub fn samples_per_frame(&self) -> usize {
        160
    }

    /// Get bytes per 20ms frame (160).
    pub fn bytes_per_frame(&self) -> usize {
        160
    }

    /// Encode 16-bit PCM samples to G.711.
    ///
    /// Input: 16-bit signed linear PCM samples
    /// Output: 8-bit G.711 encoded bytes
    pub fn encode(&self, pcm: &[i16]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(pcm.len());

        match self.variant {
            G711Variant::MuLaw => {
                for &sample in pcm {
                    encoded.push(encode_ulaw(sample));
                }
            }
            G711Variant::ALaw => {
                for &sample in pcm {
                    encoded.push(encode_alaw(sample));
                }
            }
        }

        encoded
    }

    /// Decode G.711 to 16-bit PCM samples.
    ///
    /// Input: 8-bit G.711 encoded bytes
    /// Output: 16-bit signed linear PCM samples
    pub fn decode(&self, data: &[u8]) -> Vec<i16> {
        let mut decoded = Vec::with_capacity(data.len());

        match self.variant {
            G711Variant::MuLaw => {
                for &byte in data {
                    decoded.push(decode_ulaw(byte));
                }
            }
            G711Variant::ALaw => {
                for &byte in data {
                    decoded.push(decode_alaw(byte));
                }
            }
        }

        decoded
    }

    /// Encode a single sample.
    pub fn encode_sample(&self, sample: i16) -> u8 {
        match self.variant {
            G711Variant::MuLaw => encode_ulaw(sample),
            G711Variant::ALaw => encode_alaw(sample),
        }
    }

    /// Decode a single sample.
    pub fn decode_sample(&self, byte: u8) -> i16 {
        match self.variant {
            G711Variant::MuLaw => decode_ulaw(byte),
            G711Variant::ALaw => decode_alaw(byte),
        }
    }
}

/// Generate silence for G.711.
///
/// Returns the appropriate silence byte for the codec variant.
pub fn silence_byte(variant: G711Variant) -> u8 {
    match variant {
        // Mu-law silence (0x7F = -1 PCM, 0xFF = +1 PCM, both near zero)
        G711Variant::MuLaw => 0xFF,
        // A-law silence (0xD5 = 0 PCM)
        G711Variant::ALaw => 0xD5,
    }
}

/// Generate a silence frame.
pub fn silence_frame(variant: G711Variant, samples: usize) -> Vec<u8> {
    vec![silence_byte(variant); samples]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcmu_roundtrip() {
        let codec = G711Codec::pcmu();

        // Test a range of values
        let samples: Vec<i16> = (-32000..=32000).step_by(1000).collect();
        let encoded = codec.encode(&samples);
        let decoded = codec.decode(&encoded);

        // G.711 is lossy, but should be close
        for (original, decoded) in samples.iter().zip(decoded.iter()) {
            let error = (*original as i32 - *decoded as i32).abs();
            assert!(error < 500);
        }
    }

    #[test]
    fn test_pcma_roundtrip() {
        let codec = G711Codec::pcma();

        let samples: Vec<i16> = (-32000..=32000).step_by(1000).collect();
        let encoded = codec.encode(&samples);
        let decoded = codec.decode(&encoded);

        for (original, decoded) in samples.iter().zip(decoded.iter()) {
            let error = (*original as i32 - *decoded as i32).abs();
            assert!(error < 500);
        }
    }

    #[test]
    fn test_frame_sizes() {
        let codec = G711Codec::pcmu();
        assert_eq!(codec.sample_rate(), 8000);
        assert_eq!(codec.samples_per_frame(), 160);
        assert_eq!(codec.bytes_per_frame(), 160);
    }

    #[test]
    fn test_payload_types() {
        assert_eq!(G711Variant::MuLaw.payload_type(), 0);
        assert_eq!(G711Variant::ALaw.payload_type(), 8);
    }

    #[test]
    fn test_variant_and_name() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        assert_eq!(codec_mu.variant(), G711Variant::MuLaw);
        assert_eq!(codec_a.variant(), G711Variant::ALaw);
        assert_eq!(G711Variant::MuLaw.name(), "PCMU");
        assert_eq!(G711Variant::ALaw.name(), "PCMA");
    }

    #[test]
    fn test_encode_decode_single_sample() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        let sample = -12345;
        let encoded_mu = codec_mu.encode_sample(sample);
        let decoded_mu = codec_mu.decode_sample(encoded_mu);
        let encoded_a = codec_a.encode_sample(sample);
        let decoded_a = codec_a.decode_sample(encoded_a);

        assert!((sample as i32 - decoded_mu as i32).abs() < 500);
        assert!((sample as i32 - decoded_a as i32).abs() < 500);
    }

    #[test]
    fn test_silence_frame_values() {
        let mu = silence_frame(G711Variant::MuLaw, 3);
        let a = silence_frame(G711Variant::ALaw, 2);

        assert_eq!(mu, vec![silence_byte(G711Variant::MuLaw); 3]);
        assert_eq!(a, vec![silence_byte(G711Variant::ALaw); 2]);
    }

    #[test]
    fn test_silence() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        // Silence should decode to near-zero
        let mu_silence = codec_mu.decode_sample(silence_byte(G711Variant::MuLaw));
        let a_silence = codec_a.decode_sample(silence_byte(G711Variant::ALaw));

        assert!(mu_silence.abs() < 10);
        assert!(a_silence.abs() < 10);
    }

    #[test]
    fn test_silence_frame() {
        let frame = silence_frame(G711Variant::MuLaw, 160);
        assert_eq!(frame.len(), 160);
        assert!(frame.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_pcmu_boundary_values() {
        let codec = G711Codec::pcmu();

        // Test boundary values
        let boundary_values = [0i16, 1, -1, 32767, -32768, 16383, -16384, 8191, -8192];
        for &value in &boundary_values {
            let encoded = codec.encode_sample(value);
            let decoded = codec.decode_sample(encoded);
            // G.711 quantization allows some error
            let error = (value as i32 - decoded as i32).abs();
            assert!(error < 1000);
        }
    }

    #[test]
    fn test_pcma_boundary_values() {
        let codec = G711Codec::pcma();

        // Test boundary values
        let boundary_values = [0i16, 1, -1, 32767, -32768, 16383, -16384, 8191, -8192];
        for &value in &boundary_values {
            let encoded = codec.encode_sample(value);
            let decoded = codec.decode_sample(encoded);
            let error = (value as i32 - decoded as i32).abs();
            assert!(error < 1000);
        }
    }

    #[test]
    fn test_pcmu_full_range_monotonic() {
        let codec = G711Codec::pcmu();

        // Encode ascending values and verify decoded values are generally non-decreasing
        let mut last_decoded: i32 = i16::MIN as i32;
        for value in (-32000i16..=32000).step_by(100) {
            let encoded = codec.encode_sample(value);
            let decoded = codec.decode_sample(encoded) as i32;
            // Allow small non-monotonicity due to quantization
            assert!(decoded >= last_decoded - 200);
            last_decoded = decoded;
        }
    }

    #[test]
    fn test_pcma_full_range_monotonic() {
        let codec = G711Codec::pcma();

        let mut last_decoded: i32 = i16::MIN as i32;
        for value in (-32000i16..=32000).step_by(100) {
            let encoded = codec.encode_sample(value);
            let decoded = codec.decode_sample(encoded) as i32;
            assert!(decoded >= last_decoded - 200);
            last_decoded = decoded;
        }
    }

    #[test]
    fn test_codec_names() {
        assert_eq!(G711Variant::MuLaw.name(), "PCMU");
        assert_eq!(G711Variant::ALaw.name(), "PCMA");
    }

    #[test]
    fn test_codec_variant_accessors() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        assert_eq!(codec_mu.variant(), G711Variant::MuLaw);
        assert_eq!(codec_a.variant(), G711Variant::ALaw);
    }

    #[test]
    fn test_empty_encode_decode() {
        let codec = G711Codec::pcmu();

        let empty: Vec<i16> = vec![];
        let encoded = codec.encode(&empty);
        assert!(encoded.is_empty());

        let decoded = codec.decode(&encoded);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_single_sample_encode_decode() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        let sample = 1000i16;

        // PCMU single sample
        let encoded_mu = codec_mu.encode(&[sample]);
        assert_eq!(encoded_mu.len(), 1);
        let decoded_mu = codec_mu.decode(&encoded_mu);
        assert_eq!(decoded_mu.len(), 1);

        // PCMA single sample
        let encoded_a = codec_a.encode(&[sample]);
        assert_eq!(encoded_a.len(), 1);
        let decoded_a = codec_a.decode(&encoded_a);
        assert_eq!(decoded_a.len(), 1);
    }

    #[test]
    fn test_silence_frame_alaw() {
        let frame = silence_frame(G711Variant::ALaw, 160);
        assert_eq!(frame.len(), 160);
        assert!(frame.iter().all(|&b| b == 0xD5));
    }

    #[test]
    fn test_all_encoded_values_decode() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        // Ensure all 256 possible encoded values decode without panic
        for byte in 0u8..=255 {
            let decoded_mu = codec_mu.decode_sample(byte);
            let decoded_a = codec_a.decode_sample(byte);
            let _ = decoded_mu;
            let _ = decoded_a;
        }
    }

    #[test]
    fn test_frame_size_constants() {
        let codec = G711Codec::pcmu();

        // 20ms at 8kHz = 160 samples = 160 bytes
        assert_eq!(codec.samples_per_frame(), 160);
        assert_eq!(codec.bytes_per_frame(), 160);

        // 160 samples encoded should give 160 bytes
        let samples: Vec<i16> = vec![1000; 160];
        let encoded = codec.encode(&samples);
        assert_eq!(encoded.len(), 160);
    }

    #[test]
    fn test_codec_clone() {
        let codec1 = G711Codec::pcmu();
        let codec2 = codec1.clone();

        assert_eq!(codec1.variant(), codec2.variant());
        assert_eq!(codec1.sample_rate(), codec2.sample_rate());

        // Both should produce same output
        let sample = 5000i16;
        assert_eq!(codec1.encode_sample(sample), codec2.encode_sample(sample));
    }
}
