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
            assert!(error < 500, "Error too large: {} vs {}", original, decoded);
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
            assert!(error < 500, "Error too large: {} vs {}", original, decoded);
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
    fn test_silence() {
        let codec_mu = G711Codec::pcmu();
        let codec_a = G711Codec::pcma();

        // Silence should decode to near-zero
        let mu_silence = codec_mu.decode_sample(silence_byte(G711Variant::MuLaw));
        let a_silence = codec_a.decode_sample(silence_byte(G711Variant::ALaw));

        assert!(
            mu_silence.abs() < 10,
            "Mu-law silence not quiet: {}",
            mu_silence
        );
        assert!(
            a_silence.abs() < 10,
            "A-law silence not quiet: {}",
            a_silence
        );
    }

    #[test]
    fn test_silence_frame() {
        let frame = silence_frame(G711Variant::MuLaw, 160);
        assert_eq!(frame.len(), 160);
        assert!(frame.iter().all(|&b| b == 0xFF));
    }
}
