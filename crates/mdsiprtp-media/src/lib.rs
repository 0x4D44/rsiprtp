//! Audio processing: codecs, jitter buffer, mixing, and file I/O.

pub mod codec;
pub mod jitter;
pub mod mixer;
pub mod wav;

// Re-export main types
pub use codec::g711::{G711Codec, G711Variant, silence_byte, silence_frame};
pub use codec::g722::{G722Codec, G722_PAYLOAD_TYPE, G722_RTP_RATE, G722_SAMPLE_RATE};
pub use jitter::{
    BufferedPacket, JitterBuffer, JitterBufferConfig, JitterStats, PlayoutDecision,
};
pub use mixer::{AudioMixer, ConferenceMixer, ActiveSpeakerDetector, auto_gain_control, is_silence};
pub use wav::{WavReader, WavWriter, generate_tone, generate_dtmf_tone, generate_silence};

#[cfg(feature = "opus")]
pub use codec::opus::{OpusCodec, OpusConfig, OPUS_SAMPLE_RATE, OPUS_SAMPLES_PER_FRAME};
