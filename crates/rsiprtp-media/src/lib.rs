//! Audio processing: codecs, jitter buffer, mixing, and file I/O.

pub mod codec;
pub mod jitter;
pub mod mixer;
pub mod wav;

// Re-export main types
pub use codec::g711::{silence_byte, silence_frame, G711Codec, G711Variant};
pub use codec::g722::{G722Codec, G722_PAYLOAD_TYPE, G722_RTP_RATE, G722_SAMPLE_RATE};
pub use codec::AdaptiveBitrate;
pub use jitter::{BufferedPacket, JitterBuffer, JitterBufferConfig, JitterStats, PlayoutDecision};
pub use mixer::{
    auto_gain_control, is_silence, ActiveSpeakerDetector, AudioMixer, ConferenceMixer,
};
pub use wav::{generate_dtmf_tone, generate_silence, generate_tone, WavReader, WavWriter};

#[cfg(feature = "opus")]
pub use codec::opus::{
    Bitrate, InbandFec, OpusCodec, OpusConfig, OPUS_SAMPLES_PER_FRAME, OPUS_SAMPLE_RATE,
};
