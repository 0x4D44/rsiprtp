//! Audio codec implementations.

pub mod g711;
pub mod g722;

#[cfg(feature = "opus")]
pub mod opus;

// Re-export main types
pub use g711::{G711Codec, G711Variant};
pub use g722::{G722Codec, G722_PAYLOAD_TYPE, G722_RTP_RATE, G722_SAMPLE_RATE};

#[cfg(feature = "opus")]
pub use opus::{OpusCodec, OpusConfig, OPUS_SAMPLE_RATE, OPUS_SAMPLES_PER_FRAME};
