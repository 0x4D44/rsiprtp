//! Audio codec implementations.

pub mod g711;
pub mod g722;

#[cfg(feature = "opus")]
pub mod opus;

/// Capability trait implemented by codecs whose encoder bitrate can be
/// adjusted at runtime.
///
/// Only adaptive codecs (e.g. Opus) implement this; fixed-rate codecs such as
/// G.711 and G.722 deliberately do not, so the type system prevents callers
/// from pretending they can be adapted.
///
/// Implementations may return `Err` if the requested rate is outside the
/// codec's valid range (e.g. ropus rejecting zero).
pub trait AdaptiveBitrate {
    /// Apply a target bitrate in bits per second.
    fn set_target_bitrate_bps(&mut self, bps: u32) -> Result<(), String>;
}

// Re-export main types
pub use g711::{G711Codec, G711Variant};
pub use g722::{G722Codec, G722_PAYLOAD_TYPE, G722_RTP_RATE, G722_SAMPLE_RATE};

#[cfg(feature = "opus")]
pub use opus::{
    Bitrate, InbandFec, OpusCodec, OpusConfig, OPUS_SAMPLES_PER_FRAME, OPUS_SAMPLE_RATE,
};
