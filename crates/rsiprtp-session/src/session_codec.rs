//! Concrete codec dispatch for negotiated SDP entries.
//!
//! [`SessionCodec`] is a small enum that owns whichever audio codec was
//! selected during SDP negotiation. It is the single point at which a
//! `MediaSession` knows what codec it is using; encode/decode go through
//! it, and adaptive-bitrate control only reaches the underlying encoder
//! when the variant supports it.
//!
//! Adding a codec means adding an arm here (and turning on the matching
//! feature in `rsiprtp-media` if needed) — no common `Codec` trait, by
//! design.
//!
//! See `wrk_docs/2026.04.30 - HLD - Production wiring for the bitrate bridge.md`.

use rsiprtp_media::{AdaptiveBitrate, G711Codec, G711Variant, G722Codec, OpusCodec, OpusConfig};
use rsiprtp_sdp::Codec;

/// Concrete audio codec selected for a media session.
///
/// Variants wrap the per-codec types from `rsiprtp-media`. Construct via
/// [`SessionCodec::for_negotiated`]; encode/decode through the inherent
/// methods; obtain an [`AdaptiveBitrate`] handle (when applicable) via
/// [`SessionCodec::as_adaptive_mut`].
pub enum SessionCodec {
    /// G.711 (PCMU or PCMA) — fixed 64 kbps, non-adaptive.
    G711(G711Codec),
    /// G.722 — fixed 64 kbps, non-adaptive.
    ///
    /// Boxed because `G722Codec` carries ADPCM encoder + decoder state
    /// (~944 bytes); inlining would dominate the enum size for every
    /// session. See `clippy::large_enum_variant`.
    G722(Box<G722Codec>),
    /// Opus — variable bitrate, adaptive via [`AdaptiveBitrate`].
    ///
    /// Boxed because `OpusCodec` is ~13 KB (encoder + decoder + scratch
    /// buffer); inlining it would balloon every `SessionCodec` to that
    /// size. See `clippy::large_enum_variant`.
    Opus(Box<OpusCodec>),
}

impl SessionCodec {
    /// Build the concrete codec for an SDP-negotiated entry.
    ///
    /// Dispatch is case-insensitive on `negotiated.encoding` (real SDP
    /// capitalisation varies). Returns `Err` for any encoding the workspace
    /// does not support — the caller decides whether to reject the call.
    pub fn for_negotiated(negotiated: &Codec) -> Result<Self, String> {
        match negotiated.encoding.to_lowercase().as_str() {
            "pcmu" => Ok(SessionCodec::G711(G711Codec::new(G711Variant::MuLaw))),
            "pcma" => Ok(SessionCodec::G711(G711Codec::new(G711Variant::ALaw))),
            "g722" => Ok(SessionCodec::G722(Box::new(G722Codec::new()))),
            "opus" => OpusCodec::with_config(OpusConfig::fullband_speech())
                .map(|c| SessionCodec::Opus(Box::new(c)))
                .map_err(|e| format!("failed to build Opus codec: {e}")),
            _ => Err(format!(
                "unsupported codec encoding: {}",
                negotiated.encoding
            )),
        }
    }

    /// Encode 16-bit PCM samples for the active codec.
    ///
    /// G.711 and G.722 are infallible at the codec level; their results
    /// are wrapped as `Ok(_)` for a uniform `Result` surface.
    pub fn encode(&mut self, samples: &[i16]) -> Result<Vec<u8>, String> {
        match self {
            SessionCodec::G711(c) => Ok(c.encode(samples)),
            SessionCodec::G722(c) => Ok(c.encode(samples)),
            SessionCodec::Opus(c) => c.encode(samples),
        }
    }

    /// Decode an encoded payload into 16-bit PCM samples.
    pub fn decode(&mut self, payload: &[u8]) -> Result<Vec<i16>, String> {
        match self {
            SessionCodec::G711(c) => Ok(c.decode(payload)),
            SessionCodec::G722(c) => Ok(c.decode(payload)),
            SessionCodec::Opus(c) => c.decode(payload),
        }
    }

    /// Samples per encoded frame at the codec's native sample rate.
    pub fn samples_per_frame(&self) -> usize {
        match self {
            SessionCodec::G711(c) => c.samples_per_frame(),
            SessionCodec::G722(c) => c.samples_per_frame(),
            SessionCodec::Opus(c) => c.samples_per_frame(),
        }
    }

    /// Adaptive-bitrate handle, present only for codecs whose encoder rate
    /// can be adjusted at runtime.
    pub fn as_adaptive_mut(&mut self) -> Option<&mut dyn AdaptiveBitrate> {
        match self {
            SessionCodec::Opus(c) => Some(c.as_mut() as &mut dyn AdaptiveBitrate),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec(encoding: &str) -> Codec {
        // Payload type / clock rate are not consulted by `for_negotiated`;
        // any plausible values will do.
        Codec::new(0, encoding, 8000)
    }

    #[test]
    fn for_negotiated_routes_pcmu() {
        let sc = SessionCodec::for_negotiated(&codec("PCMU")).unwrap();
        match sc {
            SessionCodec::G711(c) => assert_eq!(c.variant(), G711Variant::MuLaw),
            _ => panic!("expected G711(MuLaw)"),
        }
    }

    #[test]
    fn for_negotiated_routes_pcma() {
        let sc = SessionCodec::for_negotiated(&codec("PCMA")).unwrap();
        match sc {
            SessionCodec::G711(c) => assert_eq!(c.variant(), G711Variant::ALaw),
            _ => panic!("expected G711(ALaw)"),
        }
    }

    #[test]
    fn for_negotiated_routes_g722() {
        let sc = SessionCodec::for_negotiated(&codec("G722")).unwrap();
        assert!(matches!(sc, SessionCodec::G722(_)));
    }

    #[test]
    fn for_negotiated_routes_opus() {
        let sc = SessionCodec::for_negotiated(&codec("opus")).unwrap();
        assert!(matches!(sc, SessionCodec::Opus(_)));
    }

    #[test]
    fn for_negotiated_is_case_insensitive() {
        for name in ["PCMU", "pcmu", "Pcmu"] {
            let sc = SessionCodec::for_negotiated(&codec(name)).unwrap();
            match sc {
                SessionCodec::G711(c) => assert_eq!(c.variant(), G711Variant::MuLaw),
                _ => panic!("expected G711(MuLaw) for {name}"),
            }
        }

        for name in ["OPUS", "opus", "Opus"] {
            let sc = SessionCodec::for_negotiated(&codec(name)).unwrap();
            assert!(
                matches!(sc, SessionCodec::Opus(_)),
                "expected Opus for {name}"
            );
        }
    }

    #[test]
    fn for_negotiated_rejects_unknown() {
        // `Result::expect_err` would require `SessionCodec: Debug`; we
        // deliberately do not derive Debug on the codec wrappers, so match.
        match SessionCodec::for_negotiated(&codec("AMR")) {
            Ok(_) => panic!("AMR must be rejected as unsupported"),
            Err(e) => assert!(e.contains("AMR"), "error should mention encoding: {e}"),
        }
    }

    #[test]
    fn as_adaptive_mut_only_for_opus() {
        // G.711 (mu-law) — non-adaptive.
        let mut g711 = SessionCodec::for_negotiated(&codec("PCMU")).unwrap();
        assert!(g711.as_adaptive_mut().is_none());

        // G.722 — non-adaptive.
        let mut g722 = SessionCodec::for_negotiated(&codec("G722")).unwrap();
        assert!(g722.as_adaptive_mut().is_none());

        // Opus — adaptive.
        let mut opus = SessionCodec::for_negotiated(&codec("opus")).unwrap();
        assert!(opus.as_adaptive_mut().is_some());
    }
}
