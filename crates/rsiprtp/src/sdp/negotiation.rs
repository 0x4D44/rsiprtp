//! SDP offer/answer negotiation per RFC 3264.
//!
//! Implements the offer/answer model for SDP session negotiation.

use crate::sdp::ice_attrs;
use crate::sdp::parser::{
    Attribute, Direction, MediaDescription, MediaType, RtpMap, SessionDescription,
};

/// Codec information for negotiation.
#[derive(Debug, Clone, PartialEq)]
pub struct Codec {
    /// Payload type.
    pub payload_type: u8,
    /// Encoding name.
    pub encoding: String,
    /// Clock rate.
    pub clock_rate: u32,
    /// Number of channels (for audio).
    pub channels: u8,
    /// Format-specific parameters.
    pub fmtp: Option<String>,
}

impl Codec {
    /// Create a new codec.
    pub fn new(pt: u8, encoding: impl Into<String>, clock_rate: u32) -> Self {
        Self {
            payload_type: pt,
            encoding: encoding.into(),
            clock_rate,
            channels: 1,
            fmtp: None,
        }
    }

    /// Set channels.
    pub fn with_channels(mut self, channels: u8) -> Self {
        self.channels = channels;
        self
    }

    /// Set fmtp.
    pub fn with_fmtp(mut self, fmtp: impl Into<String>) -> Self {
        self.fmtp = Some(fmtp.into());
        self
    }

    /// Create PCMU (G.711 mu-law).
    pub fn pcmu() -> Self {
        Self::new(0, "PCMU", 8000)
    }

    /// Create PCMA (G.711 A-law).
    pub fn pcma() -> Self {
        Self::new(8, "PCMA", 8000)
    }

    /// Create G722.
    pub fn g722() -> Self {
        Self::new(9, "G722", 8000)
    }

    /// Check if this codec matches another.
    pub fn matches(&self, other: &RtpMap) -> bool {
        self.encoding.to_uppercase() == other.encoding.to_uppercase()
            && self.clock_rate == other.clock_rate
    }
}

/// Negotiation result.
#[derive(Debug, Clone)]
pub struct NegotiatedMedia {
    /// Selected codec.
    pub codec: Codec,
    /// Remote port.
    pub remote_port: u16,
    /// Remote address.
    pub remote_addr: Option<String>,
    /// Direction (from our perspective).
    pub direction: Direction,
}

/// Negotiate an answer to an SDP offer.
///
/// Returns the negotiated media descriptions or None if no compatible codec found.
pub fn create_answer(
    offer: &SessionDescription,
    local_codecs: &[Codec],
    local_port: u16,
) -> Option<(SessionDescription, Vec<NegotiatedMedia>)> {
    let mut answer = offer.clone();
    let mut negotiated = Vec::new();

    // Get connection address for remote
    let session_addr = offer.connection.as_ref().map(|c| c.address.clone());

    for media in &mut answer.media {
        if media.media_type != MediaType::Audio {
            // Reject non-audio media for now
            media.port = 0;
            continue;
        }

        // Inspect offer-side ICE/rtcp-mux state before we overwrite attrs.
        let offer_has_ice = !ice_attrs::read_candidates(media).is_empty();
        let offer_has_mux = ice_attrs::read_rtcp_mux(media);

        // ICE without rtcp-mux: reject the media (we don't grow a
        // separate-RTCP path). Wipe the line's attributes too — it
        // was cloned from the offer and would otherwise carry the
        // offerer's ufrag/pwd/candidate lines onto the answer's
        // dead m=. Port=0 already signals rejection; no attrs are
        // meaningful on a rejected line.
        if offer_has_ice && !offer_has_mux {
            media.port = 0;
            media.attributes.clear();
            continue;
        }

        // Get remote address (prefer media-level, fall back to session-level)
        let remote_addr = media
            .connection
            .as_ref()
            .map(|c| c.address.clone())
            .or_else(|| session_addr.clone());

        // Find matching codec
        if let Some(negotiated_media) =
            negotiate_media(media, local_codecs, local_port, remote_addr)
        {
            // Update the media description for the answer
            media.port = local_port;
            media.formats = vec![negotiated_media.codec.payload_type.to_string()];

            // Update direction (swap send/recv)
            let new_direction = match media.direction() {
                Direction::SendRecv => Direction::SendRecv,
                Direction::SendOnly => Direction::RecvOnly,
                Direction::RecvOnly => Direction::SendOnly,
                Direction::Inactive => Direction::Inactive,
            };

            // Update attributes
            media.attributes = create_media_attributes(&negotiated_media.codec, new_direction);

            // Mirror rtcp-mux from the offer if it was present.
            if offer_has_mux {
                ice_attrs::write_rtcp_mux(media);
            }

            negotiated.push(NegotiatedMedia {
                direction: new_direction,
                ..negotiated_media
            });
        } else {
            // No compatible codec - reject media
            media.port = 0;
        }
    }

    if negotiated.is_empty() {
        return None;
    }

    Some((answer, negotiated))
}

/// Negotiate a single media stream.
fn negotiate_media(
    offer_media: &MediaDescription,
    local_codecs: &[Codec],
    _local_port: u16,
    remote_addr: Option<String>,
) -> Option<NegotiatedMedia> {
    let offer_rtpmaps = offer_media.rtpmaps();

    // Find first matching codec
    for rtpmap in &offer_rtpmaps {
        for local_codec in local_codecs {
            if local_codec.matches(rtpmap) {
                // Use the offered payload type
                let codec = Codec {
                    payload_type: rtpmap.payload_type,
                    encoding: rtpmap.encoding.clone(),
                    clock_rate: rtpmap.clock_rate,
                    channels: rtpmap.channels(),
                    fmtp: local_codec.fmtp.clone(),
                };

                return Some(NegotiatedMedia {
                    codec,
                    remote_port: offer_media.port,
                    remote_addr,
                    direction: offer_media.direction(),
                });
            }
        }
    }

    // Check static payload types (0=PCMU, 8=PCMA, 9=G722)
    for fmt in &offer_media.formats {
        let pt: u8 = match fmt.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let static_codec = match pt {
            0 => Some(Codec::pcmu()),
            8 => Some(Codec::pcma()),
            9 => Some(Codec::g722()),
            _ => None,
        };

        if let Some(codec) = static_codec {
            if local_codecs.iter().any(|c| {
                c.matches(&RtpMap {
                    payload_type: pt,
                    encoding: codec.encoding.clone(),
                    clock_rate: codec.clock_rate,
                    params: None,
                })
            }) {
                return Some(NegotiatedMedia {
                    codec,
                    remote_port: offer_media.port,
                    remote_addr,
                    direction: offer_media.direction(),
                });
            }
        }
    }

    None
}

/// Create media attributes for a negotiated codec.
///
/// Crate-visible so the deferred-answer path in
/// `CallManager::build_answer_for` can rebuild media attrs from a cached
/// `NegotiatedMedia` without re-running offer/answer matching.
pub(crate) fn create_media_attributes(codec: &Codec, direction: Direction) -> Vec<Attribute> {
    let mut attrs = Vec::new();

    // rtpmap
    let rtpmap_value = if codec.channels > 1 {
        format!(
            "{} {}/{}/{}",
            codec.payload_type, codec.encoding, codec.clock_rate, codec.channels
        )
    } else {
        format!(
            "{} {}/{}",
            codec.payload_type, codec.encoding, codec.clock_rate
        )
    };
    attrs.push(Attribute {
        name: "rtpmap".to_string(),
        value: Some(rtpmap_value),
    });

    // fmtp
    if let Some(ref fmtp) = codec.fmtp {
        attrs.push(Attribute {
            name: "fmtp".to_string(),
            value: Some(format!("{} {}", codec.payload_type, fmtp)),
        });
    }

    // Direction
    attrs.push(Attribute {
        name: match direction {
            Direction::SendRecv => "sendrecv".to_string(),
            Direction::SendOnly => "sendonly".to_string(),
            Direction::RecvOnly => "recvonly".to_string(),
            Direction::Inactive => "inactive".to_string(),
        },
        value: None,
    });

    attrs
}

/// Process an answer to our offer.
///
/// Returns the negotiated media or None if rejected.
pub fn process_answer(answer: &SessionDescription) -> Vec<NegotiatedMedia> {
    let mut negotiated = Vec::new();
    let session_addr = answer.connection.as_ref().map(|c| c.address.clone());

    for media in &answer.media {
        if media.is_rejected() {
            continue;
        }

        if media.media_type != MediaType::Audio {
            continue;
        }

        let remote_addr = media
            .connection
            .as_ref()
            .map(|c| c.address.clone())
            .or_else(|| session_addr.clone());

        // Get the selected codec from the answer
        let rtpmaps = media.rtpmaps();
        let codec = if let Some(rtpmap) = rtpmaps.first() {
            Codec {
                payload_type: rtpmap.payload_type,
                encoding: rtpmap.encoding.clone(),
                clock_rate: rtpmap.clock_rate,
                channels: rtpmap.channels(),
                fmtp: None,
            }
        } else if let Some(fmt) = media.formats.first() {
            // Try static payload type
            let pt: u8 = match fmt.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            match pt {
                0 => Codec::pcmu(),
                8 => Codec::pcma(),
                9 => Codec::g722(),
                _ => continue,
            }
        } else {
            continue;
        };

        negotiated.push(NegotiatedMedia {
            codec,
            remote_port: media.port,
            remote_addr,
            direction: media.direction(),
        });
    }

    negotiated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdp::parser::{
        Connection, MediaDescription, MediaType, Origin, SessionDescription, Timing,
    };
    use std::collections::HashMap;

    const OFFER_SDP: &str = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-16
a=sendrecv
"#;

    #[test]
    fn test_create_answer() {
        let offer = SessionDescription::parse(OFFER_SDP).unwrap();
        let local_codecs = vec![Codec::pcmu(), Codec::pcma()];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "PCMU");
        assert_eq!(negotiated[0].remote_port, 49170);

        let audio = answer.audio_media().unwrap();
        assert_eq!(audio.port, 5000);
        assert_eq!(audio.formats, vec!["0"]);
    }

    #[test]
    fn test_create_answer_static_payload_match() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (_, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "PCMU");
        assert_eq!(negotiated[0].codec.payload_type, 0);
    }

    #[test]
    fn test_create_answer_invalid_format_skips() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP abc
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcma()];

        let result = create_answer(&offer, &local_codecs, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_answer_with_fmtp_attributes() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 101
a=rtpmap:101 telephone-event/8000
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::new(101, "telephone-event", 8000).with_fmtp("0-16")];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].codec.fmtp.as_deref(), Some("0-16"));

        let audio = answer.audio_media().unwrap();
        let fmtp = audio
            .attributes
            .iter()
            .find(|attr| attr.name == "fmtp")
            .and_then(|attr| attr.value.as_ref())
            .unwrap();
        assert_eq!(fmtp, "101 0-16");
    }

    #[test]
    fn test_no_matching_codec() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()]; // We only support PCMU

        let result = create_answer(&offer, &local_codecs, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_answer_stereo_attributes() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::new(96, "opus", 48000).with_channels(2)];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].codec.channels, 2);

        let audio = answer.audio_media().unwrap();
        let rtpmap = audio
            .attributes
            .iter()
            .find(|attr| attr.name == "rtpmap")
            .and_then(|attr| attr.value.as_ref())
            .unwrap();
        assert!(rtpmap.ends_with("/2"));
    }

    #[test]
    fn test_process_answer() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "PCMA");
        assert_eq!(negotiated[0].codec.payload_type, 8);
        assert_eq!(negotiated[0].remote_port, 6000);
    }

    #[test]
    fn test_process_answer_media_level_connection() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 0
c=IN IP4 10.0.0.10
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].remote_addr.as_deref(), Some("10.0.0.10"));
    }

    #[test]
    fn test_process_answer_static_payload() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 0
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "PCMU");
        assert_eq!(negotiated[0].codec.payload_type, 0);
    }

    #[test]
    fn test_process_answer_rejected_media() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 0 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_process_answer_non_audio_ignored() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=video 6000 RTP/AVP 96
a=rtpmap:96 H264/90000
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_process_answer_invalid_format() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP abc
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_direction_swap() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendonly
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();

        // sendonly offer -> recvonly answer
        assert_eq!(negotiated[0].direction, Direction::RecvOnly);

        let audio = answer.audio_media().unwrap();
        assert_eq!(audio.direction(), Direction::RecvOnly);
    }

    // Codec tests
    #[test]
    fn test_codec_new() {
        let codec = Codec::new(96, "opus", 48000);
        assert_eq!(codec.payload_type, 96);
        assert_eq!(codec.encoding, "opus");
        assert_eq!(codec.clock_rate, 48000);
        assert_eq!(codec.channels, 1);
        assert!(codec.fmtp.is_none());
    }

    #[test]
    fn test_codec_with_channels() {
        let codec = Codec::new(96, "opus", 48000).with_channels(2);
        assert_eq!(codec.channels, 2);
    }

    #[test]
    fn test_codec_with_fmtp() {
        let codec = Codec::new(101, "telephone-event", 8000).with_fmtp("0-16");
        assert_eq!(codec.fmtp, Some("0-16".to_string()));
    }

    #[test]
    fn test_codec_pcmu() {
        let codec = Codec::pcmu();
        assert_eq!(codec.payload_type, 0);
        assert_eq!(codec.encoding, "PCMU");
        assert_eq!(codec.clock_rate, 8000);
    }

    #[test]
    fn test_codec_pcma() {
        let codec = Codec::pcma();
        assert_eq!(codec.payload_type, 8);
        assert_eq!(codec.encoding, "PCMA");
        assert_eq!(codec.clock_rate, 8000);
    }

    #[test]
    fn test_codec_g722() {
        let codec = Codec::g722();
        assert_eq!(codec.payload_type, 9);
        assert_eq!(codec.encoding, "G722");
        assert_eq!(codec.clock_rate, 8000);
    }

    #[test]
    fn test_codec_matches_case_insensitive() {
        let codec = Codec::new(0, "pcmu", 8000);
        let rtpmap = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 8000,
            params: None,
        };
        assert!(codec.matches(&rtpmap));
    }

    #[test]
    fn test_codec_no_match_clock_rate() {
        let codec = Codec::new(0, "PCMU", 8000);
        let rtpmap = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 16000,
            params: None,
        };
        assert!(!codec.matches(&rtpmap));
    }

    #[test]
    fn test_codec_no_match_encoding() {
        let codec = Codec::new(0, "PCMU", 8000);
        let rtpmap = RtpMap {
            payload_type: 0,
            encoding: "PCMA".to_string(),
            clock_rate: 8000,
            params: None,
        };
        assert!(!codec.matches(&rtpmap));
    }

    #[test]
    fn test_codec_debug() {
        let codec = Codec::pcmu();
        let debug = format!("{:?}", codec);
        assert!(debug.contains("Codec"));
        assert!(debug.contains("PCMU"));
    }

    #[test]
    fn test_codec_clone() {
        let codec = Codec::pcmu();
        let cloned = codec.clone();
        assert_eq!(codec, cloned);
    }

    #[test]
    fn test_codec_eq() {
        let c1 = Codec::pcmu();
        let c2 = Codec::pcmu();
        let c3 = Codec::pcma();
        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    // NegotiatedMedia tests
    #[test]
    fn test_negotiated_media_debug() {
        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 5000,
            remote_addr: Some("10.0.0.1".to_string()),
            direction: Direction::SendRecv,
        };
        let debug = format!("{:?}", media);
        assert!(debug.contains("NegotiatedMedia"));
    }

    #[test]
    fn test_negotiated_media_clone() {
        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 5000,
            remote_addr: Some("10.0.0.1".to_string()),
            direction: Direction::SendRecv,
        };
        let cloned = media.clone();
        assert_eq!(cloned.remote_port, 5000);
    }

    // Direction swap tests
    #[test]
    fn test_direction_recvonly_to_sendonly() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=recvonly
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].direction, Direction::SendOnly);
    }

    #[test]
    fn test_direction_inactive() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=inactive
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].direction, Direction::Inactive);
    }

    // Video media rejection test
    #[test]
    fn test_video_media_rejected() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=video 49170 RTP/AVP 96
a=rtpmap:96 H264/90000
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let result = create_answer(&offer, &local_codecs, 5000);
        assert!(result.is_none());
    }

    // Static payload type matching
    #[test]
    fn test_static_pcma_without_rtpmap() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 8
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcma()];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].codec.encoding, "PCMA");
        assert_eq!(negotiated[0].codec.payload_type, 8);
    }

    #[test]
    fn test_static_g722_without_rtpmap() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 9
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::g722()];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].codec.encoding, "G722");
    }

    #[test]
    fn test_static_payload_no_local_match() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcma()];

        let result = create_answer(&offer, &local_codecs, 5000);
        assert!(result.is_none());
    }

    // Media-level connection address
    #[test]
    fn test_media_level_connection() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
t=0 0
m=audio 49170 RTP/AVP 0
c=IN IP4 10.0.0.100
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated[0].remote_addr, Some("10.0.0.100".to_string()));
    }

    // Multi-codec matching with fmtp
    #[test]
    fn test_codec_with_fmtp_negotiation() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        // Codec with fmtp set
        let local_codecs = vec![Codec::pcmu().with_fmtp("ptime=20")];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        // The negotiated codec should have the fmtp from local codec
        assert_eq!(negotiated[0].codec.fmtp, Some("ptime=20".to_string()));
    }

    // process_answer edge cases
    #[test]
    fn test_process_answer_with_channels() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 96
a=rtpmap:96 opus/48000/2
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "opus");
        assert_eq!(negotiated[0].codec.channels, 2);
    }

    #[test]
    fn test_process_answer_static_pt() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 0
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "PCMU");
        assert_eq!(negotiated[0].codec.payload_type, 0);
    }

    #[test]
    fn test_process_answer_static_pcma() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 8
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "PCMA");
        assert_eq!(negotiated[0].codec.payload_type, 8);
    }

    #[test]
    fn test_process_answer_static_g722() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 9
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        assert_eq!(negotiated.len(), 1);
        assert_eq!(negotiated[0].codec.encoding, "G722");
        assert_eq!(negotiated[0].codec.payload_type, 9);
    }

    #[test]
    fn test_process_answer_video_rejected() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        // Video should be ignored
        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_process_answer_audio_rejected() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 0 RTP/AVP 0
a=rtpmap:0 PCMU/8000
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        // Port 0 means rejected
        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_process_answer_no_rtpmap() {
        let answer_sdp = r#"v=0
o=- 123 1 IN IP4 10.0.0.1
s=-
c=IN IP4 10.0.0.1
t=0 0
m=audio 6000 RTP/AVP 100
a=sendrecv
"#;
        let answer = SessionDescription::parse(answer_sdp).unwrap();
        let negotiated = process_answer(&answer);

        // No rtpmap and not a static PT - should be empty
        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_process_answer_empty_formats() {
        let answer = SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: "123".to_string(),
                session_version: "1".to_string(),
                net_type: "IN".to_string(),
                addr_type: "IP4".to_string(),
                unicast_address: "10.0.0.1".to_string(),
            },
            session_name: "-".to_string(),
            session_info: None,
            connection: Some(Connection {
                net_type: "IN".to_string(),
                addr_type: "IP4".to_string(),
                address: "10.0.0.1".to_string(),
            }),
            timing: Timing { start: 0, stop: 0 },
            media: vec![MediaDescription {
                media_type: MediaType::Audio,
                port: 6000,
                num_ports: None,
                protocol: "RTP/AVP".to_string(),
                formats: Vec::new(),
                connection: None,
                bandwidth: HashMap::new(),
                attributes: Vec::new(),
            }],
            attributes: Vec::new(),
        };

        let negotiated = process_answer(&answer);
        assert!(negotiated.is_empty());
    }

    #[test]
    fn test_multiple_media_streams() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
m=audio 49172 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu(), Codec::pcma()];

        let (_answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        // Both audio streams should be negotiated
        assert_eq!(negotiated.len(), 2);
    }

    // rtcp-mux + ICE negotiation
    #[test]
    fn test_create_answer_ice_with_rtcp_mux_accepted() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
a=ice-ufrag:abcd1234
a=ice-pwd:0123456789abcdef01234567
a=candidate:host1 1 UDP 2130706431 192.168.1.1 49170 typ host
a=rtcp-mux
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated.len(), 1);

        let audio = answer.audio_media().unwrap();
        assert_eq!(audio.port, 5000);
        // rtcp-mux must be mirrored on the answer.
        assert!(audio.attributes.iter().any(|a| a.name == "rtcp-mux"));
    }

    #[test]
    fn test_create_answer_ice_without_rtcp_mux_rejected() {
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
a=ice-ufrag:abcd1234
a=ice-pwd:0123456789abcdef01234567
a=candidate:host1 1 UDP 2130706431 192.168.1.1 49170 typ host
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        // ICE offer without rtcp-mux must reject the media. Single media
        // line means create_answer returns None overall.
        let result = create_answer(&offer, &local_codecs, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn test_create_answer_non_ice_without_rtcp_mux_accepted() {
        // Regression: non-ICE media without rtcp-mux must still negotiate.
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated.len(), 1);

        let audio = answer.audio_media().unwrap();
        // No rtcp-mux on the answer because there was none on the offer.
        assert!(!audio.attributes.iter().any(|a| a.name == "rtcp-mux"));
    }

    #[test]
    fn test_create_answer_non_ice_with_rtcp_mux_accepted_and_mirrored() {
        // WebRTC-style: a=rtcp-mux with no ICE attrs. Must classify as
        // non-ICE (no candidates ⇒ no ICE-without-mux rejection path),
        // negotiate normally, and mirror rtcp-mux on the answer.
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
a=rtcp-mux
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        assert_eq!(negotiated.len(), 1);

        let audio = answer.audio_media().unwrap();
        // Port negotiated normally — not 0.
        assert_eq!(audio.port, 5000);
        // rtcp-mux mirrored from offer.
        assert!(audio.attributes.iter().any(|a| a.name == "rtcp-mux"));
        // No ICE attrs leaked onto the answer.
        assert!(!audio.attributes.iter().any(|a| a.name == "ice-ufrag"));
        assert!(!audio.attributes.iter().any(|a| a.name == "ice-pwd"));
        assert!(!audio.attributes.iter().any(|a| a.name == "candidate"));
    }

    #[test]
    fn test_create_answer_mixed_ice_with_and_without_mux() {
        // Two audio m-lines: first ICE+mux (accept), second ICE without
        // mux (reject). The rejected line must carry no ICE attrs.
        let offer_sdp = r#"v=0
o=- 123 1 IN IP4 192.168.1.1
s=-
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
a=ice-ufrag:firstuf
a=ice-pwd:firstpwdsecretvalue1234
a=candidate:host1 1 UDP 2130706431 192.168.1.1 49170 typ host
a=rtcp-mux
m=audio 49180 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
a=ice-ufrag:secondu
a=ice-pwd:secondpwdsecretvalue234
a=candidate:host2 1 UDP 2130706431 192.168.1.1 49180 typ host
"#;
        let offer = SessionDescription::parse(offer_sdp).unwrap();
        let local_codecs = vec![Codec::pcmu()];

        let (answer, negotiated) = create_answer(&offer, &local_codecs, 5000).unwrap();
        // Only the first line negotiated.
        assert_eq!(negotiated.len(), 1);
        assert_eq!(answer.media.len(), 2);

        // First line: accepted, port set, rtcp-mux mirrored.
        assert_eq!(answer.media[0].port, 5000);
        assert!(answer.media[0]
            .attributes
            .iter()
            .any(|a| a.name == "rtcp-mux"));

        // Second line: rejected (port 0) and ICE attrs from the offer
        // must not leak onto the answer's dead m=.
        assert_eq!(answer.media[1].port, 0);
        assert!(!answer.media[1]
            .attributes
            .iter()
            .any(|a| a.name == "ice-ufrag"));
        assert!(!answer.media[1]
            .attributes
            .iter()
            .any(|a| a.name == "ice-pwd"));
        assert!(!answer.media[1]
            .attributes
            .iter()
            .any(|a| a.name == "candidate"));
    }
}
