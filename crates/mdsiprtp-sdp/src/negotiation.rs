//! SDP offer/answer negotiation per RFC 3264.
//!
//! Implements the offer/answer model for SDP session negotiation.

use crate::parser::{
    Attribute, Direction, MediaDescription, MediaType, RtpMap,
    SessionDescription,
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
            if local_codecs.iter().any(|c| c.matches(&RtpMap {
                payload_type: pt,
                encoding: codec.encoding.clone(),
                clock_rate: codec.clock_rate,
                params: None,
            })) {
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
fn create_media_attributes(codec: &Codec, direction: Direction) -> Vec<Attribute> {
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
pub fn process_answer(
    answer: &SessionDescription,
) -> Vec<NegotiatedMedia> {
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
    use crate::parser::SessionDescription;

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
}
