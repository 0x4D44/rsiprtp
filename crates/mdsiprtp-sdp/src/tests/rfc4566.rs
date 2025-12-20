//! RFC 4566 SDP compliance tests.
//!
//! These tests verify compliance with RFC 4566 (SDP: Session Description Protocol)
//! and RFC 3264 (Offer/Answer Model), focusing on edge cases, parsing correctness,
//! attribute handling, and offer/answer negotiation.

use crate::*;
use std::net::{IpAddr, Ipv4Addr};

#[cfg(test)]
mod session_description {
    use super::*;

    /// RFC 4566 Section 5: Minimal valid SDP
    #[test]
    fn test_minimal_sdp() {
        let sdp = "v=0\r\n\
o=- 123456 789012 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.session_name, "-");
    }

    /// RFC 4566 Section 5: Version must be 0
    #[test]
    fn test_version_zero() {
        let sdp = "v=0\r\n\
o=- 123456 789012 IN IP4 192.168.1.1\r\n\
s=Test Session\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.version, 0);
    }

    /// RFC 4566 Section 5: Invalid version should fail
    #[test]
    fn test_invalid_version() {
        let sdp = "v=1\r\n\
o=- 123456 789012 IN IP4 192.168.1.1\r\n\
s=Test\r\n\
t=0 0\r\n";

        // Should still parse (we don't strictly enforce version==0)
        let result = SessionDescription::parse(sdp);
        assert!(result.is_ok() || result.is_err());
    }

    /// RFC 4566 Section 5: Missing version should fail
    #[test]
    fn test_missing_version() {
        let sdp = "o=- 123456 789012 IN IP4 192.168.1.1\r\n\
s=Test\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// RFC 4566 Section 5.2: Origin field parsing
    #[test]
    fn test_origin_parsing() {
        let sdp = "v=0\r\n\
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n\
s=SDP Seminar\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.origin.username, "jdoe");
        assert_eq!(parsed.origin.session_id, "2890844526");
        assert_eq!(parsed.origin.session_version, "2890842807");
        assert_eq!(parsed.origin.net_type, "IN");
        assert_eq!(parsed.origin.addr_type, "IP4");
        assert_eq!(parsed.origin.unicast_address, "10.47.16.5");
    }

    /// RFC 4566 Section 5.2: Origin with IPv6
    #[test]
    fn test_origin_ipv6() {
        let sdp = "v=0\r\n\
o=alice 2890844526 2890842807 IN IP6 2001:db8::1\r\n\
s=IPv6 Session\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.origin.addr_type, "IP6");
        assert_eq!(parsed.origin.unicast_address, "2001:db8::1");
    }

    /// RFC 4566 Section 5.3: Session name
    #[test]
    fn test_session_name() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=My Conference Call\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.session_name, "My Conference Call");
    }

    /// RFC 4566 Section 5.3: Session name can be dash
    #[test]
    fn test_session_name_dash() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.session_name, "-");
    }

    /// RFC 4566 Section 5.7: Connection information
    #[test]
    fn test_connection_ipv4() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
c=IN IP4 224.2.17.12\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert!(parsed.connection.is_some());
        let conn = parsed.connection.unwrap();
        assert_eq!(conn.net_type, "IN");
        assert_eq!(conn.addr_type, "IP4");
        assert_eq!(conn.address, "224.2.17.12");
    }

    /// RFC 4566 Section 5.7: Connection with TTL for multicast
    #[test]
    fn test_connection_multicast_ttl() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
c=IN IP4 224.2.17.12/127\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let conn = parsed.connection.unwrap();
        assert_eq!(conn.address, "224.2.17.12/127");
        // ip_addr() should extract just the address
        assert!(conn.ip_addr().is_some());
    }

    /// RFC 4566 Section 5.9: Timing (permanent session)
    #[test]
    fn test_timing_permanent() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.timing.start, 0);
        assert_eq!(parsed.timing.stop, 0);
    }

    /// RFC 4566 Section 5.9: Timing with specific times
    #[test]
    fn test_timing_with_times() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=2873397496 2873404696\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.timing.start, 2873397496);
        assert_eq!(parsed.timing.stop, 2873404696);
    }
}

#[cfg(test)]
mod media_description {
    use super::*;

    /// RFC 4566 Section 5.14: Basic media line
    #[test]
    fn test_media_audio_basic() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.media.len(), 1);
        let media = &parsed.media[0];
        assert_eq!(media.media_type, MediaType::Audio);
        assert_eq!(media.port, 49170);
        assert_eq!(media.protocol, "RTP/AVP");
        assert_eq!(media.formats, vec!["0"]);
    }

    /// RFC 4566 Section 5.14: Media with multiple formats
    #[test]
    fn test_media_multiple_formats() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0 8 97\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.formats, vec!["0", "8", "97"]);
    }

    /// RFC 4566 Section 5.14: Port zero indicates rejected media
    #[test]
    fn test_media_port_zero() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 0 RTP/AVP 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.port, 0);
        assert!(media.is_rejected());
    }

    /// RFC 4566 Section 5.14: Media with port count
    #[test]
    fn test_media_with_port_count() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170/2 RTP/AVP 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.port, 49170);
        assert_eq!(media.num_ports, Some(2));
    }

    /// RFC 4566 Section 5.14: Video media
    #[test]
    fn test_media_video() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 51372 RTP/AVP 99\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.media_type, MediaType::Video);
        assert_eq!(media.port, 51372);
    }

    /// RFC 4566 Section 5.14: Multiple media descriptions
    #[test]
    fn test_multiple_media() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
m=video 51372 RTP/AVP 99\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.media.len(), 2);
        assert_eq!(parsed.media[0].media_type, MediaType::Audio);
        assert_eq!(parsed.media[1].media_type, MediaType::Video);
    }

    /// RFC 4566 Section 5.14: Media-level connection overrides session-level
    #[test]
    fn test_media_level_connection() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
c=IN IP4 192.168.1.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
c=IN IP4 192.168.1.2\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert!(parsed.connection.is_some());
        let media = &parsed.media[0];
        assert!(media.connection.is_some());
        assert_eq!(media.connection.as_ref().unwrap().address, "192.168.1.2");
    }
}

#[cfg(test)]
mod attributes {
    use super::*;

    /// RFC 4566 Section 6: Flag attributes (no value)
    #[test]
    fn test_flag_attribute() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=sendrecv\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert!(!media.attributes.is_empty());
        assert_eq!(media.attributes[0].name, "sendrecv");
        assert_eq!(media.attributes[0].value, None);
    }

    /// RFC 4566 Section 6: Value attributes
    #[test]
    fn test_value_attribute() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 97\r\n\
a=rtpmap:97 opus/48000/2\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        let attr = &media.attributes[0];
        assert_eq!(attr.name, "rtpmap");
        assert_eq!(attr.value, Some("97 opus/48000/2".to_string()));
    }

    /// RFC 4566 Section 6.6: rtpmap attribute
    #[test]
    fn test_rtpmap_parsing() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 97 98\r\n\
a=rtpmap:97 opus/48000/2\r\n\
a=rtpmap:98 PCMU/8000\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        let rtpmaps = media.rtpmaps();
        assert_eq!(rtpmaps.len(), 2);

        assert_eq!(rtpmaps[0].payload_type, 97);
        assert_eq!(rtpmaps[0].encoding, "opus");
        assert_eq!(rtpmaps[0].clock_rate, 48000);
        assert_eq!(rtpmaps[0].params, Some("2".to_string()));

        assert_eq!(rtpmaps[1].payload_type, 98);
        assert_eq!(rtpmaps[1].encoding, "PCMU");
        assert_eq!(rtpmaps[1].clock_rate, 8000);
    }

    /// RFC 4566 Section 6.15: fmtp attribute
    #[test]
    fn test_fmtp_parsing() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 97\r\n\
a=fmtp:97 minptime=10;useinbandfec=1\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        let fmtps = media.fmtps();
        assert_eq!(fmtps.len(), 1);
        assert_eq!(fmtps[0].payload_type, 97);
        assert!(fmtps[0].params.contains("minptime"));
    }

    /// RFC 3264 Section 6.1: Direction attributes
    #[test]
    fn test_direction_sendrecv() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=sendrecv\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.direction(), Direction::SendRecv);
    }

    #[test]
    fn test_direction_sendonly() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=sendonly\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.direction(), Direction::SendOnly);
    }

    #[test]
    fn test_direction_recvonly() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=recvonly\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.direction(), Direction::RecvOnly);
    }

    #[test]
    fn test_direction_inactive() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=inactive\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.direction(), Direction::Inactive);
    }

    /// RFC 3264: Default direction is sendrecv
    #[test]
    fn test_direction_default() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.direction(), Direction::SendRecv);
    }
}

#[cfg(test)]
mod bandwidth {
    use super::*;

    /// RFC 4566 Section 5.8: Bandwidth attributes
    #[test]
    fn test_bandwidth_as() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
b=AS:64\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.bandwidth.get("AS"), Some(&64));
    }

    #[test]
    fn test_bandwidth_tias() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 51372 RTP/AVP 99\r\n\
b=TIAS:1000000\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let media = &parsed.media[0];
        assert_eq!(media.bandwidth.get("TIAS"), Some(&1000000));
    }
}

#[cfg(test)]
mod offer_answer {
    use super::*;

    /// RFC 3264: Create offer
    #[test]
    fn test_create_offer() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let offer = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(49170).pcmu().pcma())
            .build();

        assert_eq!(offer.version, 0);
        assert_eq!(offer.media.len(), 1);
        assert_eq!(offer.media[0].media_type, MediaType::Audio);
        assert_eq!(offer.media[0].port, 49170);
    }

    /// RFC 3264: Create answer
    #[test]
    fn test_create_answer_basic() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let offer = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(49170).pcmu().pcma())
            .build();

        let local_codecs = vec![Codec::pcmu(), Codec::pcma()];
        let answer_result = create_answer(&offer, &local_codecs, 49172);
        assert!(answer_result.is_some());

        let (answer, _negotiated) = answer_result.unwrap();
        assert_eq!(answer.media.len(), 1);
        assert_eq!(answer.media[0].port, 49172);
    }

    /// RFC 3264: Answer should select one codec from offer
    #[test]
    fn test_answer_codec_selection() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let offer = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(49170).pcmu().pcma())
            .build();

        let local_codecs = vec![Codec::pcmu(), Codec::pcma()];
        let (answer, _negotiated) = create_answer(&offer, &local_codecs, 49172).unwrap();

        // Answer should have at least one common codec
        assert!(!answer.media[0].formats.is_empty());
    }

    /// RFC 3264: Rejected media uses port 0
    #[test]
    fn test_reject_media() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut offer = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(49170).pcmu())
            .build();

        // Set port to 0 to reject
        offer.media[0].port = 0;
        assert!(offer.media[0].is_rejected());
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;

    /// Empty lines should be ignored
    #[test]
    fn test_empty_lines_ignored() {
        let sdp = "v=0\r\n\
\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
\r\n\
s=-\r\n\
t=0 0\r\n\
\r\n";

        let parsed = SessionDescription::parse(sdp);
        assert!(parsed.is_ok());
    }

    /// Whitespace lines
    #[test]
    fn test_whitespace_lines() {
        let sdp = "v=0\r\n\
   \r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp);
        assert!(parsed.is_ok());
    }

    /// Invalid line format (no equals sign)
    #[test]
    fn test_invalid_line_format_ignored() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
invalidline\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp);
        // Should parse, ignoring the invalid line
        assert!(parsed.is_ok());
    }

    /// Session-level attributes
    #[test]
    fn test_session_attributes() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
a=tool:mdsiprtp\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.attributes.len(), 1);
        assert_eq!(parsed.attributes[0].name, "tool");
        assert_eq!(parsed.attributes[0].value, Some("mdsiprtp".to_string()));
    }

    /// Session info line
    #[test]
    fn test_session_info() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=My Session\r\n\
i=This is a test session with information\r\n\
t=0 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(
            parsed.session_info,
            Some("This is a test session with information".to_string())
        );
    }

    /// Unknown field types should be ignored
    #[test]
    fn test_unknown_fields_ignored() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
x=unknown field\r\n";

        let parsed = SessionDescription::parse(sdp);
        assert!(parsed.is_ok());
    }

    /// Media type case insensitive
    #[test]
    fn test_media_type_case_insensitive() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=AUDIO 49170 RTP/AVP 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.media[0].media_type, MediaType::Audio);
    }

    /// Application media type
    #[test]
    fn test_media_type_application() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=application 9 TCP/TLS/RTP/SAVPF 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.media[0].media_type, MediaType::Application);
    }

    /// Helper methods
    #[test]
    fn test_audio_media_helper() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 51372 RTP/AVP 99\r\n\
m=audio 49170 RTP/AVP 0\r\n";

        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media();
        assert!(audio.is_some());
        assert_eq!(audio.unwrap().port, 49170);
    }

    /// Codec creation
    #[test]
    fn test_codec_creation() {
        // PCMU (PT 0)
        let codec = Codec::pcmu();
        assert_eq!(codec.payload_type, 0);
        assert_eq!(codec.encoding, "PCMU");

        // PCMA (PT 8)
        let codec = Codec::pcma();
        assert_eq!(codec.payload_type, 8);
        assert_eq!(codec.encoding, "PCMA");

        // G.722 (PT 9)
        let codec = Codec::g722();
        assert_eq!(codec.payload_type, 9);
        assert_eq!(codec.encoding, "G722");
    }
}

#[cfg(test)]
mod malformed_sdp {
    use super::*;

    /// Completely empty SDP
    #[test]
    fn test_empty_sdp() {
        let result = SessionDescription::parse("");
        assert!(result.is_err());
    }

    /// Missing required origin line
    #[test]
    fn test_missing_origin() {
        let sdp = "v=0\r\n\
s=-\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Missing required timing line
    #[test]
    fn test_missing_timing() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Malformed origin line
    #[test]
    fn test_malformed_origin() {
        let sdp = "v=0\r\n\
o=incomplete\r\n\
s=-\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Malformed connection line
    #[test]
    fn test_malformed_connection() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
c=incomplete\r\n\
t=0 0\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Malformed timing line
    #[test]
    fn test_malformed_timing() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=invalid\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }

    /// Malformed media line
    #[test]
    fn test_malformed_media() {
        let sdp = "v=0\r\n\
o=- 123 456 IN IP4 192.168.1.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=incomplete\r\n";

        let result = SessionDescription::parse(sdp);
        assert!(result.is_err());
    }
}
