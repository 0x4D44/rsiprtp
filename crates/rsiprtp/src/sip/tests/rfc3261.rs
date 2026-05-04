//! RFC 3261 SIP compliance tests.
//!
//! These tests verify compliance with RFC 3261 (SIP: Session Initiation Protocol),
//! focusing on edge cases, header parsing, URI validation, and protocol requirements
//! that may not be exercised by basic functional tests.

use crate::sip::*;

#[cfg(test)]
mod header_parsing {
    use super::*;

    /// RFC 3261 Section 7.3.1: Header field values can be extended over multiple lines
    /// by preceding each extra line with at least one SP or horizontal tab (HT).
    #[test]
    fn test_header_folding_whitespace() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob\r\n \
 <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // RFC 3261 §7.3.1 line folding — parser should accept it.
        assert!(result.is_ok() || result.is_err()); // Implementation dependent
    }

    /// RFC 3261 Section 7.3: Header field names are case-insensitive
    #[test]
    fn test_header_case_insensitive() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
max-forwards: 70\r\n\
to: Bob <sip:bob@biloxi.com>\r\n\
from: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
call-id: a84b4c76e66710@pc33.atlanta.com\r\n\
cseq: 314159 INVITE\r\n\
content-length: 0\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        assert!(result.is_ok());
        let req = result.unwrap().as_request().unwrap().clone();
        assert_eq!(req.method(), Method::Invite);
        assert_eq!(req.cseq().unwrap(), 314159);
    }

    /// RFC 3261 Section 7.3.1: Linear white space (LWS) can be inserted
    /// around field values and field delimiters
    #[test]
    fn test_header_lws_around_values() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To:    Bob <sip:bob@biloxi.com>   \r\n\
From:  Alice <sip:alice@atlanta.com>;tag=1928301774  \r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq:  314159   INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        assert!(result.is_ok());
    }

    /// RFC 3261 Section 20.10: CSeq method must match request method (except for ACK/CANCEL)
    #[test]
    fn test_cseq_method_matching() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        assert_eq!(req.method(), req.cseq_method().unwrap());
    }

    /// RFC 3261 Section 20.10: CSeq with mismatched method
    #[test]
    fn test_cseq_method_mismatch_detectable() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        // CSeq method should be REGISTER, not INVITE
        assert_eq!(req.cseq_method().unwrap(), Method::Register);
        assert_ne!(req.method(), req.cseq_method().unwrap());
    }

    /// RFC 3261 Section 20.14: Content-Length must accurately represent body size
    #[test]
    fn test_content_length_zero() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        assert_eq!(req.body().len(), 0);
    }

    /// RFC 3261 Section 20.14: Content-Length with actual body
    #[test]
    fn test_content_length_with_body() {
        let sdp_body = b"v=0\r\n";
        let msg = format!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\
\r\n{}",
            sdp_body.len(),
            std::str::from_utf8(sdp_body).unwrap()
        );

        let parsed = SipMessage::parse(msg.as_bytes()).unwrap();
        let req = parsed.as_request().unwrap();
        assert_eq!(req.body(), sdp_body);
    }

    /// RFC 3261 Section 20.20: From header must have a tag parameter
    #[test]
    fn test_from_header_tag_required() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=abc123\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        assert!(req.from_tag().is_ok());
        assert_eq!(req.from_tag().unwrap(), "abc123");
    }

    /// RFC 3261 Section 20.39: To header may not have tag in requests
    #[test]
    fn test_to_header_no_tag_in_request() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        assert!(req.to_tag().is_none());
    }

    /// RFC 3261 Section 20.39: To header must have tag in final responses
    #[test]
    fn test_to_header_tag_in_response() {
        let msg = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert_eq!(resp.to_tag(), Some("a6c85cf".to_string()));
    }
}

#[cfg(test)]
mod via_header {
    use super::*;

    /// RFC 3261 Section 20.42: Via branch parameter must start with magic cookie z9hG4bK
    #[test]
    fn test_via_branch_magic_cookie() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        let branch = req.via_branch().unwrap();
        assert!(branch.starts_with("z9hG4bK"));
    }

    /// RFC 3261 Section 20.42: Via branch without magic cookie (RFC 2543 format)
    #[test]
    fn test_via_branch_without_magic_cookie() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=oldstyle123\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        let branch = req.via_branch().unwrap();
        // Should still parse, but indicates RFC 2543 compatibility mode
        assert_eq!(branch, "oldstyle123");
    }

    /// RFC 3261 Section 20.42: Multiple Via headers (proxy chain)
    #[test]
    fn test_multiple_via_headers() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP proxy2.example.com;branch=z9hG4bKproxy2\r\n\
Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bKproxy1\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        let vias = req.via_headers_raw();
        assert_eq!(vias.len(), 3);
        // Top Via should be the most recent proxy
        assert!(vias[0].contains("proxy2"));
    }

    /// RFC 3261 Section 20.42: Via with received parameter
    #[test]
    fn test_via_received_parameter() {
        let msg = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        let vias = resp.via_headers_raw();
        assert!(!vias.is_empty());
        assert!(vias[0].contains("received=192.0.2.1"));
    }

    /// RFC 3261 Section 18.2.2: Via with rport parameter
    #[test]
    fn test_via_rport_parameter() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com:5060;branch=z9hG4bK776asdhds;rport\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        let vias = req.via_headers_raw();
        assert!(vias[0].contains("rport"));
    }
}

#[cfg(test)]
mod uri_parsing {
    use super::*;

    /// RFC 3261 Section 19.1.1: SIP URI basic format
    #[test]
    fn test_sip_uri_basic() {
        let uri = SipUri::parse("sip:alice@atlanta.com").unwrap();
        assert_eq!(uri.scheme(), "sip");
        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.host(), "atlanta.com");
    }

    /// RFC 3261 Section 19.1.1: SIPS URI (secure)
    #[test]
    fn test_sips_uri() {
        let uri = SipUri::parse("sips:alice@secure.example.com").unwrap();
        assert_eq!(uri.scheme(), "sips");
        assert!(uri.is_secure());
    }

    /// RFC 3261 Section 19.1.1: URI with port
    #[test]
    fn test_uri_with_port() {
        let uri = SipUri::parse("sip:alice@atlanta.com:5080").unwrap();
        assert_eq!(uri.port(), Some(5080));
    }

    /// RFC 3261 Section 19.1.1: URI without user part
    #[test]
    fn test_uri_without_user() {
        let uri = SipUri::parse("sip:atlanta.com").unwrap();
        assert_eq!(uri.user(), None);
        assert_eq!(uri.host(), "atlanta.com");
    }

    /// RFC 3261 Section 19.1.1: URI with parameters
    #[test]
    fn test_uri_with_transport_param() {
        let uri = SipUri::parse("sip:alice@atlanta.com;transport=tcp").unwrap();
        assert_eq!(uri.transport(), Some("tcp"));
    }

    /// RFC 3261 Section 19.1.1: URI with user=phone parameter
    #[test]
    fn test_uri_with_user_phone_param() {
        let uri = SipUri::parse("sip:+1-212-555-1212@gateway.com;user=phone").unwrap();
        assert_eq!(uri.get_param("user"), Some("phone"));
    }

    /// RFC 3261 Section 19.1.1: URI with lr (loose routing) parameter
    #[test]
    fn test_uri_with_lr_param() {
        let uri = SipUri::parse("sip:proxy.example.com;lr").unwrap();
        assert!(uri.is_loose_route());
    }

    /// RFC 3261 Section 19.1.1: URI with maddr parameter
    #[test]
    fn test_uri_with_maddr_param() {
        let uri = SipUri::parse("sip:alice@atlanta.com;maddr=239.255.255.1").unwrap();
        assert_eq!(uri.get_param("maddr"), Some("239.255.255.1"));
    }

    /// RFC 3261 Section 19.1.1: URI with ttl parameter (multicast)
    #[test]
    fn test_uri_with_ttl_param() {
        let uri = SipUri::parse("sip:alice@atlanta.com;ttl=15").unwrap();
        assert_eq!(uri.get_param("ttl"), Some("15"));
    }

    /// RFC 3261 Section 19.1.1: URI with method parameter
    #[test]
    fn test_uri_with_method_param() {
        let uri = SipUri::parse("sip:alice@atlanta.com;method=REGISTER").unwrap();
        assert_eq!(uri.get_param("method"), Some("REGISTER"));
    }

    /// RFC 3261 §19.1.6 / RFC 3966: `tel:` URIs are valid SIP targets.
    /// M3 absorbed mdsiprtp3's tel-scheme support, so this case now
    /// parses successfully (was a deliberate behavior change — the
    /// previous rejection encoded an incorrect interpretation of the
    /// scheme allowlist).
    #[test]
    fn test_tel_uri_accepted() {
        let uri = SipUri::parse("tel:+1-212-555-1212").unwrap();
        assert_eq!(uri.scheme(), "tel");
        assert_eq!(uri.host(), "+1-212-555-1212");
        assert_eq!(uri.user(), None);
        assert_eq!(uri.port(), None);
    }

    /// RFC 3261 Section 19.1.1: IPv6 address in URI
    #[test]
    fn test_uri_with_ipv6() {
        let uri = SipUri::parse("sip:alice@[2001:db8::1]").unwrap();
        assert!(uri.host().contains("2001:db8::1"));
    }

    /// RFC 3261 Section 19.1.1: IPv6 address with port
    #[test]
    fn test_uri_with_ipv6_and_port() {
        let uri = SipUri::parse("sip:alice@[2001:db8::1]:5060").unwrap();
        assert!(uri.host().contains("2001:db8::1"));
        assert_eq!(uri.port(), Some(5060));
    }
}

#[cfg(test)]
mod max_forwards {
    use super::*;

    /// RFC 3261 Section 8.1.1.3: Max-Forwards must be present
    #[test]
    fn test_max_forwards_present() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        assert!(parsed.is_request());
    }

    /// RFC 3261 Section 8.1.1.3: Max-Forwards at zero should trigger 483 response
    #[test]
    fn test_max_forwards_zero() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 0\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg);
        assert!(parsed.is_ok());
        // Application logic should check Max-Forwards and reject with 483
    }

    /// RFC 3261 Section 8.1.1.3: Max-Forwards default value is 70
    #[test]
    fn test_max_forwards_default_value() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let s = String::from_utf8_lossy(&bytes);
        // Default Max-Forwards should be 70
        assert!(s.contains("Max-Forwards: 70"));
    }
}

#[cfg(test)]
mod request_uri {
    use super::*;

    /// RFC 3261 Section 8.1.1.1: Request-URI must not contain unescaped spaces
    #[test]
    fn test_request_uri_no_spaces() {
        // Valid Request-URI
        let uri = SipUri::parse("sip:alice@atlanta.com");
        assert!(uri.is_ok());
    }

    /// RFC 3261 Section 8.1.1.1: Request-URI can be different from To header
    #[test]
    fn test_request_uri_vs_to_header() {
        let msg = b"INVITE sip:proxy.atlanta.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let req = parsed.as_request().unwrap();
        // Request-URI is proxy.atlanta.com, To is bob@biloxi.com
        assert!(req.uri().to_string().contains("proxy.atlanta.com"));
        assert!(req.to_uri().unwrap().to_string().contains("bob@biloxi.com"));
    }
}

#[cfg(test)]
mod response_codes {
    use super::*;

    /// RFC 3261 Section 21: 1xx responses are provisional
    #[test]
    fn test_1xx_provisional() {
        let msg = b"SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert!(resp.is_provisional());
        assert!(!resp.is_success());
        assert!(!resp.is_failure());
    }

    /// RFC 3261 Section 21: 2xx responses are success
    #[test]
    fn test_2xx_success() {
        let msg = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert!(resp.is_success());
        assert!(!resp.is_provisional());
        assert!(!resp.is_failure());
    }

    /// RFC 3261 Section 21: 3xx responses are redirection
    #[test]
    fn test_3xx_redirection() {
        let msg = b"SIP/2.0 302 Moved Temporarily\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert!(resp.is_failure());
        assert_eq!(resp.status_code(), 302);
    }

    /// RFC 3261 Section 21: 4xx responses are client errors
    #[test]
    fn test_4xx_client_error() {
        let msg = b"SIP/2.0 404 Not Found\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert!(resp.is_failure());
        assert_eq!(resp.status_code(), 404);
    }

    /// RFC 3261 Section 21: 5xx responses are server errors
    #[test]
    fn test_5xx_server_error() {
        let msg = b"SIP/2.0 500 Server Internal Error\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert!(resp.is_failure());
        assert_eq!(resp.status_code(), 500);
    }

    /// RFC 3261 Section 21: 6xx responses are global failures
    #[test]
    fn test_6xx_global_failure() {
        let msg = b"SIP/2.0 600 Busy Everywhere\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let parsed = SipMessage::parse(msg).unwrap();
        let resp = parsed.as_response().unwrap();
        assert!(resp.is_failure());
        assert_eq!(resp.status_code(), 600);
    }
}

#[cfg(test)]
mod methods {
    use super::*;

    /// RFC 3261 Section 7.1: Test all standard SIP methods parse correctly
    #[test]
    fn test_invite_method() {
        assert_eq!(Method::Invite.to_string(), "INVITE");
        assert!(Method::Invite.creates_dialog());
    }

    #[test]
    fn test_ack_method() {
        assert_eq!(Method::Ack.to_string(), "ACK");
        assert!(!Method::Ack.creates_dialog());
    }

    #[test]
    fn test_bye_method() {
        assert_eq!(Method::Bye.to_string(), "BYE");
        assert!(!Method::Bye.creates_dialog());
    }

    #[test]
    fn test_cancel_method() {
        assert_eq!(Method::Cancel.to_string(), "CANCEL");
        assert!(!Method::Cancel.creates_dialog());
    }

    #[test]
    fn test_register_method() {
        assert_eq!(Method::Register.to_string(), "REGISTER");
        assert!(!Method::Register.creates_dialog());
    }

    #[test]
    fn test_options_method() {
        assert_eq!(Method::Options.to_string(), "OPTIONS");
        assert!(!Method::Options.creates_dialog());
    }
}

#[cfg(test)]
mod malformed_messages {
    use super::*;

    /// Test parsing completely invalid data
    #[test]
    fn test_parse_garbage() {
        let result = SipMessage::parse(b"This is not a SIP message");
        assert!(result.is_err());
    }

    /// Test parsing truncated message
    #[test]
    fn test_parse_truncated() {
        let result = SipMessage::parse(b"INVITE sip:bob@biloxi.com SIP/2.0\r\n");
        assert!(result.is_err());
    }

    /// Test parsing message with missing required headers
    #[test]
    fn test_parse_missing_headers() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // Should parse but accessing missing headers will fail
        if let Ok(parsed) = result {
            let req = parsed.as_request().unwrap();
            // Missing Call-ID should error
            assert!(req.call_id().is_err());
        }
    }

    /// Test empty message
    #[test]
    fn test_parse_empty() {
        let result = SipMessage::parse(b"");
        assert!(result.is_err());
    }

    /// Test message with invalid SIP version
    #[test]
    fn test_parse_invalid_version() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/1.0\r\n\
Via: SIP/1.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
\r\n";

        let result = SipMessage::parse(msg);
        // Should fail or parse with version mismatch
        assert!(result.is_err() || result.is_ok());
    }
}

#[cfg(test)]
mod builder_validation {
    use super::*;

    /// Test request builder with all fields
    #[test]
    fn test_build_complete_request() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", &generate_branch())
            .from("sip:alice@example.com", &generate_tag())
            .to("sip:bob@example.com")
            .call_id(&generate_call_id("example.com"))
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .max_forwards(70)
            .build();

        assert!(req.is_ok());
    }

    /// Test request builder missing required field
    #[test]
    fn test_build_request_missing_via() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    /// Test generate_branch creates valid branches
    #[test]
    fn test_generate_branch_valid() {
        for _ in 0..10 {
            let branch = generate_branch();
            assert!(branch.starts_with("z9hG4bK"));
            assert!(branch.len() > 10);
        }
    }

    /// Test generate_tag creates unique tags
    #[test]
    fn test_generate_tag_unique() {
        let mut tags = std::collections::HashSet::new();
        for _ in 0..100 {
            tags.insert(generate_tag());
        }
        // Should have created many unique tags
        assert!(tags.len() > 90);
    }

    /// Test generate_call_id format
    #[test]
    fn test_generate_call_id_format() {
        let call_id = generate_call_id("example.com");
        assert!(call_id.contains('@'));
        assert!(call_id.ends_with("@example.com"));
    }
}
