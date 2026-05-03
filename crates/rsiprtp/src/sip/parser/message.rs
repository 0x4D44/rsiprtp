//! SIP request/response value types and parser entry points.
//!
//! Note: this is `crate::sip::parser::message`, distinct from the
//! wrapper layer `crate::sip::message`. The wrapper layer (M8 owns
//! its cutover) currently builds on rsip; this module is the
//! rsip-independent replacement.

use super::framing::{parse_header_block, parse_request_line, parse_status_line, split_message};
use super::header::{Header, Headers};
use super::method::Method;
use super::status::StatusCode;
use crate::core::SipError;

/// SIP request: method + Request-URI + version + headers + body.
///
/// Fields are public — this module is `pub(crate)` and the typed
/// accessors live in the outer wrapper layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// SIP method (e.g. `INVITE`, `BYE`).
    pub method: Method,
    /// Raw Request-URI string. Typed URI parsing lives in M3.
    pub uri: String,
    /// Version token from the request line, e.g. `"SIP/2.0"`.
    pub version: String,
    /// Headers in wire-order.
    pub headers: Headers,
    /// Message body as raw octets.
    pub body: Vec<u8>,
}

impl Request {
    /// Parse a complete SIP request from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, SipError> {
        let (start_line, header_block, body) = split_message(data)?;
        let (method, uri, version) = parse_request_line(start_line)?;
        let headers = parse_header_block(header_block)?;
        let body = trim_body(&headers, body);
        Ok(Request {
            method,
            uri,
            version,
            headers,
            body,
        })
    }

    /// Serialize to canonical wire format: long header names, single
    /// space after the colon, `\r\n` line endings, blank line before
    /// the body.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.uri.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_bytes());
        out.extend_from_slice(b"\r\n");
        write_headers(&mut out, &self.headers, self.body.len());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// SIP response: version + status + reason + headers + body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Version token from the status line, e.g. `"SIP/2.0"`.
    pub version: String,
    /// Numeric status code.
    pub status_code: StatusCode,
    /// Reason phrase as parsed off the wire.
    pub reason: String,
    /// Headers in wire-order.
    pub headers: Headers,
    /// Message body as raw octets.
    pub body: Vec<u8>,
}

impl Response {
    /// Parse a complete SIP response from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, SipError> {
        let (start_line, header_block, body) = split_message(data)?;
        let (version, status_code, reason) = parse_status_line(start_line)?;
        let headers = parse_header_block(header_block)?;
        let body = trim_body(&headers, body);
        Ok(Response {
            version,
            status_code,
            reason,
            headers,
            body,
        })
    }

    /// Serialize to canonical wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(self.version.as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status_code.as_u16().to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.reason.as_bytes());
        out.extend_from_slice(b"\r\n");
        write_headers(&mut out, &self.headers, self.body.len());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// SIP message — request or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A SIP request.
    Request(Request),
    /// A SIP response.
    Response(Response),
}

impl Message {
    /// Parse a SIP message of either kind. Dispatches by inspecting
    /// the first line: starts with `SIP/` ⇒ response, else request.
    pub fn parse(data: &[u8]) -> Result<Self, SipError> {
        let first = first_line_bytes(data);
        if first.starts_with(b"SIP/") {
            Response::parse(data).map(Message::Response)
        } else {
            Request::parse(data).map(Message::Request)
        }
    }

    /// Serialize to canonical wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::Request(r) => r.to_bytes(),
            Message::Response(r) => r.to_bytes(),
        }
    }
}

/// Apply Content-Length if present, otherwise return the body
/// verbatim. mdsiprtp3's behavior: if Content-Length is parseable
/// and shorter than the body, truncate. Longer or missing → keep
/// the body as framed.
fn trim_body(headers: &Headers, body: &[u8]) -> Vec<u8> {
    if let Some(v) = headers.get_first_value("Content-Length") {
        if let Ok(n) = v.trim().parse::<usize>() {
            if n <= body.len() {
                return body[..n].to_vec();
            }
        }
    }
    body.to_vec()
}

/// First line as bytes, stopping at the first `\r` or `\n`.
fn first_line_bytes(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    &data[..end]
}

/// Append all headers in canonical form: `Name: value\r\n`. Long
/// names per [`Header::name`].
///
/// If a `Content-Length` header is present, its emitted value is
/// overridden with `body_len` so the wire form always agrees with
/// the body actually being serialized. `self.headers` is not
/// mutated — round-trip-via-struct equality still holds. If
/// `Content-Length` is absent we do NOT add one; that is the
/// caller's responsibility.
fn write_headers(out: &mut Vec<u8>, headers: &Headers, body_len: usize) {
    for h in headers.iter() {
        match h {
            Header::ContentLength(_) => {
                out.extend_from_slice(b"Content-Length: ");
                out.extend_from_slice(body_len.to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            _ => {
                out.extend_from_slice(h.name().as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(h.value().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::header::Header;

    fn invite() -> &'static [u8] {
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
          From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
          To: Bob <sip:bob@example.com>\r\n\
          Call-ID: a84b4c76e66710@pc33.example.com\r\n\
          CSeq: 314159 INVITE\r\n\
          Max-Forwards: 70\r\n\
          Content-Length: 0\r\n\
          \r\n"
    }

    fn ok_200() -> &'static [u8] {
        b"SIP/2.0 200 OK\r\n\
          Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
          From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
          To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
          Call-ID: a84b4c76e66710@pc33.example.com\r\n\
          CSeq: 314159 INVITE\r\n\
          Content-Length: 0\r\n\
          \r\n"
    }

    #[test]
    fn test_request_parse_basic() {
        let req = Request::parse(invite()).unwrap();
        assert_eq!(req.method, Method::Invite);
        assert_eq!(req.uri, "sip:bob@example.com");
        assert_eq!(req.version, "SIP/2.0");
        assert_eq!(req.headers.len(), 7);
        assert_eq!(
            req.headers.get_first_value("Call-ID"),
            Some("a84b4c76e66710@pc33.example.com")
        );
        assert_eq!(req.headers.get_first_value("CSeq"), Some("314159 INVITE"));
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_request_round_trip() {
        let req = Request::parse(invite()).unwrap();
        let bytes = req.to_bytes();
        let req2 = Request::parse(&bytes).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn test_response_parse_basic() {
        let resp = Response::parse(ok_200()).unwrap();
        assert_eq!(resp.version, "SIP/2.0");
        assert_eq!(resp.status_code, StatusCode::OK);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.headers.len(), 6);
    }

    #[test]
    fn test_response_round_trip() {
        let resp = Response::parse(ok_200()).unwrap();
        let bytes = resp.to_bytes();
        let resp2 = Response::parse(&bytes).unwrap();
        assert_eq!(resp, resp2);
    }

    #[test]
    fn test_response_busy_here_round_trip() {
        let raw: &[u8] = b"SIP/2.0 486 Busy Here\r\n\
                          Via: SIP/2.0/UDP h\r\n\
                          \r\n";
        let resp = Response::parse(raw).unwrap();
        assert_eq!(resp.status_code, StatusCode::BUSY_HERE);
        assert_eq!(resp.reason, "Busy Here");
        let resp2 = Response::parse(&resp.to_bytes()).unwrap();
        assert_eq!(resp, resp2);
    }

    #[test]
    fn test_message_parse_dispatches_request() {
        match Message::parse(invite()).unwrap() {
            Message::Request(r) => assert_eq!(r.method, Method::Invite),
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn test_message_parse_dispatches_response() {
        match Message::parse(ok_200()).unwrap() {
            Message::Response(r) => assert_eq!(r.status_code, StatusCode::OK),
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn test_message_round_trip_request() {
        let m = Message::parse(invite()).unwrap();
        let bytes = m.to_bytes();
        let m2 = Message::parse(&bytes).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_message_round_trip_response() {
        let m = Message::parse(ok_200()).unwrap();
        let bytes = m.to_bytes();
        let m2 = Message::parse(&bytes).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn test_body_with_content_length() {
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          Via: SIP/2.0/UDP h\r\n\
                          Content-Length: 4\r\n\
                          \r\n\
                          v=0\n";
        let req = Request::parse(raw).unwrap();
        assert_eq!(req.body, b"v=0\n");
    }

    #[test]
    fn test_body_without_content_length() {
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          Via: SIP/2.0/UDP h\r\n\
                          \r\n\
                          v=0\n";
        let req = Request::parse(raw).unwrap();
        assert_eq!(req.body, b"v=0\n");
    }

    #[test]
    fn test_body_content_length_truncates() {
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          Content-Length: 3\r\n\
                          \r\n\
                          v=0extra";
        let req = Request::parse(raw).unwrap();
        assert_eq!(req.body, b"v=0");
    }

    /// Pragmatic behavior: when `Content-Length` exceeds the actual
    /// number of body bytes available, we keep the partial body
    /// rather than erroring. Real-world UDP truncation and split
    /// receives benefit from this leniency. Pinned by this test so
    /// any future stricter behavior is a deliberate choice.
    #[test]
    fn test_body_content_length_under_run() {
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          Content-Length: 100\r\n\
                          \r\n\
                          v=0";
        let req = Request::parse(raw).unwrap();
        assert_eq!(req.body, b"v=0");
    }

    #[test]
    fn test_canonical_serialization_format() {
        // Headers serialize as `Name: value\r\n` with the long-form
        // canonical name even if parsed from a compact form.
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          v: SIP/2.0/UDP h\r\n\
                          i: abc\r\n\
                          \r\n";
        let req = Request::parse(raw).unwrap();
        let out = String::from_utf8(req.to_bytes()).unwrap();
        assert!(out.contains("Via: SIP/2.0/UDP h\r\n"));
        assert!(out.contains("Call-ID: abc\r\n"));
        assert!(!out.contains("v: "));
        assert!(!out.contains("i: "));
    }

    #[test]
    fn test_request_parse_no_separator_rejects() {
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\nVia: x\r\n";
        let err = Request::parse(raw).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_response_parse_no_separator_rejects() {
        let raw: &[u8] = b"SIP/2.0 200 OK\r\nVia: x\r\n";
        let err = Response::parse(raw).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_to_bytes_rewrites_stale_content_length_under_run() {
        // Body shorter than the header claims: serializer must emit
        // the actual body length, not the stale stored value.
        let mut headers = Headers::new();
        headers
            .push(Header::Via("SIP/2.0/UDP h".to_string()))
            .unwrap();
        headers
            .push(Header::ContentLength("100".to_string()))
            .unwrap();
        let req = Request {
            method: Method::Invite,
            uri: "sip:b@h".to_string(),
            version: "SIP/2.0".to_string(),
            headers,
            body: b"v=0".to_vec(),
        };
        let out = String::from_utf8(req.to_bytes()).unwrap();
        assert!(
            out.contains("Content-Length: 3\r\n"),
            "expected rewritten Content-Length: 3, got {out:?}"
        );
        assert!(!out.contains("Content-Length: 100"));
    }

    #[test]
    fn test_to_bytes_rewrites_stale_content_length_over_run() {
        // Body longer than the header claims: serializer must emit
        // the actual body length, not the stale stored value.
        let mut headers = Headers::new();
        headers
            .push(Header::Via("SIP/2.0/UDP h".to_string()))
            .unwrap();
        headers
            .push(Header::ContentLength("3".to_string()))
            .unwrap();
        let req = Request {
            method: Method::Invite,
            uri: "sip:b@h".to_string(),
            version: "SIP/2.0".to_string(),
            headers,
            body: b"v=0extra".to_vec(),
        };
        let out = String::from_utf8(req.to_bytes()).unwrap();
        assert!(
            out.contains("Content-Length: 8\r\n"),
            "expected rewritten Content-Length: 8, got {out:?}"
        );
    }

    #[test]
    fn test_to_bytes_omits_content_length_when_header_absent() {
        // No Content-Length in headers: serializer must NOT add one.
        let mut headers = Headers::new();
        headers
            .push(Header::Via("SIP/2.0/UDP h".to_string()))
            .unwrap();
        let req = Request {
            method: Method::Invite,
            uri: "sip:b@h".to_string(),
            version: "SIP/2.0".to_string(),
            headers,
            body: b"v=0".to_vec(),
        };
        let out = String::from_utf8(req.to_bytes()).unwrap();
        assert!(
            !out.contains("Content-Length"),
            "should not synthesize Content-Length, got {out:?}"
        );
    }

    #[test]
    fn test_round_trip_with_mismatched_content_length() {
        // Parse a message whose Content-Length over-reports vs the body
        // actually present. After to_bytes() the wire form must agree
        // with the body, and re-parsing must produce a coherent struct.
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          Via: SIP/2.0/UDP h\r\n\
                          Content-Length: 100\r\n\
                          \r\n\
                          v=0";
        let req = Request::parse(raw).unwrap();
        assert_eq!(req.body, b"v=0");
        let out = req.to_bytes();
        let req2 = Request::parse(&out).unwrap();
        assert_eq!(req2.body.len(), 3);
        assert_eq!(
            req2.headers.get_first_value("Content-Length"),
            Some("3"),
            "after round-trip Content-Length must reflect the real body length",
        );
    }

    #[test]
    fn test_request_parse_other_headers_preserved() {
        let raw: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
                          Via: SIP/2.0/UDP h\r\n\
                          User-Agent: rsiprtp/test\r\n\
                          X-Custom: stuff\r\n\
                          \r\n";
        let req = Request::parse(raw).unwrap();
        let names: Vec<String> = req.headers.iter().map(|h| h.name().to_string()).collect();
        assert_eq!(names, vec!["Via", "User-Agent", "X-Custom"]);
        // Unknown long names land in Other.
        match req.headers.get_first("User-Agent").unwrap() {
            Header::Other(n, v) => {
                assert_eq!(n, "User-Agent");
                assert_eq!(v, "rsiprtp/test");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }
}
