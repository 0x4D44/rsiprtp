//! SIP header recognition (Tier 1 of the two-tier model).
//!
//! Each header line is recognized into one of 19 native typed variants
//! (the set we actually match against today) or `Header::Other` for
//! everything else. Values are kept as raw `String`s — no Tier-2
//! parsing happens here. Typed forms (`From`, `To`, `Via`, `CSeq`,
//! `Contact`) come in M4–M5.
//!
//! The collection is `Vec<Header>`-backed, NOT HashMap. Wire-format
//! round-trip relies on insertion order, and rsip's design (which we
//! mirror) is also `Vec`-based. mdsiprtp3's HashMap is the bug we
//! deliberately fix.

use crate::core::SipError;
use std::borrow::Cow;

/// Maximum number of headers in a single message.
pub const MAX_HEADERS: usize = 256;

/// Maximum length of any single header value (after folding).
pub const MAX_HEADER_VALUE_LEN: usize = 8192;

/// Maximum length of the start line (request or status line).
pub const MAX_START_LINE_LEN: usize = 4096;

/// SIP header — Tier-1 recognition.
///
/// Native variants store the raw header value as `String`. The 26
/// rsip-typed headers we don't currently consume (Accept, Server,
/// User-Agent, etc.) ride through as `Other`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// `Allow:` — RFC 3261 §20.5.
    Allow(String),
    /// `Authorization:` — RFC 3261 §20.7.
    Authorization(String),
    /// `CSeq:` — RFC 3261 §20.16.
    CSeq(String),
    /// `Call-ID:` — RFC 3261 §20.8 (compact `i`).
    CallId(String),
    /// `Contact:` — RFC 3261 §20.10 (compact `m`).
    Contact(String),
    /// `Content-Length:` — RFC 3261 §20.14 (compact `l`).
    ContentLength(String),
    /// `Content-Type:` — RFC 3261 §20.15 (compact `c`).
    ContentType(String),
    /// `Expires:` — RFC 3261 §20.19.
    Expires(String),
    /// `From:` — RFC 3261 §20.20 (compact `f`).
    From(String),
    /// `Max-Forwards:` — RFC 3261 §20.22.
    MaxForwards(String),
    /// `Proxy-Authenticate:` — RFC 3261 §20.27.
    ProxyAuthenticate(String),
    /// `Proxy-Authorization:` — RFC 3261 §20.28.
    ProxyAuthorization(String),
    /// `Record-Route:` — RFC 3261 §20.30.
    RecordRoute(String),
    /// `Require:` — RFC 3261 §20.32.
    Require(String),
    /// `Route:` — RFC 3261 §20.34.
    Route(String),
    /// `Supported:` — RFC 3261 §20.37 (compact `k`).
    Supported(String),
    /// `To:` — RFC 3261 §20.39 (compact `t`).
    To(String),
    /// `Via:` — RFC 3261 §20.42 (compact `v`).
    Via(String),
    /// `WWW-Authenticate:` — RFC 3261 §20.44.
    WwwAuthenticate(String),
    /// Any other header. Name preserves original case from the wire;
    /// matching is still case-insensitive via [`Header::name_matches`].
    Other(String, String),
}

impl Header {
    /// Canonical long-form header name. For `Other`, returns the
    /// stored name (original case from the wire).
    pub fn name(&self) -> Cow<'_, str> {
        match self {
            Header::Allow(_) => Cow::Borrowed("Allow"),
            Header::Authorization(_) => Cow::Borrowed("Authorization"),
            Header::CSeq(_) => Cow::Borrowed("CSeq"),
            Header::CallId(_) => Cow::Borrowed("Call-ID"),
            Header::Contact(_) => Cow::Borrowed("Contact"),
            Header::ContentLength(_) => Cow::Borrowed("Content-Length"),
            Header::ContentType(_) => Cow::Borrowed("Content-Type"),
            Header::Expires(_) => Cow::Borrowed("Expires"),
            Header::From(_) => Cow::Borrowed("From"),
            Header::MaxForwards(_) => Cow::Borrowed("Max-Forwards"),
            Header::ProxyAuthenticate(_) => Cow::Borrowed("Proxy-Authenticate"),
            Header::ProxyAuthorization(_) => Cow::Borrowed("Proxy-Authorization"),
            Header::RecordRoute(_) => Cow::Borrowed("Record-Route"),
            Header::Require(_) => Cow::Borrowed("Require"),
            Header::Route(_) => Cow::Borrowed("Route"),
            Header::Supported(_) => Cow::Borrowed("Supported"),
            Header::To(_) => Cow::Borrowed("To"),
            Header::Via(_) => Cow::Borrowed("Via"),
            Header::WwwAuthenticate(_) => Cow::Borrowed("WWW-Authenticate"),
            Header::Other(name, _) => Cow::Borrowed(name.as_str()),
        }
    }

    /// Raw header value, exactly as recognized (untrimmed beyond the
    /// "Name: value" split).
    pub fn value(&self) -> &str {
        match self {
            Header::Allow(v)
            | Header::Authorization(v)
            | Header::CSeq(v)
            | Header::CallId(v)
            | Header::Contact(v)
            | Header::ContentLength(v)
            | Header::ContentType(v)
            | Header::Expires(v)
            | Header::From(v)
            | Header::MaxForwards(v)
            | Header::ProxyAuthenticate(v)
            | Header::ProxyAuthorization(v)
            | Header::RecordRoute(v)
            | Header::Require(v)
            | Header::Route(v)
            | Header::Supported(v)
            | Header::To(v)
            | Header::Via(v)
            | Header::WwwAuthenticate(v) => v.as_str(),
            Header::Other(_, v) => v.as_str(),
        }
    }

    /// True if this header's canonical long-form name matches
    /// `query` case-insensitively. Compact-form queries (`v`, `i`, …)
    /// are resolved before comparison.
    pub fn name_matches(&self, query: &str) -> bool {
        let resolved = resolve_name(query);
        match self {
            Header::Other(name, _) => name.eq_ignore_ascii_case(&resolved),
            _ => self.name().eq_ignore_ascii_case(&resolved),
        }
    }

    /// If this is a `From:` header, parse its value into the typed
    /// form. Returns `None` for any other variant. The inner
    /// `Result` surfaces parse errors on the value.
    ///
    /// This is the Tier-2 entry point for `From` — the raw string
    /// is held in the variant, parsed only when the consumer asks.
    pub fn typed_from(&self) -> Option<Result<super::typed::From, SipError>> {
        match self {
            Header::From(value) => Some(super::typed::From::parse(value)),
            _ => None,
        }
    }

    /// If this is a `To:` header, parse its value into the typed
    /// form. Returns `None` for any other variant.
    pub fn typed_to(&self) -> Option<Result<super::typed::To, SipError>> {
        match self {
            Header::To(value) => Some(super::typed::To::parse(value)),
            _ => None,
        }
    }

    /// Parse one wire-format header line of the form `"Name: value"`.
    ///
    /// The line must NOT contain CRLF (framing strips that). Folding
    /// continuations are merged before this is called.
    pub fn parse_line(line: &str) -> Result<Header, SipError> {
        let colon = line
            .find(':')
            .ok_or_else(|| SipError::InvalidHeader(format!("missing ':' in header: {line}")))?;
        let raw_name = line[..colon].trim();
        if raw_name.is_empty() {
            return Err(SipError::InvalidHeader("empty header name".to_string()));
        }
        let value = line[colon + 1..].trim();
        if value.len() > MAX_HEADER_VALUE_LEN {
            return Err(SipError::InvalidHeader(format!(
                "header value exceeds {MAX_HEADER_VALUE_LEN} bytes",
            )));
        }
        Ok(build_header(raw_name, value.to_string()))
    }
}

/// Resolve a compact form letter to its long-form name. Anything
/// else passes through unchanged. Case-insensitive.
///
/// Compact forms covered:
/// - RFC 3261 §20: `i`, `m`, `f`, `t`, `v`, `c`, `l`, `s`, `k`, `e`,
///   `r`, `b`, `d`.
/// - RFC 3265 §7.2: `o` (Event), `u` (Allow-Events).
fn resolve_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.len() == 1 {
        let c = trimmed.as_bytes()[0].to_ascii_lowercase();
        return match c {
            b'i' => "Call-ID".to_string(),
            b'm' => "Contact".to_string(),
            b'f' => "From".to_string(),
            b't' => "To".to_string(),
            b'v' => "Via".to_string(),
            b'c' => "Content-Type".to_string(),
            b'l' => "Content-Length".to_string(),
            b's' => "Subject".to_string(),
            b'k' => "Supported".to_string(),
            b'e' => "Content-Encoding".to_string(),
            b'r' => "Refer-To".to_string(),
            b'b' => "Referred-By".to_string(),
            b'd' => "Content-Disposition".to_string(),
            b'o' => "Event".to_string(),
            b'u' => "Allow-Events".to_string(),
            _ => trimmed.to_string(),
        };
    }
    trimmed.to_string()
}

/// Build a typed `Header` variant from a (raw_name, value) pair. The
/// raw name may be a compact form (one letter) or any case-variant of
/// a long form.
///
/// Unknown long names produce `Header::Other` with the original
/// raw_name preserved (case kept). Compact forms whose long-form name
/// is not in our 19 typed variants produce `Header::Other` carrying
/// the *resolved* long-form name (e.g. `o:` ⇒ `Other("Event", ...)`)
/// so wire-format round-trip emits the canonical long form.
fn build_header(raw_name: &str, value: String) -> Header {
    let resolved = resolve_name(raw_name);
    let trimmed_raw = raw_name.trim();
    // For compact-form letters, prefer the resolved long-form name in
    // the fallback `Other` arm so wire round-trip is canonical.
    let other_name: &str = if trimmed_raw.len() == 1 && resolved != trimmed_raw {
        resolved.as_str()
    } else {
        raw_name
    };
    match_long_name(&resolved, other_name, value)
}

fn match_long_name(resolved: &str, other_name: &str, value: String) -> Header {
    // Long-form recognition is case-insensitive.
    let lc = resolved.to_ascii_lowercase();
    match lc.as_str() {
        "allow" => Header::Allow(value),
        "authorization" => Header::Authorization(value),
        "cseq" => Header::CSeq(value),
        "call-id" => Header::CallId(value),
        "contact" => Header::Contact(value),
        "content-length" => Header::ContentLength(value),
        "content-type" => Header::ContentType(value),
        "expires" => Header::Expires(value),
        "from" => Header::From(value),
        "max-forwards" => Header::MaxForwards(value),
        "proxy-authenticate" => Header::ProxyAuthenticate(value),
        "proxy-authorization" => Header::ProxyAuthorization(value),
        "record-route" => Header::RecordRoute(value),
        "require" => Header::Require(value),
        "route" => Header::Route(value),
        "supported" => Header::Supported(value),
        "to" => Header::To(value),
        "via" => Header::Via(value),
        "www-authenticate" => Header::WwwAuthenticate(value),
        _ => Header::Other(other_name.to_string(), value),
    }
}

/// Ordered collection of headers (insertion order preserved).
///
/// Wire-format round-trip depends on this. Methods that look up by
/// name are case-insensitive and compact-form aware.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    inner: Vec<Header>,
}

impl Headers {
    /// New empty collection.
    pub fn new() -> Self {
        Headers { inner: Vec::new() }
    }

    /// Append a header. Returns `Err` if doing so would exceed
    /// [`MAX_HEADERS`].
    pub fn push(&mut self, header: Header) -> Result<(), SipError> {
        if self.inner.len() >= MAX_HEADERS {
            return Err(SipError::InvalidHeader(format!(
                "too many headers (limit {MAX_HEADERS})",
            )));
        }
        self.inner.push(header);
        Ok(())
    }

    /// Number of headers stored.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no headers.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.inner.iter()
    }

    /// First header matching `name` (case-insensitive, compact-aware).
    pub fn get_first(&self, name: &str) -> Option<&Header> {
        self.inner.iter().find(|h| h.name_matches(name))
    }

    /// All headers matching `name`, in insertion order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Header> + 'a {
        self.inner.iter().filter(move |h| h.name_matches(name))
    }

    /// Raw value of the first header matching `name`.
    pub fn get_first_value(&self, name: &str) -> Option<&str> {
        self.get_first(name).map(Header::value)
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(line: &str, expect_name: &str, expect_value: &str) {
        let h = Header::parse_line(line).expect("parse_line failed");
        assert_eq!(h.name(), expect_name, "name mismatch for line {line:?}");
        assert_eq!(h.value(), expect_value, "value mismatch for line {line:?}");
    }

    #[test]
    fn test_typed_variant_round_trip_all_19() {
        round_trip("Allow: INVITE, ACK", "Allow", "INVITE, ACK");
        round_trip("Authorization: Digest x", "Authorization", "Digest x");
        round_trip("CSeq: 1 INVITE", "CSeq", "1 INVITE");
        round_trip("Call-ID: abc@host", "Call-ID", "abc@host");
        round_trip("Contact: <sip:a@b>", "Contact", "<sip:a@b>");
        round_trip("Content-Length: 0", "Content-Length", "0");
        round_trip(
            "Content-Type: application/sdp",
            "Content-Type",
            "application/sdp",
        );
        round_trip("Expires: 60", "Expires", "60");
        round_trip("From: <sip:a@b>;tag=1", "From", "<sip:a@b>;tag=1");
        round_trip("Max-Forwards: 70", "Max-Forwards", "70");
        round_trip("Proxy-Authenticate: Digest", "Proxy-Authenticate", "Digest");
        round_trip(
            "Proxy-Authorization: Digest",
            "Proxy-Authorization",
            "Digest",
        );
        round_trip("Record-Route: <sip:p@x>", "Record-Route", "<sip:p@x>");
        round_trip("Require: 100rel", "Require", "100rel");
        round_trip("Route: <sip:p@x>", "Route", "<sip:p@x>");
        round_trip("Supported: timer", "Supported", "timer");
        round_trip("To: <sip:b@c>", "To", "<sip:b@c>");
        round_trip("Via: SIP/2.0/UDP h", "Via", "SIP/2.0/UDP h");
        round_trip("WWW-Authenticate: Digest", "WWW-Authenticate", "Digest");
    }

    #[test]
    fn test_long_name_case_insensitive() {
        let h = Header::parse_line("via: SIP/2.0/UDP host").unwrap();
        assert!(matches!(h, Header::Via(_)));
        let h = Header::parse_line("CONTENT-TYPE: application/sdp").unwrap();
        assert!(matches!(h, Header::ContentType(_)));
        let h = Header::parse_line("call-id: foo").unwrap();
        assert!(matches!(h, Header::CallId(_)));
    }

    type CompactCase = (&'static str, fn(&Header) -> bool);

    #[test]
    fn test_compact_forms_all_13() {
        // RFC 3261 §20 compact forms plus the ones rsiprtp's brief enumerates.
        let cases: &[CompactCase] = &[
            ("i", |h| matches!(h, Header::CallId(_))),
            ("m", |h| matches!(h, Header::Contact(_))),
            ("f", |h| matches!(h, Header::From(_))),
            ("t", |h| matches!(h, Header::To(_))),
            ("v", |h| matches!(h, Header::Via(_))),
            ("c", |h| matches!(h, Header::ContentType(_))),
            ("l", |h| matches!(h, Header::ContentLength(_))),
            // s, e, r, b have no native typed variant — they resolve to
            // long-form names but those long-forms aren't in our 19, so
            // they land in Other. k = Supported is in our 19.
            ("k", |h| matches!(h, Header::Supported(_))),
        ];
        for (compact, pred) in cases {
            let line = format!("{compact}: value");
            let h = Header::parse_line(&line).unwrap();
            assert!(pred(&h), "compact {compact} dispatched wrong: {h:?}");
        }
        // Compact forms whose long form isn't in our 19 → Other with
        // the long-form name (resolved, NOT the compact letter).
        for compact in ["s", "e", "r", "b"] {
            let line = format!("{compact}: value");
            let h = Header::parse_line(&line).unwrap();
            assert!(
                matches!(h, Header::Other(_, _)),
                "compact {compact} should be Other"
            );
        }
    }

    #[test]
    fn test_compact_forms_extra_rfc3261_rfc3265() {
        // RFC 3265 §7.2 adds `o` (Event), `u` (Allow-Events).
        // RFC 3261 §20.11 lists `d` (Content-Disposition).
        // None of these long-form names are in our 19 typed variants,
        // so they all land in `Header::Other` carrying the resolved
        // long-form name.
        for (compact, expected_long) in [
            ("o", "Event"),
            ("u", "Allow-Events"),
            ("d", "Content-Disposition"),
        ] {
            let line = format!("{compact}: value");
            let h = Header::parse_line(&line).unwrap();
            match &h {
                Header::Other(name, value) => {
                    assert_eq!(
                        name, expected_long,
                        "compact {compact} should resolve to {expected_long}"
                    );
                    assert_eq!(value, "value");
                }
                other => panic!("compact {compact} should be Other, got {other:?}"),
            }
            // name_matches must accept both the compact letter and
            // the long form.
            assert!(h.name_matches(compact));
            assert!(h.name_matches(expected_long));
        }
    }

    #[test]
    fn test_compact_case_insensitive() {
        let h = Header::parse_line("V: SIP/2.0/UDP host").unwrap();
        assert!(matches!(h, Header::Via(_)));
        let h = Header::parse_line("L: 0").unwrap();
        assert!(matches!(h, Header::ContentLength(_)));
    }

    #[test]
    fn test_other_preserves_case() {
        let h = Header::parse_line("X-MyCustom-Header: value").unwrap();
        match &h {
            Header::Other(n, v) => {
                assert_eq!(n, "X-MyCustom-Header");
                assert_eq!(v, "value");
            }
            _ => panic!("expected Other, got {h:?}"),
        }
        assert_eq!(h.name(), "X-MyCustom-Header");
    }

    #[test]
    fn test_other_for_unmatched_long_name() {
        let h = Header::parse_line("Server: rsiprtp/0.3.0").unwrap();
        assert!(matches!(h, Header::Other(_, _)));
        assert_eq!(h.name(), "Server");
        assert_eq!(h.value(), "rsiprtp/0.3.0");
    }

    #[test]
    fn test_parse_line_missing_colon_rejects() {
        let err = Header::parse_line("NoColonHere").unwrap_err();
        assert!(matches!(err, SipError::InvalidHeader(_)));
    }

    #[test]
    fn test_parse_line_empty_name_rejects() {
        let err = Header::parse_line(": value").unwrap_err();
        assert!(matches!(err, SipError::InvalidHeader(_)));
    }

    #[test]
    fn test_parse_line_oversized_value_rejects() {
        let big = "x".repeat(MAX_HEADER_VALUE_LEN + 1);
        let line = format!("X-Big: {big}");
        let err = Header::parse_line(&line).unwrap_err();
        assert!(matches!(err, SipError::InvalidHeader(_)));
    }

    #[test]
    fn test_parse_line_max_value_size_accepted() {
        let big = "x".repeat(MAX_HEADER_VALUE_LEN);
        let line = format!("X-Big: {big}");
        Header::parse_line(&line).expect("at-limit value should be accepted");
    }

    #[test]
    fn test_name_matches_compact_and_long() {
        let h = Header::Via("SIP/2.0/UDP h".to_string());
        assert!(h.name_matches("Via"));
        assert!(h.name_matches("via"));
        assert!(h.name_matches("VIA"));
        assert!(h.name_matches("v"));
        assert!(h.name_matches("V"));
        assert!(!h.name_matches("From"));
    }

    #[test]
    fn test_headers_push_iter_preserves_order() {
        let mut hs = Headers::new();
        hs.push(Header::Via("v1".to_string())).unwrap();
        hs.push(Header::Via("v2".to_string())).unwrap();
        hs.push(Header::From("<sip:a@b>".to_string())).unwrap();
        let collected: Vec<&str> = hs.iter().map(Header::value).collect();
        assert_eq!(collected, vec!["v1", "v2", "<sip:a@b>"]);
    }

    #[test]
    fn test_headers_get_all_preserves_order() {
        let mut hs = Headers::new();
        hs.push(Header::Via("v1".to_string())).unwrap();
        hs.push(Header::From("f".to_string())).unwrap();
        hs.push(Header::Via("v2".to_string())).unwrap();
        let vias: Vec<&str> = hs.get_all("Via").map(Header::value).collect();
        assert_eq!(vias, vec!["v1", "v2"]);
        let vias_compact: Vec<&str> = hs.get_all("v").map(Header::value).collect();
        assert_eq!(vias_compact, vec!["v1", "v2"]);
    }

    #[test]
    fn test_headers_get_first_returns_first_match() {
        let mut hs = Headers::new();
        hs.push(Header::Via("v1".to_string())).unwrap();
        hs.push(Header::Via("v2".to_string())).unwrap();
        assert_eq!(hs.get_first("Via").unwrap().value(), "v1");
        assert_eq!(hs.get_first("VIA").unwrap().value(), "v1");
        assert_eq!(hs.get_first("v").unwrap().value(), "v1");
        assert!(hs.get_first("From").is_none());
    }

    #[test]
    fn test_headers_get_first_value() {
        let mut hs = Headers::new();
        hs.push(Header::CallId("abc".to_string())).unwrap();
        assert_eq!(hs.get_first_value("Call-ID"), Some("abc"));
        assert_eq!(hs.get_first_value("i"), Some("abc"));
        assert_eq!(hs.get_first_value("From"), None);
    }

    #[test]
    fn test_headers_max_cap_enforced() {
        let mut hs = Headers::new();
        for _ in 0..MAX_HEADERS {
            hs.push(Header::Via("x".to_string())).unwrap();
        }
        let err = hs.push(Header::Via("overflow".to_string())).unwrap_err();
        assert!(matches!(err, SipError::InvalidHeader(_)));
        assert_eq!(hs.len(), MAX_HEADERS);
    }

    #[test]
    fn test_headers_default_and_is_empty() {
        let hs = Headers::default();
        assert!(hs.is_empty());
        assert_eq!(hs.len(), 0);
    }

    #[test]
    fn test_headers_into_iter_ref() {
        let mut hs = Headers::new();
        hs.push(Header::Via("v".to_string())).unwrap();
        let count = (&hs).into_iter().count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_other_name_matches_case_insensitive() {
        let h = Header::Other("X-Foo".to_string(), "v".to_string());
        assert!(h.name_matches("x-foo"));
        assert!(h.name_matches("X-FOO"));
        assert!(!h.name_matches("X-Bar"));
    }

    /// Whitespace before the colon (`"Foo : value"`) is RFC 3261
    /// permitted-by-tolerance: the spec disallows it strictly, but
    /// many real-world stacks (and rsip) accept it. We trim around
    /// the colon and accept it. Pinned by this test so future
    /// stricter parsing is a deliberate choice, not accidental drift.
    #[test]
    fn test_parse_line_whitespace_before_colon() {
        let h = Header::parse_line("Foo : value").unwrap();
        match &h {
            Header::Other(name, value) => {
                assert_eq!(name, "Foo");
                assert_eq!(value, "value");
            }
            other => panic!("expected Other, got {other:?}"),
        }

        // Same behavior for typed variants.
        let h = Header::parse_line("Via : SIP/2.0/UDP h").unwrap();
        assert!(matches!(h, Header::Via(_)));
        assert_eq!(h.value(), "SIP/2.0/UDP h");
    }
}
