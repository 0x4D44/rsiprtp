//! Typed `From` header (RFC 3261 §20.20).
//!
//! `From: [ display-name ] <addr-spec> *( ; from-param )`
//!
//! Per RFC 3261 §8.1.1.3 the From header MUST contain a `tag`
//! parameter. **At parse time** we mirror rsip 0.4's behavior and
//! accept absence — the From with no tag is still structurally a
//! valid header value (it's the *protocol* requirement, not the
//! *grammar* requirement). The transaction layer (RFC 3261 §17)
//! is the right place to enforce the tag, not the parser.

use super::super::name_addr::NameAddr;
use crate::core::SipError;
use crate::sip::uri::SipUri;
use std::fmt;

/// Typed form of the `From` header.
///
/// Field shape mirrors `rsip::typed::From`: public `display_name`,
/// `uri`, `params` so call sites can field-access without going
/// through accessors.
#[derive(Debug, Clone, PartialEq)]
pub struct From {
    /// Display name with quoted-pair escapes resolved (see
    /// [`NameAddr`] for details).
    pub display_name: Option<String>,
    /// Request-URI (or addr-spec) for the From header.
    pub uri: SipUri,
    /// Header parameters in wire order. The `tag` MAY appear here;
    /// look it up via [`From::tag`].
    pub params: Vec<(String, Option<String>)>,
}

impl From {
    /// Parse a `From` header value (the part after `From: `) into
    /// the typed form. The `tag` requirement (RFC 3261 §8.1.1.3)
    /// is NOT enforced here — callers that need it should check
    /// `tag().is_some()` separately. This matches rsip 0.4.
    pub fn parse(value: &str) -> Result<From, SipError> {
        let na = NameAddr::parse(value)?;
        Ok(From {
            display_name: na.display_name,
            uri: na.uri,
            params: na.parameters,
        })
    }

    /// Return the `tag` parameter value, if present. Lookup is
    /// case-insensitive on the parameter name per RFC 3261 §25.1.
    pub fn tag(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("tag"))
            .and_then(|(_, v)| v.as_deref())
    }
}

impl fmt::Display for From {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to NameAddr's Display by reconstructing — this
        // keeps the wire-format quoting logic in one place.
        let na = NameAddr {
            display_name: self.display_name.clone(),
            uri: self.uri.clone(),
            parameters: self.params.clone(),
        };
        write!(f, "{}", na)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_with_tag() {
        let f = From::parse("Alice <sip:alice@example.com>;tag=1928301774").unwrap();
        assert_eq!(f.display_name, Some("Alice".to_string()));
        assert_eq!(f.uri.user(), Some("alice"));
        assert_eq!(f.tag(), Some("1928301774"));
    }

    #[test]
    fn test_parse_without_tag_still_succeeds() {
        // RFC 3261 §8.1.1.3 says the protocol requires a tag; the
        // grammar does not. We mirror rsip's permissive parse.
        let f = From::parse("Alice <sip:alice@example.com>").unwrap();
        assert_eq!(f.tag(), None);
    }

    #[test]
    fn test_parse_quoted_display_name() {
        let f = From::parse(r#""Alice Smith" <sip:a@b>;tag=t"#).unwrap();
        assert_eq!(f.display_name, Some("Alice Smith".to_string()));
        assert_eq!(f.tag(), Some("t"));
    }

    #[test]
    fn test_parse_bare_addr_spec() {
        let f = From::parse("sip:bob@example.com;tag=t").unwrap();
        assert_eq!(f.display_name, None);
        assert_eq!(f.uri.user(), Some("bob"));
        assert_eq!(f.tag(), Some("t"));
    }

    #[test]
    fn test_tag_lookup_case_insensitive() {
        let f = From::parse("<sip:a@b>;TAG=x").unwrap();
        assert_eq!(f.tag(), Some("x"));
    }

    #[test]
    fn test_invalid_rejected() {
        assert!(From::parse("not a name-addr <").is_err());
        assert!(From::parse("").is_err());
    }

    #[test]
    fn test_display_round_trip() {
        let v = "Alice <sip:alice@example.com>;tag=1";
        let f = From::parse(v).unwrap();
        assert_eq!(f.to_string(), v);
    }

    #[test]
    fn test_display_quoted_round_trip() {
        let v = r#""Alice Smith" <sip:a@b>;tag=1"#;
        let f = From::parse(v).unwrap();
        assert_eq!(f.to_string(), v);
    }
}
