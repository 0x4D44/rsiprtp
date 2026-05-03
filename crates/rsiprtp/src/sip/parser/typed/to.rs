//! Typed `To` header (RFC 3261 §20.39).
//!
//! `To: [ display-name ] <addr-spec> *( ; to-param )`
//!
//! Per RFC 3261 §8.1.1.2, the To header has a `tag` only after
//! dialog establishment (or in dialog-creating responses). Absence
//! at parse time is therefore *expected* for an initial INVITE's
//! To header. We do not reject on missing tag.

use super::super::name_addr::NameAddr;
use crate::core::SipError;
use crate::sip::uri::SipUri;
use std::fmt;

/// Typed form of the `To` header. Field shape mirrors
/// `rsip::typed::To`.
#[derive(Debug, Clone, PartialEq)]
pub struct To {
    /// Display name with quoted-pair escapes resolved.
    pub display_name: Option<String>,
    /// Request-URI (or addr-spec) for the To header.
    pub uri: SipUri,
    /// Header parameters in wire order. May or may not contain a
    /// `tag`; the absence of one is normal for initial requests.
    pub params: Vec<(String, Option<String>)>,
}

impl To {
    /// Parse a `To` header value into the typed form.
    pub fn parse(value: &str) -> Result<To, SipError> {
        let na = NameAddr::parse(value)?;
        Ok(To {
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

impl fmt::Display for To {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn test_parse_without_tag_initial_request() {
        // To on an initial INVITE has no tag — that's the common case.
        let t = To::parse("Bob <sip:bob@example.com>").unwrap();
        assert_eq!(t.display_name, Some("Bob".to_string()));
        assert_eq!(t.uri.user(), Some("bob"));
        assert_eq!(t.tag(), None);
    }

    #[test]
    fn test_parse_with_tag_dialog_response() {
        // After dialog-establishment the To carries a tag.
        let t = To::parse("Bob <sip:bob@example.com>;tag=a6c85cf").unwrap();
        assert_eq!(t.tag(), Some("a6c85cf"));
    }

    #[test]
    fn test_parse_bare_addr_spec() {
        let t = To::parse("sip:bob@example.com").unwrap();
        assert_eq!(t.display_name, None);
        assert_eq!(t.uri.user(), Some("bob"));
    }

    #[test]
    fn test_parse_quoted_display_name() {
        let t = To::parse(r#""The Operator" <sip:op@x>"#).unwrap();
        assert_eq!(t.display_name, Some("The Operator".to_string()));
    }

    #[test]
    fn test_invalid_rejected() {
        assert!(To::parse("").is_err());
    }

    #[test]
    fn test_tag_lookup_case_insensitive() {
        let t = To::parse("<sip:a@b>;Tag=x").unwrap();
        assert_eq!(t.tag(), Some("x"));
    }

    #[test]
    fn test_display_round_trip_no_tag() {
        let v = "Bob <sip:bob@example.com>";
        let t = To::parse(v).unwrap();
        assert_eq!(t.to_string(), v);
    }

    #[test]
    fn test_display_round_trip_with_tag() {
        let v = "Bob <sip:bob@example.com>;tag=a6c85cf";
        let t = To::parse(v).unwrap();
        assert_eq!(t.to_string(), v);
    }
}
