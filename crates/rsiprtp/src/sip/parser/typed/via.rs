//! Typed `Via` header (RFC 3261 §20.42).
//!
//! Wire form (per RFC 3261 §20.42 ABNF):
//!
//! ```text
//! Via             =  ( "Via" / "v" ) HCOLON via-parm *( COMMA via-parm )
//! via-parm        =  sent-protocol LWS sent-by *( SEMI via-params )
//! sent-protocol   =  protocol-name SLASH protocol-version SLASH transport
//! sent-by         =  host [ COLON port ]
//! ```
//!
//! Field shape mirrors `rsip::typed::Via` (see
//! `~/.cargo/registry/.../rsip-0.4.0/src/headers/typed/via.rs`)
//! adjusted to keep our parser owned-`String`-only:
//!
//! - `protocol`: `"SIP/2.0"` (or whatever was on the wire — we
//!   accept any `protocol-name "/" protocol-version`).
//! - `transport`: `"UDP" | "TCP" | "TLS" | …` — case preserved
//!   from the wire.
//! - `sent_by`: the literal `host[:port]` token, including IPv6
//!   bracketing, so `[2001:db8::1]:5060` round-trips.
//! - `params`: ordered `(key, Option<value>)` list.
//!
//! Tri-state `rport` accessor matches mdsiprtp3's via.rs and our
//! existing `crate::sip::headers::Via`:
//! - `None` — no `rport` parameter present
//! - `Some(None)` — `;rport` (flag, client requesting symmetric)
//! - `Some(Some(p))` — `;rport=12345` (server-rewritten)

use crate::core::SipError;
use std::fmt;

/// Typed form of one `Via` header value (one `via-parm`).
///
/// Multiple `Via` headers in a message are stored as separate
/// `Header::Via` entries; this typed form represents one such
/// entry. We do not split a single comma-separated `Via` value
/// into multiple typed forms — at parse time we leave that
/// concern to the caller (matches our Tier-1 framing, which
/// also does not split on `,`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    /// Protocol name + version, e.g. `"SIP/2.0"`.
    pub protocol: String,
    /// Transport token, e.g. `"UDP"`, `"TCP"`, `"TLS"`.
    pub transport: String,
    /// Sent-by `host[:port]`, verbatim from the wire (preserves
    /// IPv6 bracketing like `[2001:db8::1]:5060`).
    pub sent_by: String,
    /// Header parameters in wire order. `(key, Option<value>)`
    /// where `None` distinguishes a flag param (`;rport`) from
    /// an empty-valued one (`;foo=`).
    pub params: Vec<(String, Option<String>)>,
}

impl Via {
    /// Parse one `Via` value (the part after `Via: `).
    ///
    /// Splits on the first ASCII space: the left side is
    /// `<protocol>/<transport>`, the right is `sent-by` plus
    /// optional `;param[=value]` chain.
    pub fn parse(value: &str) -> Result<Via, SipError> {
        let s = value.trim();
        if s.is_empty() {
            return Err(SipError::InvalidHeader(
                "empty Via header value".to_string(),
            ));
        }

        // Split sent-protocol from sent-by + params at first space.
        let space = s.find(' ').ok_or_else(|| {
            SipError::InvalidHeader(format!(
                "Via header missing space between sent-protocol and sent-by: {s:?}",
            ))
        })?;
        let proto_part = s[..space].trim();
        let rest = s[space + 1..].trim_start();

        // Split sent-protocol = protocol-name "/" protocol-version "/" transport.
        // We canonicalize `<name>/<ver>` as `protocol` and the trailing token
        // as `transport`. RFC 3261 §20.42 has exactly two `/` separators.
        let last_slash = proto_part.rfind('/').ok_or_else(|| {
            SipError::InvalidHeader(format!(
                "Via header sent-protocol missing '/': {proto_part:?}",
            ))
        })?;
        let protocol = proto_part[..last_slash].trim().to_string();
        let transport = proto_part[last_slash + 1..].trim().to_string();
        if protocol.is_empty() || transport.is_empty() {
            return Err(SipError::InvalidHeader(format!(
                "Via header sent-protocol incomplete: {proto_part:?}",
            )));
        }
        // Sanity-check the protocol contains at least one `/` (i.e.
        // the form `name/version`). RFC 3261's `sent-protocol`
        // grammar requires it.
        if !protocol.contains('/') {
            return Err(SipError::InvalidHeader(format!(
                "Via header sent-protocol must be name/version/transport: {proto_part:?}",
            )));
        }

        // Split sent-by from params at the first `;` outside any
        // bracketed IPv6 reference. RFC 3261 §20.42:
        // `sent-by = host [ COLON port ]`; the host can be `[v6]`.
        let (sent_by, params_part) = split_sent_by_params(rest)?;
        let sent_by = sent_by.trim().to_string();
        if sent_by.is_empty() {
            return Err(SipError::InvalidHeader(format!(
                "Via header missing sent-by: {value:?}",
            )));
        }

        // Reject embedded whitespace in sent-by — RFC 3261 §20.42
        // `sent-by = host [ COLON port ]` permits none. This catches
        // garbage like "SIP/2.0/UDP host trailing".
        if sent_by.bytes().any(|b| b == b' ' || b == b'\t') {
            return Err(SipError::InvalidHeader(format!(
                "Via sent-by contains whitespace: {sent_by:?}",
            )));
        }

        let params = parse_params(params_part)?;
        Ok(Via {
            protocol,
            transport,
            sent_by,
            params,
        })
    }

    /// Lookup the `branch` parameter (RFC 3261 §8.1.1.7). Cookie
    /// must start with `z9hG4bK` for an RFC 3261 compliant
    /// transaction; we don't enforce that at parse time (that's
    /// the transaction layer's job). Case-insensitive on the
    /// parameter name.
    pub fn branch(&self) -> Option<&str> {
        self.find_param("branch")
    }

    /// Lookup the `received` parameter (RFC 3261 §18.2.1) — the
    /// server-stamped source IP. Case-insensitive on the
    /// parameter name. Returns the raw value; IP parsing is the
    /// caller's responsibility.
    pub fn received(&self) -> Option<&str> {
        self.find_param("received")
    }

    /// Tri-state lookup for the `rport` parameter
    /// (RFC 3581 §3):
    /// - `None` — no `rport` parameter present
    /// - `Some(None)` — `;rport` flag (client request)
    /// - `Some(Some(p))` — `;rport=NNN` (server response with
    ///   actual port). Non-numeric values yield `Some(None)`
    ///   (we treat them as the flag form rather than failing).
    pub fn rport(&self) -> Option<Option<u16>> {
        for (k, v) in &self.params {
            if k.eq_ignore_ascii_case("rport") {
                return Some(match v {
                    None => None,
                    Some(text) => text.parse::<u16>().ok(),
                });
            }
        }
        None
    }

    /// Lookup the `maddr` parameter (RFC 3261 §20.42 / §19.1.1).
    pub fn maddr(&self) -> Option<&str> {
        self.find_param("maddr")
    }

    /// Lookup the `ttl` parameter (RFC 3261 §20.42 / §19.1.1).
    /// Returns `None` if absent or not a valid `u8`.
    pub fn ttl(&self) -> Option<u8> {
        self.find_param("ttl").and_then(|v| v.parse::<u8>().ok())
    }

    fn find_param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .and_then(|(_, v)| v.as_deref())
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{} {}", self.protocol, self.transport, self.sent_by)?;
        for (key, value) in &self.params {
            match value {
                Some(v) => write!(f, ";{}={}", key, v)?,
                None => write!(f, ";{}", key)?,
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

/// Split `rest` into `(sent-by, params-tail)` at the first `;`
/// that lies outside any IPv6 `[...]` reference. The returned
/// `params-tail` either starts with `;` or is empty.
fn split_sent_by_params(rest: &str) -> Result<(&str, &str), SipError> {
    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut in_v6 = false;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                if in_v6 {
                    return Err(SipError::InvalidHeader(format!(
                        "Via sent-by has nested '[': {rest:?}",
                    )));
                }
                in_v6 = true;
            }
            b']' => {
                if !in_v6 {
                    return Err(SipError::InvalidHeader(format!(
                        "Via sent-by has unmatched ']': {rest:?}",
                    )));
                }
                in_v6 = false;
            }
            b';' if !in_v6 => return Ok((&rest[..i], &rest[i..])),
            _ => {}
        }
        i += 1;
    }
    if in_v6 {
        return Err(SipError::InvalidHeader(format!(
            "Via sent-by has unterminated IPv6 reference: {rest:?}",
        )));
    }
    Ok((rest, ""))
}

/// Parse `;k=v;k2;k3=v3` into a parameter list. Empty input is
/// fine (returns `Vec::new()`). Mirrors `name_addr::parse_params`
/// shape but is local — we deliberately do not import from
/// there to keep typed::* modules independent of one another.
fn parse_params(s: &str) -> Result<Vec<(String, Option<String>)>, SipError> {
    let s = s.trim_start();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if !s.starts_with(';') {
        return Err(SipError::InvalidHeader(format!(
            "Via trailing data after sent-by (expected ';' or end): {s:?}",
        )));
    }
    let mut params = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 1; // skip leading `;`
    while i < bytes.len() {
        let start = i;
        let mut in_quoted = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_quoted {
                if b == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    in_quoted = false;
                }
                i += 1;
                continue;
            }
            match b {
                b'"' => in_quoted = true,
                b';' => break,
                _ => {}
            }
            i += 1;
        }
        let chunk = s[start..i].trim();
        if !chunk.is_empty() {
            if let Some(eq) = chunk.find('=') {
                let (k, v) = chunk.split_at(eq);
                params.push((k.trim().to_string(), Some(v[1..].trim().to_string())));
            } else {
                params.push((chunk.to_string(), None));
            }
        }
        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
        }
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal() {
        let v = Via::parse("SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK1").unwrap();
        assert_eq!(v.protocol, "SIP/2.0");
        assert_eq!(v.transport, "UDP");
        assert_eq!(v.sent_by, "host.example.com:5060");
        assert_eq!(v.branch(), Some("z9hG4bK1"));
    }

    #[test]
    fn test_parse_no_port() {
        let v = Via::parse("SIP/2.0/TCP proxy.example.com;branch=z9hG4bK999").unwrap();
        assert_eq!(v.transport, "TCP");
        assert_eq!(v.sent_by, "proxy.example.com");
        assert_eq!(v.branch(), Some("z9hG4bK999"));
    }

    #[test]
    fn test_parse_ipv6_with_port() {
        let v = Via::parse("SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKabc").unwrap();
        assert_eq!(v.sent_by, "[2001:db8::1]:5060");
        assert_eq!(v.branch(), Some("z9hG4bKabc"));
    }

    #[test]
    fn test_parse_ipv6_no_port() {
        let v = Via::parse("SIP/2.0/UDP [::1];branch=z9hG4bK1").unwrap();
        assert_eq!(v.sent_by, "[::1]");
    }

    #[test]
    fn test_received_param() {
        let v = Via::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK1;received=192.0.2.10").unwrap();
        assert_eq!(v.received(), Some("192.0.2.10"));
    }

    #[test]
    fn test_rport_tri_state_absent() {
        let v = Via::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK1").unwrap();
        assert_eq!(v.rport(), None);
    }

    #[test]
    fn test_rport_tri_state_flag() {
        let v = Via::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK1;rport").unwrap();
        // Flag form: present, value None.
        assert_eq!(v.rport(), Some(None));
    }

    #[test]
    fn test_rport_tri_state_with_value() {
        let v = Via::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK1;rport=12345").unwrap();
        assert_eq!(v.rport(), Some(Some(12345)));
    }

    #[test]
    fn test_rport_non_numeric_value_treated_as_flag() {
        let v = Via::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK1;rport=abc").unwrap();
        assert_eq!(v.rport(), Some(None));
    }

    #[test]
    fn test_maddr_and_ttl() {
        let v = Via::parse("SIP/2.0/UDP host:5060;branch=z9hG4bK1;maddr=224.0.0.1;ttl=16").unwrap();
        assert_eq!(v.maddr(), Some("224.0.0.1"));
        assert_eq!(v.ttl(), Some(16));
    }

    #[test]
    fn test_multiple_params() {
        let v = Via::parse(
            "SIP/2.0/TLS edge.example.com:5061;branch=z9hG4bKxy;received=10.0.0.1;rport=33445",
        )
        .unwrap();
        assert_eq!(v.transport, "TLS");
        assert_eq!(v.params.len(), 3);
        assert_eq!(v.branch(), Some("z9hG4bKxy"));
        assert_eq!(v.received(), Some("10.0.0.1"));
        assert_eq!(v.rport(), Some(Some(33445)));
    }

    #[test]
    fn test_empty_params() {
        let v = Via::parse("SIP/2.0/UDP host.example.com").unwrap();
        assert!(v.params.is_empty());
        assert!(v.branch().is_none());
    }

    #[test]
    fn test_param_key_lookup_case_insensitive() {
        let v = Via::parse("SIP/2.0/UDP host;BRANCH=z9hG4bK1;Received=10.0.0.1").unwrap();
        assert_eq!(v.branch(), Some("z9hG4bK1"));
        assert_eq!(v.received(), Some("10.0.0.1"));
    }

    #[test]
    fn test_missing_space_rejected() {
        // No space between sent-protocol and sent-by — malformed.
        assert!(Via::parse("SIP/2.0/UDPhost.example.com;branch=z").is_err());
    }

    #[test]
    fn test_missing_slash_in_protocol_rejected() {
        // "FOO BAR" — no slash, can't be `name/version/transport`.
        assert!(Via::parse("FOO bar.example.com").is_err());
    }

    #[test]
    fn test_protocol_only_one_slash_rejected() {
        // Only one slash → no transport segment.
        assert!(Via::parse("SIP/2.0 host.example.com").is_err());
    }

    #[test]
    fn test_empty_input_rejected() {
        assert!(Via::parse("").is_err());
        assert!(Via::parse("   ").is_err());
    }

    #[test]
    fn test_trailing_garbage_after_sent_by_rejected() {
        // Anything after the sent-by token that isn't `;` or end is
        // malformed.
        assert!(Via::parse("SIP/2.0/UDP host garbage").is_err());
    }

    #[test]
    fn test_unmatched_ipv6_bracket_rejected() {
        assert!(Via::parse("SIP/2.0/UDP [2001:db8::1;branch=z").is_err());
        assert!(Via::parse("SIP/2.0/UDP 2001:db8::1];branch=z").is_err());
    }

    #[test]
    fn test_display_round_trip() {
        let inputs = [
            "SIP/2.0/UDP host:5060;branch=z9hG4bK1",
            "SIP/2.0/TCP proxy.example.com;branch=z9hG4bK999",
            "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKabc",
            "SIP/2.0/UDP host:5060;branch=z9hG4bK1;received=10.0.0.1;rport=33445",
            "SIP/2.0/UDP host:5060;branch=z9hG4bK1;rport",
        ];
        for input in inputs {
            let v = Via::parse(input).unwrap();
            assert_eq!(v.to_string(), input, "round-trip mismatch for {input:?}");
        }
    }

    #[test]
    fn test_display_emits_flag_then_value_params() {
        let v = Via::parse("SIP/2.0/UDP host;branch=b;rport;ttl=10").unwrap();
        assert_eq!(v.to_string(), "SIP/2.0/UDP host;branch=b;rport;ttl=10");
    }
}
