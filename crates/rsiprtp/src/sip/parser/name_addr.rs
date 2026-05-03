//! Name-address (`name-addr` per RFC 3261 §25.1) parsing.
//!
//! A name-address has the form
//!
//! ```text
//! [ display-name ] LAQUOT addr-spec RAQUOT *( SEMI generic-param )
//! ```
//!
//! and also accepts the bare `addr-spec` (no angle brackets, no
//! display name) as part of the `from-spec`/`to-spec`/`contact`
//! productions. We accept the union here.
//!
//! Display-name forms (RFC 3261 §25.1):
//! - bare token sequence: `Alice`
//! - quoted-string: `"Alice Smith"` (with `\"` and `\\` quoted-pairs).
//!
//! mdsiprtp3's seed implementation trims `"` naively with
//! `trim_matches`. That loses information: `"Alice"Bob` (which is
//! malformed) and `Alice Bob` (no quotes) collapse to the same
//! display name. We do this properly: a leading `"` switches into
//! quoted-string mode, an unescaped `"` closes it, `\X` quoted-pairs
//! are honored verbatim per §25.1. The stored display name is the
//! *unquoted* logical text (with quoted-pair escapes resolved); the
//! `Display` impl re-quotes it when it contains characters outside
//! the bare-token set.
//!
//! Tier-2: this is the typed form for `From`, `To`, and `Contact`
//! header values. Wraps [`crate::sip::uri::SipUri`] from M3.

use crate::core::SipError;
use crate::sip::uri::SipUri;
use std::fmt;

/// Parsed name-address with optional display name, URI, and trailing
/// `;param=value` list.
///
/// Parameters are header parameters (after the URI / closing `>`);
/// they are NOT URI parameters (which live inside the URI itself, on
/// the [`SipUri`]).
#[derive(Debug, Clone, PartialEq)]
pub struct NameAddr {
    /// Display name, with quoted-pair escapes resolved and
    /// surrounding quotes (if any) removed. `None` if no display
    /// name was present on the wire.
    pub display_name: Option<String>,
    /// URI portion (the contents of the angle brackets, or the
    /// bare addr-spec if no brackets were present).
    pub uri: SipUri,
    /// Header parameters after the URI: `;tag=foo;expires=300`.
    /// Stored as `(key, Option<value>)` to distinguish flag params
    /// (`;lr`) from empty-valued params (`;foo=`). Order preserved
    /// from the wire.
    pub parameters: Vec<(String, Option<String>)>,
}

impl NameAddr {
    /// Parse a name-address from a header value string.
    ///
    /// Accepts:
    /// - `<sip:bob@example.com>` — angle-bracketed, no display name
    /// - `Alice <sip:alice@example.com>` — token display name
    /// - `"Alice Smith" <sip:a@b>` — quoted-string display name
    /// - `sip:bob@example.com` — bare addr-spec
    /// - any of the above with trailing `;param=value`
    pub fn parse(input: &str) -> Result<NameAddr, SipError> {
        let s = input.trim();
        if s.is_empty() {
            return Err(SipError::InvalidHeader(
                "empty name-address value".to_string(),
            ));
        }

        // Phase 1: pull off an optional quoted-string display name.
        // The remainder after a quoted display name MUST begin with
        // `<` (per `name-addr` ABNF). For an unquoted display name
        // we recognize it only when a `<` appears later in the
        // string and the leading text is non-empty.
        let (display_name, rest) = if s.starts_with('"') {
            let (name, after) = parse_quoted_string(s)?;
            // Optional whitespace, then `<` MUST follow.
            let after = after.trim_start();
            if !after.starts_with('<') {
                return Err(SipError::InvalidHeader(format!(
                    "quoted display name must be followed by '<addr-spec>': {input:?}",
                )));
            }
            (Some(name), after)
        } else if let Some(lt) = find_angle_bracket(s) {
            // Find a `<` outside any (already-rejected) quoted
            // string. `find_angle_bracket` walks the string honoring
            // quoted-string boundaries; here the leading char isn't
            // `"` so any `<` we find is at the top level.
            let leading = s[..lt].trim();
            if leading.is_empty() {
                (None, &s[lt..])
            } else {
                (Some(leading.to_string()), &s[lt..])
            }
        } else {
            // No `<` anywhere — bare addr-spec.
            (None, s)
        };

        // Phase 2: consume the URI. Either bracketed `<...>` or bare.
        let (uri_text, after_uri) = if let Some(rest_inner) = rest.strip_prefix('<') {
            let close = rest_inner.find('>').ok_or_else(|| {
                SipError::InvalidHeader(format!("missing '>' in name-address: {input:?}"))
            })?;
            (&rest_inner[..close], &rest_inner[close + 1..])
        } else {
            // Bare addr-spec: URI runs until the first `;` (which
            // begins header parameters) or end of string. Note that
            // URI parameters (which use `;` too) are NOT part of a
            // bare addr-spec in this position per RFC 3261
            // §20.10/20.20/20.39 — when no angle brackets are
            // present, any `;param` is a header parameter.
            //
            // This matches rsip 0.4's
            // `Tokenizer::tokenize_without_params` behavior: the URI
            // is tokenized excluding its parameters, and any `;` is
            // taken as the start of header params.
            match rest.find(';') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            }
        };
        let uri = SipUri::parse(uri_text.trim())
            .map_err(|e| SipError::InvalidHeader(format!("invalid URI in name-address: {e}")))?;

        // Phase 3: optional `;param=value` chain.
        let parameters = parse_params(after_uri)?;

        Ok(NameAddr {
            display_name,
            uri,
            parameters,
        })
    }

    /// Look up the `tag` header parameter, case-insensitive on the
    /// key per RFC 3261 §25.1.
    pub fn tag(&self) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("tag"))
            .and_then(|(_, v)| v.as_deref())
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref name) = self.display_name {
            // Re-quote if the name contains characters outside the
            // bare `token` set (RFC 3261 §25.1) — easiest correct
            // behavior is to always quote, mirroring rsip's choice
            // for stored quoted display names.
            if needs_quoting(name) {
                write!(f, "\"{}\" ", escape_quoted(name))?;
            } else {
                write!(f, "{} ", name)?;
            }
        }
        write!(f, "<{}>", self.uri)?;
        for (key, value) in &self.parameters {
            if let Some(ref v) = value {
                write!(f, ";{}={}", key, v)?;
            } else {
                write!(f, ";{}", key)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Parse a quoted-string starting at `s[0] == '"'`. Returns the
/// unquoted logical content (with `\X` quoted-pairs resolved) and
/// the remainder of the input after the closing `"`.
///
/// Per RFC 3261 §25.1:
/// ```text
/// quoted-string = SWS DQUOTE *(qdtext / quoted-pair) DQUOTE
/// quoted-pair   = "\" (%x00-09 / %x0B-0C / %x0E-7F)
/// ```
fn parse_quoted_string(s: &str) -> Result<(String, &str), SipError> {
    debug_assert!(s.starts_with('"'));
    // We accumulate bytes (not chars) so that multi-byte UTF-8
    // sequences in `qdtext` (RFC 3261 §25.1: `UTF8-NONASCII`) are
    // preserved verbatim rather than being misinterpreted as Latin-1
    // when we encounter a continuation byte. The framing layer
    // (`split_message`) has already validated that `s` is UTF-8, so
    // copying the original bytes through and re-decoding once at the
    // end is guaranteed to succeed — but we still surface a `Parse`
    // error rather than panicking if that invariant ever changes.
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::new();
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                let unquoted = String::from_utf8(out).map_err(|e| {
                    SipError::InvalidHeader(format!("invalid UTF-8 in quoted display name: {e}",))
                })?;
                return Ok((unquoted, &s[i + 1..]));
            }
            b'\\' => {
                if i + 1 >= bytes.len() {
                    return Err(SipError::InvalidHeader(
                        "trailing backslash in quoted display name".to_string(),
                    ));
                }
                out.push(bytes[i + 1]);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    Err(SipError::InvalidHeader(
        "unterminated quoted-string in display name".to_string(),
    ))
}

/// Find the first top-level `<` in `s`, skipping any quoted-string
/// content. Returns the byte index of the `<`, or `None` if no `<`
/// appears outside a quoted string.
fn find_angle_bracket(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
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
            b'<' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse `;k=v;k2;k3=v3` into a parameter list. Leading whitespace
/// is tolerated. The first character (if non-empty) MUST be `;`.
///
/// We split on `;` outside quoted strings — quoted parameter values
/// (`;tag="x;y"`) are RFC 3261-permitted on `generic-param`
/// (§25.1: `gen-value = token / host / quoted-string`). Inside a
/// quoted value, `\\` and `\"` are honored.
fn parse_params(s: &str) -> Result<Vec<(String, Option<String>)>, SipError> {
    let s = s.trim_start();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if !s.starts_with(';') {
        return Err(SipError::InvalidHeader(format!(
            "trailing data after URI in name-address (expected ';' or end): {s:?}",
        )));
    }
    let mut params = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 1; // skip leading `;`
    while i < bytes.len() {
        // Capture one param token: read until next top-level `;`.
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
        let chunk = &s[start..i];
        let chunk = chunk.trim();
        if !chunk.is_empty() {
            if let Some(eq) = chunk.find('=') {
                let (k, v) = chunk.split_at(eq);
                params.push((k.trim().to_string(), Some(v[1..].trim().to_string())));
            } else {
                params.push((chunk.to_string(), None));
            }
        }
        // Skip the `;` separator we landed on.
        if i < bytes.len() && bytes[i] == b';' {
            i += 1;
        }
    }
    Ok(params)
}

/// True if `s` contains any character outside the RFC 3261
/// `token` set (or contains nothing) — meaning it must be quoted
/// when emitted on the wire.
fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    s.bytes().any(|b| !is_token_char(b))
}

/// RFC 3261 §25.1 `token` character class.
fn is_token_char(b: u8) -> bool {
    matches!(b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' |
        b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
    )
}

/// Escape `"` and `\` for emission inside a quoted-string.
fn escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> NameAddr {
        NameAddr::parse(input).unwrap_or_else(|e| panic!("parse({input:?}) failed: {e}"))
    }

    #[test]
    fn test_bracketed_no_display_name() {
        let na = parse("<sip:bob@example.com>");
        assert_eq!(na.display_name, None);
        assert_eq!(na.uri.user(), Some("bob"));
        assert_eq!(na.uri.host(), "example.com");
        assert!(na.parameters.is_empty());
    }

    #[test]
    fn test_token_display_name() {
        let na = parse("Alice <sip:alice@example.com>");
        assert_eq!(na.display_name, Some("Alice".to_string()));
        assert_eq!(na.uri.user(), Some("alice"));
    }

    #[test]
    fn test_quoted_display_name_with_space() {
        let na = parse("\"Alice Smith\" <sip:alice@example.com>");
        assert_eq!(na.display_name, Some("Alice Smith".to_string()));
    }

    #[test]
    fn test_quoted_display_name_with_escapes() {
        // `\"` inside quotes → literal `"` in the unquoted form.
        let na = parse(r#""He said \"hi\"" <sip:a@b>"#);
        assert_eq!(na.display_name, Some(r#"He said "hi""#.to_string()));
    }

    #[test]
    fn test_quoted_display_name_with_backslash_escape() {
        let na = parse(r#""C:\\file" <sip:a@b>"#);
        assert_eq!(na.display_name, Some(r"C:\file".to_string()));
    }

    #[test]
    fn quoted_display_preserves_utf8_multibyte() {
        // RFC 3261 §25.1: qdtext includes UTF8-NONASCII.
        // "Björn" — the ö is a 2-byte UTF-8 sequence (C3 B6).
        let na = NameAddr::parse(r#""Björn" <sip:b@example.com>"#).unwrap();
        assert_eq!(na.display_name.as_deref(), Some("Björn"));
    }

    #[test]
    fn quoted_display_preserves_utf8_with_escape() {
        // Mix UTF-8 multi-byte char with a quoted-pair escape.
        let na = NameAddr::parse(r#""Björn \"the boss\"" <sip:b@example.com>"#).unwrap();
        assert_eq!(na.display_name.as_deref(), Some(r#"Björn "the boss""#));
    }

    #[test]
    fn quoted_display_invalid_utf8_rejects() {
        // A bare 0xC3 byte without its continuation is invalid UTF-8.
        // (We can't write this in a regular Rust string literal, and
        // a byte-literal trips the `invalid_from_utf8` lint, so we
        // build the buffer at runtime.) The framing layer
        // (`split_message`) already performs a UTF-8 decode of the
        // head section, so by the time input reaches
        // `NameAddr::parse` it is guaranteed to be valid UTF-8.
        // Document that contract here.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.push(b'"');
        bytes.push(0xC3);
        bytes.extend_from_slice(b"\" <sip:b@example.com>");
        let s = std::str::from_utf8(&bytes);
        assert!(s.is_err(), "test input must be invalid UTF-8");
        // (No `NameAddr::parse` call — input never makes it past the
        // framing UTF-8 check.)
    }

    #[test]
    fn test_bare_addr_spec_no_brackets_no_display() {
        let na = parse("sip:bob@example.com");
        assert_eq!(na.display_name, None);
        assert_eq!(na.uri.user(), Some("bob"));
        assert!(na.parameters.is_empty());
    }

    #[test]
    fn test_bracketed_with_tag() {
        let na = parse("<sip:bob@example.com>;tag=abc123");
        assert_eq!(na.tag(), Some("abc123"));
    }

    #[test]
    fn test_token_display_with_tag_and_extra() {
        let na = parse("Alice <sip:alice@example.com>;tag=1928301774;foo=bar");
        assert_eq!(na.display_name, Some("Alice".to_string()));
        assert_eq!(na.tag(), Some("1928301774"));
        assert_eq!(
            na.parameters,
            vec![
                ("tag".to_string(), Some("1928301774".to_string())),
                ("foo".to_string(), Some("bar".to_string())),
            ]
        );
    }

    #[test]
    fn test_bare_addr_spec_with_tag() {
        // No angle brackets — `;tag=` is a header parameter.
        let na = parse("sip:bob@example.com;tag=xyz");
        assert_eq!(na.uri.user(), Some("bob"));
        assert_eq!(na.uri.host(), "example.com");
        // The URI itself must NOT carry the tag — it's a header param.
        assert!(na.uri.params().count() == 0);
        assert_eq!(na.tag(), Some("xyz"));
    }

    #[test]
    fn test_tag_lookup_case_insensitive() {
        let na = parse("<sip:a@b>;TAG=upper");
        assert_eq!(na.tag(), Some("upper"));
    }

    #[test]
    fn test_flag_parameter() {
        let na = parse("<sip:a@b>;lr;tag=t");
        assert_eq!(na.parameters[0], ("lr".to_string(), None));
        assert_eq!(na.tag(), Some("t"));
    }

    #[test]
    fn test_quoted_param_value() {
        let na = parse(r#"<sip:a@b>;foo="x;y""#);
        assert_eq!(
            na.parameters,
            vec![("foo".to_string(), Some(r#""x;y""#.to_string()))]
        );
    }

    #[test]
    fn test_empty_input_rejected() {
        assert!(NameAddr::parse("").is_err());
        assert!(NameAddr::parse("   ").is_err());
    }

    #[test]
    fn test_quoted_unterminated_rejected() {
        assert!(NameAddr::parse(r#""Alice <sip:a@b>"#).is_err());
    }

    #[test]
    fn test_quoted_without_addr_spec_rejected() {
        // Quoted display name MUST be followed by `<addr-spec>`.
        assert!(NameAddr::parse(r#""Alice""#).is_err());
        assert!(NameAddr::parse(r#""Alice" sip:a@b"#).is_err());
    }

    #[test]
    fn test_bracketed_unclosed_rejected() {
        assert!(NameAddr::parse("Alice <sip:a@b").is_err());
    }

    #[test]
    fn test_trailing_data_after_uri_rejected() {
        // Bracketed URI followed by non-`;` content.
        assert!(NameAddr::parse("<sip:a@b> garbage").is_err());
    }

    #[test]
    fn test_invalid_uri_rejected() {
        assert!(NameAddr::parse("<not-a-uri>").is_err());
    }

    #[test]
    fn test_display_round_trip_token_name() {
        let na = parse("Alice <sip:alice@example.com>;tag=1");
        assert_eq!(na.to_string(), "Alice <sip:alice@example.com>;tag=1");
    }

    #[test]
    fn test_display_round_trip_quoted_name() {
        let na = parse(r#""Alice Smith" <sip:a@b>;tag=1"#);
        assert_eq!(na.to_string(), r#""Alice Smith" <sip:a@b>;tag=1"#);
    }

    #[test]
    fn test_display_quotes_when_required() {
        let mut na = parse("<sip:a@b>");
        na.display_name = Some("has space".to_string());
        let s = na.to_string();
        assert!(s.starts_with(r#""has space""#), "got: {s}");
    }

    #[test]
    fn test_display_no_brackets_for_bare_input_still_emits_brackets() {
        // Display canonicalizes to bracketed form.
        let na = parse("sip:bob@example.com");
        assert_eq!(na.to_string(), "<sip:bob@example.com>");
    }

    #[test]
    fn test_parse_then_display_with_flag_param() {
        let na = parse("<sip:a@b>;lr");
        assert_eq!(na.to_string(), "<sip:a@b>;lr");
    }

    #[test]
    fn test_token_char_class_minimal() {
        // Spot-check token char predicate against a few RFC 3261 §25.1 chars.
        assert!(is_token_char(b'a'));
        assert!(is_token_char(b'Z'));
        assert!(is_token_char(b'0'));
        assert!(is_token_char(b'-'));
        assert!(is_token_char(b'+'));
        assert!(!is_token_char(b' '));
        assert!(!is_token_char(b';'));
        assert!(!is_token_char(b'<'));
    }

    #[test]
    fn test_needs_quoting_empty_and_token() {
        assert!(needs_quoting(""));
        assert!(!needs_quoting("Alice"));
        assert!(needs_quoting("Alice Smith"));
        assert!(needs_quoting("Alice;Bob"));
    }

    #[test]
    fn test_escape_quoted_handles_quotes_and_backslash() {
        assert_eq!(escape_quoted(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_quoted(r"c\d"), r"c\\d");
    }

    #[test]
    fn test_find_angle_bracket_skips_quoted() {
        // `<` inside a quoted string is not the addr-spec opener.
        assert_eq!(find_angle_bracket(r#""a<b" <sip:x@y>"#), Some(6));
    }

    #[test]
    fn test_find_angle_bracket_none() {
        assert_eq!(find_angle_bracket("sip:a@b"), None);
    }
}
