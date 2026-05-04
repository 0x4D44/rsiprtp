//! SIP URI handling.
//!
//! This module provides a wrapper around SIP URIs with convenience methods
//! for common operations like extracting user, host, and transport information.
//!
//! Coverage of RFC 3261 §19.1 and RFC 3966 (`tel:` URIs):
//!
//! - `sip:` and `sips:` schemes with full `user@host:port;params?headers`
//!   syntax (RFC 3261 §19.1.1).
//! - `tel:` URIs (RFC 3966) — phone-number, parameters, headers. Stored in
//!   the same `SipUri` struct with `scheme = Tel`; the phone-number lives
//!   in the `host` field, `user` is always `None`, `port` is always `None`.
//! - URI headers (`?key=value&...`) are parsed, preserved, and re-emitted
//!   on `Display`. Used for embedded message-construction targets such as
//!   `sip:foo@bar?Subject=Hi&Body=`.
//! - IPv6 references in brackets, `lr`, `transport`, and other parameters.
//!
//! Internally we now expose a [`Scheme`] enum for type-safe matching, but
//! the legacy `scheme(&self) -> &str` accessor is preserved verbatim so
//! existing call sites continue to compile and existing tests still pass.

use crate::core::SipError;
use std::fmt;

/// URI scheme as defined in RFC 3261 §19.1 and RFC 3966.
///
/// We model the three schemes we actually support directly. Anything
/// else is rejected at parse time with [`SipError::Parse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Plain SIP — RFC 3261 §19.1.
    Sip,
    /// Secure SIP (TLS-required) — RFC 3261 §19.1.
    Sips,
    /// Telephone URI — RFC 3966.
    Tel,
}

impl Scheme {
    /// Return the canonical lowercase wire form (`"sip"`, `"sips"`, `"tel"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Sip => "sip",
            Scheme::Sips => "sips",
            Scheme::Tel => "tel",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// SIP URI wrapper with convenience methods.
///
/// Models RFC 3261 §19.1 SIP/SIPS URIs and RFC 3966 `tel:` URIs in a
/// single struct. For `tel:` URIs `user` is `None`, `host` carries the
/// phone-number subscriber, and `port` is `None`.
#[derive(Debug, Clone, PartialEq)]
pub struct SipUri {
    /// The scheme (sip, sips, or tel).
    scheme: Scheme,
    /// User part (optional). Always `None` for `tel:` URIs.
    user: Option<String>,
    /// Host part (required) — the authority for `sip`/`sips`, or the
    /// phone-number subscriber for `tel`.
    host: String,
    /// Port (optional). Always `None` for `tel:` URIs.
    port: Option<u16>,
    /// URI parameters (`;key=value` pairs after the host[:port]).
    params: Vec<(String, Option<String>)>,
    /// URI headers (`?key=value&...` after the parameters). Per RFC 3261
    /// §19.1.1 these are *not* the same as message headers — they are
    /// part of the URI itself, used to populate the headers of any
    /// message constructed from the URI (e.g. `sip:foo@bar?Subject=Hi`).
    headers: Vec<(String, String)>,
}

impl SipUri {
    /// Parse a SIP URI from a string.
    ///
    /// Supports formats like:
    /// - `sip:user@host`
    /// - `sip:user@host:5060`
    /// - `sips:user@host;transport=tcp`
    /// - `sip:host;lr`
    /// - `sip:user@host;param=v?Header1=A&Header2=B`
    /// - `tel:+1-212-555-1212`
    /// - `tel:+1-212-555-1212;phone-context=example.com`
    pub fn parse(s: &str) -> Result<Self, SipError> {
        let s = s.trim();

        // Parse scheme.
        let (scheme, rest) = if let Some(idx) = s.find(':') {
            let scheme_str = s[..idx].to_lowercase();
            let scheme = match scheme_str.as_str() {
                "sip" => Scheme::Sip,
                "sips" => Scheme::Sips,
                "tel" => Scheme::Tel,
                _ => {
                    return Err(SipError::Parse(format!(
                        "Invalid SIP URI scheme: {}",
                        scheme_str
                    )))
                }
            };
            (scheme, &s[idx + 1..])
        } else {
            return Err(SipError::Parse("Missing scheme in SIP URI".to_string()));
        };

        // Split off URI headers (after `?`).
        //
        // RFC 3261 §19.1.1: the `?` introduces URI-headers. They are
        // separated by `&` and each is `key=value`. We do not attempt
        // percent-decoding here — values stay as-on-the-wire.
        let (rest, headers) = if let Some(idx) = rest.find('?') {
            let (uri_part, header_part) = rest.split_at(idx);
            let header_part = &header_part[1..]; // skip '?'
            let mut hs: Vec<(String, String)> = Vec::new();
            for h in header_part.split('&') {
                if h.is_empty() {
                    continue;
                }
                if let Some(eq) = h.find('=') {
                    hs.push((h[..eq].to_string(), h[eq + 1..].to_string()));
                } else {
                    // No `=` — store the whole token as a header name
                    // with an empty value. Lenient by design.
                    hs.push((h.to_string(), String::new()));
                }
            }
            (uri_part, hs)
        } else {
            (rest, Vec::new())
        };

        // Split off parameters (after first `;` that is part of the
        // hostport-and-params section, NOT the userinfo).
        //
        // RFC 3261 §19.1.1: the URI grammar is
        //
        //   SIP-URI = "sip:" [ userinfo ] hostport
        //             *( ";" uri-parameter ) [ "?" headers ]
        //   userinfo = ( user / telephone-subscriber ) [ ":" password ] "@"
        //
        // and `user` may legitimately contain `;` (per the
        // user-unreserved set: `& = + $ , ; ? /`). RFC 4475 §3.1.2.8
        // (semiuri) tortures this corner. So if there's an `@` in
        // `rest`, parameters can only start *after* the `@`. If
        // there's no `@`, the whole prefix is hostport and the first
        // `;` is the param separator.
        let userinfo_end = rest.find('@').map(|i| i + 1).unwrap_or(0);
        let (user_host_port, params_str) = match rest[userinfo_end..].find(';') {
            Some(rel_idx) => {
                let abs_idx = userinfo_end + rel_idx;
                (&rest[..abs_idx], Some(&rest[abs_idx + 1..]))
            }
            None => (rest, None),
        };

        // Resolve user / host / port. `tel:` URIs have no user and no
        // port — the entire `user_host_port` slice is the phone number.
        let (user, host, port) = if scheme == Scheme::Tel {
            (None, user_host_port.to_string(), None)
        } else {
            // Parse user and host
            let (user, host_port) = if let Some(idx) = user_host_port.find('@') {
                (
                    Some(user_host_port[..idx].to_string()),
                    &user_host_port[idx + 1..],
                )
            } else {
                (None, user_host_port)
            };

            // Parse host and port
            let (host, port) = if host_port.starts_with('[') {
                // IPv6 address
                if let Some(bracket_end) = host_port.find(']') {
                    let ipv6_host = host_port[..bracket_end + 1].to_string();
                    let after_bracket = &host_port[bracket_end + 1..];
                    let port = if let Some(port_str) = after_bracket.strip_prefix(':') {
                        port_str.parse().ok()
                    } else {
                        None
                    };
                    (ipv6_host, port)
                } else {
                    return Err(SipError::Parse(
                        "Invalid IPv6 address in SIP URI".to_string(),
                    ));
                }
            } else if let Some(idx) = host_port.rfind(':') {
                let potential_port = &host_port[idx + 1..];
                if potential_port.chars().all(|c| c.is_ascii_digit()) {
                    (host_port[..idx].to_string(), potential_port.parse().ok())
                } else {
                    (host_port.to_string(), None)
                }
            } else {
                (host_port.to_string(), None)
            };
            (user, host, port)
        };

        // Parse parameters
        let mut params = Vec::new();
        if let Some(params_str) = params_str {
            for param in params_str.split(';') {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }
                if let Some(idx) = param.find('=') {
                    params.push((param[..idx].to_string(), Some(param[idx + 1..].to_string())));
                } else {
                    params.push((param.to_string(), None));
                }
            }
        }

        Ok(SipUri {
            scheme,
            user,
            host,
            port,
            params,
            headers,
        })
    }

    /// Get the URI scheme as its lowercase wire string (`"sip"`,
    /// `"sips"`, or `"tel"`). Preserved for backward compatibility with
    /// pre-M3 callers; new code should prefer [`SipUri::scheme_enum`].
    pub fn scheme(&self) -> &str {
        self.scheme.as_str()
    }

    /// Get the URI scheme as a typed [`Scheme`] enum.
    pub fn scheme_enum(&self) -> Scheme {
        self.scheme
    }

    /// Get the user part (if present).
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Get the host part. For a `tel:` URI this is the phone-number
    /// subscriber; for `sip`/`sips` it is the authority host.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port (if present).
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Get the effective port (returns default 5060/5061 if not specified).
    /// For `tel:` URIs (no port concept) this still returns 5060 to keep
    /// the contract uniform; callers should gate on the scheme first.
    pub fn effective_port(&self) -> u16 {
        self.port
            .unwrap_or(if self.is_secure() { 5061 } else { 5060 })
    }

    /// Get the transport parameter.
    pub fn transport(&self) -> Option<&str> {
        self.get_param("transport")
    }

    /// Check if this is a secure URI (`sips:`).
    pub fn is_secure(&self) -> bool {
        self.scheme == Scheme::Sips
    }

    /// Check if this is a `tel:` URI.
    pub fn is_tel(&self) -> bool {
        self.scheme == Scheme::Tel
    }

    /// Get the user part for routing.
    pub fn user_part(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Create request URI from this AOR.
    ///
    /// Returns the URI string suitable for use as a Request-URI.
    pub fn to_request_uri(&self) -> String {
        self.to_string()
    }

    /// Get a parameter value.
    pub fn get_param(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .and_then(|(_, v)| v.as_deref())
    }

    /// Check if a parameter exists (even without a value).
    pub fn has_param(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.params
            .iter()
            .any(|(k, _)| k.to_lowercase() == name_lower)
    }

    /// Iterate over all URI parameters in wire order.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_deref()))
    }

    /// Iterate over all URI headers in wire order.
    ///
    /// URI headers (RFC 3261 §19.1.1) are the `?key=value&...` portion
    /// of a SIP URI — distinct from the headers of a SIP message. They
    /// are typically used to seed the headers of any message
    /// constructed from this URI (e.g. `sip:foo@bar?Subject=Hi`).
    pub fn headers(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Get a URI-header value by name (case-insensitive lookup).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Returns true if any URI headers are attached.
    pub fn has_headers(&self) -> bool {
        !self.headers.is_empty()
    }

    /// Check if the lr (loose routing) parameter is present.
    pub fn is_loose_route(&self) -> bool {
        self.has_param("lr")
    }

    /// Create a new SipUri builder.
    pub fn builder() -> SipUriBuilder {
        SipUriBuilder::new()
    }

    /// Internal: convert from rsip's URI form. Used by the wrapper layer
    /// during M7-M9 transition; will be removed in M10 when rsip leaves
    /// the runtime deps and the parser layer becomes authoritative.
    pub(crate) fn from_rsip(rsip_uri: &rsip::Uri) -> Result<Self, SipError> {
        Self::parse(&rsip_uri.to_string())
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme.as_str())?;

        if let Some(ref user) = self.user {
            write!(f, "{}@", user)?;
        }

        write!(f, "{}", self.host)?;

        if let Some(port) = self.port {
            write!(f, ":{}", port)?;
        }

        for (key, value) in &self.params {
            if let Some(v) = value {
                write!(f, ";{}={}", key, v)?;
            } else {
                write!(f, ";{}", key)?;
            }
        }

        if !self.headers.is_empty() {
            f.write_str("?")?;
            for (i, (k, v)) in self.headers.iter().enumerate() {
                if i > 0 {
                    f.write_str("&")?;
                }
                write!(f, "{}={}", k, v)?;
            }
        }

        Ok(())
    }
}

/// Builder for SIP URIs.
#[derive(Debug, Default)]
pub struct SipUriBuilder {
    scheme: Option<Scheme>,
    user: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    params: Vec<(String, Option<String>)>,
    headers: Vec<(String, String)>,
}

impl SipUriBuilder {
    /// Create a new SipUriBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the scheme by name (defaults to `"sip"`). Accepts `"sip"`,
    /// `"sips"`, `"tel"`, case-insensitive. Unknown schemes silently
    /// fall back to `"sip"` to preserve pre-M3 builder semantics
    /// (the builder never returned an error before, so we don't
    /// introduce a new error path here — `build()` validates the host
    /// presence and that's enough).
    pub fn scheme(mut self, scheme: &str) -> Self {
        let s = scheme.to_lowercase();
        let scheme_enum = match s.as_str() {
            "sips" => Scheme::Sips,
            "tel" => Scheme::Tel,
            _ => Scheme::Sip,
        };
        self.scheme = Some(scheme_enum);
        self
    }

    /// Set the scheme directly via the typed enum.
    pub fn scheme_enum(mut self, scheme: Scheme) -> Self {
        self.scheme = Some(scheme);
        self
    }

    /// Set the user part.
    pub fn user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }

    /// Set the host part.
    pub fn host(mut self, host: &str) -> Self {
        self.host = Some(host.to_string());
        self
    }

    /// Set the port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Add a parameter with a value.
    pub fn param(mut self, key: &str, value: &str) -> Self {
        self.params.push((key.to_string(), Some(value.to_string())));
        self
    }

    /// Add a parameter without a value (flag).
    pub fn flag(mut self, key: &str) -> Self {
        self.params.push((key.to_string(), None));
        self
    }

    /// Set the transport parameter.
    pub fn transport(self, transport: &str) -> Self {
        self.param("transport", transport)
    }

    /// Add the lr (loose routing) parameter.
    pub fn loose_route(self) -> Self {
        self.flag("lr")
    }

    /// Append a URI header (`?key=value&...` portion).
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    /// Build the SipUri.
    pub fn build(self) -> Result<SipUri, SipError> {
        let host = self
            .host
            .ok_or_else(|| SipError::InvalidHeader("Missing host in SIP URI".to_string()))?;

        Ok(SipUri {
            scheme: self.scheme.unwrap_or(Scheme::Sip),
            user: self.user,
            host,
            port: self.port,
            params: self.params,
            headers: self.headers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn test_parse_simple_uri() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        assert_eq!(uri.scheme(), "sip");
        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.host(), "example.com");
        assert_eq!(uri.port(), None);
        assert!(!uri.is_secure());
    }

    #[test]
    fn test_parse_uri_with_port() {
        let uri = SipUri::parse("sip:bob@192.168.1.1:5080").unwrap();
        assert_eq!(uri.user(), Some("bob"));
        assert_eq!(uri.host(), "192.168.1.1");
        assert_eq!(uri.port(), Some(5080));
        assert_eq!(uri.effective_port(), 5080);
    }

    #[test]
    fn test_parse_sips_uri() {
        let uri = SipUri::parse("sips:secure@example.com").unwrap();
        assert_eq!(uri.scheme(), "sips");
        assert!(uri.is_secure());
        assert_eq!(uri.effective_port(), 5061);
    }

    #[test]
    fn test_parse_uri_with_params() {
        let uri = SipUri::parse("sip:proxy.example.com;transport=tcp;lr").unwrap();
        assert_eq!(uri.user(), None);
        assert_eq!(uri.host(), "proxy.example.com");
        assert_eq!(uri.transport(), Some("tcp"));
        assert!(uri.is_loose_route());
    }

    #[test]
    fn test_parse_uri_host_only() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        assert_eq!(uri.user(), None);
        assert_eq!(uri.host(), "example.com");
    }

    #[test]
    fn test_uri_to_string() {
        let uri = SipUri::parse("sip:alice@example.com:5060;transport=udp").unwrap();
        let s = uri.to_string();
        assert!(s.starts_with("sip:"));
        assert!(s.contains("alice@"));
        assert!(s.contains("example.com"));
        assert!(s.contains(":5060"));
        assert!(s.contains("transport=udp"));
    }

    #[test]
    fn test_uri_display_error_paths() {
        struct CountingWriter {
            writes: usize,
        }

        impl std::fmt::Write for CountingWriter {
            fn write_str(&mut self, _s: &str) -> std::fmt::Result {
                self.writes += 1;
                Ok(())
            }
        }

        struct FailingWriter {
            fail_at: usize,
            writes: usize,
        }

        impl FailingWriter {
            fn new(fail_at: usize) -> Self {
                Self { fail_at, writes: 0 }
            }
        }

        impl std::fmt::Write for FailingWriter {
            fn write_str(&mut self, _s: &str) -> std::fmt::Result {
                self.writes += 1;
                if self.writes == self.fail_at {
                    return Err(std::fmt::Error);
                }
                Ok(())
            }
        }

        let uri = SipUri::builder()
            .scheme("sip")
            .user("alice")
            .host("example.com")
            .port(5060)
            .transport("udp")
            .loose_route()
            .header("Subject", "hi")
            .build()
            .unwrap();

        let mut counter = CountingWriter { writes: 0 };
        let _ = write!(&mut counter, "{}", uri);
        let total_writes = counter.writes;

        for fail_at in 1..=total_writes {
            let mut writer = FailingWriter::new(fail_at);
            let _ = write!(&mut writer, "{}", uri);
        }
    }

    #[test]
    fn test_uri_builder() {
        let uri = SipUri::builder()
            .host("proxy.example.com")
            .port(5060)
            .transport("tcp")
            .loose_route()
            .build()
            .unwrap();

        assert_eq!(uri.host(), "proxy.example.com");
        assert_eq!(uri.port(), Some(5060));
        assert_eq!(uri.transport(), Some("tcp"));
        assert!(uri.is_loose_route());
    }

    #[test]
    fn test_uri_builder_with_user() {
        let uri = SipUri::builder()
            .scheme("sips")
            .user("alice")
            .host("example.com")
            .build()
            .unwrap();

        assert_eq!(uri.scheme(), "sips");
        assert_eq!(uri.user(), Some("alice"));
        assert!(uri.is_secure());
    }

    #[test]
    fn test_uri_builder_missing_host() {
        let result = SipUri::builder().user("alice").build();

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_scheme() {
        let result = SipUri::parse("http://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_uri_has_param() {
        let uri = SipUri::parse("sip:proxy.example.com;lr;transport=tcp").unwrap();
        assert!(uri.has_param("lr"));
        assert!(uri.has_param("transport"));
        assert!(!uri.has_param("maddr"));
    }

    #[test]
    fn test_uri_roundtrip() {
        let original = "sip:alice@example.com:5060;transport=tcp;lr";
        let uri = SipUri::parse(original).unwrap();
        let serialized = uri.to_string();
        let reparsed = SipUri::parse(&serialized).unwrap();

        assert_eq!(uri.scheme(), reparsed.scheme());
        assert_eq!(uri.user(), reparsed.user());
        assert_eq!(uri.host(), reparsed.host());
        assert_eq!(uri.port(), reparsed.port());
        assert_eq!(uri.transport(), reparsed.transport());
        assert_eq!(uri.is_loose_route(), reparsed.is_loose_route());
    }

    // Additional tests for uncovered paths

    #[test]
    fn test_parse_ipv6_address() {
        let uri = SipUri::parse("sip:alice@[::1]").unwrap();
        assert_eq!(uri.host(), "[::1]");
        assert_eq!(uri.port(), None);
    }

    #[test]
    fn test_parse_ipv6_address_with_port() {
        let uri = SipUri::parse("sip:alice@[2001:db8::1]:5060").unwrap();
        assert_eq!(uri.host(), "[2001:db8::1]");
        assert_eq!(uri.port(), Some(5060));
    }

    #[test]
    fn test_parse_ipv6_invalid_bracket() {
        let result = SipUri::parse("sip:alice@[::1");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_scheme() {
        let result = SipUri::parse("alice@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_user_part() {
        let uri = SipUri::parse("sip:bob@example.com").unwrap();
        assert_eq!(uri.user_part(), Some("bob"));

        let uri2 = SipUri::parse("sip:example.com").unwrap();
        assert_eq!(uri2.user_part(), None);
    }

    /// RFC 3261 §25.1 `user-unreserved` includes `;`, so a SIP URI
    /// `sip:user;par=v@host` has user `user;par=v` and host `host` —
    /// the `;` before the `@` is part of the user portion, NOT the
    /// boundary between hostport and parameters. RFC 4475 §3.1.2.8
    /// (semiuri) tortures this corner.
    #[test]
    fn test_semicolon_in_user_part_rfc4475_semiuri() {
        let uri = SipUri::parse("sip:user;par=u%40example.net@example.com").unwrap();
        assert_eq!(uri.user(), Some("user;par=u%40example.net"));
        assert_eq!(uri.host(), "example.com");
        assert_eq!(uri.params().count(), 0, "no URI parameters");
    }

    /// Without an `@` the first `;` IS the params boundary —
    /// `sip:host;lr` has host `host` and a flag param `lr`.
    #[test]
    fn test_semicolon_with_no_user_is_param_boundary() {
        let uri = SipUri::parse("sip:host.example.com;lr").unwrap();
        assert_eq!(uri.user(), None);
        assert_eq!(uri.host(), "host.example.com");
        let params: Vec<_> = uri.params().collect();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "lr");
    }

    #[test]
    fn test_empty_host_after_at_is_lenient() {
        // Pathological: `sip:bob@;param`. Currently parses with host = "".
        // RFC 3261 §19.1.1 implies host MUST be present, but our parser is
        // lenient. Pinned here so any future strict-parse change is deliberate.
        let uri = SipUri::parse("sip:bob@;lr").unwrap();
        assert_eq!(uri.user(), Some("bob"));
        assert_eq!(uri.host(), "");
    }

    /// With an `@` and `;` BOTH before AND after, the user portion
    /// captures everything up to the `@`; URI params start after.
    #[test]
    fn test_semicolon_in_user_and_params() {
        let uri = SipUri::parse("sip:user;a=1@host.example.com;lr;b=2").unwrap();
        assert_eq!(uri.user(), Some("user;a=1"));
        assert_eq!(uri.host(), "host.example.com");
        let params: Vec<_> = uri.params().collect();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].0, "lr");
        assert_eq!(params[1].0, "b");
        assert_eq!(params[1].1, Some("2"));
    }

    #[test]
    fn test_to_request_uri() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let req_uri = uri.to_request_uri();
        assert_eq!(req_uri, "sip:alice@example.com");
    }

    #[test]
    fn test_effective_port_default_sip() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        assert_eq!(uri.effective_port(), 5060);
    }

    #[test]
    fn test_effective_port_default_sips() {
        let uri = SipUri::parse("sips:example.com").unwrap();
        assert_eq!(uri.effective_port(), 5061);
    }

    #[test]
    fn test_display_host_only() {
        let uri = SipUri::builder().host("example.com").build().unwrap();
        let s = uri.to_string();
        assert_eq!(s, "sip:example.com");
    }

    #[test]
    fn test_display_with_flag_param() {
        let uri = SipUri::builder()
            .host("proxy.example.com")
            .flag("lr")
            .build()
            .unwrap();
        let s = uri.to_string();
        assert!(s.contains(";lr"));
        assert!(!s.contains("="));
    }

    #[test]
    fn test_get_param_case_insensitive() {
        let uri = SipUri::parse("sip:proxy.example.com;Transport=TCP").unwrap();
        assert_eq!(uri.get_param("transport"), Some("TCP"));
        assert_eq!(uri.get_param("TRANSPORT"), Some("TCP"));
    }

    #[test]
    fn test_has_param_case_insensitive() {
        let uri = SipUri::parse("sip:proxy.example.com;LR").unwrap();
        assert!(uri.has_param("lr"));
        assert!(uri.has_param("LR"));
        assert!(uri.has_param("Lr"));
    }

    #[test]
    fn test_transport_none() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        assert_eq!(uri.transport(), None);
    }

    #[test]
    fn test_is_loose_route_false() {
        let uri = SipUri::parse("sip:example.com").unwrap();
        assert!(!uri.is_loose_route());
    }

    #[test]
    fn test_parse_empty_params() {
        // Empty param section after semicolon
        let uri = SipUri::parse("sip:example.com;").unwrap();
        assert_eq!(uri.host(), "example.com");
    }

    #[test]
    fn test_parse_multiple_semicolons() {
        let uri = SipUri::parse("sip:example.com;;lr;;transport=tcp").unwrap();
        assert!(uri.is_loose_route());
        assert_eq!(uri.transport(), Some("tcp"));
    }

    #[test]
    fn test_uri_debug() {
        let uri = SipUri::parse("sip:alice@example.com").unwrap();
        let debug = format!("{:?}", uri);
        assert!(debug.contains("SipUri"));
    }

    #[test]
    fn test_uri_clone() {
        let uri = SipUri::parse("sip:alice@example.com:5060;transport=tcp").unwrap();
        let cloned = uri.clone();
        assert_eq!(uri.scheme(), cloned.scheme());
        assert_eq!(uri.user(), cloned.user());
        assert_eq!(uri.host(), cloned.host());
        assert_eq!(uri.port(), cloned.port());
    }

    #[test]
    fn test_uri_eq() {
        let uri1 = SipUri::parse("sip:alice@example.com").unwrap();
        let uri2 = SipUri::parse("sip:alice@example.com").unwrap();
        assert_eq!(uri1, uri2);

        let uri3 = SipUri::parse("sip:bob@example.com").unwrap();
        assert_ne!(uri1, uri3);
    }

    #[test]
    fn test_uri_builder_default() {
        let builder = SipUriBuilder::default();
        let result = builder.host("example.com").build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_uri_builder_debug() {
        let builder = SipUri::builder().host("example.com");
        let debug = format!("{:?}", builder);
        assert!(debug.contains("SipUriBuilder"));
    }

    #[test]
    fn test_uri_builder_flag() {
        let uri = SipUri::builder()
            .host("example.com")
            .flag("rport")
            .flag("lr")
            .build()
            .unwrap();

        assert!(uri.has_param("rport"));
        assert!(uri.has_param("lr"));
    }

    #[test]
    fn test_uri_builder_param() {
        let uri = SipUri::builder()
            .host("example.com")
            .param("maddr", "proxy.example.com")
            .build()
            .unwrap();

        assert_eq!(uri.get_param("maddr"), Some("proxy.example.com"));
    }

    #[test]
    fn test_parse_host_with_colon_no_port() {
        // Host that happens to have non-digit after last colon
        let uri = SipUri::parse("sip:example.com:abc").unwrap();
        assert_eq!(uri.host(), "example.com:abc");
        assert_eq!(uri.port(), None);
    }

    #[test]
    fn test_parse_whitespace_trimmed() {
        let uri = SipUri::parse("  sip:alice@example.com  ").unwrap();
        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.host(), "example.com");
    }

    #[test]
    fn test_scheme_case_normalized() {
        let uri = SipUri::parse("SIP:alice@example.com").unwrap();
        assert_eq!(uri.scheme(), "sip");

        let uri2 = SipUri::parse("SIPS:alice@example.com").unwrap();
        assert_eq!(uri2.scheme(), "sips");
        assert!(uri2.is_secure());
    }

    #[test]
    fn test_builder_scheme_case_normalized() {
        let uri = SipUri::builder()
            .scheme("SIPS")
            .host("example.com")
            .build()
            .unwrap();
        assert_eq!(uri.scheme(), "sips");
        assert!(uri.is_secure());
    }

    // ----- M3 additions: tel scheme, URI headers, Scheme enum, accessors -----

    /// RFC 3966: a bare `tel:` URI parses as `scheme=Tel`, no user, the
    /// phone-number subscriber in `host`, no port.
    #[test]
    fn test_parse_tel_uri_basic() {
        let uri = SipUri::parse("tel:+1-212-555-1212").unwrap();
        assert_eq!(uri.scheme(), "tel");
        assert_eq!(uri.scheme_enum(), Scheme::Tel);
        assert!(uri.is_tel());
        assert!(!uri.is_secure());
        assert_eq!(uri.user(), None);
        assert_eq!(uri.host(), "+1-212-555-1212");
        assert_eq!(uri.port(), None);
    }

    /// `tel:` URIs carry parameters (e.g. `phone-context`); they must
    /// not be misread as a SIP-style host:port — the colon between `+1`
    /// and `212` would otherwise be mis-parsed as a port boundary.
    #[test]
    fn test_parse_tel_uri_with_params_and_colons() {
        let uri = SipUri::parse("tel:+1-212-555-1212;phone-context=example.com").unwrap();
        assert_eq!(uri.scheme(), "tel");
        assert_eq!(uri.host(), "+1-212-555-1212");
        assert_eq!(uri.port(), None);
        assert_eq!(uri.get_param("phone-context"), Some("example.com"));
    }

    /// A tel-URI without the `+` global indicator is also valid per
    /// RFC 3966 §5.1.5 (local subscriber). Round-trip via Display.
    #[test]
    fn test_tel_uri_round_trip_local() {
        let uri = SipUri::parse("tel:7042;phone-context=example.com").unwrap();
        let s = uri.to_string();
        assert_eq!(s, "tel:7042;phone-context=example.com");
        let reparsed = SipUri::parse(&s).unwrap();
        assert_eq!(uri, reparsed);
    }

    /// URI headers (the `?key=value&...` portion of RFC 3261 §19.1.1)
    /// are parsed into the `headers` collection and survive Display.
    #[test]
    fn test_parse_uri_with_headers() {
        let uri = SipUri::parse("sip:alice@example.com?Subject=Hi&Body=Hello").unwrap();
        assert_eq!(uri.user(), Some("alice"));
        assert_eq!(uri.host(), "example.com");
        assert_eq!(uri.get_header("Subject"), Some("Hi"));
        assert_eq!(uri.get_header("body"), Some("Hello")); // case-insensitive
        assert!(uri.has_headers());
        let collected: Vec<(&str, &str)> = uri.headers().collect();
        assert_eq!(collected, vec![("Subject", "Hi"), ("Body", "Hello")]);
    }

    /// URI with both parameters and headers — must split correctly on
    /// `;` (params) vs `?` (headers).
    #[test]
    fn test_parse_uri_params_and_headers() {
        let uri =
            SipUri::parse("sip:alice@example.com:5060;transport=tcp?Subject=Hi&X-Foo=Bar").unwrap();
        assert_eq!(uri.port(), Some(5060));
        assert_eq!(uri.transport(), Some("tcp"));
        assert_eq!(uri.get_header("Subject"), Some("Hi"));
        assert_eq!(uri.get_header("X-Foo"), Some("Bar"));
    }

    /// URI headers round-trip via Display — emitted in original order
    /// with `?` prefix and `&` separators.
    #[test]
    fn test_uri_headers_display_round_trip() {
        let original = "sip:alice@example.com?Subject=Hi&Body=Hello";
        let uri = SipUri::parse(original).unwrap();
        assert_eq!(uri.to_string(), original);
        // Reparse for full structural round-trip.
        let reparsed = SipUri::parse(&uri.to_string()).unwrap();
        assert_eq!(uri, reparsed);
    }

    /// URI header with no `=` is preserved as a name-only token with an
    /// empty value (lenient parse — real-world inputs occasionally omit
    /// `=` for boolean-style header markers).
    #[test]
    fn test_parse_uri_header_no_equals() {
        let uri = SipUri::parse("sip:alice@example.com?Foo").unwrap();
        assert_eq!(uri.get_header("Foo"), Some(""));
    }

    /// Empty header tokens between `&` separators are silently dropped
    /// (e.g. `?A=1&&B=2`).
    #[test]
    fn test_parse_uri_headers_empty_tokens() {
        let uri = SipUri::parse("sip:alice@example.com?A=1&&B=2").unwrap();
        assert_eq!(uri.get_header("A"), Some("1"));
        assert_eq!(uri.get_header("B"), Some("2"));
        let count = uri.headers().count();
        assert_eq!(count, 2);
    }

    /// Scheme enum exposes typed matching alongside the legacy
    /// `scheme()` &str accessor — both must agree.
    #[test]
    fn test_scheme_enum_variants() {
        let sip = SipUri::parse("sip:a@b").unwrap();
        let sips = SipUri::parse("sips:a@b").unwrap();
        let tel = SipUri::parse("tel:+1234").unwrap();

        assert_eq!(sip.scheme_enum(), Scheme::Sip);
        assert_eq!(sips.scheme_enum(), Scheme::Sips);
        assert_eq!(tel.scheme_enum(), Scheme::Tel);

        assert_eq!(Scheme::Sip.as_str(), "sip");
        assert_eq!(Scheme::Sips.as_str(), "sips");
        assert_eq!(Scheme::Tel.as_str(), "tel");

        // Display agrees with as_str.
        assert_eq!(format!("{}", Scheme::Sip), "sip");
        assert_eq!(format!("{}", Scheme::Sips), "sips");
        assert_eq!(format!("{}", Scheme::Tel), "tel");
    }

    /// Builder accepts the typed Scheme enum directly.
    #[test]
    fn test_builder_scheme_enum() {
        let uri = SipUri::builder()
            .scheme_enum(Scheme::Tel)
            .host("+12125551212")
            .build()
            .unwrap();
        assert!(uri.is_tel());
        assert_eq!(uri.to_string(), "tel:+12125551212");
    }

    /// Unknown scheme strings on the builder fall back to `sip` (the
    /// builder is total — preserves the pre-M3 contract that
    /// `.scheme(s).host(h).build()` never errors on a bad scheme).
    #[test]
    fn test_builder_unknown_scheme_defaults_to_sip() {
        let uri = SipUri::builder()
            .scheme("ftp")
            .host("example.com")
            .build()
            .unwrap();
        assert_eq!(uri.scheme(), "sip");
    }

    /// Builder appends URI headers; Display emits them.
    #[test]
    fn test_builder_with_headers() {
        let uri = SipUri::builder()
            .host("example.com")
            .header("Subject", "Hi")
            .header("Body", "Hello")
            .build()
            .unwrap();
        assert!(uri.has_headers());
        let s = uri.to_string();
        assert!(s.ends_with("?Subject=Hi&Body=Hello"), "got {}", s);
    }

    /// Iterating params yields wire order with case preserved.
    #[test]
    fn test_params_iterator_preserves_order_and_case() {
        let uri = SipUri::parse("sip:host;Foo=1;bar;Baz=3").unwrap();
        let collected: Vec<(&str, Option<&str>)> = uri.params().collect();
        assert_eq!(
            collected,
            vec![("Foo", Some("1")), ("bar", None), ("Baz", Some("3"))]
        );
    }
}
