//! SIP URI handling.
//!
//! This module provides a wrapper around SIP URIs with convenience methods
//! for common operations like extracting user, host, and transport information.

use crate::core::SipError;
use std::fmt;

/// SIP URI wrapper with convenience methods.
#[derive(Debug, Clone, PartialEq)]
pub struct SipUri {
    /// The scheme (sip or sips).
    scheme: String,
    /// User part (optional).
    user: Option<String>,
    /// Host part (required).
    host: String,
    /// Port (optional).
    port: Option<u16>,
    /// URI parameters (key=value pairs).
    params: Vec<(String, Option<String>)>,
}

impl SipUri {
    /// Parse a SIP URI from a string.
    ///
    /// Supports formats like:
    /// - sip:user@host
    /// - sip:user@host:5060
    /// - sips:user@host;transport=tcp
    /// - sip:host;lr
    pub fn parse(s: &str) -> Result<Self, SipError> {
        let s = s.trim();

        // Parse scheme
        let (scheme, rest) = if let Some(idx) = s.find(':') {
            let scheme = s[..idx].to_lowercase();
            if scheme != "sip" && scheme != "sips" {
                return Err(SipError::Parse(format!(
                    "Invalid SIP URI scheme: {}",
                    scheme
                )));
            }
            (scheme, &s[idx + 1..])
        } else {
            return Err(SipError::Parse("Missing scheme in SIP URI".to_string()));
        };

        // Parse user@host:port;params
        let (user_host_port, params_str) = if let Some(idx) = rest.find(';') {
            (&rest[..idx], Some(&rest[idx + 1..]))
        } else {
            (rest, None)
        };

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
        })
    }

    /// Get the URI scheme ("sip" or "sips").
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Get the user part (if present).
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// Get the host part.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the port (if present).
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Get the effective port (returns default 5060/5061 if not specified).
    pub fn effective_port(&self) -> u16 {
        self.port
            .unwrap_or(if self.is_secure() { 5061 } else { 5060 })
    }

    /// Get the transport parameter.
    pub fn transport(&self) -> Option<&str> {
        self.get_param("transport")
    }

    /// Check if this is a secure URI (sips:).
    pub fn is_secure(&self) -> bool {
        self.scheme == "sips"
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

    /// Check if the lr (loose routing) parameter is present.
    pub fn is_loose_route(&self) -> bool {
        self.has_param("lr")
    }

    /// Create a new SipUri builder.
    pub fn builder() -> SipUriBuilder {
        SipUriBuilder::new()
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;

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

        Ok(())
    }
}

/// Builder for SIP URIs.
#[derive(Debug, Default)]
pub struct SipUriBuilder {
    scheme: Option<String>,
    user: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    params: Vec<(String, Option<String>)>,
}

impl SipUriBuilder {
    /// Create a new SipUriBuilder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the scheme (defaults to "sip").
    pub fn scheme(mut self, scheme: &str) -> Self {
        self.scheme = Some(scheme.to_lowercase());
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

    /// Build the SipUri.
    pub fn build(self) -> Result<SipUri, SipError> {
        let host = self
            .host
            .ok_or_else(|| SipError::InvalidHeader("Missing host in SIP URI".to_string()))?;

        Ok(SipUri {
            scheme: self.scheme.unwrap_or_else(|| "sip".to_string()),
            user: self.user,
            host,
            port: self.port,
            params: self.params,
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
}
