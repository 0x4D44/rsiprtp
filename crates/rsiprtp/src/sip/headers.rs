//! SIP header types and utilities.
//!
//! This module provides typed wrappers for common SIP headers,
//! making it easier to extract and manipulate header values.

use crate::sip::uri::SipUri;
use crate::core::SipError;
use std::fmt;

/// Typed wrapper for Via header (RFC 3261 Section 20.42).
#[derive(Debug, Clone, PartialEq)]
pub struct Via {
    /// Transport protocol (e.g., "UDP", "TCP", "TLS").
    pub protocol: String,
    /// Host address.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Branch parameter (transaction identifier).
    pub branch: String,
    /// Received parameter (actual source IP).
    pub received: Option<String>,
    /// rport parameter (actual source port).
    pub rport: Option<u16>,
}

impl Via {
    /// Parse a Via header value string.
    ///
    /// Format: `SIP/2.0/UDP host:port;branch=xxx[;received=ip][;rport=port]`
    pub fn parse(value: &str) -> Result<Self, SipError> {
        // Parse format: "SIP/2.0/UDP host:port;params"
        let value = value.trim();

        // Split protocol and the rest
        let parts: Vec<&str> = value.splitn(2, ' ').collect();
        if parts.len() < 2 {
            return Err(SipError::Parse("Invalid Via header format".to_string()));
        }

        // Parse protocol (e.g., "SIP/2.0/UDP")
        let protocol_parts: Vec<&str> = parts[0].split('/').collect();
        let protocol = protocol_parts.last().unwrap_or(&"");
        if protocol.is_empty() {
            return Err(SipError::Parse("Missing transport protocol".to_string()));
        }
        let protocol = protocol.to_string();

        // Parse host:port and parameters
        let rest = parts[1];
        let (host_port, params) = if let Some(idx) = rest.find(';') {
            (&rest[..idx], Some(&rest[idx + 1..]))
        } else {
            (rest, None)
        };

        // Parse host and port
        let (host, port) = if let Some(idx) = host_port.rfind(':') {
            let port_str = &host_port[idx + 1..];
            // Check if it's actually a port (all digits) or part of IPv6
            if port_str.chars().all(|c| c.is_ascii_digit()) && !host_port.contains('[') {
                (
                    host_port[..idx].to_string(),
                    port_str.parse().unwrap_or(5060),
                )
            } else {
                (host_port.to_string(), 5060)
            }
        } else {
            (host_port.to_string(), 5060)
        };

        // Parse parameters
        let mut branch = String::new();
        let mut received = None;
        let mut rport = None;

        if let Some(params_str) = params {
            for param in params_str.split(';') {
                let param = param.trim();
                if let Some(value) = param.strip_prefix("branch=") {
                    branch = value.to_string();
                } else if let Some(value) = param.strip_prefix("received=") {
                    received = Some(value.to_string());
                } else if let Some(value) = param.strip_prefix("rport=") {
                    rport = value.parse().ok();
                } else if param == "rport" {
                    // rport without value (client requesting rport)
                    rport = None;
                }
            }
        }

        if branch.is_empty() {
            return Err(SipError::Parse(
                "Via header missing branch parameter".to_string(),
            ));
        }

        Ok(Via {
            protocol,
            host,
            port,
            branch,
            received,
            rport,
        })
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        let mut result = format!(
            "SIP/2.0/{} {}:{};branch={}",
            self.protocol, self.host, self.port, self.branch
        );

        if let Some(ref received) = self.received {
            result.push_str(&format!(";received={}", received));
        }

        if let Some(rport) = self.rport {
            result.push_str(&format!(";rport={}", rport));
        }

        result
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for Contact header (RFC 3261 Section 20.10).
#[derive(Debug, Clone, PartialEq)]
pub struct Contact {
    /// Contact URI.
    pub uri: SipUri,
    /// Display name (optional).
    pub display_name: Option<String>,
    /// Expires parameter (optional).
    pub expires: Option<u32>,
    /// q-value for priority (optional, 0.0-1.0).
    pub q: Option<f32>,
}

impl Contact {
    /// Parse a Contact header value string.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();

        let (display_name, uri_part) = if let Some(stripped) = value.strip_prefix('"') {
            // Has display name in quotes
            if let Some(end_quote) = stripped.find('"') {
                let name = stripped[..end_quote].to_string();
                let rest = stripped[end_quote + 1..].trim();
                (Some(name), rest)
            } else {
                (None, value)
            }
        } else if let Some(lt_pos) = value.find('<') {
            // Display name without quotes before <
            let name = value[..lt_pos].trim();
            let rest = &value[lt_pos..];
            if name.is_empty() {
                (None, rest)
            } else {
                (Some(name.to_string()), rest)
            }
        } else {
            (None, value)
        };

        // Extract URI from angle brackets
        let (uri_str, params) = if uri_part.starts_with('<') {
            if let Some(gt_pos) = uri_part.find('>') {
                let uri = &uri_part[1..gt_pos];
                let params = if gt_pos + 1 < uri_part.len() {
                    Some(&uri_part[gt_pos + 1..])
                } else {
                    None
                };
                (uri, params)
            } else {
                return Err(SipError::Parse("Contact URI missing closing >".to_string()));
            }
        } else {
            // URI without angle brackets
            if let Some(semi_pos) = uri_part.find(';') {
                (&uri_part[..semi_pos], Some(&uri_part[semi_pos..]))
            } else {
                (uri_part, None)
            }
        };

        let uri = SipUri::parse(uri_str)?;

        // Parse parameters
        let mut expires = None;
        let mut q = None;

        if let Some(params_str) = params {
            for param in params_str.split(';') {
                let param = param.trim();
                if let Some(value) = param.strip_prefix("expires=") {
                    expires = value.parse().ok();
                } else if let Some(value) = param.strip_prefix("q=") {
                    q = value.parse().ok();
                }
            }
        }

        Ok(Contact {
            uri,
            display_name,
            expires,
            q,
        })
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        let mut result = String::new();

        if let Some(ref name) = self.display_name {
            result.push_str(&format!("\"{}\" ", name));
        }

        result.push('<');
        result.push_str(&self.uri.to_string());
        result.push('>');

        if let Some(expires) = self.expires {
            result.push_str(&format!(";expires={}", expires));
        }

        if let Some(q) = self.q {
            result.push_str(&format!(";q={:.1}", q));
        }

        result
    }
}

impl fmt::Display for Contact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for Record-Route header (RFC 3261 Section 20.30).
#[derive(Debug, Clone, PartialEq)]
pub struct RecordRoute {
    /// Record-Route URI.
    pub uri: SipUri,
    /// Whether the lr (loose routing) parameter is present.
    pub lr: bool,
}

impl RecordRoute {
    /// Parse a Record-Route header value string.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();

        // Extract URI from angle brackets
        let (uri_str, params) = if value.starts_with('<') {
            if let Some(gt_pos) = value.find('>') {
                let uri = &value[1..gt_pos];
                let params = if gt_pos + 1 < value.len() {
                    Some(&value[gt_pos + 1..])
                } else {
                    None
                };
                (uri, params)
            } else {
                return Err(SipError::Parse(
                    "Record-Route URI missing closing >".to_string(),
                ));
            }
        } else {
            return Err(SipError::Parse(
                "Record-Route must have URI in angle brackets".to_string(),
            ));
        };

        let uri = SipUri::parse(uri_str)?;

        // Check for lr parameter
        let lr = params.map(|p| p.contains("lr")).unwrap_or(false);

        Ok(RecordRoute { uri, lr })
    }

    /// Parse multiple Record-Route headers from a comma-separated value or multiple values.
    pub fn parse_all(values: &[String]) -> Vec<Self> {
        let mut routes = Vec::new();

        for value in values {
            // Record-Route can be comma-separated
            for part in value.split(',') {
                if let Ok(rr) = Self::parse(part) {
                    routes.push(rr);
                }
            }
        }

        routes
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        if self.lr {
            format!("<{}>;lr", self.uri)
        } else {
            format!("<{}>", self.uri)
        }
    }
}

impl fmt::Display for RecordRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Typed wrapper for Route header (RFC 3261 Section 20.34).
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    /// Route URI.
    pub uri: SipUri,
    /// Whether the lr (loose routing) parameter is present.
    pub lr: bool,
}

impl Route {
    /// Parse a Route header value string.
    pub fn parse(value: &str) -> Result<Self, SipError> {
        let value = value.trim();

        // Extract URI from angle brackets
        let (uri_str, params) = if value.starts_with('<') {
            if let Some(gt_pos) = value.find('>') {
                let uri = &value[1..gt_pos];
                let params = if gt_pos + 1 < value.len() {
                    Some(&value[gt_pos + 1..])
                } else {
                    None
                };
                (uri, params)
            } else {
                return Err(SipError::Parse("Route URI missing closing >".to_string()));
            }
        } else {
            return Err(SipError::Parse(
                "Route must have URI in angle brackets".to_string(),
            ));
        };

        let uri = SipUri::parse(uri_str)?;

        // Check for lr parameter
        let lr = params.map(|p| p.contains("lr")).unwrap_or(false);

        Ok(Route { uri, lr })
    }

    /// Parse multiple Route headers from a comma-separated value or multiple values.
    pub fn parse_all(values: &[String]) -> Vec<Self> {
        let mut routes = Vec::new();

        for value in values {
            for part in value.split(',') {
                if let Ok(r) = Self::parse(part) {
                    routes.push(r);
                }
            }
        }

        routes
    }

    /// Convert to header value string.
    pub fn to_header_value(&self) -> String {
        if self.lr {
            format!("<{}>;lr", self.uri)
        } else {
            format!("<{}>", self.uri)
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Route set for dialog routing (RFC 3261 Section 12.2).
#[derive(Debug, Clone, Default)]
pub struct RouteSet {
    routes: Vec<Route>,
}

impl RouteSet {
    /// Create an empty route set.
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Create a route set from Record-Route headers.
    ///
    /// For UAC (caller), reverse should be true (routes are reversed).
    /// For UAS (callee), reverse should be false.
    pub fn from_record_routes(record_routes: Vec<RecordRoute>, reverse: bool) -> Self {
        let mut routes: Vec<Route> = record_routes
            .into_iter()
            .map(|rr| Route {
                uri: rr.uri,
                lr: rr.lr,
            })
            .collect();

        if reverse {
            routes.reverse();
        }

        Self { routes }
    }

    /// Check if the route set is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Get the number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Get the routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// Get the first route (for determining request URI in loose routing).
    pub fn first(&self) -> Option<&Route> {
        self.routes.first()
    }

    /// Add a route to the set.
    pub fn push(&mut self, route: Route) {
        self.routes.push(route);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Via tests
    #[test]
    fn test_via_parse() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776").unwrap();
        assert_eq!(via.protocol, "UDP");
        assert_eq!(via.host, "192.168.1.1");
        assert_eq!(via.port, 5060);
        assert_eq!(via.branch, "z9hG4bK776");
        assert!(via.received.is_none());
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_with_received() {
        let via = Via::parse(
            "SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bK123;received=10.0.0.1;rport=12345",
        )
        .unwrap();
        assert_eq!(via.protocol, "TCP");
        assert_eq!(via.host, "proxy.example.com");
        assert_eq!(via.received, Some("10.0.0.1".to_string()));
        assert_eq!(via.rport, Some(12345));
    }

    #[test]
    fn test_via_parse_ipv6_with_port() {
        let via = Via::parse("SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK123").unwrap();
        assert_eq!(via.host, "[2001:db8::1]:5060");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_rport_without_value() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776;rport").unwrap();
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_tls() {
        let via = Via::parse("SIP/2.0/TLS secure.example.com:5061;branch=z9hG4bKsecure").unwrap();
        assert_eq!(via.protocol, "TLS");
        assert_eq!(via.host, "secure.example.com");
        assert_eq!(via.port, 5061);
    }

    #[test]
    fn test_via_parse_default_port() {
        let via = Via::parse("SIP/2.0/UDP proxy.example.com;branch=z9hG4bKabc").unwrap();
        assert_eq!(via.host, "proxy.example.com");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_missing_protocol() {
        let result = Via::parse("SIP/2.0/ 192.168.1.1:5060;branch=z9hG4bK123");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_non_numeric_port() {
        let via = Via::parse("SIP/2.0/UDP proxy.example.com:abc;branch=z9hG4bK123").unwrap();
        assert_eq!(via.host, "proxy.example.com:abc");
        assert_eq!(via.port, 5060);
    }

    #[test]
    fn test_via_parse_rport_no_value() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776;rport").unwrap();
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_unknown_param_without_value() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776;foo").unwrap();
        assert!(via.rport.is_none());
    }

    #[test]
    fn test_via_parse_invalid_format() {
        let result = Via::parse("InvalidVia");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_no_branch() {
        let result = Via::parse("SIP/2.0/UDP 192.168.1.1:5060");
        assert!(result.is_err());
    }

    #[test]
    fn test_via_parse_whitespace() {
        let via = Via::parse("  SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123  ").unwrap();
        assert_eq!(via.protocol, "UDP");
        assert_eq!(via.branch, "z9hG4bK123");
    }

    #[test]
    fn test_via_to_string() {
        let via = Via {
            protocol: "UDP".to_string(),
            host: "192.168.1.1".to_string(),
            port: 5060,
            branch: "z9hG4bK776".to_string(),
            received: Some("10.0.0.1".to_string()),
            rport: Some(12345),
        };

        let s = via.to_string();
        assert!(s.contains("SIP/2.0/UDP"));
        assert!(s.contains("192.168.1.1:5060"));
        assert!(s.contains("branch=z9hG4bK776"));
        assert!(s.contains("received=10.0.0.1"));
        assert!(s.contains("rport=12345"));
    }

    #[test]
    fn test_via_to_header_value_no_optional() {
        let via = Via {
            protocol: "TCP".to_string(),
            host: "example.com".to_string(),
            port: 5060,
            branch: "z9hG4bK999".to_string(),
            received: None,
            rport: None,
        };

        let s = via.to_header_value();
        assert_eq!(s, "SIP/2.0/TCP example.com:5060;branch=z9hG4bK999");
    }

    #[test]
    fn test_via_clone() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123").unwrap();
        let cloned = via.clone();
        assert_eq!(via, cloned);
    }

    #[test]
    fn test_via_debug() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK123").unwrap();
        let debug = format!("{:?}", via);
        assert!(debug.contains("Via"));
    }

    // Contact tests
    #[test]
    fn test_contact_parse() {
        let contact = Contact::parse("<sip:alice@192.168.1.1:5060>").unwrap();
        assert_eq!(contact.uri.to_string(), "sip:alice@192.168.1.1:5060");
        assert!(contact.display_name.is_none());
    }

    #[test]
    fn test_contact_parse_with_display_name() {
        let contact = Contact::parse("\"Alice\" <sip:alice@example.com>;expires=3600").unwrap();
        assert_eq!(contact.display_name, Some("Alice".to_string()));
        assert_eq!(contact.expires, Some(3600));
    }

    #[test]
    fn test_contact_parse_missing_end_quote() {
        let result = Contact::parse("\"Alice <sip:alice@example.com>");
        assert!(result.is_err());
    }

    #[test]
    fn test_contact_parse_with_q_value() {
        let contact = Contact::parse("<sip:alice@example.com>;q=0.5").unwrap();
        assert_eq!(contact.q, Some(0.5));
    }

    #[test]
    fn test_contact_parse_with_all_params() {
        let contact = Contact::parse("\"Bob\" <sip:bob@example.com>;expires=7200;q=0.8").unwrap();
        assert_eq!(contact.display_name, Some("Bob".to_string()));
        assert_eq!(contact.expires, Some(7200));
        assert_eq!(contact.q, Some(0.8));
    }

    #[test]
    fn test_contact_parse_display_name_no_quotes() {
        let contact = Contact::parse("Alice <sip:alice@example.com>").unwrap();
        assert_eq!(contact.display_name, Some("Alice".to_string()));
    }

    #[test]
    fn test_contact_parse_no_angle_brackets() {
        let contact = Contact::parse("sip:alice@example.com").unwrap();
        assert!(contact.display_name.is_none());
        assert!(contact.uri.to_string().contains("alice"));
    }

    #[test]
    fn test_contact_parse_no_angle_brackets_with_params() {
        let contact = Contact::parse("sip:alice@example.com;expires=1800").unwrap();
        assert_eq!(contact.expires, Some(1800));
    }

    #[test]
    fn test_contact_parse_missing_closing_bracket() {
        let result = Contact::parse("<sip:alice@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_contact_to_header_value() {
        let contact = Contact {
            uri: SipUri::parse("sip:alice@example.com").unwrap(),
            display_name: Some("Alice".to_string()),
            expires: Some(3600),
            q: Some(0.7),
        };

        let s = contact.to_header_value();
        assert!(s.contains("\"Alice\""));
        assert!(s.contains("<sip:alice@example.com>"));
        assert!(s.contains("expires=3600"));
        assert!(s.contains("q=0.7"));
    }

    #[test]
    fn test_contact_to_header_value_no_optional() {
        let contact = Contact {
            uri: SipUri::parse("sip:bob@example.com").unwrap(),
            display_name: None,
            expires: None,
            q: None,
        };

        let s = contact.to_header_value();
        assert_eq!(s, "<sip:bob@example.com>");
    }

    #[test]
    fn test_contact_display() {
        let contact = Contact::parse("<sip:alice@example.com>").unwrap();
        let s = contact.to_string();
        assert!(s.contains("sip:alice@example.com"));
    }

    #[test]
    fn test_contact_clone() {
        let contact = Contact::parse("<sip:alice@example.com>").unwrap();
        let cloned = contact.clone();
        assert_eq!(contact, cloned);
    }

    // RecordRoute tests
    #[test]
    fn test_record_route_parse() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        assert!(rr.lr);
        assert!(rr.uri.to_string().contains("proxy.example.com"));
    }

    #[test]
    fn test_record_route_parse_no_lr() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>").unwrap();
        assert!(!rr.lr);
    }

    #[test]
    fn test_record_route_parse_with_port() {
        let rr = RecordRoute::parse("<sip:proxy.example.com:5060>;lr").unwrap();
        assert!(rr.lr);
    }

    #[test]
    fn test_record_route_parse_missing_brackets() {
        let result = RecordRoute::parse("sip:proxy.example.com;lr");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_route_parse_missing_closing() {
        let result = RecordRoute::parse("<sip:proxy.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_route_parse_invalid_uri() {
        let result = RecordRoute::parse("<sip:proxy@[::1>");
        assert!(result.is_err());
    }

    #[test]
    fn test_record_route_parse_all() {
        let values = vec![
            "<sip:p1.example.com>;lr, <sip:p2.example.com>;lr".to_string(),
            "<sip:p3.example.com>".to_string(),
        ];
        let routes = RecordRoute::parse_all(&values);
        assert_eq!(routes.len(), 3);
    }

    #[test]
    fn test_record_route_parse_all_ignores_invalid() {
        let values = vec!["<sip:proxy.example.com>;lr, invalid".to_string()];
        let routes = RecordRoute::parse_all(&values);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn test_record_route_parse_all_empty() {
        let values: Vec<String> = vec![];
        let routes = RecordRoute::parse_all(&values);
        assert!(routes.is_empty());
    }

    #[test]
    fn test_record_route_to_header_value() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = rr.to_header_value();
        assert!(s.contains("<sip:proxy.example.com>"));
        assert!(s.contains("lr"));
    }

    #[test]
    fn test_record_route_to_header_value_no_lr() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>").unwrap();
        let s = rr.to_header_value();
        assert!(!s.contains("lr"));
    }

    #[test]
    fn test_record_route_display() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = rr.to_string();
        assert!(s.contains("proxy.example.com"));
    }

    #[test]
    fn test_record_route_clone() {
        let rr = RecordRoute::parse("<sip:proxy.example.com>;lr").unwrap();
        let cloned = rr.clone();
        assert_eq!(rr, cloned);
    }

    // Route tests
    #[test]
    fn test_route_parse() {
        let route = Route::parse("<sip:proxy.example.com:5060>;lr").unwrap();
        assert!(route.lr);
    }

    #[test]
    fn test_route_parse_no_lr() {
        let route = Route::parse("<sip:proxy.example.com>").unwrap();
        assert!(!route.lr);
    }

    #[test]
    fn test_route_parse_missing_brackets() {
        let result = Route::parse("sip:proxy.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_parse_missing_closing() {
        let result = Route::parse("<sip:proxy.example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_parse_invalid_uri() {
        let result = Route::parse("<sip:proxy@[::1>");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_parse_all() {
        let values = vec!["<sip:p1.example.com>;lr, <sip:p2.example.com>;lr".to_string()];
        let routes = Route::parse_all(&values);
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_route_parse_all_ignores_invalid() {
        let values = vec!["<sip:p1.example.com>;lr, invalid".to_string()];
        let routes = Route::parse_all(&values);
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn test_route_parse_all_empty() {
        let values: Vec<String> = vec![];
        let routes = Route::parse_all(&values);
        assert!(routes.is_empty());
    }

    #[test]
    fn test_route_to_header_value() {
        let route = Route::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = route.to_header_value();
        assert!(s.contains("<sip:proxy.example.com>"));
        assert!(s.contains("lr"));
    }

    #[test]
    fn test_route_to_header_value_no_lr() {
        let route = Route::parse("<sip:proxy.example.com>").unwrap();
        let s = route.to_header_value();
        assert!(!s.contains("lr"));
    }

    #[test]
    fn test_route_display() {
        let route = Route::parse("<sip:proxy.example.com>;lr").unwrap();
        let s = route.to_string();
        assert!(s.contains("proxy.example.com"));
    }

    #[test]
    fn test_route_clone() {
        let route = Route::parse("<sip:proxy.example.com>;lr").unwrap();
        let cloned = route.clone();
        assert_eq!(route, cloned);
    }

    // RouteSet tests
    #[test]
    fn test_route_set_new() {
        let route_set = RouteSet::new();
        assert!(route_set.is_empty());
        assert_eq!(route_set.len(), 0);
    }

    #[test]
    fn test_route_set_default() {
        let route_set = RouteSet::default();
        assert!(route_set.is_empty());
    }

    #[test]
    fn test_route_set_from_record_routes() {
        let rrs = vec![
            RecordRoute::parse("<sip:p1.example.com;lr>").unwrap(),
            RecordRoute::parse("<sip:p2.example.com;lr>").unwrap(),
        ];

        // UAC reverses
        let route_set = RouteSet::from_record_routes(rrs.clone(), true);
        assert_eq!(route_set.len(), 2);
        assert!(route_set.routes()[0].uri.to_string().contains("p2"));
        assert!(route_set.routes()[1].uri.to_string().contains("p1"));

        // UAS doesn't reverse
        let route_set = RouteSet::from_record_routes(rrs, false);
        assert!(route_set.routes()[0].uri.to_string().contains("p1"));
        assert!(route_set.routes()[1].uri.to_string().contains("p2"));
    }

    #[test]
    fn test_route_set_is_empty() {
        let mut route_set = RouteSet::new();
        assert!(route_set.is_empty());

        route_set.push(Route::parse("<sip:proxy.example.com>;lr").unwrap());
        assert!(!route_set.is_empty());
    }

    #[test]
    fn test_route_set_len() {
        let mut route_set = RouteSet::new();
        assert_eq!(route_set.len(), 0);

        route_set.push(Route::parse("<sip:p1.example.com>;lr").unwrap());
        assert_eq!(route_set.len(), 1);

        route_set.push(Route::parse("<sip:p2.example.com>;lr").unwrap());
        assert_eq!(route_set.len(), 2);
    }

    #[test]
    fn test_route_set_first() {
        let mut route_set = RouteSet::new();
        assert!(route_set.first().is_none());

        route_set.push(Route::parse("<sip:first.example.com>;lr").unwrap());
        route_set.push(Route::parse("<sip:second.example.com>;lr").unwrap());

        let first = route_set.first().unwrap();
        assert!(first.uri.to_string().contains("first"));
    }

    #[test]
    fn test_route_set_routes() {
        let mut route_set = RouteSet::new();
        route_set.push(Route::parse("<sip:p1.example.com>;lr").unwrap());
        route_set.push(Route::parse("<sip:p2.example.com>;lr").unwrap());

        let routes = route_set.routes();
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn test_route_set_push() {
        let mut route_set = RouteSet::new();
        route_set.push(Route::parse("<sip:proxy.example.com>;lr").unwrap());
        assert_eq!(route_set.len(), 1);
    }

    #[test]
    fn test_route_set_clone() {
        let mut route_set = RouteSet::new();
        route_set.push(Route::parse("<sip:proxy.example.com>;lr").unwrap());
        let cloned = route_set.clone();
        assert_eq!(cloned.len(), 1);
    }

    #[test]
    fn test_route_set_debug() {
        let route_set = RouteSet::new();
        let debug = format!("{:?}", route_set);
        assert!(debug.contains("RouteSet"));
    }
}
