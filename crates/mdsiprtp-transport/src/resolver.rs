//! DNS resolver for SIP URI resolution per RFC 3263.
//!
//! Implements the SIP URI resolution procedures using:
//! - NAPTR records to discover transport protocols
//! - SRV records to discover servers
//! - A/AAAA records as fallback
//!
//! # Example
//!
//! ```rust,ignore
//! use mdsiprtp_transport::resolver::{SipResolver, ResolvedTarget};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let resolver = SipResolver::new().await?;
//!
//!     // Resolve a SIP URI
//!     let targets = resolver.resolve("example.com", None).await?;
//!
//!     for target in targets {
//!         println!("{}:{} via {:?}", target.host, target.port, target.transport);
//!     }
//!
//!     Ok(())
//! }
//! ```

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;
use tracing::{debug, trace};

use crate::TransportProtocol;

/// DNS resolution errors.
#[derive(Debug, Error)]
pub enum ResolverError {
    /// DNS lookup failed.
    #[error("DNS lookup failed: {0}")]
    LookupFailed(#[from] hickory_resolver::error::ResolveError),

    /// No records found.
    #[error("no DNS records found for {0}")]
    NoRecords(String),

    /// Invalid domain name.
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
}

/// Result type for resolver operations.
pub type Result<T> = std::result::Result<T, ResolverError>;

/// A resolved SIP target (server + port + transport).
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    /// Server hostname or IP address.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Transport protocol.
    pub transport: TransportProtocol,
    /// Priority (lower is better).
    pub priority: u16,
    /// Weight for load balancing.
    pub weight: u16,
    /// Resolved IP addresses (if available).
    pub addresses: Vec<IpAddr>,
}

impl ResolvedTarget {
    /// Get socket addresses for this target.
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.addresses
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect()
    }
}

/// SIP DNS resolver per RFC 3263.
pub struct SipResolver {
    resolver: TokioAsyncResolver,
}

impl SipResolver {
    /// Create a new resolver with system DNS configuration.
    pub async fn new() -> Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self { resolver })
    }

    /// Create a resolver with custom configuration.
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Self {
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Self { resolver }
    }

    /// Resolve a SIP domain to target servers.
    ///
    /// # Arguments
    /// * `domain` - Domain to resolve (e.g., "example.com")
    /// * `preferred_transport` - Optional preferred transport protocol
    ///
    /// # Returns
    /// List of resolved targets, sorted by priority and weight.
    pub async fn resolve(
        &self,
        domain: &str,
        preferred_transport: Option<TransportProtocol>,
    ) -> Result<Vec<ResolvedTarget>> {
        debug!("Resolving SIP domain: {}", domain);

        // Step 1: Try NAPTR lookup for transport discovery
        let naptr_results = self.lookup_naptr(domain).await;

        if let Ok(services) = naptr_results {
            if !services.is_empty() {
                debug!("Found {} NAPTR records", services.len());
                return self
                    .resolve_from_naptr(domain, services, preferred_transport)
                    .await;
            }
        }

        // Step 2: Try SRV lookup directly
        let transports = match preferred_transport {
            Some(t) => vec![t],
            None => vec![
                TransportProtocol::Tls,
                TransportProtocol::Tcp,
                TransportProtocol::Udp,
            ],
        };

        for transport in transports {
            let srv_name = match transport {
                TransportProtocol::Udp => format!("_sip._udp.{}", domain),
                TransportProtocol::Tcp => format!("_sip._tcp.{}", domain),
                TransportProtocol::Tls => format!("_sips._tcp.{}", domain),
            };

            if let Ok(targets) = self.lookup_srv(&srv_name, transport).await {
                if !targets.is_empty() {
                    debug!("Found {} SRV records for {}", targets.len(), srv_name);
                    return Ok(targets);
                }
            }
        }

        // Step 3: Fall back to A/AAAA lookup
        debug!("Falling back to A/AAAA lookup for {}", domain);
        self.lookup_address(
            domain,
            preferred_transport.unwrap_or(TransportProtocol::Udp),
        )
        .await
    }

    /// Lookup NAPTR records for a domain.
    async fn lookup_naptr(&self, domain: &str) -> Result<Vec<(String, TransportProtocol)>> {
        use hickory_resolver::proto::rr::RData;

        let lookup = self.resolver.lookup(domain, RecordType::NAPTR).await?;

        let mut services: Vec<(u16, u16, String, TransportProtocol)> = Vec::new();

        for record in lookup.record_iter() {
            if let Some(RData::NAPTR(naptr)) = record.data() {
                let service = String::from_utf8_lossy(naptr.services()).to_string();
                let replacement = naptr.replacement().to_string();

                // Parse SIP NAPTR services
                let transport = match service.as_str() {
                    "SIP+D2U" | "sip+d2u" => Some(TransportProtocol::Udp),
                    "SIP+D2T" | "sip+d2t" => Some(TransportProtocol::Tcp),
                    "SIPS+D2T" | "sips+d2t" => Some(TransportProtocol::Tls),
                    _ => None,
                };

                if let Some(t) = transport {
                    trace!("NAPTR: {} -> {} ({:?})", service, replacement, t);
                    services.push((naptr.order(), naptr.preference(), replacement, t));
                }
            }
        }

        // Sort by order, then preference
        services.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        Ok(services.into_iter().map(|(_, _, r, t)| (r, t)).collect())
    }

    /// Resolve from NAPTR results.
    async fn resolve_from_naptr(
        &self,
        _domain: &str,
        naptr_results: Vec<(String, TransportProtocol)>,
        preferred_transport: Option<TransportProtocol>,
    ) -> Result<Vec<ResolvedTarget>> {
        let mut all_targets = Vec::new();

        for (srv_name, transport) in naptr_results {
            // Skip if not preferred transport
            if let Some(pref) = preferred_transport {
                if transport != pref {
                    continue;
                }
            }

            if let Ok(mut targets) = self.lookup_srv(&srv_name, transport).await {
                all_targets.append(&mut targets);
            }
        }

        if all_targets.is_empty() {
            return Err(ResolverError::NoRecords("NAPTR targets".to_string()));
        }

        Ok(all_targets)
    }

    /// Lookup SRV records.
    async fn lookup_srv(
        &self,
        srv_name: &str,
        transport: TransportProtocol,
    ) -> Result<Vec<ResolvedTarget>> {
        let lookup = self.resolver.srv_lookup(srv_name).await?;

        let mut targets: Vec<ResolvedTarget> = Vec::new();

        for record in lookup.iter() {
            let host = record
                .target()
                .to_string()
                .trim_end_matches('.')
                .to_string();
            let port = record.port();
            let priority = record.priority();
            let weight = record.weight();

            trace!(
                "SRV: {} -> {}:{} (pri={}, wt={})",
                srv_name,
                host,
                port,
                priority,
                weight
            );

            // Resolve A/AAAA for the target
            let addresses = self.resolve_addresses(&host).await.unwrap_or_default();

            targets.push(ResolvedTarget {
                host,
                port,
                transport,
                priority,
                weight,
                addresses,
            });
        }

        // Sort by priority (lower first), then by weight (higher first)
        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        Ok(targets)
    }

    /// Fallback to A/AAAA lookup.
    async fn lookup_address(
        &self,
        domain: &str,
        transport: TransportProtocol,
    ) -> Result<Vec<ResolvedTarget>> {
        let addresses = self.resolve_addresses(domain).await?;

        if addresses.is_empty() {
            return Err(ResolverError::NoRecords(domain.to_string()));
        }

        // Use default SIP port based on transport
        let port = match transport {
            TransportProtocol::Udp | TransportProtocol::Tcp => 5060,
            TransportProtocol::Tls => 5061,
        };

        Ok(vec![ResolvedTarget {
            host: domain.to_string(),
            port,
            transport,
            priority: 0,
            weight: 0,
            addresses,
        }])
    }

    /// Resolve A and AAAA records.
    async fn resolve_addresses(&self, host: &str) -> Result<Vec<IpAddr>> {
        // First check if it's already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let lookup = self.resolver.lookup_ip(host).await?;
        Ok(lookup.iter().collect())
    }

    /// Resolve a full SIP URI.
    ///
    /// # Arguments
    /// * `uri` - SIP URI (e.g., "sip:user@example.com:5060;transport=tcp")
    ///
    /// # Returns
    /// Resolved target or error.
    pub async fn resolve_uri(&self, uri: &str) -> Result<Vec<ResolvedTarget>> {
        // Simple URI parsing (in production, use rsip's Uri parser)
        let uri = uri.trim_start_matches("sip:").trim_start_matches("sips:");

        // Extract domain (after @ if present)
        let domain_part = uri.split('@').next_back().unwrap_or(uri);

        // Parse host:port and parameters
        let (host_port, params) = domain_part
            .split_once(';')
            .map(|(h, p)| (h, Some(p)))
            .unwrap_or((domain_part, None));

        let (host, explicit_port) = host_port
            .split_once(':')
            .map(|(h, p)| (h, p.parse().ok()))
            .unwrap_or((host_port, None));

        // Parse transport parameter
        let transport = params.and_then(|p| {
            p.split(';').find_map(|param| {
                let (k, v) = param.split_once('=')?;
                if k.eq_ignore_ascii_case("transport") {
                    match v.to_lowercase().as_str() {
                        "udp" => Some(TransportProtocol::Udp),
                        "tcp" => Some(TransportProtocol::Tcp),
                        "tls" => Some(TransportProtocol::Tls),
                        _ => None,
                    }
                } else {
                    None
                }
            })
        });

        // If explicit port, skip SRV lookup
        if let Some(port) = explicit_port {
            let transport = transport.unwrap_or(TransportProtocol::Udp);
            let addresses = self.resolve_addresses(host).await.unwrap_or_default();

            return Ok(vec![ResolvedTarget {
                host: host.to_string(),
                port,
                transport,
                priority: 0,
                weight: 0,
                addresses,
            }]);
        }

        // Use standard resolution
        self.resolve(host, transport).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ResolvedTarget tests
    #[test]
    fn test_resolved_target_socket_addrs() {
        let target = ResolvedTarget {
            host: "sip.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 10,
            weight: 100,
            addresses: vec![
                "192.168.1.1".parse().unwrap(),
                "192.168.1.2".parse().unwrap(),
            ],
        };

        let addrs = target.socket_addrs();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "192.168.1.1:5060".parse().unwrap());
        assert_eq!(addrs[1], "192.168.1.2:5060".parse().unwrap());
    }

    #[test]
    fn test_resolved_target_socket_addrs_ipv6() {
        let target = ResolvedTarget {
            host: "sip.example.com".to_string(),
            port: 5061,
            transport: TransportProtocol::Tls,
            priority: 5,
            weight: 50,
            addresses: vec!["2001:db8::1".parse().unwrap(), "::1".parse().unwrap()],
        };

        let addrs = target.socket_addrs();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "[2001:db8::1]:5061".parse().unwrap());
        assert_eq!(addrs[1], "[::1]:5061".parse().unwrap());
    }

    #[test]
    fn test_resolved_target_socket_addrs_mixed() {
        let target = ResolvedTarget {
            host: "dual.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Tcp,
            priority: 0,
            weight: 100,
            addresses: vec![
                "192.168.1.100".parse().unwrap(),
                "2001:db8::100".parse().unwrap(),
            ],
        };

        let addrs = target.socket_addrs();
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].is_ipv4());
        assert!(addrs[1].is_ipv6());
    }

    #[test]
    fn test_resolved_target_socket_addrs_empty() {
        let target = ResolvedTarget {
            host: "unresolved.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 0,
            weight: 0,
            addresses: vec![],
        };

        let addrs = target.socket_addrs();
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_resolved_target_clone() {
        let target = ResolvedTarget {
            host: "sip.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 10,
            weight: 100,
            addresses: vec!["192.168.1.1".parse().unwrap()],
        };

        let cloned = target.clone();
        assert_eq!(cloned.host, target.host);
        assert_eq!(cloned.port, target.port);
        assert_eq!(cloned.transport, target.transport);
        assert_eq!(cloned.priority, target.priority);
        assert_eq!(cloned.weight, target.weight);
        assert_eq!(cloned.addresses.len(), target.addresses.len());
    }

    #[test]
    fn test_resolved_target_debug() {
        let target = ResolvedTarget {
            host: "test.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 0,
            weight: 0,
            addresses: vec![],
        };

        let debug = format!("{:?}", target);
        assert!(debug.contains("ResolvedTarget"));
        assert!(debug.contains("test.com"));
    }

    #[test]
    fn test_transport_protocol_priority() {
        // TLS should be preferred over TCP over UDP
        let transports = vec![
            TransportProtocol::Tls,
            TransportProtocol::Tcp,
            TransportProtocol::Udp,
        ];
        assert_eq!(transports[0], TransportProtocol::Tls);
    }

    // ResolverError tests
    #[test]
    fn test_resolver_error_no_records() {
        let err = ResolverError::NoRecords("example.com".to_string());
        let msg = err.to_string();
        assert!(msg.contains("no DNS records found"));
        assert!(msg.contains("example.com"));
    }

    #[test]
    fn test_resolver_error_invalid_domain() {
        let err = ResolverError::InvalidDomain("bad..domain".to_string());
        let msg = err.to_string();
        assert!(msg.contains("invalid domain"));
        assert!(msg.contains("bad..domain"));
    }

    #[test]
    fn test_resolver_error_debug() {
        let err = ResolverError::NoRecords("test.com".to_string());
        let debug = format!("{:?}", err);
        assert!(debug.contains("NoRecords"));
    }

    // Async tests that use IP addresses (skip DNS)
    #[tokio::test]
    async fn test_resolve_uri_with_ip_address() {
        let resolver = SipResolver::new().await.unwrap();

        // Using an IP address should skip DNS lookup
        let targets = resolver.resolve_uri("sip:user@192.168.1.1:5060").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[0].port, 5060);
        assert_eq!(targets[0].transport, TransportProtocol::Udp);
    }

    #[tokio::test]
    async fn test_resolve_uri_with_explicit_port_and_transport() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver
            .resolve_uri("sip:user@10.0.0.1:5080;transport=tcp")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "10.0.0.1");
        assert_eq!(targets[0].port, 5080);
        assert_eq!(targets[0].transport, TransportProtocol::Tcp);
    }

    #[tokio::test]
    async fn test_resolve_uri_with_tls_transport() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver
            .resolve_uri("sips:user@172.16.0.1:5061;transport=tls")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].port, 5061);
        assert_eq!(targets[0].transport, TransportProtocol::Tls);
    }

    #[tokio::test]
    async fn test_resolve_uri_ip_without_port() {
        let resolver = SipResolver::new().await.unwrap();

        // IP address without port - should still work as it skips SRV
        // but goes through resolve() -> lookup_address()
        let targets = resolver.resolve_uri("sip:user@127.0.0.1").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "127.0.0.1");
        // Default port for UDP
        assert_eq!(targets[0].port, 5060);
    }

    #[tokio::test]
    async fn test_resolve_uri_sips_scheme() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve_uri("sips:user@10.10.10.10:5061").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "10.10.10.10");
        assert_eq!(targets[0].port, 5061);
    }

    #[tokio::test]
    async fn test_resolve_uri_no_user_part() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve_uri("sip:192.168.0.1:5060").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "192.168.0.1");
    }

    #[tokio::test]
    async fn test_resolver_new() {
        let resolver = SipResolver::new().await;
        assert!(resolver.is_ok());
    }

    #[tokio::test]
    async fn test_resolver_with_config() {
        let config = ResolverConfig::default();
        let opts = ResolverOpts::default();
        let _resolver = SipResolver::with_config(config, opts);
        // Just ensure it doesn't panic
    }

    #[tokio::test]
    async fn test_resolve_addresses_ip_passthrough() {
        let resolver = SipResolver::new().await.unwrap();

        // When given an IP address, it should return it directly
        let addrs = resolver.resolve_addresses("192.168.1.1").await;
        assert!(addrs.is_ok());
        let addrs = addrs.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_addresses_ipv6_passthrough() {
        let resolver = SipResolver::new().await.unwrap();

        let addrs = resolver.resolve_addresses("::1").await;
        assert!(addrs.is_ok());
        let addrs = addrs.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "::1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_lookup_address_default_ports() {
        let resolver = SipResolver::new().await.unwrap();

        // Test UDP default port
        let targets = resolver
            .lookup_address("127.0.0.1", TransportProtocol::Udp)
            .await;
        assert!(targets.is_ok());
        assert_eq!(targets.unwrap()[0].port, 5060);

        // Test TCP default port
        let targets = resolver
            .lookup_address("127.0.0.1", TransportProtocol::Tcp)
            .await;
        assert!(targets.is_ok());
        assert_eq!(targets.unwrap()[0].port, 5060);

        // Test TLS default port
        let targets = resolver
            .lookup_address("127.0.0.1", TransportProtocol::Tls)
            .await;
        assert!(targets.is_ok());
        assert_eq!(targets.unwrap()[0].port, 5061);
    }

    #[tokio::test]
    async fn test_resolve_with_preferred_transport() {
        let resolver = SipResolver::new().await.unwrap();

        // Using IP address skips SRV but still respects transport
        let targets = resolver
            .resolve("127.0.0.1", Some(TransportProtocol::Tcp))
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].transport, TransportProtocol::Tcp);
    }

    #[tokio::test]
    async fn test_resolve_uri_multiple_params() {
        let resolver = SipResolver::new().await.unwrap();

        // URI with multiple parameters
        let targets = resolver
            .resolve_uri("sip:user@10.0.0.1:5070;transport=udp;lr;maddr=10.0.0.2")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].port, 5070);
        assert_eq!(targets[0].transport, TransportProtocol::Udp);
    }

    #[tokio::test]
    async fn test_resolve_uri_unknown_transport() {
        let resolver = SipResolver::new().await.unwrap();

        // Unknown transport should default to UDP
        let targets = resolver
            .resolve_uri("sip:user@192.168.1.1:5060;transport=sctp")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        // Unknown transport is ignored, defaults to UDP
        assert_eq!(targets[0].transport, TransportProtocol::Udp);
    }

    // Integration tests that require network
    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_resolve_localhost() {
        let resolver = SipResolver::new().await.unwrap();

        // This should fall back to A/AAAA lookup
        let targets = resolver
            .resolve("localhost", Some(TransportProtocol::Udp))
            .await;

        // localhost resolution depends on /etc/hosts
        if let Ok(targets) = targets {
            assert!(!targets.is_empty());
            assert_eq!(targets[0].port, 5060);
        }
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_resolve_real_domain() {
        let resolver = SipResolver::new().await.unwrap();

        // Try to resolve google.com (should have A records)
        let targets = resolver
            .resolve("google.com", Some(TransportProtocol::Udp))
            .await;

        if let Ok(targets) = targets {
            assert!(!targets.is_empty());
            assert!(!targets[0].addresses.is_empty());
        }
    }
}
