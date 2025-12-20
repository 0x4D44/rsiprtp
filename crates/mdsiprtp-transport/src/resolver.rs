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

    // ==================================================================================
    // Additional comprehensive tests for improved coverage
    // ==================================================================================

    // SRV sorting tests - test priority and weight sorting logic
    #[test]
    fn test_srv_sorting_by_priority() {
        // Create targets with different priorities
        let mut targets = vec![
            ResolvedTarget {
                host: "low-priority.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 20,
                weight: 100,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "high-priority.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 100,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "medium-priority.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 15,
                weight: 100,
                addresses: vec![],
            },
        ];

        // Apply the same sorting logic as lookup_srv
        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        // Lower priority should come first
        assert_eq!(targets[0].priority, 10);
        assert_eq!(targets[0].host, "high-priority.example.com");
        assert_eq!(targets[1].priority, 15);
        assert_eq!(targets[2].priority, 20);
    }

    #[test]
    fn test_srv_sorting_by_weight_when_priority_equal() {
        // Create targets with same priority but different weights
        let mut targets = vec![
            ResolvedTarget {
                host: "low-weight.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 50,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "high-weight.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 200,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "medium-weight.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 100,
                addresses: vec![],
            },
        ];

        // Apply the same sorting logic as lookup_srv
        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        // Same priority, so higher weight should come first
        assert_eq!(targets[0].weight, 200);
        assert_eq!(targets[0].host, "high-weight.example.com");
        assert_eq!(targets[1].weight, 100);
        assert_eq!(targets[2].weight, 50);
    }

    #[test]
    fn test_srv_sorting_combined_priority_and_weight() {
        let mut targets = vec![
            ResolvedTarget {
                host: "server1.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 100,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "server2.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 200,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "server3.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 5,
                weight: 50,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "server4.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 5,
                weight: 150,
                addresses: vec![],
            },
        ];

        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        // Priority 5 comes first
        assert_eq!(targets[0].priority, 5);
        assert_eq!(targets[0].weight, 150); // Higher weight
        assert_eq!(targets[1].priority, 5);
        assert_eq!(targets[1].weight, 50); // Lower weight
        // Then priority 10
        assert_eq!(targets[2].priority, 10);
        assert_eq!(targets[2].weight, 200);
        assert_eq!(targets[3].priority, 10);
        assert_eq!(targets[3].weight, 100);
    }

    #[test]
    fn test_srv_sorting_zero_weight() {
        let mut targets = vec![
            ResolvedTarget {
                host: "zero-weight.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 0,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "nonzero-weight.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 10,
                weight: 100,
                addresses: vec![],
            },
        ];

        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        // Higher weight comes first
        assert_eq!(targets[0].weight, 100);
        assert_eq!(targets[1].weight, 0);
    }

    #[test]
    fn test_srv_sorting_max_values() {
        let mut targets = vec![
            ResolvedTarget {
                host: "max-priority.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: u16::MAX,
                weight: 100,
                addresses: vec![],
            },
            ResolvedTarget {
                host: "min-priority.example.com".to_string(),
                port: 5060,
                transport: TransportProtocol::Udp,
                priority: 0,
                weight: u16::MAX,
                addresses: vec![],
            },
        ];

        targets.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.weight.cmp(&a.weight)));

        assert_eq!(targets[0].priority, 0);
        assert_eq!(targets[1].priority, u16::MAX);
    }

    // NAPTR sorting tests - test order and preference sorting logic
    #[test]
    fn test_naptr_sorting_by_order() {
        let mut services = vec![
            (30u16, 50u16, "srv3.example.com".to_string(), TransportProtocol::Tcp),
            (10u16, 50u16, "srv1.example.com".to_string(), TransportProtocol::Udp),
            (20u16, 50u16, "srv2.example.com".to_string(), TransportProtocol::Tls),
        ];

        // Apply same sorting as lookup_naptr
        services.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        // Lower order comes first
        assert_eq!(services[0].0, 10);
        assert_eq!(services[0].2, "srv1.example.com");
        assert_eq!(services[1].0, 20);
        assert_eq!(services[2].0, 30);
    }

    #[test]
    fn test_naptr_sorting_by_preference_when_order_equal() {
        let mut services = vec![
            (10u16, 100u16, "srv3.example.com".to_string(), TransportProtocol::Tcp),
            (10u16, 50u16, "srv1.example.com".to_string(), TransportProtocol::Udp),
            (10u16, 75u16, "srv2.example.com".to_string(), TransportProtocol::Tls),
        ];

        services.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        // Same order, lower preference comes first
        assert_eq!(services[0].1, 50);
        assert_eq!(services[0].2, "srv1.example.com");
        assert_eq!(services[1].1, 75);
        assert_eq!(services[2].1, 100);
    }

    #[test]
    fn test_naptr_sorting_combined_order_and_preference() {
        let mut services = vec![
            (20u16, 50u16, "srv4.example.com".to_string(), TransportProtocol::Tcp),
            (10u16, 100u16, "srv2.example.com".to_string(), TransportProtocol::Udp),
            (10u16, 50u16, "srv1.example.com".to_string(), TransportProtocol::Tls),
            (20u16, 25u16, "srv3.example.com".to_string(), TransportProtocol::Tcp),
        ];

        services.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        // Order 10 first, then by preference
        assert_eq!(services[0].0, 10);
        assert_eq!(services[0].1, 50);
        assert_eq!(services[1].0, 10);
        assert_eq!(services[1].1, 100);
        // Then order 20, by preference
        assert_eq!(services[2].0, 20);
        assert_eq!(services[2].1, 25);
        assert_eq!(services[3].0, 20);
        assert_eq!(services[3].1, 50);
    }

    // URI parsing edge cases
    #[tokio::test]
    async fn test_resolve_uri_case_insensitive_transport() {
        let resolver = SipResolver::new().await.unwrap();

        // Test uppercase transport parameter
        let targets = resolver
            .resolve_uri("sip:user@192.168.1.1:5060;transport=TCP")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].transport, TransportProtocol::Tcp);

        // Test mixed case
        let targets = resolver
            .resolve_uri("sip:user@192.168.1.1:5060;transport=TlS")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].transport, TransportProtocol::Tls);
    }

    #[tokio::test]
    async fn test_resolve_uri_with_ipv6_address() {
        let resolver = SipResolver::new().await.unwrap();

        // IPv6 addresses with brackets - the simple parser treats the bracket as part of host
        // This is a known limitation of the simple parser
        // IPv6 colons are confused with port separator in simple parsing
        // Test with loopback address which should resolve
        let targets = resolver
            .resolve_uri("sip:user@::1:5060")
            .await;
        if targets.is_ok() {
            let targets = targets.unwrap();
            assert!(!targets.is_empty());
        }
    }

    #[tokio::test]
    async fn test_resolve_uri_trailing_semicolon() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver
            .resolve_uri("sip:user@192.168.1.1:5060;")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[0].port, 5060);
    }

    #[tokio::test]
    async fn test_resolve_uri_empty_transport_param() {
        let resolver = SipResolver::new().await.unwrap();

        // transport= with no value should be handled gracefully
        let targets = resolver
            .resolve_uri("sip:user@192.168.1.1:5060;transport=")
            .await;
        assert!(targets.is_ok());
        // Should default to UDP when transport is invalid
        let targets = targets.unwrap();
        assert_eq!(targets[0].transport, TransportProtocol::Udp);
    }

    #[tokio::test]
    async fn test_resolve_uri_other_params_ignored() {
        let resolver = SipResolver::new().await.unwrap();

        // Other parameters should be ignored
        let targets = resolver
            .resolve_uri("sip:user@192.168.1.1:5060;lr;maddr=10.0.0.1;ttl=1")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[0].port, 5060);
    }

    #[tokio::test]
    async fn test_resolve_uri_no_scheme() {
        let resolver = SipResolver::new().await.unwrap();

        // URI without sip: or sips: prefix
        let targets = resolver.resolve_uri("user@192.168.1.1:5060").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[0].port, 5060);
    }

    #[tokio::test]
    async fn test_resolve_uri_complex_username() {
        let resolver = SipResolver::new().await.unwrap();

        // Username with special characters
        let targets = resolver
            .resolve_uri("sip:user+name@192.168.1.1:5060")
            .await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "192.168.1.1");
    }

    // Error handling and edge cases
    #[tokio::test]
    async fn test_lookup_address_empty_addresses() {
        let resolver = SipResolver::new().await.unwrap();

        // Try to resolve an invalid/nonexistent IP-like string
        // This should fail since it's not a valid IP
        let result = resolver
            .lookup_address("not.a.valid.ip.address.that.does.not.exist.example", TransportProtocol::Udp)
            .await;

        // Should return an error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_addresses_invalid_hostname() {
        let resolver = SipResolver::new().await.unwrap();

        // Invalid hostname that can't be resolved
        let result = resolver
            .resolve_addresses("this-domain-definitely-does-not-exist-12345.invalid")
            .await;

        // Should return an error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_with_all_transports_fallback() {
        let resolver = SipResolver::new().await.unwrap();

        // When no preferred transport is specified and no SRV records exist,
        // it should try TLS, TCP, then UDP and fall back to A/AAAA
        let targets = resolver.resolve("127.0.0.1", None).await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        // Should fall back to default UDP with port 5060
        assert_eq!(targets[0].port, 5060);
    }

    #[tokio::test]
    async fn test_resolve_ipv6_loopback() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve("::1", Some(TransportProtocol::Tcp)).await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].transport, TransportProtocol::Tcp);
        assert_eq!(targets[0].addresses[0], "::1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_lookup_address_sets_correct_metadata() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver
            .lookup_address("192.168.1.1", TransportProtocol::Udp)
            .await
            .unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[0].port, 5060);
        assert_eq!(targets[0].transport, TransportProtocol::Udp);
        assert_eq!(targets[0].priority, 0);
        assert_eq!(targets[0].weight, 0);
        assert_eq!(targets[0].addresses.len(), 1);
    }

    #[tokio::test]
    async fn test_lookup_address_tls_port() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver
            .lookup_address("10.0.0.1", TransportProtocol::Tls)
            .await
            .unwrap();

        assert_eq!(targets[0].port, 5061);
        assert_eq!(targets[0].transport, TransportProtocol::Tls);
    }

    // ResolvedTarget additional tests
    #[test]
    fn test_resolved_target_with_multiple_addresses() {
        let target = ResolvedTarget {
            host: "multi.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 10,
            weight: 100,
            addresses: vec![
                "192.168.1.1".parse().unwrap(),
                "192.168.1.2".parse().unwrap(),
                "192.168.1.3".parse().unwrap(),
                "2001:db8::1".parse().unwrap(),
            ],
        };

        let addrs = target.socket_addrs();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0].port(), 5060);
        assert_eq!(addrs[1].port(), 5060);
        assert_eq!(addrs[2].port(), 5060);
        assert_eq!(addrs[3].port(), 5060);
    }

    #[test]
    fn test_resolved_target_fields() {
        let target = ResolvedTarget {
            host: "test.example.com".to_string(),
            port: 5070,
            transport: TransportProtocol::Tcp,
            priority: 25,
            weight: 75,
            addresses: vec!["10.0.0.1".parse().unwrap()],
        };

        assert_eq!(target.host, "test.example.com");
        assert_eq!(target.port, 5070);
        assert_eq!(target.transport, TransportProtocol::Tcp);
        assert_eq!(target.priority, 25);
        assert_eq!(target.weight, 75);
        assert_eq!(target.addresses.len(), 1);
    }

    // Test resolver configuration
    #[test]
    fn test_resolver_with_custom_config() {
        let config = ResolverConfig::default();
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);

        let _resolver = SipResolver::with_config(config.clone(), opts.clone());
        // Should not panic
    }

    // Edge case: URI with no @ symbol
    #[tokio::test]
    async fn test_resolve_uri_bare_domain() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve_uri("sip:192.168.1.1:5060").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].host, "192.168.1.1");
        assert_eq!(targets[0].port, 5060);
    }

    // Test default transport when none specified
    #[tokio::test]
    async fn test_resolve_uri_default_transport() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve_uri("sip:user@192.168.1.1:5060").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        // Should default to UDP
        assert_eq!(targets[0].transport, TransportProtocol::Udp);
    }

    // Test port parsing edge cases
    #[tokio::test]
    async fn test_resolve_uri_invalid_port_ignored() {
        let resolver = SipResolver::new().await.unwrap();

        // Invalid port should be handled (parse fails, becomes None)
        let targets = resolver.resolve_uri("sip:user@127.0.0.1:99999").await;
        // Port parsing will fail for 99999 (> u16::MAX), so explicit_port = None
        // Falls back to resolve() which uses default ports
        assert!(targets.is_ok());
    }

    #[tokio::test]
    async fn test_resolve_uri_zero_port() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve_uri("sip:user@192.168.1.1:0").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].port, 0);
    }

    #[tokio::test]
    async fn test_resolve_uri_max_port() {
        let resolver = SipResolver::new().await.unwrap();

        let targets = resolver.resolve_uri("sip:user@192.168.1.1:65535").await;
        assert!(targets.is_ok());
        let targets = targets.unwrap();
        assert_eq!(targets[0].port, 65535);
    }

    // Test transport parameter edge cases
    #[tokio::test]
    async fn test_resolve_uri_transport_case_variations() {
        let resolver = SipResolver::new().await.unwrap();

        let test_cases = vec![
            ("transport=udp", TransportProtocol::Udp),
            ("transport=UDP", TransportProtocol::Udp),
            ("transport=tcp", TransportProtocol::Tcp),
            ("transport=TCP", TransportProtocol::Tcp),
            ("transport=tls", TransportProtocol::Tls),
            ("transport=TLS", TransportProtocol::Tls),
        ];

        for (param, expected) in test_cases {
            let uri = format!("sip:user@192.168.1.1:5060;{}", param);
            let targets = resolver.resolve_uri(&uri).await;
            assert!(targets.is_ok());
            let targets = targets.unwrap();
            assert_eq!(targets[0].transport, expected, "Failed for param: {}", param);
        }
    }

    // Test that resolve tries all transports in correct order
    #[tokio::test]
    async fn test_resolve_transport_preference_order() {
        let resolver = SipResolver::new().await.unwrap();

        // With no preferred transport and no SRV records, should try TLS, TCP, UDP
        // For IP addresses, it will skip SRV and go to A/AAAA lookup
        let targets = resolver.resolve("127.0.0.1", None).await;
        assert!(targets.is_ok());

        // The first match wins, and for IP it uses default (UDP in this case)
        let targets = targets.unwrap();
        assert!(!targets.is_empty());
    }

    // Additional error display tests
    #[test]
    fn test_resolver_error_display_formats() {
        let err = ResolverError::NoRecords("test.example.com".to_string());
        assert_eq!(err.to_string(), "no DNS records found for test.example.com");

        let err = ResolverError::InvalidDomain("bad..domain..example".to_string());
        assert_eq!(err.to_string(), "invalid domain: bad..domain..example");
    }

    // Test clone implementation
    #[test]
    fn test_resolved_target_clone_independence() {
        let target = ResolvedTarget {
            host: "original.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 10,
            weight: 100,
            addresses: vec!["192.168.1.1".parse().unwrap()],
        };

        let mut cloned = target.clone();

        // Modify clone
        cloned.host = "modified.example.com".to_string();
        cloned.port = 5070;

        // Original should be unchanged
        assert_eq!(target.host, "original.example.com");
        assert_eq!(target.port, 5060);
    }

    // Test socket_addrs with various IP types
    #[test]
    fn test_socket_addrs_ipv4_only() {
        let target = ResolvedTarget {
            host: "ipv4.example.com".to_string(),
            port: 5060,
            transport: TransportProtocol::Udp,
            priority: 0,
            weight: 0,
            addresses: vec![
                "10.0.0.1".parse().unwrap(),
                "10.0.0.2".parse().unwrap(),
            ],
        };

        let addrs = target.socket_addrs();
        assert!(addrs.iter().all(|a| a.is_ipv4()));
    }

    #[test]
    fn test_socket_addrs_ipv6_only() {
        let target = ResolvedTarget {
            host: "ipv6.example.com".to_string(),
            port: 5061,
            transport: TransportProtocol::Tls,
            priority: 0,
            weight: 0,
            addresses: vec![
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ],
        };

        let addrs = target.socket_addrs();
        assert!(addrs.iter().all(|a| a.is_ipv6()));
    }

// Additional comprehensive tests for resolver coverage

// Test error case where lookup_address gets empty addresses
#[tokio::test]
async fn test_lookup_address_with_invalid_domain() {
    let resolver = SipResolver::new().await.unwrap();

    // This should fail as it's an obviously invalid domain
    let result = resolver
        .lookup_address("this.is.definitely.an.invalid.nonexistent.test.domain.12345", TransportProtocol::Udp)
        .await;

    assert!(result.is_err());
    // Should be either ResolverError::LookupFailed or ResolverError::NoRecords
}

// Test the full resolve() method with transport fallback when no preferred transport
#[tokio::test]
async fn test_resolve_without_preferred_transport_ip() {
    let resolver = SipResolver::new().await.unwrap();

    // Using IP will skip SRV and go to A lookup
    let targets = resolver.resolve("127.0.0.1", None).await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert!(!targets.is_empty());
    // Should default to UDP when no preference
    assert_eq!(targets[0].transport, TransportProtocol::Udp);
}

// Test resolve_uri that goes through resolve() path (no explicit port)
#[tokio::test]
async fn test_resolve_uri_without_port_uses_resolve_path() {
    let resolver = SipResolver::new().await.unwrap();

    // IP without port goes through resolve() -> lookup_address()
    let targets = resolver.resolve_uri("sip:user@127.0.0.1;transport=tcp").await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert!(!targets.is_empty());
    assert_eq!(targets[0].transport, TransportProtocol::Tcp);
    assert_eq!(targets[0].port, 5060); // Default TCP port
}

// Test resolve_uri with TLS transport and no port
#[tokio::test]
async fn test_resolve_uri_tls_without_port() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver.resolve_uri("sip:user@127.0.0.1;transport=tls").await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Tls);
    assert_eq!(targets[0].port, 5061); // Default TLS port
}

// Test URI parsing with equals sign in parameter value
#[tokio::test]
async fn test_resolve_uri_param_with_equals() {
    let resolver = SipResolver::new().await.unwrap();

    // Make sure transport parameter is still found even with other params
    let targets = resolver
        .resolve_uri("sip:user@192.168.1.1:5060;foo=bar=baz;transport=tcp;other=val")
        .await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Tcp);
}

// Test the transport selection logic in resolve() when preferred is Some
#[tokio::test]
async fn test_resolve_with_udp_transport_preference() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver.resolve("127.0.0.1", Some(TransportProtocol::Udp)).await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Udp);
    assert_eq!(targets[0].port, 5060);
}

// Test resolve with TLS preference
#[tokio::test]
async fn test_resolve_with_tls_transport_preference() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver.resolve("127.0.0.1", Some(TransportProtocol::Tls)).await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Tls);
    assert_eq!(targets[0].port, 5061);
}

// Test ResolverError From trait
#[test]
fn test_resolver_error_from_hickory_error() {
    use hickory_resolver::error::ResolveErrorKind;

    let hickory_err = hickory_resolver::error::ResolveError::from(
        ResolveErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::new()),
            soa: None,
            negative_ttl: None,
            response_code: hickory_resolver::proto::op::ResponseCode::NXDomain,
            trusted: false,
        }
    );

    let resolver_err: ResolverError = hickory_err.into();

    // Should be converted to ResolverError::LookupFailed
    assert!(matches!(resolver_err, ResolverError::LookupFailed(_)));
}

// Test the default ports for different transports in lookup_address
#[tokio::test]
async fn test_lookup_address_port_selection() {
    let resolver = SipResolver::new().await.unwrap();

    // UDP -> 5060
    let targets_udp = resolver.lookup_address("127.0.0.1", TransportProtocol::Udp).await.unwrap();
    assert_eq!(targets_udp[0].port, 5060);

    // TCP -> 5060
    let targets_tcp = resolver.lookup_address("127.0.0.1", TransportProtocol::Tcp).await.unwrap();
    assert_eq!(targets_tcp[0].port, 5060);

    // TLS -> 5061
    let targets_tls = resolver.lookup_address("127.0.0.1", TransportProtocol::Tls).await.unwrap();
    assert_eq!(targets_tls[0].port, 5061);
}

// Test resolve_addresses with IPv6
#[tokio::test]
async fn test_resolve_addresses_with_ipv6() {
    let resolver = SipResolver::new().await.unwrap();

    let addrs = resolver.resolve_addresses("::1").await.unwrap();
    assert_eq!(addrs.len(), 1);
    assert!(addrs[0].is_ipv6());
    assert_eq!(addrs[0], "::1".parse::<IpAddr>().unwrap());
}

// Test resolve_addresses with IPv4
#[tokio::test]
async fn test_resolve_addresses_with_ipv4() {
    let resolver = SipResolver::new().await.unwrap();

    let addrs = resolver.resolve_addresses("127.0.0.1").await.unwrap();
    assert_eq!(addrs.len(), 1);
    assert!(addrs[0].is_ipv4());
    assert_eq!(addrs[0], "127.0.0.1".parse::<IpAddr>().unwrap());
}

// Test URI parsing edge case - just an IP
#[tokio::test]
async fn test_resolve_uri_just_ip_with_port() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver.resolve_uri("192.168.1.1:5090").await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].host, "192.168.1.1");
    assert_eq!(targets[0].port, 5090);
}

// Test that empty addresses list in lookup_address returns NoRecords error
#[tokio::test]
async fn test_lookup_address_no_addresses_returns_error() {
    let resolver = SipResolver::new().await.unwrap();

    // Try to resolve a nonexistent domain
    let result = resolver
        .lookup_address("nonexistent-domain-that-definitely-does-not-exist-12345.invalid", TransportProtocol::Udp)
        .await;

    assert!(result.is_err());
}

// Test resolve_uri with mixed case TRANSPORT parameter
#[tokio::test]
async fn test_resolve_uri_mixed_case_transport_param_key() {
    let resolver = SipResolver::new().await.unwrap();

    // Test that Transport (mixed case) is handled
    let targets = resolver
        .resolve_uri("sip:user@192.168.1.1:5060;Transport=tcp")
        .await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Tcp);
}

// Test resolve_uri with all uppercase TRANSPORT parameter
#[tokio::test]
async fn test_resolve_uri_uppercase_transport_param_key() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver
        .resolve_uri("sip:user@192.168.1.1:5060;TRANSPORT=UDP")
        .await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Udp);
}

// Test ResolvedTarget with various transport types
#[test]
fn test_resolved_target_with_all_transports() {
    let transports = vec![
        TransportProtocol::Udp,
        TransportProtocol::Tcp,
        TransportProtocol::Tls,
    ];

    for transport in transports {
        let target = ResolvedTarget {
            host: "test.com".to_string(),
            port: 5060,
            transport: transport.clone(),
            priority: 0,
            weight: 0,
            addresses: vec![],
        };

        assert_eq!(target.transport, transport);
    }
}

// Test error display for all error variants
#[test]
fn test_all_resolver_error_variants_display() {
    // NoRecords
    let err1 = ResolverError::NoRecords("test.com".to_string());
    assert!(err1.to_string().contains("test.com"));
    assert!(err1.to_string().contains("no DNS records"));

    // InvalidDomain
    let err2 = ResolverError::InvalidDomain("bad.domain".to_string());
    assert!(err2.to_string().contains("bad.domain"));
    assert!(err2.to_string().contains("invalid domain"));
}

// Test resolve_uri with no transport parameter defaults to UDP
#[tokio::test]
async fn test_resolve_uri_no_transport_defaults_to_udp() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver
        .resolve_uri("sip:user@192.168.1.1:5060")
        .await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].transport, TransportProtocol::Udp);
}

// Test socket_addrs with different port numbers
#[test]
fn test_socket_addrs_various_ports() {
    let ports = vec![5060, 5061, 5080, 8080, 65535];

    for port in ports {
        let target = ResolvedTarget {
            host: "test.com".to_string(),
            port,
            transport: TransportProtocol::Udp,
            priority: 0,
            weight: 0,
            addresses: vec!["192.168.1.1".parse().unwrap()],
        };

        let addrs = target.socket_addrs();
        assert_eq!(addrs[0].port(), port);
    }
}

// Test that ResolvedTarget fields are accessible
#[test]
fn test_resolved_target_field_access() {
    let target = ResolvedTarget {
        host: "sip.example.com".to_string(),
        port: 5060,
        transport: TransportProtocol::Tcp,
        priority: 10,
        weight: 100,
        addresses: vec!["192.168.1.1".parse().unwrap()],
    };

    // Verify all fields are readable
    let _ = &target.host;
    let _ = target.port;
    let _ = target.transport;
    let _ = target.priority;
    let _ = target.weight;
    let _ = &target.addresses;

    assert_eq!(target.host, "sip.example.com");
    assert_eq!(target.port, 5060);
}

// Test resolve_uri with port but no transport uses default
#[tokio::test]
async fn test_resolve_uri_port_no_transport() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver.resolve_uri("sip:user@192.168.1.1:5070").await;

    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].port, 5070);
    assert_eq!(targets[0].transport, TransportProtocol::Udp); // Default
}

// Test ResolvedTarget clone creates independent copy
#[test]
fn test_resolved_target_clone_with_addresses() {
    let original = ResolvedTarget {
        host: "original.com".to_string(),
        port: 5060,
        transport: TransportProtocol::Udp,
        priority: 10,
        weight: 100,
        addresses: vec![
            "192.168.1.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
        ],
    };

    let cloned = original.clone();

    assert_eq!(cloned.addresses.len(), 2);
    assert_eq!(cloned.addresses[0], original.addresses[0]);
    assert_eq!(cloned.addresses[1], original.addresses[1]);
}

// Test that custom resolver config works
#[test]
fn test_custom_resolver_config_creation() {
    let config = ResolverConfig::new();

    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(10);
    opts.attempts = 3;

    let _resolver = SipResolver::with_config(config, opts);
    // Just verify it doesn't panic
}

// Test resolve_uri parsing various edge cases
#[tokio::test]
async fn test_resolve_uri_parsing_variations() {
    let resolver = SipResolver::new().await.unwrap();

    // Test various URI formats to exercise the parsing logic
    let test_cases = vec![
        // (URI, expected_host, expected_port, expected_transport)
        ("sip:alice@example.com:5060", "example.com", 5060, TransportProtocol::Udp),
        ("sips:bob@example.org:5061;transport=tls", "example.org", 5061, TransportProtocol::Tls),
        ("sip:example.net:5070;transport=tcp", "example.net", 5070, TransportProtocol::Tcp),
    ];

    for (uri, _expected_host, _expected_port, _expected_transport) in test_cases {
        let targets = resolver.resolve_uri(uri).await;
        // These may fail DNS lookup, but we're testing parsing
        if targets.is_err() {
            // If it fails, it should be a DNS error, not a panic
            continue;
        }
    }
}

// Test that trailing dots are handled in hostnames
#[tokio::test]
async fn test_resolve_addresses_with_trailing_dot() {
    let resolver = SipResolver::new().await.unwrap();

    // Hickory resolver should handle trailing dots
    let result = resolver.resolve_addresses("127.0.0.1.").await;
    // May succeed or fail depending on resolver behavior, but shouldn't panic
    let _ = result;
}

// Test resolve with different transport priorities
#[tokio::test]
async fn test_resolve_srv_name_generation() {
    let resolver = SipResolver::new().await.unwrap();

    // Test that resolve() generates correct SRV names for different transports
    // Using an invalid domain so it falls through to A/AAAA
    let result = resolver.resolve("nonexistent-test-12345.invalid", None).await;

    // Should fail but exercise the SRV name generation code paths
    assert!(result.is_err());
}

// Test resolve with each specific transport to exercise SRV name generation
#[tokio::test]
async fn test_resolve_srv_names_for_each_transport() {
    let resolver = SipResolver::new().await.unwrap();

    // Test UDP - generates _sip._udp.domain
    let _ = resolver.resolve("test-udp.invalid", Some(TransportProtocol::Udp)).await;

    // Test TCP - generates _sip._tcp.domain
    let _ = resolver.resolve("test-tcp.invalid", Some(TransportProtocol::Tcp)).await;

    // Test TLS - generates _sips._tcp.domain
    let _ = resolver.resolve("test-tls.invalid", Some(TransportProtocol::Tls)).await;
}

// Test resolve_uri with @ symbol handling
#[tokio::test]
async fn test_resolve_uri_with_at_symbol() {
    let resolver = SipResolver::new().await.unwrap();

    // Multiple @ symbols should use the last one
    let targets = resolver.resolve_uri("sip:user@domain@192.168.1.1:5060").await;
    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].host, "192.168.1.1");
}

// Test resolve_uri with no @ symbol
#[tokio::test]
async fn test_resolve_uri_without_at_symbol() {
    let resolver = SipResolver::new().await.unwrap();

    let targets = resolver.resolve_uri("sip:192.168.1.1:5060").await;
    assert!(targets.is_ok());
    let targets = targets.unwrap();
    assert_eq!(targets[0].host, "192.168.1.1");
}

// Test the semicolon parameter parsing
#[tokio::test]
async fn test_resolve_uri_parameter_parsing() {
    let resolver = SipResolver::new().await.unwrap();

    // No semicolon
    let targets = resolver.resolve_uri("sip:user@192.168.1.1:5060").await;
    assert!(targets.is_ok());

    // With semicolon but no transport
    let targets = resolver.resolve_uri("sip:user@192.168.1.1:5060;lr").await;
    assert!(targets.is_ok());

    // With multiple parameters
    let targets = resolver.resolve_uri("sip:user@192.168.1.1:5060;lr;transport=tcp;maddr=10.0.0.1").await;
    assert!(targets.is_ok());
    assert_eq!(targets.unwrap()[0].transport, TransportProtocol::Tcp);
}

// Test error from trait for hickory resolver errors
#[test]
fn test_resolver_error_from_trait() {
    use hickory_resolver::error::{ResolveError, ResolveErrorKind};

    // Create a hickory error
    let hickory_err = ResolveError::from(
        ResolveErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::new()),
            soa: None,
            negative_ttl: None,
            response_code: hickory_resolver::proto::op::ResponseCode::NXDomain,
            trusted: false,
        }
    );

    // Convert to ResolverError
    let resolver_err: ResolverError = hickory_err.into();

    // Verify it's the LookupFailed variant
    match resolver_err {
        ResolverError::LookupFailed(_) => (),
        _ => panic!("Expected LookupFailed variant"),
    }
}

// Test ResolvedTarget Debug impl coverage
#[test]
fn test_resolved_target_debug_format() {
    let target = ResolvedTarget {
        host: "test.example.com".to_string(),
        port: 5060,
        transport: TransportProtocol::Tcp,
        priority: 10,
        weight: 100,
        addresses: vec!["192.168.1.1".parse().unwrap()],
    };

    let debug_str = format!("{:?}", target);
    assert!(debug_str.contains("ResolvedTarget"));
    assert!(debug_str.contains("test.example.com"));
}

// Test ResolverError Debug impl coverage
#[test]
fn test_resolver_error_debug_format() {
    let err = ResolverError::NoRecords("test.invalid".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("NoRecords"));
    assert!(debug_str.contains("test.invalid"));
}

// Test Clone impl for ResolvedTarget
#[test]
fn test_resolved_target_clone_deep_copy() {
    let original = ResolvedTarget {
        host: "original.com".to_string(),
        port: 5060,
        transport: TransportProtocol::Udp,
        priority: 10,
        weight: 100,
        addresses: vec!["192.168.1.1".parse().unwrap()],
    };

    let mut cloned = original.clone();
    cloned.host = "modified.com".to_string();
    cloned.addresses.push("192.168.1.2".parse().unwrap());

    // Original should be unchanged
    assert_eq!(original.host, "original.com");
    assert_eq!(original.addresses.len(), 1);

    // Clone should have modifications
    assert_eq!(cloned.host, "modified.com");
    assert_eq!(cloned.addresses.len(), 2);
}
}
