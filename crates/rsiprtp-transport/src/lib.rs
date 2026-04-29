//! Network transport layer for SIP signaling.
//!
//! Provides UDP, TCP, and TLS transports for SIP messages.
//!
//! # Overview
//!
//! This crate provides the network transport layer for SIP signaling.
//! Implements UDP, TCP, and TLS transports.
//!
//! # Example
//!
//! ```no_run
//! use rsiprtp_transport::{UdpTransport, TcpTransport, TlsTransport, TlsClientConfig};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // UDP transport
//! let addr: SocketAddr = "0.0.0.0:5060".parse()?;
//! let udp = UdpTransport::bind(addr).await?;
//!
//! // TCP transport
//! let tcp = TcpTransport::bind(addr).await?;
//! println!("Listening on {}", tcp.local_addr());
//!
//! // TLS client transport
//! let tls = TlsTransport::new_client(addr, TlsClientConfig::default())?;
//! # Ok(())
//! # }
//! ```

pub mod resolver;
pub mod tcp;
pub mod tls;
pub mod traits;
pub mod udp;

// Re-export main types
pub use resolver::{ResolvedTarget, ResolverError, SipResolver};
pub use tcp::{TcpSender, TcpTransport, MAX_TCP_SIZE};
pub use tls::{TlsClientConfig, TlsSender, TlsServerConfig, TlsTransport, MAX_TLS_SIZE};
pub use traits::{IncomingMessage, OutgoingMessage, TransportAddress, TransportProtocol};
pub use udp::{UdpSender, UdpTransport, MAX_UDP_SIZE, MTU_SAFE_SIZE};
