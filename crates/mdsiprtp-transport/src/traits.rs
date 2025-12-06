//! Transport trait definitions.
//!
//! Defines the common interface for SIP transports (UDP, TCP, TLS).

use bytes::Bytes;
use std::net::SocketAddr;
use std::fmt;

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// UDP (unreliable).
    Udp,
    /// TCP (reliable, connection-oriented).
    Tcp,
    /// TLS over TCP (secure, reliable).
    Tls,
}

impl TransportProtocol {
    /// Check if this is a reliable transport.
    pub fn is_reliable(&self) -> bool {
        matches!(self, TransportProtocol::Tcp | TransportProtocol::Tls)
    }

    /// Check if this is a secure transport.
    pub fn is_secure(&self) -> bool {
        matches!(self, TransportProtocol::Tls)
    }

    /// Get the default port for this transport.
    pub fn default_port(&self) -> u16 {
        match self {
            TransportProtocol::Udp | TransportProtocol::Tcp => 5060,
            TransportProtocol::Tls => 5061,
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportProtocol::Udp => write!(f, "UDP"),
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::Tls => write!(f, "TLS"),
        }
    }
}

/// Incoming message with source address.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    /// Raw message data.
    pub data: Bytes,
    /// Source address.
    pub source: SocketAddr,
    /// Transport protocol.
    pub transport: TransportProtocol,
}

/// Outgoing message with destination address.
#[derive(Debug, Clone)]
pub struct OutgoingMessage {
    /// Raw message data.
    pub data: Bytes,
    /// Destination address.
    pub destination: SocketAddr,
}

impl OutgoingMessage {
    /// Create a new outgoing message.
    pub fn new(data: Bytes, destination: SocketAddr) -> Self {
        Self { data, destination }
    }
}

/// Endpoint address (host + port + transport).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportAddress {
    /// Socket address.
    pub addr: SocketAddr,
    /// Transport protocol.
    pub transport: TransportProtocol,
}

impl TransportAddress {
    /// Create a new transport address.
    pub fn new(addr: SocketAddr, transport: TransportProtocol) -> Self {
        Self { addr, transport }
    }

    /// Create a UDP transport address.
    pub fn udp(addr: SocketAddr) -> Self {
        Self::new(addr, TransportProtocol::Udp)
    }
}

impl fmt::Display for TransportAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.transport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_transport_protocol() {
        assert!(!TransportProtocol::Udp.is_reliable());
        assert!(TransportProtocol::Tcp.is_reliable());
        assert!(TransportProtocol::Tls.is_reliable());
        assert!(TransportProtocol::Tls.is_secure());
        assert!(!TransportProtocol::Tcp.is_secure());
    }

    #[test]
    fn test_default_ports() {
        assert_eq!(TransportProtocol::Udp.default_port(), 5060);
        assert_eq!(TransportProtocol::Tcp.default_port(), 5060);
        assert_eq!(TransportProtocol::Tls.default_port(), 5061);
    }

    #[test]
    fn test_transport_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let ta = TransportAddress::udp(addr);
        assert_eq!(ta.transport, TransportProtocol::Udp);
        assert_eq!(ta.addr.port(), 5060);
    }
}
