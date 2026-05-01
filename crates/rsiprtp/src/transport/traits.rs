//! Transport trait definitions.
//!
//! Defines the common interface for SIP transports (UDP, TCP, TLS).

use bytes::Bytes;
use std::fmt;
use std::net::SocketAddr;

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
    use std::collections::HashSet;
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

    // Additional tests for better coverage

    #[test]
    fn test_transport_protocol_udp_not_secure() {
        assert!(!TransportProtocol::Udp.is_secure());
    }

    #[test]
    fn test_transport_protocol_display() {
        assert_eq!(format!("{}", TransportProtocol::Udp), "UDP");
        assert_eq!(format!("{}", TransportProtocol::Tcp), "TCP");
        assert_eq!(format!("{}", TransportProtocol::Tls), "TLS");
    }

    #[test]
    fn test_transport_protocol_debug() {
        assert!(format!("{:?}", TransportProtocol::Udp).contains("Udp"));
        assert!(format!("{:?}", TransportProtocol::Tcp).contains("Tcp"));
        assert!(format!("{:?}", TransportProtocol::Tls).contains("Tls"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_transport_protocol_clone() {
        let proto = TransportProtocol::Tcp;
        let cloned = proto.clone();
        assert_eq!(proto, cloned);
    }

    #[test]
    fn test_transport_protocol_copy() {
        let proto = TransportProtocol::Tls;
        let copied: TransportProtocol = proto;
        assert_eq!(proto, copied);
    }

    #[test]
    fn test_transport_protocol_eq() {
        assert_eq!(TransportProtocol::Udp, TransportProtocol::Udp);
        assert_ne!(TransportProtocol::Udp, TransportProtocol::Tcp);
        assert_ne!(TransportProtocol::Tcp, TransportProtocol::Tls);
    }

    #[test]
    fn test_transport_protocol_hash() {
        let mut set = HashSet::new();
        set.insert(TransportProtocol::Udp);
        set.insert(TransportProtocol::Tcp);
        set.insert(TransportProtocol::Tls);
        assert_eq!(set.len(), 3);
        assert!(set.contains(&TransportProtocol::Udp));
    }

    #[test]
    fn test_incoming_message_debug() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let msg = IncomingMessage {
            data: Bytes::from("test"),
            source: addr,
            transport: TransportProtocol::Udp,
        };
        let debug = format!("{:?}", msg);
        assert!(debug.contains("IncomingMessage"));
    }

    #[test]
    fn test_incoming_message_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let msg = IncomingMessage {
            data: Bytes::from("test"),
            source: addr,
            transport: TransportProtocol::Tcp,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.source, addr);
        assert_eq!(cloned.transport, TransportProtocol::Tcp);
        assert_eq!(cloned.data, msg.data);
    }

    #[test]
    fn test_outgoing_message_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let msg = OutgoingMessage::new(Bytes::from("test"), addr);
        assert_eq!(msg.destination, addr);
        assert_eq!(msg.data, Bytes::from("test"));
    }

    #[test]
    fn test_outgoing_message_debug() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let msg = OutgoingMessage::new(Bytes::from("test"), addr);
        let debug = format!("{:?}", msg);
        assert!(debug.contains("OutgoingMessage"));
    }

    #[test]
    fn test_outgoing_message_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let msg = OutgoingMessage::new(Bytes::from("hello"), addr);
        let cloned = msg.clone();
        assert_eq!(cloned.destination, addr);
        assert_eq!(cloned.data, Bytes::from("hello"));
    }

    #[test]
    fn test_transport_address_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5061);
        let ta = TransportAddress::new(addr, TransportProtocol::Tls);
        assert_eq!(ta.addr, addr);
        assert_eq!(ta.transport, TransportProtocol::Tls);
    }

    #[test]
    fn test_transport_address_debug() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let ta = TransportAddress::udp(addr);
        let debug = format!("{:?}", ta);
        assert!(debug.contains("TransportAddress"));
    }

    #[test]
    fn test_transport_address_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let ta = TransportAddress::udp(addr);
        let cloned = ta.clone();
        assert_eq!(ta, cloned);
    }

    #[test]
    fn test_transport_address_eq() {
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 5060);
        let ta1 = TransportAddress::udp(addr1);
        let ta2 = TransportAddress::udp(addr1);
        let ta3 = TransportAddress::udp(addr2);
        assert_eq!(ta1, ta2);
        assert_ne!(ta1, ta3);
    }

    #[test]
    fn test_transport_address_hash() {
        let mut set = HashSet::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let ta = TransportAddress::udp(addr);
        set.insert(ta.clone());
        assert!(set.contains(&ta));
    }

    #[test]
    fn test_transport_address_display() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let ta = TransportAddress::new(addr, TransportProtocol::Tcp);
        let display = format!("{}", ta);
        assert!(display.contains("192.168.1.1:5060"));
        assert!(display.contains("TCP"));
    }
}
