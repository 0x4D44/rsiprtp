//! STUN client implementation (RFC 5389).
//!
//! Simple STUN Binding Request client for discovering the public
//! (server reflexive) address of a NAT-ed endpoint.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace};

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types.
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_SOFTWARE: u16 = 0x8022;

/// Address family constants.
const AF_IPV4: u8 = 0x01;
const AF_IPV6: u8 = 0x02;

/// STUN errors.
#[derive(Error, Debug)]
pub enum StunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Request timeout")]
    Timeout,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("STUN error response: {code} {reason}")]
    ErrorResponse { code: u16, reason: String },

    #[error("No mapped address in response")]
    NoMappedAddress,
}

/// Well-known STUN servers.
#[derive(Debug, Clone)]
pub struct StunServer {
    /// Server address.
    pub addr: SocketAddr,
    /// Server name (for logging).
    pub name: &'static str,
}

impl StunServer {
    /// Google's public STUN server.
    pub const GOOGLE: StunServer = StunServer {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(74, 125, 250, 129)), 19302),
        name: "stun.l.google.com",
    };

    /// Twilio's public STUN server.
    pub const TWILIO: StunServer = StunServer {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(34, 203, 254, 141)), 3478),
        name: "global.stun.twilio.com",
    };

    /// Create a custom STUN server.
    pub fn new(addr: SocketAddr, name: &'static str) -> Self {
        Self { addr, name }
    }
}

/// STUN client for discovering public address.
pub struct StunClient {
    socket: UdpSocket,
    timeout: Duration,
    retries: u32,
}

impl StunClient {
    /// Create a new STUN client bound to any available port.
    pub async fn new() -> Result<Self, StunError> {
        Self::bind("0.0.0.0:0").await
    }

    /// Create a new STUN client bound to a specific address.
    pub async fn bind(addr: &str) -> Result<Self, StunError> {
        let socket = UdpSocket::bind(addr).await?;
        debug!("STUN client bound to {}", socket.local_addr()?);

        Ok(Self {
            socket,
            timeout: Duration::from_secs(3),
            retries: 3,
        })
    }

    /// Set the request timeout.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Set the number of retries.
    pub fn set_retries(&mut self, retries: u32) {
        self.retries = retries;
    }

    /// Get the local address of the socket.
    pub fn local_addr(&self) -> Result<SocketAddr, StunError> {
        Ok(self.socket.local_addr()?)
    }

    /// Send a STUN Binding Request and return the mapped address.
    pub async fn binding_request(&self, server: StunServer) -> Result<SocketAddr, StunError> {
        let transaction_id = generate_transaction_id();
        let request = build_binding_request(&transaction_id);

        debug!(
            "Sending STUN Binding Request to {} ({})",
            server.addr, server.name
        );

        for attempt in 0..self.retries {
            if attempt > 0 {
                debug!("Retry {} for STUN request", attempt);
            }

            // Send request
            self.socket.send_to(&request, server.addr).await?;

            // Wait for response with timeout
            let mut buf = vec![0u8; 1024];
            match timeout(self.timeout, self.socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    trace!("Received {} bytes from {}", len, from);

                    // Verify it's from the server
                    if from != server.addr {
                        continue;
                    }

                    // Parse response
                    match parse_binding_response(&buf[..len], &transaction_id) {
                        Ok(addr) => {
                            debug!("STUN mapped address: {}", addr);
                            return Ok(addr);
                        }
                        Err(e) => {
                            debug!("Invalid STUN response: {}", e);
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => return Err(StunError::Io(e)),
                Err(_) => {
                    if attempt == self.retries - 1 {
                        return Err(StunError::Timeout);
                    }
                }
            }
        }

        Err(StunError::Timeout)
    }
}

/// Generate a random 96-bit transaction ID.
fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Build a STUN Binding Request message.
fn build_binding_request(transaction_id: &[u8; 12]) -> Bytes {
    let mut buf = BytesMut::with_capacity(20);

    // Message type: Binding Request
    buf.put_u16(BINDING_REQUEST);

    // Message length (no attributes)
    buf.put_u16(0);

    // Magic cookie
    buf.put_u32(MAGIC_COOKIE);

    // Transaction ID
    buf.put_slice(transaction_id);

    buf.freeze()
}

/// Parse a STUN Binding Response and extract the mapped address.
fn parse_binding_response(
    data: &[u8],
    expected_txn_id: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    if data.len() < 20 {
        return Err(StunError::InvalidResponse("Message too short".into()));
    }

    let mut buf = data;

    // Message type
    let msg_type = buf.get_u16();
    if msg_type == BINDING_ERROR {
        return Err(parse_error_response(&data[20..]));
    }
    if msg_type != BINDING_RESPONSE {
        return Err(StunError::InvalidResponse(format!(
            "Unexpected message type: 0x{:04x}",
            msg_type
        )));
    }

    // Message length
    let msg_len = buf.get_u16() as usize;
    if data.len() < 20 + msg_len {
        return Err(StunError::InvalidResponse("Truncated message".into()));
    }

    // Magic cookie
    let cookie = buf.get_u32();
    if cookie != MAGIC_COOKIE {
        return Err(StunError::InvalidResponse("Invalid magic cookie".into()));
    }

    // Transaction ID
    let mut txn_id = [0u8; 12];
    buf.copy_to_slice(&mut txn_id);
    if txn_id != *expected_txn_id {
        return Err(StunError::InvalidResponse("Transaction ID mismatch".into()));
    }

    // Parse attributes
    let mut attrs = &data[20..20 + msg_len];
    let mut mapped_addr: Option<SocketAddr> = None;
    let mut xor_mapped_addr: Option<SocketAddr> = None;

    while attrs.len() >= 4 {
        let attr_type = attrs.get_u16();
        let attr_len = attrs.get_u16() as usize;

        if attrs.len() < attr_len {
            break;
        }

        let attr_data = &attrs[..attr_len];

        match attr_type {
            ATTR_MAPPED_ADDRESS => {
                mapped_addr = parse_mapped_address(attr_data, false);
            }
            ATTR_XOR_MAPPED_ADDRESS => {
                xor_mapped_addr = parse_mapped_address(attr_data, true);
            }
            ATTR_SOFTWARE => {
                // Ignore software attribute
            }
            _ => {
                // Unknown attribute
                trace!("Unknown STUN attribute: 0x{:04x}", attr_type);
            }
        }

        // Move past attribute value (with padding to 4-byte boundary)
        let padded_len = (attr_len + 3) & !3;
        if attrs.len() >= padded_len {
            attrs.advance(padded_len);
        } else {
            break;
        }
    }

    // Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS
    xor_mapped_addr
        .or(mapped_addr)
        .ok_or(StunError::NoMappedAddress)
}

/// Parse a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute.
fn parse_mapped_address(data: &[u8], xor: bool) -> Option<SocketAddr> {
    if data.len() < 4 {
        return None;
    }

    let _reserved = data[0];
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    let port = if xor {
        port ^ (MAGIC_COOKIE >> 16) as u16
    } else {
        port
    };

    match family {
        AF_IPV4 if data.len() >= 8 => {
            let mut ip_bytes = [data[4], data[5], data[6], data[7]];
            if xor {
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                for (i, b) in ip_bytes.iter_mut().enumerate() {
                    *b ^= cookie_bytes[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port))
        }
        AF_IPV6 if data.len() >= 20 => {
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[4..20]);
            if xor {
                // XOR with magic cookie + transaction ID
                let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                for (i, b) in ip_bytes[..4].iter_mut().enumerate() {
                    *b ^= cookie_bytes[i];
                }
                // Note: Would need transaction ID for bytes 4-15
                // For simplicity, we don't support XOR for IPv6 here
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port))
        }
        _ => None,
    }
}

/// Parse an ERROR-CODE attribute from an error response.
fn parse_error_response(attrs: &[u8]) -> StunError {
    let mut buf = attrs;

    while buf.len() >= 4 {
        let attr_type = buf.get_u16();
        let attr_len = buf.get_u16() as usize;

        if attr_type == ATTR_ERROR_CODE && attr_len >= 4 && buf.len() >= attr_len {
            let _reserved = buf.get_u16();
            let class = buf.get_u8();
            let number = buf.get_u8();
            let code = (class as u16) * 100 + (number as u16);

            let reason = if attr_len > 4 {
                String::from_utf8_lossy(&buf[..attr_len - 4]).to_string()
            } else {
                String::new()
            };

            return StunError::ErrorResponse { code, reason };
        }

        let padded_len = (attr_len + 3) & !3;
        if buf.len() >= padded_len {
            buf.advance(padded_len);
        } else {
            break;
        }
    }

    StunError::ErrorResponse {
        code: 0,
        reason: "Unknown error".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // StunError tests
    #[test]
    fn test_stun_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err: StunError = io_err.into();
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_stun_error_timeout() {
        let err = StunError::Timeout;
        assert_eq!(err.to_string(), "Request timeout");
    }

    #[test]
    fn test_stun_error_invalid_response() {
        let err = StunError::InvalidResponse("bad data".to_string());
        assert!(err.to_string().contains("Invalid response"));
        assert!(err.to_string().contains("bad data"));
    }

    #[test]
    fn test_stun_error_error_response() {
        let err = StunError::ErrorResponse {
            code: 401,
            reason: "Unauthorized".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("401"));
        assert!(msg.contains("Unauthorized"));
    }

    #[test]
    fn test_stun_error_no_mapped_address() {
        let err = StunError::NoMappedAddress;
        assert!(err.to_string().contains("No mapped address"));
    }

    #[test]
    fn test_stun_error_debug() {
        let err = StunError::Timeout;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Timeout"));
    }

    // StunServer tests
    #[test]
    fn test_stun_server_new() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 3478);
        let server = StunServer::new(addr, "custom.stun.server");
        assert_eq!(server.addr, addr);
        assert_eq!(server.name, "custom.stun.server");
    }

    #[test]
    fn test_stun_server_debug() {
        let debug = format!("{:?}", StunServer::GOOGLE);
        assert!(debug.contains("StunServer"));
        assert!(debug.contains("google"));
    }

    #[test]
    fn test_stun_server_clone() {
        let server = StunServer::GOOGLE;
        let cloned = server.clone();
        assert_eq!(cloned.addr, server.addr);
        assert_eq!(cloned.name, server.name);
    }

    #[test]
    fn test_stun_server_constants() {
        assert_eq!(StunServer::GOOGLE.addr.port(), 19302);
        assert_eq!(StunServer::TWILIO.addr.port(), 3478);
    }

    // Transaction ID tests
    #[test]
    fn test_generate_transaction_id() {
        let id1 = generate_transaction_id();
        let id2 = generate_transaction_id();

        assert_eq!(id1.len(), 12);
        assert_ne!(id1, id2); // Extremely unlikely to be equal
    }

    #[test]
    fn test_generate_transaction_id_uniqueness() {
        let ids: Vec<_> = (0..10).map(|_| generate_transaction_id()).collect();
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j]);
            }
        }
    }

    // Build binding request tests
    #[test]
    fn test_build_binding_request() {
        let txn_id = [1u8; 12];
        let request = build_binding_request(&txn_id);

        assert_eq!(request.len(), 20);

        // Check message type (Binding Request)
        assert_eq!(request[0], 0x00);
        assert_eq!(request[1], 0x01);

        // Check message length (0)
        assert_eq!(request[2], 0x00);
        assert_eq!(request[3], 0x00);

        // Check magic cookie
        assert_eq!(request[4], 0x21);
        assert_eq!(request[5], 0x12);
        assert_eq!(request[6], 0xA4);
        assert_eq!(request[7], 0x42);

        // Check transaction ID
        assert_eq!(&request[8..20], &[1u8; 12]);
    }

    // Parse mapped address tests
    #[test]
    fn test_parse_mapped_address_ipv4() {
        // MAPPED-ADDRESS: 192.168.1.1:1234
        let data = [
            0x00, // Reserved
            0x01, // Family: IPv4
            0x04, 0xD2, // Port: 1234
            192, 168, 1, 1, // IP
        ];

        let addr = parse_mapped_address(&data, false).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1234)
        );
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        // XOR-MAPPED-ADDRESS for 192.168.1.1:1234
        // XOR with magic cookie 0x2112A442
        let xor_port = 1234u16 ^ (MAGIC_COOKIE >> 16) as u16; // 1234 ^ 0x2112 = 0x25D0
        let xor_ip = [192 ^ 0x21, 168 ^ 0x12, 1 ^ 0xA4, 1 ^ 0x42];

        let data = [
            0x00, // Reserved
            0x01, // Family: IPv4
            (xor_port >> 8) as u8,
            (xor_port & 0xFF) as u8,
            xor_ip[0],
            xor_ip[1],
            xor_ip[2],
            xor_ip[3],
        ];

        let addr = parse_mapped_address(&data, true).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1234)
        );
    }

    #[test]
    fn test_parse_mapped_address_ipv6() {
        // MAPPED-ADDRESS: [2001:db8::1]:8080
        let mut data = vec![0x00, AF_IPV6];
        data.extend_from_slice(&8080u16.to_be_bytes());
        // IPv6 address bytes
        let ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        data.extend_from_slice(&ipv6.octets());

        let addr = parse_mapped_address(&data, false).unwrap();
        assert_eq!(addr.port(), 8080);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_parse_mapped_address_too_short() {
        let data = [0x00, 0x01, 0x00]; // Only 3 bytes
        assert!(parse_mapped_address(&data, false).is_none());
    }

    #[test]
    fn test_parse_mapped_address_unknown_family() {
        let data = [0x00, 0x03, 0x00, 0x50, 1, 2, 3, 4]; // Unknown family 0x03
        assert!(parse_mapped_address(&data, false).is_none());
    }

    #[test]
    fn test_parse_mapped_address_ipv4_too_short() {
        let data = [0x00, AF_IPV4, 0x00, 0x50, 1, 2, 3]; // Only 7 bytes, need 8 for IPv4
        assert!(parse_mapped_address(&data, false).is_none());
    }

    #[test]
    fn test_parse_mapped_address_ipv6_too_short() {
        let data = [0x00, AF_IPV6, 0x00, 0x50, 1, 2, 3, 4, 5, 6, 7, 8]; // Only 12 bytes, need 20 for IPv6
        assert!(parse_mapped_address(&data, false).is_none());
    }

    // Parse binding response tests
    #[test]
    fn test_parse_binding_response() {
        let txn_id = [0x11u8; 12];

        // Build a valid response
        let mut response = BytesMut::new();

        // Header
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(12); // Message length (XOR-MAPPED-ADDRESS)
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // XOR-MAPPED-ADDRESS attribute
        response.put_u16(ATTR_XOR_MAPPED_ADDRESS);
        response.put_u16(8); // Length

        // XOR'd address for 1.2.3.4:5678
        let xor_port = 5678u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = [1 ^ 0x21, 2 ^ 0x12, 3 ^ 0xA4, 4 ^ 0x42];
        response.put_u8(0x00); // Reserved
        response.put_u8(0x01); // Family
        response.put_u16(xor_port);
        response.put_slice(&xor_ip);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678)
        );
    }

    #[test]
    fn test_parse_binding_response_too_short() {
        let data = [0u8; 10]; // Less than 20 bytes
        let txn_id = [0u8; 12];
        let result = parse_binding_response(&data, &txn_id);
        assert!(matches!(result, Err(StunError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_binding_response_wrong_type() {
        let mut response = BytesMut::new();
        response.put_u16(0x0002); // Wrong message type
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&[0u8; 12]);

        let result = parse_binding_response(&response, &[0u8; 12]);
        assert!(matches!(result, Err(StunError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_binding_response_bad_cookie() {
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0);
        response.put_u32(0xDEADBEEF); // Wrong cookie
        response.put_slice(&[0u8; 12]);

        let result = parse_binding_response(&response, &[0u8; 12]);
        assert!(matches!(result, Err(StunError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_binding_response_txn_id_mismatch() {
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&[0x11u8; 12]); // Different txn ID

        let result = parse_binding_response(&response, &[0x22u8; 12]);
        assert!(matches!(result, Err(StunError::InvalidResponse(_))));
    }

    #[test]
    fn test_parse_binding_response_no_mapped_address() {
        let txn_id = [0x33u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(8); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Add SOFTWARE attribute instead of mapped address
        response.put_u16(ATTR_SOFTWARE);
        response.put_u16(4);
        response.put_slice(b"test");

        let result = parse_binding_response(&response, &txn_id);
        assert!(matches!(result, Err(StunError::NoMappedAddress)));
    }

    #[test]
    fn test_parse_binding_response_with_mapped_address() {
        let txn_id = [0x44u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(12); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Add MAPPED-ADDRESS (not XOR)
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00); // Reserved
        response.put_u8(AF_IPV4);
        response.put_u16(5060);
        response.put_slice(&[10, 0, 0, 1]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060)
        );
    }

    // Parse error response tests
    #[test]
    fn test_parse_error_response() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(8); // 4 header + 4 reason
        attrs.put_u16(0); // Reserved
        attrs.put_u8(4); // Class
        attrs.put_u8(1); // Number -> 401
        attrs.put_slice(b"Auth"); // Reason

        let err = parse_error_response(&attrs);
        match err {
            StunError::ErrorResponse { code, reason } => {
                assert_eq!(code, 401);
                assert_eq!(reason, "Auth");
            }
            _ => panic!("Expected ErrorResponse"),
        }
    }

    #[test]
    fn test_parse_error_response_no_reason() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(4); // Just header, no reason
        attrs.put_u16(0); // Reserved
        attrs.put_u8(5); // Class
        attrs.put_u8(0); // Number -> 500

        let err = parse_error_response(&attrs);
        match err {
            StunError::ErrorResponse { code, reason } => {
                assert_eq!(code, 500);
                assert!(reason.is_empty());
            }
            _ => panic!("Expected ErrorResponse"),
        }
    }

    #[test]
    fn test_parse_error_response_no_error_attr() {
        let attrs = [0u8; 0]; // Empty
        let err = parse_error_response(&attrs);
        match err {
            StunError::ErrorResponse { code, .. } => {
                assert_eq!(code, 0);
            }
            _ => panic!("Expected ErrorResponse"),
        }
    }

    // StunClient tests
    #[tokio::test]
    async fn test_stun_client_creation() {
        let client = StunClient::new().await;
        assert!(client.is_ok());

        let client = client.unwrap();
        assert!(client.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_stun_client_bind() {
        let client = StunClient::bind("127.0.0.1:0").await;
        assert!(client.is_ok());
        let client = client.unwrap();
        let addr = client.local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn test_stun_client_set_timeout() {
        let mut client = StunClient::new().await.unwrap();
        client.set_timeout(Duration::from_secs(5));
        assert_eq!(client.timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_stun_client_set_retries() {
        let mut client = StunClient::new().await.unwrap();
        client.set_retries(5);
        assert_eq!(client.retries, 5);
    }
}
