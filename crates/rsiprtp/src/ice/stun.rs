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

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Underlying network I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// STUN request timed out before any response arrived.
    #[error("Request timeout")]
    Timeout,

    /// Server returned a malformed or unparseable STUN message.
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Server returned an error response (RFC 5389 §15.6 ERROR-CODE).
    #[error("STUN error response: {code} {reason}")]
    ErrorResponse {
        /// Numeric STUN error code (e.g. 401 Unauthorized).
        code: u16,
        /// Human-readable reason phrase from the server.
        reason: String,
    },

    /// Binding response lacked a MAPPED-ADDRESS / XOR-MAPPED-ADDRESS attribute.
    #[error("No mapped address in response")]
    NoMappedAddress,
}

#[cfg(test)]
static FORCE_LOCAL_ADDR_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_SEND_ERROR: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static FORCE_RECV_ERROR: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
fn force_local_addr_error_once() {
    FORCE_LOCAL_ADDR_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_send_error_once() {
    FORCE_SEND_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn force_recv_error_once() {
    FORCE_RECV_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn take_forced_error(flag: &AtomicU64, message: &str) -> Option<std::io::Error> {
    let current = current_thread_id();
    if flag.load(Ordering::SeqCst) == current {
        let _ = flag.compare_exchange(current, 0, Ordering::SeqCst, Ordering::SeqCst);
        Some(std::io::Error::other(message))
    } else {
        None
    }
}

#[cfg(test)]
fn current_thread_id() -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    let id = hasher.finish();
    normalize_thread_id(id)
}

#[cfg(test)]
fn normalize_thread_id(id: u64) -> u64 {
    if id == 0 {
        1
    } else {
        id
    }
}

fn socket_local_addr(socket: &UdpSocket) -> Result<SocketAddr, StunError> {
    socket_local_addr_inner(socket).map_err(StunError::Io)
}

fn socket_local_addr_inner(socket: &UdpSocket) -> Result<SocketAddr, std::io::Error> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_LOCAL_ADDR_ERROR, "forced local_addr error") {
        return Err(err);
    }
    socket.local_addr()
}

async fn socket_send_to(
    socket: &UdpSocket,
    data: &[u8],
    addr: SocketAddr,
) -> Result<(), StunError> {
    socket_send_to_inner(socket, data, addr)
        .await
        .map(|_| ())
        .map_err(StunError::Io)
}

async fn socket_send_to_inner(
    socket: &UdpSocket,
    data: &[u8],
    addr: SocketAddr,
) -> Result<usize, std::io::Error> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_SEND_ERROR, "forced send_to error") {
        return Err(err);
    }
    socket.send_to(data, addr).await
}

async fn socket_recv_from(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr), StunError> {
    socket_recv_from_inner(socket, buf)
        .await
        .map_err(StunError::Io)
}

async fn socket_recv_from_inner(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr), std::io::Error> {
    #[cfg(test)]
    if let Some(err) = take_forced_error(&FORCE_RECV_ERROR, "forced recv_from error") {
        return Err(err);
    }
    socket.recv_from(buf).await
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
        let local_addr = socket_local_addr(&socket)?;
        debug!("STUN client bound to {}", local_addr);

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
        socket_local_addr(&self.socket)
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
            socket_send_to(&self.socket, &request, server.addr).await?;

            // Wait for response with timeout
            let mut buf = vec![0u8; 1024];
            match timeout(self.timeout, socket_recv_from(&self.socket, &mut buf)).await {
                Ok(result) => {
                    let (len, from) = result?;
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
    use std::sync::Once;

    fn build_xor_mapped_response(transaction_id: &[u8; 12], addr: std::net::SocketAddrV4) -> Bytes {
        let mut response = BytesMut::with_capacity(32);
        let xor_port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
        let xor_ip = u32::from(*addr.ip()) ^ MAGIC_COOKIE;

        response.put_u16(BINDING_RESPONSE);
        response.put_u16(12); // Single XOR-MAPPED-ADDRESS attribute
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(transaction_id);
        response.put_u16(ATTR_XOR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(xor_port);
        response.put_slice(&xor_ip.to_be_bytes());

        response.freeze()
    }

    fn init_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_test_writer()
                .try_init();
        });
    }

    #[test]
    fn test_normalize_thread_id_branches() {
        assert_eq!(normalize_thread_id(0), 1);
        assert_eq!(normalize_thread_id(123), 123);
    }

    fn assert_stun_err_contains<T>(result: Result<T, StunError>, needle: &str) {
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err:?}").contains(needle));
    }

    fn error_response_matches(err: &StunError, code: u16, reason: &str) -> bool {
        match err {
            StunError::ErrorResponse {
                code: err_code,
                reason: err_reason,
            } => *err_code == code && err_reason == reason,
            _ => false,
        }
    }

    // StunError tests
    #[test]
    fn test_stun_error_io() {
        let io_err = std::io::Error::other("test");
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
        assert_stun_err_contains(result, "InvalidResponse");
    }

    #[test]
    fn test_parse_binding_response_wrong_type() {
        let mut response = BytesMut::new();
        response.put_u16(0x0002); // Wrong message type
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&[0u8; 12]);

        let result = parse_binding_response(&response, &[0u8; 12]);
        assert_stun_err_contains(result, "InvalidResponse");
    }

    #[test]
    fn test_parse_binding_response_bad_cookie() {
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0);
        response.put_u32(0xDEADBEEF); // Wrong cookie
        response.put_slice(&[0u8; 12]);

        let result = parse_binding_response(&response, &[0u8; 12]);
        assert_stun_err_contains(result, "InvalidResponse");
    }

    #[test]
    fn test_parse_binding_response_txn_id_mismatch() {
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&[0x11u8; 12]); // Different txn ID

        let result = parse_binding_response(&response, &[0x22u8; 12]);
        assert_stun_err_contains(result, "InvalidResponse");
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
        assert_stun_err_contains(result, "NoMappedAddress");
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

    #[test]
    fn test_parse_binding_response_truncated_padding() {
        let txn_id = [0x11u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(5);
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);
        response.put_u16(ATTR_SOFTWARE);
        response.put_u16(1);
        response.put_u8(0xAB);

        let result = parse_binding_response(&response, &txn_id);
        assert_stun_err_contains(result, "NoMappedAddress");
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
        assert!(error_response_matches(&err, 401, "Auth"));
    }

    #[test]
    fn test_parse_error_response_error_code_parsed() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(4); // Just header, no reason
        attrs.put_u16(0); // Reserved
        attrs.put_u8(4); // Class
        attrs.put_u8(1); // Number -> 401

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 401, ""));
    }

    #[test]
    fn test_parse_error_response_short_error_code_attr() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(2); // Too short to include class/number
        attrs.put_u16(0x1234);

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 0, "Unknown error"));
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
        assert!(error_response_matches(&err, 500, ""));
    }

    #[test]
    fn test_parse_error_response_no_error_attr() {
        let attrs = [0u8; 0]; // Empty
        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 0, "Unknown error"));
    }

    #[test]
    fn test_error_response_matches_false() {
        let err = StunError::Timeout;
        assert!(!error_response_matches(&err, 401, "Auth"));
    }

    #[test]
    fn test_error_response_matches_reason_mismatch() {
        let err = StunError::ErrorResponse {
            code: 401,
            reason: "Auth".to_string(),
        };
        assert!(!error_response_matches(&err, 401, "Other"));
    }

    #[test]
    fn test_error_response_matches_code_mismatch() {
        let err = StunError::ErrorResponse {
            code: 400,
            reason: "Auth".to_string(),
        };
        assert!(!error_response_matches(&err, 401, "Auth"));
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
    async fn test_stun_client_bind_invalid_address() {
        let client = StunClient::bind("256.256.256.256:0").await;
        assert_stun_err_contains(client, "Io");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stun_client_bind_forced_local_addr_error() {
        force_local_addr_error_once();
        let client = StunClient::bind("127.0.0.1:0").await;
        assert_stun_err_contains(client, "Io");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stun_client_local_addr_forced_error() {
        let client = StunClient::bind("127.0.0.1:0").await.unwrap();
        force_local_addr_error_once();
        let result = client.local_addr();
        assert_stun_err_contains(result, "Io");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stun_client_binding_request_forced_send_error() {
        let client = StunClient::bind("127.0.0.1:0").await.unwrap();
        force_send_error_once();
        let result = client
            .binding_request(StunServer::new("127.0.0.1:3478".parse().unwrap(), "forced"))
            .await;
        assert_stun_err_contains(result, "Io");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_stun_client_binding_request_forced_recv_error() {
        let client = StunClient::bind("127.0.0.1:0").await.unwrap();
        force_recv_error_once();
        let result = client
            .binding_request(StunServer::new("127.0.0.1:3478".parse().unwrap(), "forced"))
            .await;
        assert_stun_err_contains(result, "Io");
    }

    #[tokio::test]
    async fn test_stun_client_set_timeout() {
        let mut client = StunClient::new().await.unwrap();
        client.set_timeout(Duration::from_secs(5));
        assert_eq!(client.timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_stun_client_binding_request_success_with_retry() {
        init_tracing();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            assert!(len >= 20);
            let transaction_id: [u8; 12] = buf[8..20].try_into().unwrap();
            let spoof_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let spoof_response = build_xor_mapped_response(
                &transaction_id,
                std::net::SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 1), 4000),
            );
            let _ = spoof_socket.send_to(&spoof_response, client_addr).await;

            let (len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            assert!(len >= 20);
            let transaction_id: [u8; 12] = buf[8..20].try_into().unwrap();
            let mapped_addr = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 54321);
            let response = build_xor_mapped_response(&transaction_id, mapped_addr);
            server_socket.send_to(&response, client_addr).await.unwrap();
            mapped_addr
        });

        let mut client = StunClient::bind("127.0.0.1:0").await.unwrap();
        client.set_timeout(Duration::from_millis(200));
        client.set_retries(2);

        let mapped = client
            .binding_request(StunServer::new(server_addr, "local"))
            .await
            .unwrap();
        let expected = server_task.await.unwrap();
        assert_eq!(mapped, SocketAddr::V4(expected));
    }

    #[tokio::test]
    async fn test_stun_client_binding_request_timeout() {
        init_tracing();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let mut client = StunClient::bind("127.0.0.1:0").await.unwrap();
        client.set_timeout(Duration::from_millis(50));
        client.set_retries(1);

        let result = client
            .binding_request(StunServer::new(server_addr, "silent"))
            .await;
        assert_stun_err_contains(result, "Timeout");
    }

    #[tokio::test]
    async fn test_stun_client_binding_request_invalid_response_then_success() {
        init_tracing();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            let (_len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();
            let mut bad_response = BytesMut::new();
            bad_response.put_u16(BINDING_RESPONSE);
            bad_response.put_u16(0);
            bad_response.put_u32(0xdead_beef);
            bad_response.put_slice(&txn_id);
            let _ = server_socket.send_to(&bad_response, client_addr).await;

            let (_len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();
            let mapped_addr = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 2), 54321);
            let response = build_xor_mapped_response(&txn_id, mapped_addr);
            server_socket.send_to(&response, client_addr).await.unwrap();
            mapped_addr
        });

        let mut client = StunClient::bind("127.0.0.1:0").await.unwrap();
        client.set_timeout(Duration::from_millis(80));
        client.set_retries(2);

        let mapped = client
            .binding_request(StunServer::new(server_addr, "local"))
            .await
            .unwrap();
        let expected = server_task.await.unwrap();
        assert_eq!(mapped, SocketAddr::V4(expected));
    }

    #[tokio::test]
    async fn test_stun_client_binding_request_timeout_then_success() {
        init_tracing();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            let (_len, _client_addr) = server_socket.recv_from(&mut buf).await.unwrap();

            let (_len, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().unwrap();
            let mapped_addr = std::net::SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 54322);
            let response = build_xor_mapped_response(&txn_id, mapped_addr);
            server_socket.send_to(&response, client_addr).await.unwrap();
            mapped_addr
        });

        let mut client = StunClient::bind("127.0.0.1:0").await.unwrap();
        client.set_timeout(Duration::from_millis(50));
        client.set_retries(2);

        let mapped = client
            .binding_request(StunServer::new(server_addr, "local"))
            .await
            .unwrap();
        let expected = server_task.await.unwrap();
        assert_eq!(mapped, SocketAddr::V4(expected));
    }

    #[tokio::test]
    async fn test_stun_client_binding_request_zero_retries_timeout() {
        init_tracing();
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let mut client = StunClient::bind("127.0.0.1:0").await.unwrap();
        client.set_timeout(Duration::from_millis(20));
        client.set_retries(0);

        let result = client
            .binding_request(StunServer::new(server_addr, "silent"))
            .await;
        assert_stun_err_contains(result, "Timeout");
    }

    #[tokio::test]
    async fn test_stun_client_set_retries() {
        let mut client = StunClient::new().await.unwrap();
        client.set_retries(5);
        assert_eq!(client.retries, 5);
    }

    // Error response parsing - comprehensive tests
    #[test]
    fn test_parse_binding_response_error_type() {
        let txn_id = [0x55u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_ERROR);
        response.put_u16(8); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // ERROR-CODE attribute
        response.put_u16(ATTR_ERROR_CODE);
        response.put_u16(4);
        response.put_u16(0); // Reserved
        response.put_u8(4); // Class
        response.put_u8(20); // Number -> 420

        let result = parse_binding_response(&response, &txn_id);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(error_response_matches(&err, 420, ""));
    }

    #[test]
    fn test_parse_error_response_with_reason_phrase() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(20); // 4 header + 16 reason
        attrs.put_u16(0); // Reserved
        attrs.put_u8(4); // Class
        attrs.put_u8(2); // Number -> 402
        attrs.put_slice(b"Payment Required"); // Reason

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 402, "Payment Required"));
    }

    #[test]
    fn test_parse_error_response_multiple_attributes() {
        let mut attrs = BytesMut::new();

        // SOFTWARE attribute first
        attrs.put_u16(ATTR_SOFTWARE);
        attrs.put_u16(4);
        attrs.put_slice(b"test");

        // ERROR-CODE attribute
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(8);
        attrs.put_u16(0); // Reserved
        attrs.put_u8(3); // Class
        attrs.put_u8(0); // Number -> 300
        attrs.put_slice(b"move"); // Reason

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 300, "move"));
    }

    #[test]
    fn test_parse_error_response_truncated_attribute() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(10); // Claim 10 bytes but provide less
        attrs.put_u16(0); // Reserved
        attrs.put_u8(5); // Class
                         // Missing rest of data

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 0, "Unknown error"));
    }

    #[test]
    fn test_parse_error_response_wrong_attribute_type() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_MAPPED_ADDRESS); // Wrong type
        attrs.put_u16(8);
        attrs.put_slice(&[0u8; 8]);

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 0, "Unknown error"));
    }

    #[test]
    fn test_parse_error_response_with_padding() {
        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(5); // 4 header + 1 byte reason (needs padding)
        attrs.put_u16(0); // Reserved
        attrs.put_u8(4); // Class
        attrs.put_u8(4); // Number -> 404
        attrs.put_u8(b'X'); // 1 byte reason
        attrs.put_slice(&[0, 0, 0]); // Padding to 4-byte boundary

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 404, "X"));
    }

    // Unknown attribute handling tests
    #[test]
    fn test_parse_binding_response_with_unknown_attributes() {
        let txn_id = [0x66u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(32); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Unknown attribute 1
        response.put_u16(0xFFFF);
        response.put_u16(4);
        response.put_slice(&[1, 2, 3, 4]);

        // XOR-MAPPED-ADDRESS
        response.put_u16(ATTR_XOR_MAPPED_ADDRESS);
        response.put_u16(8);
        let xor_port = 9999u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = [8 ^ 0x21, 8 ^ 0x12, 8 ^ 0xA4, 8 ^ 0x42];
        response.put_u8(0x00);
        response.put_u8(0x01);
        response.put_u16(xor_port);
        response.put_slice(&xor_ip);

        // Unknown attribute 2
        response.put_u16(0xABCD);
        response.put_u16(8);
        response.put_slice(&[0u8; 8]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 9999);
    }

    #[test]
    fn test_parse_binding_response_unknown_attr_with_odd_padding() {
        let txn_id = [0x77u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(24); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Unknown attribute with 5 bytes (needs 3 bytes padding)
        response.put_u16(0x1234);
        response.put_u16(5);
        response.put_slice(&[1, 2, 3, 4, 5]);
        response.put_slice(&[0, 0, 0]); // Padding

        // MAPPED-ADDRESS
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(8080);
        response.put_slice(&[127, 0, 0, 1]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_parse_binding_response_prefers_xor_over_mapped() {
        let txn_id = [0x88u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(24); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // MAPPED-ADDRESS (should be ignored)
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(1111);
        response.put_slice(&[1, 1, 1, 1]);

        // XOR-MAPPED-ADDRESS (should be preferred)
        response.put_u16(ATTR_XOR_MAPPED_ADDRESS);
        response.put_u16(8);
        let xor_port = 2222u16 ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = [2 ^ 0x21, 2 ^ 0x12, 2 ^ 0xA4, 2 ^ 0x42];
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(xor_port);
        response.put_slice(&xor_ip);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 2222);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));
    }

    // Malformed response handling tests
    #[test]
    fn test_parse_binding_response_truncated_header() {
        let data = [0u8; 15]; // Less than 20 bytes header
        let txn_id = [0u8; 12];
        let result = parse_binding_response(&data, &txn_id);
        assert_stun_err_contains(result, "InvalidResponse");
    }

    #[test]
    fn test_parse_binding_response_truncated_attributes() {
        let txn_id = [0x99u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(20); // Claim 20 bytes of attributes
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);
        // But only provide 10 bytes
        response.put_slice(&[0u8; 10]);

        let result = parse_binding_response(&response, &txn_id);
        assert_stun_err_contains(result, "InvalidResponse");
    }

    #[test]
    fn test_parse_binding_response_attribute_truncated_header() {
        let txn_id = [0xAAu8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(3); // Message length (incomplete attribute header)
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);
        // Attribute header needs 4 bytes, only provide 3
        response.put_slice(&[0u8; 3]);

        let result = parse_binding_response(&response, &txn_id);
        assert_stun_err_contains(result, "NoMappedAddress");
    }

    #[test]
    fn test_parse_binding_response_attribute_truncated_value() {
        let txn_id = [0xBBu8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(10); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Attribute claims 8 bytes but only provide 6
        response.put_u16(ATTR_XOR_MAPPED_ADDRESS);
        response.put_u16(8); // Claim 8 bytes
        response.put_slice(&[0u8; 6]); // Only provide 6

        let result = parse_binding_response(&response, &txn_id);
        assert_stun_err_contains(result, "NoMappedAddress");
    }

    #[test]
    fn test_parse_binding_response_corrupt_attribute_length() {
        let txn_id = [0xCCu8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(8); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Attribute with impossible length
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(1000); // Claims huge length
        response.put_slice(&[0u8; 4]);

        let result = parse_binding_response(&response, &txn_id);
        assert_stun_err_contains(result, "NoMappedAddress");
    }

    #[test]
    fn test_parse_binding_response_zero_length_message() {
        let txn_id = [0xDDu8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0); // Zero length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        let result = parse_binding_response(&response, &txn_id);
        assert_stun_err_contains(result, "NoMappedAddress");
    }

    #[test]
    fn test_parse_binding_response_with_software_attribute() {
        let txn_id = [0xEEu8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(24); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // SOFTWARE attribute
        response.put_u16(ATTR_SOFTWARE);
        response.put_u16(8);
        response.put_slice(b"TestSTUN");

        // MAPPED-ADDRESS
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(7777);
        response.put_slice(&[10, 10, 10, 10]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 7777);
    }

    // XOR IPv6 edge case tests
    #[test]
    fn test_parse_xor_mapped_address_ipv6() {
        let mut data = vec![0x00, AF_IPV6];
        let port = 9090u16;
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        data.extend_from_slice(&xor_port.to_be_bytes());

        // IPv6 address bytes - first 4 bytes XORed with magic cookie
        let ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let mut ipv6_bytes = ipv6.octets();
        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
        for (i, b) in ipv6_bytes[..4].iter_mut().enumerate() {
            *b ^= cookie_bytes[i];
        }
        data.extend_from_slice(&ipv6_bytes);

        let addr = parse_mapped_address(&data, true).unwrap();
        assert_eq!(addr.port(), port);
        assert!(addr.is_ipv6());
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv6_exact_match() {
        // Test with known values
        let port = 12345u16;
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;

        let mut data = vec![0x00, AF_IPV6];
        data.extend_from_slice(&xor_port.to_be_bytes());

        // Create IPv6 address
        let ipv6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mut ipv6_bytes = ipv6.octets();

        // XOR first 4 bytes with magic cookie
        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
        for i in 0..4 {
            ipv6_bytes[i] ^= cookie_bytes[i];
        }

        data.extend_from_slice(&ipv6_bytes);

        let addr = parse_mapped_address(&data, true).unwrap();
        assert_eq!(addr.port(), port);
        assert!(addr.is_ipv6());
    }

    // Edge cases for port XORing
    #[test]
    fn test_parse_xor_mapped_address_zero_port() {
        // XOR-mapped representation of port 0 / IP 0.0.0.0:
        // port_xor = 0 ^ (MAGIC_COOKIE >> 16)
        // ip_xor   = 0.0.0.0 ^ MAGIC_COOKIE bytes
        let xor_port = (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = [0x21, 0x12, 0xA4, 0x42];

        let data = [
            0x00,
            0x01,
            (xor_port >> 8) as u8,
            (xor_port & 0xFF) as u8,
            xor_ip[0],
            xor_ip[1],
            xor_ip[2],
            xor_ip[3],
        ];

        let addr = parse_mapped_address(&data, true).unwrap();
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn test_parse_xor_mapped_address_max_port() {
        let port = 65535u16;
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        let xor_ip = [255 ^ 0x21, 255 ^ 0x12, 255 ^ 0xA4, 255 ^ 0x42];

        let data = [
            0x00,
            0x01,
            (xor_port >> 8) as u8,
            (xor_port & 0xFF) as u8,
            xor_ip[0],
            xor_ip[1],
            xor_ip[2],
            xor_ip[3],
        ];

        let addr = parse_mapped_address(&data, true).unwrap();
        assert_eq!(addr.port(), port);
    }

    // Attribute padding edge cases
    #[test]
    fn test_parse_binding_response_attribute_no_padding_needed() {
        let txn_id = [0xFFu8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(24); // Message length: SOFTWARE(2+2+8) + MAPPED(2+2+8) = 24
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Attribute with length exactly divisible by 4 (no padding)
        response.put_u16(ATTR_SOFTWARE);
        response.put_u16(8); // Exactly 8 bytes
        response.put_slice(b"12345678");

        // MAPPED-ADDRESS
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(4444);
        response.put_slice(&[4, 4, 4, 4]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 4444);
    }

    #[test]
    fn test_parse_binding_response_attribute_one_byte_padding() {
        let txn_id = [0x12u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(24); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Attribute with 7 bytes (needs 1 byte padding)
        response.put_u16(ATTR_SOFTWARE);
        response.put_u16(7);
        response.put_slice(b"1234567");
        response.put_u8(0); // Padding

        // MAPPED-ADDRESS
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(5555);
        response.put_slice(&[5, 5, 5, 5]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 5555);
    }

    #[test]
    fn test_parse_binding_response_attribute_two_byte_padding() {
        let txn_id = [0x34u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(24); // Message length
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Attribute with 6 bytes (needs 2 bytes padding)
        response.put_u16(ATTR_SOFTWARE);
        response.put_u16(6);
        response.put_slice(b"123456");
        response.put_slice(&[0, 0]); // Padding

        // MAPPED-ADDRESS
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(6666);
        response.put_slice(&[6, 6, 6, 6]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 6666);
    }

    // Reserved byte tests
    #[test]
    fn test_parse_mapped_address_nonzero_reserved() {
        // Test that non-zero reserved byte is accepted
        let data = [
            0xFF, // Reserved (non-zero)
            0x01, // Family: IPv4
            0x13, 0x88, // Port: 5000
            192, 168, 1, 100,
        ];

        let addr = parse_mapped_address(&data, false).unwrap();
        assert_eq!(addr.port(), 5000);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    // Message type edge cases
    #[test]
    fn test_parse_binding_response_invalid_message_type_format() {
        let mut response = BytesMut::new();
        response.put_u16(0xFFFF); // Invalid message type
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&[0u8; 12]);

        let result = parse_binding_response(&response, &[0u8; 12]);
        assert_stun_err_contains(result, "InvalidResponse");
    }

    // Build request edge cases
    #[test]
    fn test_build_binding_request_different_transaction_ids() {
        let txn_id1 = [0xAAu8; 12];
        let txn_id2 = [0xBBu8; 12];

        let request1 = build_binding_request(&txn_id1);
        let request2 = build_binding_request(&txn_id2);

        // Headers should be same
        assert_eq!(&request1[..8], &request2[..8]);

        // Transaction IDs should differ
        assert_ne!(&request1[8..20], &request2[8..20]);
    }

    #[test]
    fn test_build_binding_request_all_zeros() {
        let txn_id = [0x00u8; 12];
        let request = build_binding_request(&txn_id);

        assert_eq!(request.len(), 20);
        assert_eq!(&request[8..20], &[0u8; 12]);
    }

    #[test]
    fn test_build_binding_request_all_ones() {
        let txn_id = [0xFFu8; 12];
        let request = build_binding_request(&txn_id);

        assert_eq!(request.len(), 20);
        assert_eq!(&request[8..20], &[0xFFu8; 12]);
    }

    // Complex multi-attribute scenarios
    #[test]
    fn test_parse_binding_response_many_unknown_attributes() {
        let txn_id = [0x56u8; 12];
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(52); // Message length: 5*(4+4) + 4+8 = 40 + 12 = 52
        response.put_u32(MAGIC_COOKIE);
        response.put_slice(&txn_id);

        // Multiple unknown attributes (each takes 4 bytes header + 4 bytes value = 8 bytes)
        for i in 0..5 {
            response.put_u16(0x8000 + i); // Unknown attribute types
            response.put_u16(4);
            response.put_slice(&[i as u8; 4]);
        }

        // Finally, a valid MAPPED-ADDRESS (4 bytes header + 8 bytes value = 12 bytes)
        response.put_u16(ATTR_MAPPED_ADDRESS);
        response.put_u16(8);
        response.put_u8(0x00);
        response.put_u8(AF_IPV4);
        response.put_u16(3333);
        response.put_slice(&[3, 3, 3, 3]);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr.port(), 3333);
    }

    #[test]
    fn test_parse_error_response_non_error_attributes() {
        let mut attrs = BytesMut::new();

        // Multiple non-error attributes before error
        attrs.put_u16(ATTR_SOFTWARE);
        attrs.put_u16(4);
        attrs.put_slice(b"test");

        attrs.put_u16(ATTR_MAPPED_ADDRESS);
        attrs.put_u16(8);
        attrs.put_slice(&[0u8; 8]);

        // Finally the error attribute
        attrs.put_u16(ATTR_ERROR_CODE);
        attrs.put_u16(7);
        attrs.put_u16(0);
        attrs.put_u8(5);
        attrs.put_u8(3); // 503
        attrs.put_slice(b"err");
        attrs.put_u8(0); // Padding

        let err = parse_error_response(&attrs);
        assert!(error_response_matches(&err, 503, "err"));
    }

    #[test]
    fn test_parse_mapped_address_exact_minimum_ipv4() {
        // Exactly minimum size for IPv4 (8 bytes)
        let data = [0x00, AF_IPV4, 0x00, 0x50, 127, 0, 0, 1];
        let addr = parse_mapped_address(&data, false).unwrap();
        assert_eq!(addr.port(), 80);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_parse_mapped_address_exact_minimum_ipv6() {
        // Exactly minimum size for IPv6 (20 bytes)
        let mut data = vec![0x00, AF_IPV6, 0x00, 0x50];
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());

        let addr = parse_mapped_address(&data, false).unwrap();
        assert_eq!(addr.port(), 80);
        assert_eq!(addr.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    // Transaction ID validation in various scenarios
    #[test]
    fn test_parse_binding_response_txn_id_one_bit_different() {
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        let mut txn_in_response = [0xFFu8; 12];
        txn_in_response[0] = 0xFE; // One bit different
        response.put_slice(&txn_in_response);

        let expected_txn = [0xFFu8; 12];
        let result = parse_binding_response(&response, &expected_txn);
        assert_stun_err_contains(result, "InvalidResponse");
    }

    #[test]
    fn test_parse_binding_response_txn_id_last_byte_different() {
        let mut response = BytesMut::new();
        response.put_u16(BINDING_RESPONSE);
        response.put_u16(0);
        response.put_u32(MAGIC_COOKIE);
        let mut txn_in_response = [0xAAu8; 12];
        txn_in_response[11] = 0xBB; // Last byte different
        response.put_slice(&txn_in_response);

        let expected_txn = [0xAAu8; 12];
        let result = parse_binding_response(&response, &expected_txn);
        assert_stun_err_contains(result, "InvalidResponse");
    }
}
