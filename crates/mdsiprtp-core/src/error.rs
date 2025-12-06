//! Error types for the mdsiprtp stack.

use thiserror::Error;

/// Top-level error type for the entire stack.
#[derive(Error, Debug)]
pub enum Error {
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("SIP error: {0}")]
    Sip(#[from] SipError),

    #[error("Media error: {0}")]
    Media(#[from] MediaError),

    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Transport layer errors.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Connection timeout")]
    Timeout,

    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("Message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },
}

/// SIP protocol errors.
#[derive(Error, Debug)]
pub enum SipError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Missing required header: {0}")]
    MissingHeader(String),

    #[error("Transaction timeout")]
    TransactionTimeout,

    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    #[error("Dialog not found: {0}")]
    DialogNotFound(String),

    #[error("Invalid dialog state: expected {expected}, got {actual}")]
    InvalidDialogState { expected: String, actual: String },

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("SIP response error: {code} {reason}")]
    Response { code: u16, reason: String },

    #[error("Request URI mismatch")]
    RequestUriMismatch,
}

/// Media layer errors.
#[derive(Error, Debug)]
pub enum MediaError {
    #[error("Codec error: {0}")]
    Codec(String),

    #[error("RTP error: {0}")]
    Rtp(String),

    #[error("SRTP error: {0}")]
    Srtp(String),

    #[error("No compatible codec found")]
    NoCompatibleCodec,

    #[error("ICE failure: {0}")]
    IceFailure(String),

    #[error("Jitter buffer overflow")]
    JitterBufferOverflow,

    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(u8),
}

/// Session management errors.
#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Call not found: {0}")]
    CallNotFound(String),

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Operation not allowed in current state")]
    OperationNotAllowed,
}

/// Configuration errors.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid configuration: {0}")]
    Invalid(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    #[error("Invalid port range: {start}..{end}")]
    InvalidPortRange { start: u16, end: u16 },
}

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;
