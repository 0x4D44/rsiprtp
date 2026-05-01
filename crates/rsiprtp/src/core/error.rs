//! Error types for the rsiprtp stack.

use thiserror::Error;

/// Top-level error type for the entire stack.
#[derive(Error, Debug)]
pub enum Error {
    /// Error originating from the transport layer (UDP/TCP/TLS I/O).
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    /// Error from the SIP signalling layer (parsing, transactions, dialogs).
    #[error("SIP error: {0}")]
    Sip(#[from] SipError),

    /// Error from the media layer (RTP/SRTP, codecs, jitter buffer).
    #[error("Media error: {0}")]
    Media(#[from] MediaError),

    /// Error from high-level session management (calls, registrations).
    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    /// Error caused by invalid stack configuration.
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Underlying `std::io::Error` not classified by a more specific layer.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Transport layer errors.
#[derive(Error, Debug)]
pub enum TransportError {
    /// Underlying I/O failure on a socket or stream.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Peer closed the connection or the socket is no longer usable.
    #[error("Connection closed")]
    ConnectionClosed,

    /// Connection or read/write operation exceeded its time budget.
    #[error("Connection timeout")]
    Timeout,

    /// DNS lookup (NAPTR/SRV/A/AAAA) for a SIP target failed.
    #[error("DNS resolution failed: {0}")]
    DnsError(String),

    /// TLS handshake or record-layer error.
    #[error("TLS error: {0}")]
    TlsError(String),

    /// Outgoing or incoming SIP message exceeded the configured size limit.
    #[error("Message too large: {size} bytes (max {max})")]
    MessageTooLarge {
        /// Actual size of the offending message in bytes.
        size: usize,
        /// Configured maximum allowed size in bytes.
        max: usize,
    },
}

/// SIP protocol errors.
#[derive(Error, Debug)]
pub enum SipError {
    /// Failed to parse a SIP message off the wire.
    #[error("Parse error: {0}")]
    Parse(String),

    /// A header value was syntactically or semantically invalid.
    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    /// A header required by RFC 3261 (e.g. `Via`, `From`, `To`) was absent.
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// A transaction timer (Timer B/F/H) fired before completion.
    #[error("Transaction timeout")]
    TransactionTimeout,

    /// No transaction matched the given key (branch/method tuple).
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),

    /// No dialog matched the given Call-ID/tag triple.
    #[error("Dialog not found: {0}")]
    DialogNotFound(String),

    /// An operation was rejected because the dialog was in the wrong state.
    #[error("Invalid dialog state: expected {expected}, got {actual}")]
    InvalidDialogState {
        /// State the operation required.
        expected: String,
        /// State the dialog was actually in.
        actual: String,
    },

    /// Digest authentication challenge could not be satisfied.
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Peer returned a non-2xx response that surfaced as an error.
    #[error("SIP response error: {code} {reason}")]
    Response {
        /// SIP response status code (e.g. 404).
        code: u16,
        /// Human-readable reason phrase from the response line.
        reason: String,
    },

    /// In-dialog request arrived with a Request-URI that doesn't match the dialog target.
    #[error("Request URI mismatch")]
    RequestUriMismatch,
}

/// Media layer errors.
#[derive(Error, Debug)]
pub enum MediaError {
    /// Audio codec encode/decode failure.
    #[error("Codec error: {0}")]
    Codec(String),

    /// RTP packet handling error (parse, sequence, or send/recv failure).
    #[error("RTP error: {0}")]
    Rtp(String),

    /// SRTP encryption, decryption, or key-derivation failure.
    #[error("SRTP error: {0}")]
    Srtp(String),

    /// SDP negotiation produced no codec acceptable to both parties.
    #[error("No compatible codec found")]
    NoCompatibleCodec,

    /// ICE connectivity check or candidate gathering failed.
    #[error("ICE failure: {0}")]
    IceFailure(String),

    /// Adaptive jitter buffer dropped packets because it ran out of capacity.
    #[error("Jitter buffer overflow")]
    JitterBufferOverflow,

    /// RTP payload type does not map to any negotiated codec.
    #[error("Invalid payload type: {0}")]
    InvalidPayloadType(u8),
}

/// Session management errors.
#[derive(Error, Debug)]
pub enum SessionError {
    /// No active call matched the supplied identifier.
    #[error("Call not found: {0}")]
    CallNotFound(String),

    /// A call/registration state machine was asked to make an illegal transition.
    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition {
        /// State the session was in when the transition was attempted.
        from: String,
        /// State the caller tried to move it to.
        to: String,
    },

    /// A bounded resource (sockets, RTP ports, transactions) was exhausted.
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// The requested operation is not legal in the session's current state.
    #[error("Operation not allowed in current state")]
    OperationNotAllowed,
}

/// Configuration errors.
#[derive(Error, Debug)]
pub enum ConfigError {
    /// A configuration value was rejected as semantically invalid.
    #[error("Invalid configuration: {0}")]
    Invalid(String),

    /// A required configuration field was not supplied.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// A SIP URI in configuration could not be parsed.
    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    /// RTP port range is empty or inverted (`start >= end`).
    #[error("Invalid port range: {start}..{end}")]
    InvalidPortRange {
        /// Lower bound of the requested RTP port range (inclusive).
        start: u16,
        /// Upper bound of the requested RTP port range (exclusive).
        end: u16,
    },
}

/// Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;
