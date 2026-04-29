//! rsiprtp - SIP/RTP stack for Rust
//!
//! A production-ready SIP/RTP communications stack designed for:
//! - Voicemail applications
//! - AI agent call bridges with mixing
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use rsiprtp::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     // Create a call manager
//!     let config = ManagerConfig::default();
//!     let mut manager = CallManager::new(config);
//!
//!     // Create an outbound call
//!     let call_id = manager.create_call("sip:bob@example.com".to_string());
//!
//!     // ... handle call events ...
//!
//!     Ok(())
//! }
//! ```
//!
//! # Architecture
//!
//! The stack is organized into layered crates:
//!
//! - `rsiprtp-core`: Common types, errors, configuration
//! - `rsiprtp-sip`: SIP message parsing and building (wraps rsip)
//! - `rsiprtp-transaction`: RFC 3261 transaction state machines (Sans-IO)
//! - `rsiprtp-dialog`: Dialog management for INVITE sessions
//! - `rsiprtp-transport`: UDP/TCP/TLS network transport
//! - `rsiprtp-sdp`: SDP parsing and offer/answer negotiation
//! - `rsiprtp-rtp`: RTP packet handling
//! - `rsiprtp-media`: Audio codecs and jitter buffer
//! - `rsiprtp-session`: High-level call management

// Re-export crate modules
pub use rsiprtp_core as core;
pub use rsiprtp_dialog as dialog;
pub use rsiprtp_media as media;
pub use rsiprtp_rtp as rtp;
pub use rsiprtp_sdp as sdp;
pub use rsiprtp_session as session;
pub use rsiprtp_sip as sip;
pub use rsiprtp_transaction as transaction;
pub use rsiprtp_transport as transport;

/// Prelude for convenient imports.
pub mod prelude {
    // Core types
    pub use rsiprtp_core::{CodecConfig, Error, Result, StackConfig};

    // Session management
    pub use rsiprtp_session::{
        Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallManager, CallState,
        Dialog, ManagerConfig, ManagerEvent, MediaSession, RegistrationConfig, RegistrationError,
        RegistrationManager, RegistrationState,
    };

    // SIP messaging
    pub use rsiprtp_sip::{
        generate_branch, generate_call_id, generate_tag, DigestChallenge, DigestCredentials,
        DigestResponse, Method, SipMessage, SipRequest, SipResponse,
    };

    // SDP negotiation
    pub use rsiprtp_sdp::builder::SdpBuilder;
    pub use rsiprtp_sdp::negotiation::{Codec, NegotiatedMedia};
    pub use rsiprtp_sdp::parser::{Direction, MediaDescription, SessionDescription};

    // RTP/RTCP
    pub use rsiprtp_rtp::{ReceiverReport, RtcpCompound, RtpPacket, RtpSession, SenderReport};

    // Media
    pub use rsiprtp_media::{
        G711Codec, G711Variant, JitterBuffer, JitterBufferConfig, PlayoutDecision,
    };

    // Dialog
    pub use rsiprtp_dialog::DialogId;

    // Transport
    pub use rsiprtp_transport::UdpTransport;
}
