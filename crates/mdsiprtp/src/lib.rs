//! mdsiprtp - SIP/RTP stack for Rust
//!
//! A production-ready SIP/RTP communications stack designed for:
//! - Voicemail applications
//! - AI agent call bridges with mixing
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use mdsiprtp::prelude::*;
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
//! - `mdsiprtp-core`: Common types, errors, configuration
//! - `mdsiprtp-sip`: SIP message parsing and building (wraps rsip)
//! - `mdsiprtp-transaction`: RFC 3261 transaction state machines (Sans-IO)
//! - `mdsiprtp-dialog`: Dialog management for INVITE sessions
//! - `mdsiprtp-transport`: UDP/TCP/TLS network transport
//! - `mdsiprtp-sdp`: SDP parsing and offer/answer negotiation
//! - `mdsiprtp-rtp`: RTP packet handling
//! - `mdsiprtp-media`: Audio codecs and jitter buffer
//! - `mdsiprtp-session`: High-level call management

// Re-export crate modules
pub use mdsiprtp_core as core;
pub use mdsiprtp_dialog as dialog;
pub use mdsiprtp_media as media;
pub use mdsiprtp_rtp as rtp;
pub use mdsiprtp_sdp as sdp;
pub use mdsiprtp_session as session;
pub use mdsiprtp_sip as sip;
pub use mdsiprtp_transaction as transaction;
pub use mdsiprtp_transport as transport;

/// Prelude for convenient imports.
pub mod prelude {
    // Core types
    pub use mdsiprtp_core::{CodecConfig, Error, Result, StackConfig};

    // Session management
    pub use mdsiprtp_session::{
        Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallManager, CallState,
        Dialog, ManagerConfig, ManagerEvent, MediaSession, RegistrationConfig, RegistrationError,
        RegistrationManager, RegistrationState,
    };

    // SIP messaging
    pub use mdsiprtp_sip::{
        generate_branch, generate_call_id, generate_tag, DigestChallenge, DigestCredentials,
        DigestResponse, Method, SipMessage, SipRequest, SipResponse,
    };

    // SDP negotiation
    pub use mdsiprtp_sdp::builder::SdpBuilder;
    pub use mdsiprtp_sdp::negotiation::{Codec, NegotiatedMedia};
    pub use mdsiprtp_sdp::parser::{Direction, MediaDescription, SessionDescription};

    // RTP/RTCP
    pub use mdsiprtp_rtp::{ReceiverReport, RtcpCompound, RtpPacket, RtpSession, SenderReport};

    // Media
    pub use mdsiprtp_media::{
        G711Codec, G711Variant, JitterBuffer, JitterBufferConfig, PlayoutDecision,
    };

    // Dialog
    pub use mdsiprtp_dialog::DialogId;

    // Transport
    pub use mdsiprtp_transport::UdpTransport;
}
