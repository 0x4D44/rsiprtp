//! High-level call and session management.
//!
//! This crate provides the top-level abstractions for managing SIP calls:
//! - `Call`: Represents a single call with signaling and media
//! - `CallManager`: Orchestrates multiple calls
//! - `RegistrationManager`: Handles SIP registration with authentication
//!
//! # Example
//!
//! ```no_run
//! use rsiprtp::session::{CallManager, ManagerConfig};
//!
//! let config = ManagerConfig::default();
//! let mut manager = CallManager::new(config);
//!
//! // Create an outbound call
//! let call_id = manager.create_call("sip:bob@example.com".to_string());
//! ```

pub(crate) mod bitrate_bridge;
pub mod call;
pub(crate) mod hold;
pub mod ice_session;
pub(crate) mod manager;
pub(crate) mod registration;
pub(crate) mod session_codec;
pub(crate) mod transfer;

// Re-export main types
pub use bitrate_bridge::BitrateBridge;
pub use call::{
    Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallState, Dialog,
    MediaSession,
};
pub use hold::{
    CallHoldInfo, HoldError, HoldManager, HoldRequest, HoldResponse, HoldState, MediaDirection,
};
pub use ice_session::{IceLocalParams, IceRemoteParams, IceSession};
pub use manager::{CallManager, IceAnswerInputs, ManagerConfig, ManagerEvent};
pub use registration::{
    RegistrationConfig, RegistrationError, RegistrationManager, RegistrationState,
};
pub use session_codec::SessionCodec;
pub use transfer::{
    ReferTo, ReplacesHeader, TransferError, TransferInfo, TransferManager, TransferProgress,
    TransferRole, TransferState, TransferType,
};
