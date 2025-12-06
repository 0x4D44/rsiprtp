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
//! use mdsiprtp_session::{CallManager, ManagerConfig};
//!
//! let config = ManagerConfig::default();
//! let mut manager = CallManager::new(config);
//!
//! // Create an outbound call
//! let call_id = manager.create_call("sip:bob@example.com".to_string());
//! ```

pub mod call;
pub mod hold;
pub mod manager;
pub mod registration;
pub mod transfer;

// Re-export main types
pub use call::{
    Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallState, Dialog,
    MediaSession,
};
pub use hold::{
    CallHoldInfo, HoldError, HoldManager, HoldRequest, HoldResponse, HoldState, MediaDirection,
};
pub use manager::{CallManager, ManagerConfig, ManagerEvent};
pub use registration::{
    RegistrationConfig, RegistrationError, RegistrationManager, RegistrationState,
};
pub use transfer::{
    ReferTo, ReplacesHeader, TransferError, TransferInfo, TransferManager, TransferProgress,
    TransferRole, TransferState, TransferType,
};
