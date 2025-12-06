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
pub mod manager;
pub mod registration;

// Re-export main types
pub use call::{
    Call, CallConfig, CallDirection, CallEndReason, CallEvent, CallId, CallState, Dialog,
    MediaSession,
};
pub use manager::{CallManager, ManagerConfig, ManagerEvent};
pub use registration::{RegistrationConfig, RegistrationError, RegistrationManager, RegistrationState};
