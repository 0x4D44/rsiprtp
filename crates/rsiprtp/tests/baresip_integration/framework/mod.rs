//! Integration test framework for rsiprtp.
//!
//! This module provides utilities for testing the rsiprtp SIP/RTP stack
//! against external SIP implementations like baresip and Asterisk.

// Allow unused code in framework - these are utilities for various test scenarios
#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]

pub mod assertions;
pub mod asterisk;
pub mod baresip;
pub mod config;
pub mod media_validator;
pub mod sip_endpoint;

// Re-export commonly used types
pub use assertions::*;
pub use asterisk::{AsteriskConfig, AsteriskInstance};
pub use baresip::BaresipInstance;
pub use config::{is_baresip_available, TestConfig};
pub use media_validator::{Codec, RtpValidator};
pub use sip_endpoint::{TestCallState, TestEndpoint};
