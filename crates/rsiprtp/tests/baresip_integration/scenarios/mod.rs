//! Integration test scenarios.
//!
//! Each module contains tests for specific SIP/RTP functionality.

pub mod basic_call;
pub mod call_hold;
pub mod call_transfer;
pub mod codec_nego;
pub mod dtmf;
pub mod endpoint_to_endpoint;
pub mod error_recovery;
pub mod media_audio;
pub mod registration;
pub mod registration_advanced;
pub mod security;
pub mod stress;
