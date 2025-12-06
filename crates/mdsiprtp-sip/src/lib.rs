//! SIP message parsing and building for mdsiprtp.
//!
//! This crate wraps the `rsip` crate and provides convenience methods
//! for common SIP operations.

pub mod auth;
pub mod headers;
pub mod message;
pub mod uri;

// Re-export main types
pub use message::{
    generate_branch, generate_call_id, generate_tag, Method, SipMessage, SipRequest,
    SipRequestBuilder, SipResponse, SipResponseBuilder,
};

// Re-export auth types
pub use auth::{
    Algorithm, DigestAuthError, DigestChallenge, DigestCredentials, DigestResponse, Qop,
};

// Re-export header types
pub use headers::{Contact, RecordRoute, Route, RouteSet, Via};

// Re-export URI types
pub use uri::{SipUri, SipUriBuilder};

// Re-export rsip types for convenience
pub use rsip::Uri as RsipUri;
