//! SIP message parsing and building for rsiprtp.
//!
//! This crate wraps the `rsip` crate and provides convenience methods
//! for common SIP operations.

pub(crate) mod auth;
pub(crate) mod headers;
pub(crate) mod message;
pub(crate) mod uri;

#[cfg(test)]
mod tests;

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
pub use headers::{
    Contact, MinSe, RAck, RSeq, RecordRoute, Refresher, Require, Route, RouteSet, SessionExpires,
    Supported, Via,
};

// Re-export URI types
pub use uri::{SipUri, SipUriBuilder};

// Re-export rsip types for convenience
pub use rsip::Uri as RsipUri;
