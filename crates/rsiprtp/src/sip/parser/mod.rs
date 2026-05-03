//! In-tree SIP parser (work in progress).
//!
//! This module is the rewrite target for dropping the third-party `rsip`
//! dependency. It is private to `crate::sip` and currently contains only
//! the type seeds (`Method`, `StatusCode`); none of the new types are yet
//! integrated into the rest of the crate. See
//! `wrk_docs/2026.05.03 - HLD - sip-parser-rewrite.md` for the full plan.
//!
//! Two-tier model (per HLD):
//! 1. Tier 1 — eager framing + header recognition.
//! 2. Tier 2 — lazy typed parsing on demand via `.typed()`.
//!
//! `dead_code` is muted across the whole module because M1 lands the
//! types unintegrated by design (M7 wires them into the public API).
//! The `#[cfg(test)]` blocks inside each submodule still exercise every
//! item — this is not a coverage hole.

#![allow(dead_code, unused_imports)]

pub(crate) mod framing;
pub(crate) mod header;
pub(crate) mod message;
pub(crate) mod method;
pub mod name_addr;
pub(crate) mod status;
pub mod typed;

// Re-exported `pub` (not `pub(crate)`) so the in-tree integration
// test `tests/parser_diff.rs` can reach them — see comment in
// `crate::sip::mod` on why the parent module itself is `#[doc(hidden)]
// pub`. Stability is not a concern; M7 owns the public-API redesign.
pub use header::{Header, Headers};
pub use message::{Message, Request, Response};
pub use name_addr::NameAddr;
