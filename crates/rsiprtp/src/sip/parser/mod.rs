//! In-tree SIP parser.
//!
//! The runtime SIP parser used by `crate::sip`. Replaced the third-party
//! `rsip` dependency on the parse path in the M1–M9 rewrite (HLD:
//! `wrk_docs/2026.05.03 - HLD - sip-parser-rewrite.md`). `rsip 0.4`
//! survives only as a dev-dependency differential-test oracle (see
//! `tests/parser_diff.rs` and the `sip_message_parse` fuzz target).
//!
//! Two-tier model (per HLD):
//! 1. Tier 1 — eager framing + header recognition.
//! 2. Tier 2 — lazy typed parsing on demand via `.typed()`.
//!
//! `dead_code` is muted across the whole module: a handful of typed
//! header variants and helpers are exercised only by the `#[cfg(test)]`
//! blocks in each submodule and are intentionally retained for symmetry
//! with the rsip oracle.

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
