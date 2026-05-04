#![no_main]

//! Round-trip fuzz target — `Message::parse` ∘ `Message::to_bytes`
//! is a fixed point.
//!
//! Companion to `sip_message_parse_diff` (which fuzzes the parser
//! against rsip 0.4 differentially). This target fuzzes our parser
//! and serializer against each other: any non-fixed-point in the
//! parse → serialize cycle is a real bug we own.
//!
//! The semantic check is identical to the integration tests at
//! `tests/parser_roundtrip.rs`; the oracle module that both
//! consumers share lives at `tests/parser_roundtrip_oracle/mod.rs`.
//!
//! See `wrk_docs/2026.05.04 - HLD - SIP parser round-trip oracle.md`.

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/parser_roundtrip_oracle/mod.rs"]
mod oracle;

fuzz_target!(|data: &[u8]| {
    oracle::assert_roundtrip_fixed_point(data);
});
