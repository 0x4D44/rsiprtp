#![no_main]

//! Differential fuzz target — `crate::sip::parser` vs `rsip` 0.4.
//!
//! Per HLD §M11 ("Overnight fuzz campaign on `sip_message_parse_diff`
//! ≥8h"), this target feeds the same input bytes to both parsers and
//! panics on any divergence (parse-success structural mismatch or
//! one-accepts/one-rejects). The semantic check is identical to the
//! integration test at `tests/parser_diff.rs`; the oracle module that
//! both consumers share lives at `tests/parser_diff_oracle/mod.rs`.
//!
//! Launch instructions: see `crates/rsiprtp/fuzz/M11_LAUNCH.md`.

use libfuzzer_sys::fuzz_target;

#[path = "../../tests/parser_diff_oracle/mod.rs"]
mod oracle;

fuzz_target!(|data: &[u8]| {
    oracle::assert_equivalent(data);
});
