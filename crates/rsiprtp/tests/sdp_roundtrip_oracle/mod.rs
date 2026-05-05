//! Round-trip oracle: `SessionDescription::parse` ∘
//! `SessionDescription::to_string` is a fixed point after one
//! normalization.
//!
//! See `wrk_docs/2026.05.05 - HLD - SDP parser round-trip oracle.md`
//! for the full design. The first round-trip is allowed to normalize
//! (whitespace collapse, defaulted `s=`, lossy bandwidth/timing values,
//! `MediaType::Other` collapse, dropped unknown SDP types). After that,
//! the parse/serialize cycle must be a fixed point.
//!
//! # Layout note
//!
//! Mirrors `parser_roundtrip_oracle/mod.rs`: lives in a subdirectory
//! so Cargo's integration-test discovery skips it, then is brought in
//! by both the static-fixture driver (`tests/sdp_roundtrip.rs`) and
//! the fuzz target (`fuzz/fuzz_targets/sdp_session_roundtrip.rs`) via
//! `#[path]`.

#![allow(dead_code)]

use rsiprtp::sdp::SessionDescription;

/// Assert the round-trip fixed-point invariant on `bytes`.
///
/// If the bytes are not UTF-8, or if the first parse fails, returns
/// silently — round-trip is undefined for inputs we reject.
///
/// On parse-success: serialize, re-parse, serialize, re-parse, and
/// assert that the two re-parses produce both byte-equal and
/// AST-equal results.
pub fn assert_roundtrip_fixed_point(bytes: &[u8]) {
    let Ok(input) = std::str::from_utf8(bytes) else {
        return;
    };
    let Ok(s1) = SessionDescription::parse(input) else {
        return;
    };
    let t2 = s1.to_string();
    let s2 = SessionDescription::parse(&t2).unwrap_or_else(|e| {
        panic!(
            "second parse failed: serializer produced text our parser \
             cannot accept.\ns1: {s1:#?}\nt2:\n{t2}\nerror: {e:?}",
        )
    });
    let t3 = s2.to_string();
    let s3 = SessionDescription::parse(&t3).unwrap_or_else(|e| {
        panic!(
            "third parse failed: round-trip not idempotent at parse step.\n\
             s2: {s2:#?}\nt3:\n{t3}\nerror: {e:?}",
        )
    });
    assert_eq!(
        s2, s3,
        "round-trip not a fixed point at s2 (AST inequality).\n\
         t2:\n{t2}\nt3:\n{t3}",
    );
    assert_eq!(
        t2, t3,
        "round-trip not a fixed point at s2 (bytes inequality).\n\
         t2:\n{t2}\nt3:\n{t3}",
    );
}
