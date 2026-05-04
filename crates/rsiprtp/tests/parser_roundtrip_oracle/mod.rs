//! Round-trip oracle: `Message::parse` ∘ `Message::to_bytes` is a
//! fixed point after one normalization.
//!
//! See `wrk_docs/2026.05.04 - HLD - SIP parser round-trip oracle.md`
//! for the full design. The first round-trip is allowed to normalize
//! (compact → long header names, whitespace collapse, stale
//! Content-Length → real length, fold collapse). After that, the
//! parse/serialize cycle must be a fixed point.
//!
//! # Layout note
//!
//! Mirrors `parser_diff_oracle/mod.rs`: lives in a subdirectory so
//! Cargo's integration-test discovery skips it, then is brought in
//! by both the static-fixture driver
//! (`tests/parser_roundtrip.rs`) and the fuzz target
//! (`fuzz/fuzz_targets/sip_message_roundtrip.rs`) via `#[path]`.

#![allow(dead_code)]

use rsiprtp::sip::parser::Message as OurMessage;

/// Assert the round-trip fixed-point invariant on `bytes`.
///
/// If the first parse fails, returns silently — round-trip is
/// undefined for inputs we reject.
///
/// On parse-success: serialize, re-parse, serialize, re-parse, and
/// assert that the two re-parses produce both byte-equal and
/// AST-equal results.
pub fn assert_roundtrip_fixed_point(bytes: &[u8]) {
    let Ok(m1) = OurMessage::parse(bytes) else {
        return;
    };
    let b2 = m1.to_bytes();
    let m2 = OurMessage::parse(&b2).unwrap_or_else(|e| {
        panic!(
            "second parse failed: serializer produced bytes our parser \
             cannot accept.\nm1: {m1:#?}\nb2:\n{}\nerror: {e:?}",
            String::from_utf8_lossy(&b2),
        )
    });
    let b3 = m2.to_bytes();
    let m3 = OurMessage::parse(&b3).unwrap_or_else(|e| {
        panic!(
            "third parse failed: round-trip not idempotent at parse step.\n\
             m2: {m2:#?}\nb3:\n{}\nerror: {e:?}",
            String::from_utf8_lossy(&b3),
        )
    });
    assert_eq!(
        m2,
        m3,
        "round-trip not a fixed point at m2 (AST inequality).\n\
         b2:\n{}\nb3:\n{}",
        String::from_utf8_lossy(&b2),
        String::from_utf8_lossy(&b3),
    );
    assert_eq!(
        b2,
        b3,
        "round-trip not a fixed point at m2 (bytes inequality).\n\
         b2:\n{}\nb3:\n{}",
        String::from_utf8_lossy(&b2),
        String::from_utf8_lossy(&b3),
    );
}
