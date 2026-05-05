//! Round-trip oracle driver: runs `assert_roundtrip_fixed_point`
//! against every fixture our parser accepts.
//!
//! The oracle itself (the `assert_roundtrip_fixed_point` machinery)
//! lives at `tests/parser_roundtrip_oracle/mod.rs` so it can be
//! shared with the fuzz target
//! `fuzz/fuzz_targets/sip_message_roundtrip.rs`. See the oracle
//! module's docstring for the design note.
//!
//! See `wrk_docs/2026.05.04 - HLD - SIP parser round-trip oracle.md`.

#[path = "parser_roundtrip_oracle/mod.rs"]
mod oracle;

use oracle::assert_roundtrip_fixed_point;

// ---------------------------------------------------------------
// mdsiprtp3 fixture corpus
// ---------------------------------------------------------------

#[test]
fn rt_mdsiprtp3_invite_with_via() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/mdsiprtp3/invite_with_via.sip"));
}

#[test]
fn rt_mdsiprtp3_response_200_ok() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/mdsiprtp3/response_200_ok.sip"));
}

#[test]
fn rt_mdsiprtp3_invite_with_body() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/mdsiprtp3/invite_with_body.sip"));
}

// ---------------------------------------------------------------
// Hand-curated fixture corpus
// ---------------------------------------------------------------

#[test]
fn rt_handcrafted_register_with_contact() {
    assert_roundtrip_fixed_point(include_bytes!(
        "fixtures/handcrafted/register_with_contact.sip"
    ));
}

#[test]
fn rt_handcrafted_invite_compact_via() {
    assert_roundtrip_fixed_point(include_bytes!(
        "fixtures/handcrafted/invite_compact_via.sip"
    ));
}

/// Folded-header fixture: rsip 0.4 rejects RFC 3261 §7.3.1 line
/// folding (see `parser_diff.rs::diff_handcrafted_invite_folded_subject`),
/// but our parser correctly accepts and merges the fold. Round-trip
/// is well-defined on our side: the first serialization collapses
/// the fold to a single line; the fixed point holds at m2.
#[test]
fn rt_handcrafted_invite_folded_subject() {
    assert_roundtrip_fixed_point(include_bytes!(
        "fixtures/handcrafted/invite_folded_subject.sip"
    ));
}

#[test]
fn rt_handcrafted_response_407_with_proxy_authenticate() {
    assert_roundtrip_fixed_point(include_bytes!(
        "fixtures/handcrafted/response_407_with_proxy_authenticate.sip"
    ));
}

#[test]
fn rt_handcrafted_ack_for_2xx() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/handcrafted/ack_for_2xx.sip"));
}

#[test]
fn rt_handcrafted_cancel() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/handcrafted/cancel.sip"));
}

#[test]
fn rt_handcrafted_response_with_multi_via() {
    assert_roundtrip_fixed_point(include_bytes!(
        "fixtures/handcrafted/response_with_multi_via.sip"
    ));
}

// ---------------------------------------------------------------
// RFC 4475 §3 — Valid Messages: our parser accepts, must round-trip
// ---------------------------------------------------------------

#[test]
fn rt_rfc4475_wsinv() {
    // §3.1.1 short tortuous INVITE — folding + interior whitespace.
    // First serialization collapses the folding.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/wsinv.sip"));
}

#[test]
fn rt_rfc4475_esc01() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/esc01.sip"));
}

#[test]
fn rt_rfc4475_escnull() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/escnull.sip"));
}

#[test]
fn rt_rfc4475_esc02() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/esc02.sip"));
}

#[test]
fn rt_rfc4475_lwsdisp() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/lwsdisp.sip"));
}

#[test]
fn rt_rfc4475_longreq() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/longreq.sip"));
}

#[test]
fn rt_rfc4475_dblreq() {
    // §3.1.2.7 trailing octets after Content-Length: 0. Our parser
    // truncates body to the declared length per RFC 3261 §18.3, so
    // the trailing octets are dropped on first serialize. Fixed
    // point holds at m2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/dblreq.sip"));
}

#[test]
fn rt_rfc4475_semiuri() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/semiuri.sip"));
}

#[test]
fn rt_rfc4475_transports() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/transports.sip"));
}

#[test]
fn rt_rfc4475_unreason() {
    assert_roundtrip_fixed_point(include_bytes!("fixtures/rfc4475/unreason.sip"));
}

// ---------------------------------------------------------------
// Sanity checks on the oracle itself
// ---------------------------------------------------------------

#[test]
fn rt_oracle_skips_parse_failures() {
    // Garbage bytes — parse fails, oracle must return silently.
    assert_roundtrip_fixed_point(b"this is not a SIP message");
    assert_roundtrip_fixed_point(b"");
    assert_roundtrip_fixed_point(b"\r\n\r\n");
}

#[test]
fn rt_oracle_holds_on_canonical_input() {
    // Already-canonical message: no normalization on first round-trip,
    // so the fixed point holds immediately at m1. The `\` line
    // continuations consume the indentation so the raw bytes start at
    // column 0 — otherwise the parser's per-line trim would strip the
    // leading whitespace and normalize on m1→m2, defeating the test's
    // claim that the input is canonical.
    let canonical: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
To: Bob <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710@pc33.example.com\r\n\
CSeq: 314159 INVITE\r\n\
Max-Forwards: 70\r\n\
Content-Length: 0\r\n\
\r\n";
    // Sanity: input is a true fixed point of parse∘serialize (m1 == input).
    let m1 = rsiprtp::sip::parser::Message::parse(canonical).expect("canonical fixture must parse");
    assert_eq!(
        m1.to_bytes().as_slice(),
        canonical,
        "fixture is not actually canonical — first round-trip mutates it",
    );
    assert_roundtrip_fixed_point(canonical);
}

#[test]
fn rt_oracle_holds_after_normalization() {
    // Compact header names + stale Content-Length — first round-trip
    // normalizes both. Fixed point must hold at m2.
    let messy: &[u8] = b"INVITE sip:b@h SIP/2.0\r\n\
        v: SIP/2.0/UDP h\r\n\
        i: abc\r\n\
        l: 100\r\n\
        \r\n\
        v=0";
    assert_roundtrip_fixed_point(messy);
}
