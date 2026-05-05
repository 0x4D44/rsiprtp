//! SDP round-trip oracle driver: runs `assert_roundtrip_fixed_point`
//! against every SDP fixture our parser accepts.
//!
//! The oracle itself (the `assert_roundtrip_fixed_point` machinery)
//! lives at `tests/sdp_roundtrip_oracle/mod.rs` so it can be shared
//! with the fuzz target `fuzz/fuzz_targets/sdp_session_roundtrip.rs`.
//! See the oracle module's docstring for the design note.
//!
//! See `wrk_docs/2026.05.05 - HLD - SDP parser round-trip oracle.md`.

#[path = "sdp_roundtrip_oracle/mod.rs"]
mod oracle;

use oracle::assert_roundtrip_fixed_point;

// ---------------------------------------------------------------
// Static fixture corpus
// ---------------------------------------------------------------

#[test]
fn rt_sdp_minimal() {
    // Mandatory fields only: v=, o=, s=, t=. No media, no connection.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/minimal.sdp"));
}

#[test]
fn rt_sdp_audio_pcmu() {
    // Single audio m-line with PCMU (PT 0), session-level c=, sendrecv.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/audio_pcmu.sdp"));
}

#[test]
fn rt_sdp_audio_video() {
    // Two m-lines (audio + video) with rtpmap and fmtp attributes.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/audio_video.sdp"));
}

#[test]
fn rt_sdp_bandwidth() {
    // Exercises sorted-bandwidth serialization fix (b=AS:, b=CT: at
    // media level on two separate m-lines). Session-level b= would be
    // silently dropped per HLD's lossy-normalizations list, so none here.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/bandwidth.sdp"));
}

#[test]
fn rt_sdp_rfc4566_example() {
    // Canonical RFC 4566 §5-style example with literal CRLF line
    // endings. Drops u=/e=/p= (unknown SDP types) on first round-trip;
    // fixed point holds at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/rfc4566_example.sdp"));
}

#[test]
fn rt_sdp_compact_whitespace() {
    // Multiple spaces in o=, c=, t=, m= lines. First serialize collapses
    // runs of whitespace to single spaces; fixed point holds at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/compact_whitespace.sdp"));
}

// ---------------------------------------------------------------
// Sanity checks on the oracle itself
// ---------------------------------------------------------------

#[test]
fn rt_sdp_oracle_skips_parse_failures() {
    // Garbage / empty / non-UTF-8 — parse fails or UTF-8 decode fails,
    // oracle returns silently.
    assert_roundtrip_fixed_point(b"not an SDP");
    assert_roundtrip_fixed_point(b"");
    assert_roundtrip_fixed_point(&[0xFF, 0xFE, 0xFD]); // non-UTF-8
}

#[test]
fn rt_sdp_oracle_holds_on_canonical_input() {
    // Already-canonical SDP — no normalization on first round-trip,
    // so the fixed point holds immediately at s1. The `\` line
    // continuations consume the indentation so the raw bytes start
    // at column 0 (otherwise the parser's per-line trim() would
    // strip leading whitespace and normalize on s1→s2, defeating
    // the test's claim).
    let canonical: &[u8] = b"v=0\n\
o=- 1234567890 1 IN IP4 192.168.1.1\n\
s=Canonical\n\
c=IN IP4 192.168.1.1\n\
t=0 0\n\
m=audio 49170 RTP/AVP 0\n\
a=rtpmap:0 PCMU/8000\n\
a=sendrecv\n";
    // Sanity: input is a true fixed point of parse∘serialize (s1 == input).
    let s1 = rsiprtp::sdp::SessionDescription::parse(
        std::str::from_utf8(canonical).unwrap(),
    )
    .expect("canonical fixture must parse");
    assert_eq!(
        s1.to_string().as_bytes(),
        canonical,
        "fixture is not actually canonical — first round-trip mutates it",
    );
    assert_roundtrip_fixed_point(canonical);
}

#[test]
fn rt_sdp_oracle_holds_after_normalization() {
    // Triggers known normalizations — missing s= (defaults to "-"),
    // collapsed whitespace in o=, dropped unknown types (u=, e=).
    // Fixed point must hold at s2.
    let messy: &[u8] = b"v=0\n\
        o=-    99    1    IN    IP4    10.0.0.1\n\
        u=http://example.com/\n\
        e=ops@example.com\n\
        c=IN IP4 10.0.0.1\n\
        t=0 0\n\
        m=audio  5000  RTP/AVP  0\n\
        a=rtpmap:0 PCMU/8000\n";
    assert_roundtrip_fixed_point(messy);
}
