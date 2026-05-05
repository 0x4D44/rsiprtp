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
// Lossy-normalization corpus — fixtures targeting individual entries
// from the HLD's "What we already absorb on the first round-trip"
// list. Each verifies the s2 fixed-point survives a specific
// normalization, even when that normalization drops information.
// ---------------------------------------------------------------

#[test]
fn rt_sdp_media_type_other() {
    // m=image ... → MediaType::Other → emitted as `m=other ...` on s1.
    // Fixed point holds at s2 after the literal-collapse.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/media_type_other.sdp"));
}

#[test]
fn rt_sdp_num_ports() {
    // m=audio 49170/2 RTP/AVP 0 — port pair. Parser stores num_ports:
    // Some(2) but write_media drops it (HLD calls this a latent
    // semantic bug). Fixed point still holds at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/num_ports.sdp"));
}

#[test]
fn rt_sdp_lossy_timing() {
    // t=abc def — non-numeric timing values lossy-parse to (0, 0)
    // via parse().unwrap_or(0); s1 emits `t=0 0`. Fixed at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/lossy_timing.sdp"));
}

#[test]
fn rt_sdp_multi_c_per_media() {
    // Two c= lines on a single m=audio block: parser overwrites
    // (last-wins via `m.connection = Some(...)`); the first c= is
    // silently dropped. Fixed point holds at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/multi_c_per_media.sdp"));
}

#[test]
fn rt_sdp_misordered_after_m() {
    // s=, v=, o= appearing AFTER an m= line are dropped by the
    // current_media routing branch (only c/b/a are accepted there;
    // anything else falls through `_ => {}` and is consumed by the
    // `continue`). Fixed point holds at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/misordered_after_m.sdp"));
}

#[test]
fn rt_sdp_session_b_dropped() {
    // Session-level b=AS:1024 / b=CT:2048 — parser has no `'b'` arm
    // in the session-level match (parser.rs:89-98), so both are
    // silently dropped on s1. Fixed point holds at s2.
    assert_roundtrip_fixed_point(include_bytes!("fixtures/sdp/session_b_dropped.sdp"));
}

#[test]
fn rt_sdp_bandwidth_sort_is_deterministic() {
    // Determinism regression for the builder.rs sort fix: HashMap
    // iteration order is randomized per-instance via RandomState, so
    // a serializer that iterates `media.bandwidth` directly will
    // (with non-zero probability per parse) emit b= lines in a
    // different order than the previous serialization. The s2/s3
    // bytes-equality assertion catches that.
    //
    // Five bandwidth keys per m-line (TIAS, AS, CT, RR, RS) make
    // non-sorted iteration overwhelmingly likely on at least one of
    // the 20 fresh-HashMap iterations below.
    for _ in 0..20 {
        assert_roundtrip_fixed_point(include_bytes!(
            "fixtures/sdp/bandwidth_collision.sdp"
        ));
    }
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
