//! Round-trip oracle driver for the `Via` typed header.
//!
//! The oracle itself (`assert_via_roundtrip_fixed_point`) lives at
//! `tests/via_roundtrip_oracle/mod.rs` so it can be shared with the
//! fuzz target `fuzz/fuzz_targets/sip_via_typed_roundtrip.rs` via
//! `#[path]`. See the oracle module's docstring for the design note.
//!
//! See `wrk_docs/2026.05.06 - HLD - per-header roundtrip fuzz oracle.md`.

#[path = "via_roundtrip_oracle/mod.rs"]
mod oracle;

use oracle::assert_via_roundtrip_fixed_point;

// ---------------------------------------------------------------
// Early-reject branches: oracle must return silently, not panic.
// ---------------------------------------------------------------

#[test]
fn rt_via_skips_empty() {
    assert_via_roundtrip_fixed_point(b"");
}

#[test]
fn rt_via_skips_non_utf8() {
    // Lone continuation byte — not valid UTF-8.
    assert_via_roundtrip_fixed_point(&[0x80, 0x81, 0x82]);
}

#[test]
fn rt_via_skips_garbage() {
    // No `/` in sent-protocol → parser rejects → oracle returns.
    assert_via_roundtrip_fixed_point(b"not a Via header");
}

#[test]
fn rt_via_skips_unmatched_ipv6() {
    // Unterminated IPv6 reference → parser rejects.
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP [::1;branch=z9hG4bK1");
}

// ---------------------------------------------------------------
// Canonical inputs — already at fixed point on first parse.
// ---------------------------------------------------------------

#[test]
fn rt_via_minimal() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1");
}

#[test]
fn rt_via_with_port() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK1");
}

#[test]
fn rt_via_ipv4_sent_by() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-abc");
}

#[test]
fn rt_via_tcp_transport() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/TCP host;branch=z9hG4bK1");
}

#[test]
fn rt_via_tls_transport() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/TLS host:5061;branch=z9hG4bK1");
}

// ---------------------------------------------------------------
// IPv6 sent-by — exercises split_sent_by_params bracket walker
// (HLD §R5).
// ---------------------------------------------------------------

#[test]
fn rt_via_ipv6_no_port() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP [::1];branch=z9hG4bK1");
}

#[test]
fn rt_via_ipv6_with_port() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bK1");
}

#[test]
fn rt_via_ipv6_link_local() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP [fe80::1]:5060;branch=z9hG4bK1");
}

// Empty IPv6 brackets — Via stores sent_by as a raw string, so this
// just round-trips as the literal `[]` token (HLD §R5).
#[test]
fn rt_via_empty_ipv6_brackets() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP [];branch=z9hG4bK1");
}

// ---------------------------------------------------------------
// rport tri-state (None / flag / value).
// ---------------------------------------------------------------

#[test]
fn rt_via_rport_absent() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1");
}

#[test]
fn rt_via_rport_flag() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1;rport");
}

#[test]
fn rt_via_rport_with_value() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1;rport=12345");
}

// ---------------------------------------------------------------
// maddr + ttl + received.
// ---------------------------------------------------------------

#[test]
fn rt_via_maddr_ttl() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1;maddr=224.0.1.1;ttl=16");
}

#[test]
fn rt_via_received() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1;received=192.0.2.1");
}

#[test]
fn rt_via_multi_param() {
    assert_via_roundtrip_fixed_point(
        b"SIP/2.0/UDP host:5060;branch=z9hG4bK1;received=192.0.2.1;rport=5060;ttl=16",
    );
}

// ---------------------------------------------------------------
// Quoted-string parameter values — exercises parse_params'
// quoted-string state machine (HLD §R4).
// ---------------------------------------------------------------

#[test]
fn rt_via_quoted_param_value_with_space() {
    // The quoted form is stored verbatim (including quotes); Display
    // emits it verbatim; reparse yields the same param vec.
    assert_via_roundtrip_fixed_point(
        b"SIP/2.0/UDP host;branch=z9hG4bK1;custom=\"value with space\"",
    );
}

#[test]
fn rt_via_quoted_param_with_semicolon_inside() {
    // `;` inside quoted string must not split the param.
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1;custom=\"a;b\"");
}

// ---------------------------------------------------------------
// Lossy-on-first-pass inputs — first parse normalizes, then must
// be a fixed point.
// ---------------------------------------------------------------

#[test]
fn rt_via_double_semicolon_collapses() {
    // `;;` between params yields no entry; second parse is the
    // canonical form.
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;;branch=z9hG4bK1");
}

#[test]
fn rt_via_leading_trailing_whitespace() {
    assert_via_roundtrip_fixed_point(b"   SIP/2.0/UDP host;branch=z9hG4bK1   ");
}

#[test]
fn rt_via_inter_param_whitespace() {
    // parse_params trims each chunk (`via.rs:282`).
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host ; branch=z9hG4bK1 ; rport");
}

#[test]
fn rt_via_flag_param_with_empty_chunk() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/UDP host;branch=z9hG4bK1;rport;");
}

// ---------------------------------------------------------------
// Real-world-shaped fixtures.
// ---------------------------------------------------------------

#[test]
fn rt_via_realistic_ua() {
    assert_via_roundtrip_fixed_point(
        b"SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKnashds7;received=198.51.100.1;rport=5060",
    );
}

#[test]
fn rt_via_ws_transport() {
    assert_via_roundtrip_fixed_point(b"SIP/2.0/WS df7jal23ls0d.invalid;branch=z9hG4bK-7531");
}
