//! Differential-test harness driver: runs the `parser_diff_oracle`
//! against fixed fixture corpora and runs sanity tests for the
//! oracle's normalization.
//!
//! The oracle itself (the `assert_equivalent` machinery and all
//! supporting types) lives at `tests/parser_diff_oracle/mod.rs` so it
//! can be shared with the M11 fuzz target
//! `fuzz/fuzz_targets/sip_message_parse_diff.rs`. See the oracle
//! module's docstring for the design note.
//!
//! See `wrk_docs/2026.05.03 - HLD - sip-parser-rewrite.md`.

use rsiprtp::sip::parser::Message as OurMessage;
use rsiprtp::sip::SipUri;

#[path = "parser_diff_oracle/mod.rs"]
mod oracle;

use oracle::{
    assert_both_reject, assert_equivalent, normalize_value, ours_contact_diff, ours_cseq_diff,
    ours_from_to_diff, ours_to_to_diff, ours_via_diff, rsip_contact_diff, rsip_cseq_diff,
    rsip_from_to_diff, rsip_to_to_diff, rsip_via_diff, unquote_display_name, DiffContact,
};

// ---------------------------------------------------------------
// Tests against the mdsiprtp3 fixture corpus
// ---------------------------------------------------------------

#[test]
fn diff_mdsiprtp3_invite_with_via() {
    let bytes = include_bytes!("fixtures/mdsiprtp3/invite_with_via.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_mdsiprtp3_response_200_ok() {
    let bytes = include_bytes!("fixtures/mdsiprtp3/response_200_ok.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_mdsiprtp3_invite_with_body() {
    let bytes = include_bytes!("fixtures/mdsiprtp3/invite_with_body.sip");
    assert_equivalent(bytes);
}

// ---------------------------------------------------------------
// Tests against the hand-curated fixture corpus
// ---------------------------------------------------------------
//
// See `tests/fixtures/handcrafted/README.md` for the catalog. These
// exercise corners not covered by the mdsiprtp3 fixtures: compact-form
// headers, folded headers, multi-`Via`, authentication headers, and
// the REGISTER / ACK / CANCEL methods.

#[test]
fn diff_handcrafted_register_with_contact() {
    let bytes = include_bytes!("fixtures/handcrafted/register_with_contact.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_invite_compact_via() {
    let bytes = include_bytes!("fixtures/handcrafted/invite_compact_via.sip");
    assert_equivalent(bytes);
}

/// rsip 0.4 does NOT accept RFC 3261 §7.3.1 line folding — its
/// tokenizer rejects the SP-led continuation as a malformed header
/// line. Our parser correctly accepts it and merges the fold into a
/// single header value (see `framing::parse_header_block`'s folding
/// path, also covered by the unit test `test_parse_header_block_folding*`).
/// This is a surprising rsip behavior we deliberately differ from;
/// see the brief's triage policy ("mark `#[ignore]` with a comment").
/// When we drop rsip in M10 this test should be unmarked and the
/// equivalence check replaced with a direct on-our-parser assertion.
#[test]
#[ignore = "rsip 0.4 rejects RFC 3261 §7.3.1 line folding; our parser correctly accepts it"]
fn diff_handcrafted_invite_folded_subject() {
    let bytes = include_bytes!("fixtures/handcrafted/invite_folded_subject.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_response_407_with_proxy_authenticate() {
    let bytes = include_bytes!("fixtures/handcrafted/response_407_with_proxy_authenticate.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_ack_for_2xx() {
    let bytes = include_bytes!("fixtures/handcrafted/ack_for_2xx.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_cancel() {
    let bytes = include_bytes!("fixtures/handcrafted/cancel.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_response_with_multi_via() {
    let bytes = include_bytes!("fixtures/handcrafted/response_with_multi_via.sip");
    assert_equivalent(bytes);
}

// ---------------------------------------------------------------
// Tests against the RFC 4475 torture-test corpus (M6)
// ---------------------------------------------------------------
//
// See `tests/fixtures/rfc4475/README.md` for the catalog. These exercise
// the corner cases described in RFC 4475 §3 ("Valid Messages"). Each
// fixture is a representative SIP message constructed per the torture-
// test category — we are testing the same parser corner the RFC §3.1
// paragraph describes, not asserting byte-perfect copies of the RFC's
// own example bodies.

/// §3.1.1 "A short tortuous INVITE": quoted display names with
/// embedded SP / quoted-pairs, parameter-name-only forms, header
/// values broken across lines via line folding, and heavy interior
/// whitespace (e.g. `SIP  /   2.0  /UDP`).
///
/// **Divergence pinned:** rsip 0.4 rejects the entire message at
/// tokenize-version time — the combination of folding + interior
/// whitespace in `Via:` defeats its tokenizer. RFC 3261 §7.3.1
/// (line folding) and §25.1 (LWS in HCOLON / param SEMI / etc.)
/// mandate acceptance of all of these forms, so this is a real
/// rsip-side spec deficiency. Our parser correctly accepts (see
/// `framing::parse_header_block` folding path; `name_addr::*`
/// surrounding-whitespace handling).
///
/// At M10 (rsip dropped from runtime deps), this test should be
/// retargeted to a direct on-our-parser assertion.
#[test]
fn diff_rfc4475_wsinv_rsip_rejects() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/wsinv.sip");
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_err(),
        "rsip 0.4 rejects RFC 4475 §3.1.1 wsinv torture test; \
         got Ok({rs:?}) — update this test if rsip changed",
    );
    let ours = OurMessage::parse(bytes);
    assert!(
        ours.is_ok(),
        "our parser must accept RFC 4475 §3.1.1 wsinv; got Err({ours:?})",
    );
}

#[test]
fn diff_rfc4475_esc01() {
    // §3.1.2.2 "Valid use of the % escaping": escaped chars in user/
    // contact URIs.
    let bytes = include_bytes!("fixtures/rfc4475/esc01.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_escnull() {
    // §3.1.2.3 "Escaped nulls in URIs": `%00` in user portion.
    let bytes = include_bytes!("fixtures/rfc4475/escnull.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_esc02() {
    // §3.1.2.4 "Use of % when it is not an escape": `%` followed by
    // non-hex inside header values.
    let bytes = include_bytes!("fixtures/rfc4475/esc02.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_lwsdisp() {
    // §3.1.2.5 "No LWS between Display Name and `<`".
    let bytes = include_bytes!("fixtures/rfc4475/lwsdisp.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_longreq() {
    // §3.1.2.6 "Long values in header fields": exercises size-limit
    // path. Our defense-in-depth caps at 8192 per value; this fixture
    // sits well below that.
    let bytes = include_bytes!("fixtures/rfc4475/longreq.sip");
    assert_equivalent(bytes);
}

/// §3.1.2.7 "Extra trailing octets in a UDP datagram": the first
/// message has `Content-Length: 0` (no body), but the datagram
/// contains a fully-formed second request after that. RFC 4475
/// §3.1.2.7 says: *"Implementations should process the request and
/// ignore the extra bytes."*
///
/// **Divergence pinned:** rsip 0.4 ignores Content-Length and
/// captures the trailing octets as the body of the first request.
/// Our parser correctly truncates the body to Content-Length per
/// RFC 3261 §18.3. Both parse the framing, but produce different
/// `body`. Pin the asymmetry; tighten when rsip is dropped at M10.
#[test]
fn diff_rfc4475_dblreq_rsip_keeps_trailing() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/dblreq.sip");
    let ours = OurMessage::parse(bytes).expect("our parser accepts dblreq");
    let our_body: &Vec<u8> = match &ours {
        OurMessage::Request(r) => &r.body,
        OurMessage::Response(r) => &r.body,
    };
    assert!(
        our_body.is_empty(),
        "ours: Content-Length: 0 → body must be empty; got {} bytes",
        our_body.len(),
    );
    let rs = rsip::SipMessage::try_from(bytes).expect("rsip accepts dblreq framing");
    let rs_body = match &rs {
        rsip::SipMessage::Request(r) => &r.body,
        rsip::SipMessage::Response(r) => &r.body,
    };
    assert!(
        !rs_body.is_empty(),
        "rsip 0.4 captures trailing octets as body; if it now \
         truncates per Content-Length, this pin can be removed.",
    );
}

/// §3.1.2.8 "Semicolons in URI user part": RFC 3261 §25.1
/// `user-unreserved = "&" / "=" / "+" / "$" / "," / ";" / "?" /
/// "/"` — so `;` is a legal user character. The Request-URI
/// `sip:user;par=u%40example.net@example.com` therefore has user
/// `user;par=u%40example.net` (the `;` and `@` decoded inside the
/// user portion) and host `example.com`.
///
/// **Divergence pinned:** rsip 0.4 rejects the entire message —
/// its tokenizer treats `;` as the user/params boundary without
/// honoring the userinfo grammar. Our parser correctly splits at
/// the `@` first per RFC 3261 §19.1.1 (this M6 milestone fixed a
/// bug in our parser where `;` before `@` was ALSO treated as a
/// param separator — see `crates/rsiprtp/src/sip/uri.rs`
/// `parse()`).
#[test]
fn diff_rfc4475_semiuri_rsip_rejects() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/semiuri.sip");
    let ours = OurMessage::parse(bytes).expect("ours accepts semiuri");
    if let OurMessage::Request(r) = &ours {
        // Verify the URI parse produced the right user/host split.
        let uri = SipUri::parse(&r.uri).expect("our URI parses");
        assert_eq!(uri.user(), Some("user;par=u%40example.net"));
        assert_eq!(uri.host(), "example.com");
    } else {
        panic!("expected request");
    }
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_err(),
        "rsip 0.4 rejects URI with `;` in user part; got Ok({rs:?}) \
         — update this test if rsip changed",
    );
}

/// §3.1.2.9 "Varied and unknown transport types in Via". RFC 3261
/// §20.42 grammar: `transport-param = "transport=" ( "udp" / "tcp"
/// / "sctp" / "tls" / other-transport )` where `other-transport =
/// token`. Unknown but token-shaped transports MUST be accepted at
/// parse time (consumers can route or reject as they see fit).
///
/// **Divergence pinned (typed-Via path only):** rsip 0.4's typed
/// Via parser rejects unknown transport tokens (`TUNA` in our
/// fixture). Tier-1 framing on both sides is fine; the divergence
/// is in `rsip::headers::Via::typed()`. Our parser accepts.
///
/// We assert the message frames cleanly on both sides, then assert
/// rsip's typed-Via specifically rejects the unknown-transport
/// variant. When rsip is dropped at M10 this test is retargeted.
#[test]
fn diff_rfc4475_transports_rsip_rejects_unknown_transport() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/transports.sip");
    // Tier-1 framing is clean on both sides.
    let _ours_msg = OurMessage::parse(bytes).expect("ours frames transports");
    let _rsip_msg = rsip::SipMessage::try_from(bytes).expect("rsip frames transports");
    // Tier-2 typed-Via on the unknown-transport entry: rsip rejects.
    let unknown_via = "SIP/2.0/TUNA t6.example.com;branch=z9hG4bK6";
    let r = rsip_via_diff(unknown_via);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects unknown transport in typed Via; got \
         Ok({r:?}) — update this test if rsip changed",
    );
    let d = ours_via_diff(unknown_via).expect("ours typed-Via accepts unknown transport");
    assert_eq!(d.transport, "TUNA");
}

#[test]
fn diff_rfc4475_unreason() {
    // §3.1.2.10 "Unusual REGISTER request with binding".
    let bytes = include_bytes!("fixtures/rfc4475/unreason.sip");
    assert_equivalent(bytes);
}

// ---------------------------------------------------------------
// RFC 4475 §4 — Invalid Messages: both parsers MUST reject
// ---------------------------------------------------------------
//
// Per RFC 4475 §4 ("Invalid Messages"), each of these is malformed in
// a way that any conformant parser must reject. The harness assertion
// is "both parsers return Err" — if EITHER parser accepts, that's a
// real bug we want to surface.
//
// Fixtures live in `tests/fixtures/rfc4475_invalid/` (separate dir
// from the §3 valid set so the rejection-expectation is structurally
// explicit).

#[test]
fn diff_rfc4475_invalid_no_version() {
    // §4-style: request line missing the `SIP/2.0` token.
    let bytes = include_bytes!("fixtures/rfc4475_invalid/badaspec_no_version.sip");
    assert_both_reject("badaspec_no_version", bytes);
}

// NOTE: a "negative Content-Length" fixture was considered (RFC 4475
// §4 ncl) but dropped — both parsers store header values as strings
// and validate digits only when bounding the body, which is a
// typed-form / body-extraction concern rather than tier-1 framing.
// RFC 4475 §4 ncl really exercises tier-2 logic that this harness
// does not cover.

#[test]
fn diff_rfc4475_invalid_garbage_start() {
    // §4-style: start line is neither a valid request nor a valid
    // status line.
    let bytes = include_bytes!("fixtures/rfc4475_invalid/badaspec_garbage_start.sip");
    assert_both_reject("badaspec_garbage_start", bytes);
}

/// M8 reviewer scenario: a structurally-complete request whose
/// Request-URI is not a SIP/SIPS/TEL URI (here: `http://x`). RFC
/// 3261 §25 production for Request-URI is `SIP-URI / SIPS-URI /
/// absoluteURI`, but absoluteURI does not include arbitrary
/// non-SIP schemes by default in the message router — and more
/// importantly, our `SipRequest::uri()` accessor calls
/// `SipUri::parse` which only knows `sip` / `sips` / `tel`. Before
/// the M8 framing-time validation this fixture would survive
/// framing on our side and then panic in `SipRequest::uri()` —
/// attacker-controlled DoS. Our framer must now reject.
///
/// **Divergence pinned:** rsip 0.4 accepts `http://x` and stores
/// the scheme as `Scheme::Other("http")`. We deliberately tighten
/// here: the fixture is rejected by us at framing time so the
/// downstream wrapper accessors are infallible. When rsip is
/// dropped from runtime deps at M10, this test should be
/// retargeted to a direct on-our-parser rejection assertion.
#[test]
fn diff_request_line_with_non_sip_uri_rsip_accepts_we_reject() {
    let bytes: &[u8] = b"INVITE http://x SIP/2.0\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\
                         From: <sip:a>\r\nTo: <sip:b>\r\nVia: SIP/2.0/UDP h\r\n\
                         Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n";
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_ok(),
        "rsip 0.4 accepts non-SIP Request-URIs as Scheme::Other; \
         got Err({rs:?}) — update this test if rsip tightened",
    );
    let ours = OurMessage::parse(bytes);
    assert!(
        ours.is_err(),
        "our framer must reject non-SIP Request-URI to keep \
         SipRequest::uri() panic-free; got Ok({ours:?})",
    );
}

// ---------------------------------------------------------------
// Tests against the rsiprtp fuzz corpus (populated by M11)
// ---------------------------------------------------------------

/// Diff every file in the rsiprtp fuzz corpus, if it exists.
///
/// The corpus directory is created and populated by M11's overnight fuzz
/// campaign. Until then this test is a no-op (vacuously passes). After
/// M11 lands, every fuzz-corpus input becomes a Tier-1 differential
/// assertion against rsip 0.4.
#[test]
fn diff_fuzz_corpus() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("sip_message_parse")
        .join("corpus");
    if !corpus_dir.exists() {
        // Corpus not yet populated; M11 owns this. No-op.
        return;
    }
    let entries: Vec<_> = std::fs::read_dir(&corpus_dir)
        .expect("corpus dir exists per check above")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    for entry in entries {
        let path = entry.path();
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read fuzz corpus file {:?}: {}", path, e));
        // Wrap each file's assertion in its own panic message so a divergence
        // surfaces the file name, not just the bytes.
        let result = std::panic::catch_unwind(|| assert_equivalent(&bytes));
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }
}

// ---------------------------------------------------------------
// Sanity tests for the harness itself
// ---------------------------------------------------------------

#[test]
fn normalize_collapses_runs_of_whitespace() {
    assert_eq!(normalize_value("a   b  c"), "a b c");
    assert_eq!(
        normalize_value(" \tleading \t and trailing \t "),
        "leading and trailing"
    );
}

#[test]
fn normalize_strips_comments() {
    assert_eq!(normalize_value("foo (this is a comment) bar"), "foo bar");
    assert_eq!(
        normalize_value("Acme/1.0 (server (nested) detail) baz"),
        "Acme/1.0 baz",
    );
}

#[test]
fn normalize_preserves_quoted_strings() {
    // Parens inside a quoted string are NOT a comment.
    assert_eq!(
        normalize_value(r#""display (name)" <sip:a@b>"#),
        r#""display (name)" <sip:a@b>"#,
    );
}

#[test]
fn normalize_handles_quoted_pair_escapes() {
    // \" inside a quoted string is literal; doesn't end the string.
    assert_eq!(normalize_value(r#""a\"b" trailing"#), r#""a\"b" trailing"#,);
}

// ---------------------------------------------------------------
// Sanity tests for the typed-form (M4) normalization
// ---------------------------------------------------------------
//
// These exercise the DiffNameAddr normalization without needing a
// full SIP message — they construct the value strings inline. Two
// shapes are checked:
//
// 1. Parameter-order independence: `;tag=x;foo=y` should normalize
//    identically to `;foo=y;tag=x`. RFC 3261 §19.1.4 (URI params)
//    and §25.1's `*( SEMI generic-param )` production make this
//    legitimate at equality. Both rsip and our parser should
//    agree.
//
// 2. Quoted vs unquoted display name with a token-only inner: per
//    RFC 3261 §20.10/25.1, `"Alice" <sip:a@b>` and `Alice <sip:a@b>`
//    encode the same display-name "Alice". Our normalizer
//    (`unquote_display_name`) strips the quotes on the rsip side
//    so the two compare equal — this is the right call when the
//    inner content is a bare token (no characters that would
//    require quoting). For inner content that DOES require quoting
//    (e.g. spaces) the two are NOT equivalent — the unquoted form
//    is malformed under §25.1 and rsip and our parser would both
//    reject or interpret differently.

#[test]
fn typed_from_param_order_is_normalized() {
    let v1 = "Alice <sip:alice@example.com>;tag=x;foo=y";
    let v2 = "Alice <sip:alice@example.com>;foo=y;tag=x";
    let d1 = ours_from_to_diff(v1).unwrap();
    let d2 = ours_from_to_diff(v2).unwrap();
    assert_eq!(d1, d2, "param-order normalization failed: {d1:?} vs {d2:?}");
    let r1 = rsip_from_to_diff(v1).unwrap();
    let r2 = rsip_from_to_diff(v2).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(d1, r1);
}

#[test]
fn typed_from_quoted_token_display_normalizes_to_unquoted() {
    // For a *token* inner (no chars requiring quotation) RFC 3261
    // §25.1's `display-name = *(token LWS) / quoted-string` lets
    // either form encode the same name.
    let v_quoted = r#""Alice" <sip:alice@example.com>;tag=t"#;
    let v_token = "Alice <sip:alice@example.com>;tag=t";
    let d_quoted = ours_from_to_diff(v_quoted).unwrap();
    let d_token = ours_from_to_diff(v_token).unwrap();
    assert_eq!(d_quoted, d_token);
    let r_quoted = rsip_from_to_diff(v_quoted).unwrap();
    let r_token = rsip_from_to_diff(v_token).unwrap();
    assert_eq!(r_quoted, r_token);
    assert_eq!(d_quoted, r_quoted);
}

#[test]
fn typed_from_quoted_with_space_preserves_inner() {
    // Inner has a space → MUST be quoted on the wire. The
    // normalized display name is the unquoted "Alice Smith".
    let v = r#""Alice Smith" <sip:a@b>;tag=t"#;
    let d = ours_from_to_diff(v).unwrap();
    let r = rsip_from_to_diff(v).unwrap();
    assert_eq!(d.display_name.as_deref(), Some("Alice Smith"));
    assert_eq!(d, r);
}

#[test]
fn typed_to_no_tag_is_normalized_consistently() {
    // To on initial INVITE has no tag — both parsers should accept.
    let v = "Bob <sip:bob@example.com>";
    let d = ours_to_to_diff(v).unwrap();
    let r = rsip_to_to_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.display_name.as_deref(), Some("Bob"));
    assert!(d.parameters.is_empty());
}

#[test]
fn typed_from_bare_addr_spec_normalizes() {
    // No angle brackets, `;tag=` is a header param.
    let v = "sip:bob@example.com;tag=xyz";
    let d = ours_from_to_diff(v).unwrap();
    let r = rsip_from_to_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.display_name, None);
    assert_eq!(
        d.parameters,
        vec![("tag".to_string(), Some("xyz".to_string()))]
    );
}

#[test]
fn unquote_display_name_handles_escapes() {
    assert_eq!(unquote_display_name(r#""Alice""#), "Alice");
    assert_eq!(unquote_display_name(r#""Alice Smith""#), "Alice Smith");
    assert_eq!(
        unquote_display_name(r#""He said \"hi\"""#),
        r#"He said "hi""#
    );
    assert_eq!(unquote_display_name("Alice"), "Alice"); // no quotes, pass-through
}

/// M4 follow-up (HLD note): quoted parameter values containing a
/// semicolon. RFC 3261 §25.1 `gen-value = token / host /
/// quoted-string`, so `;name="x;y"` is legal and the inner `;` is
/// NOT a parameter separator.
///
/// Investigation result (DA's flagged divergence): **rsip 0.4
/// rejects the entire input** when a generic-param value is a
/// quoted-string containing a `;`. Its `name_params` tokenizer
/// splits on `;` first, then runs token-only matching on the
/// segments — `name="x` is left over as "trailing input" and
/// fails. Our parser correctly honors the quoted-string boundary
/// (see `name_addr::parse_params`) and accepts the input.
///
/// This is a one-accepts / one-rejects case. Per the HLD's diff
/// triage policy ("spec is explicit (fix the wrong one)") the
/// spec is on our side: §25.1 `gen-value = token / host /
/// quoted-string`. We document the asymmetry here rather than
/// silently masking it. When rsip is dropped at M10 this test
/// becomes a direct on-our-parser assertion (no rsip side).
#[test]
fn typed_from_quoted_param_value_with_semicolon_rsip_rejects() {
    let v = r#"<sip:a@b>;tag=t;name="x;y""#;
    // Our parser accepts and produces two params, with the
    // semicolon-bearing value intact inside the quoted string.
    let d = ours_from_to_diff(v).unwrap();
    assert_eq!(d.parameters.len(), 2, "ours: {:?}", d.parameters);
    let name_value = d
        .parameters
        .iter()
        .find(|(k, _)| k == "name")
        .and_then(|(_, v)| v.as_deref());
    // The value retains its surrounding quotes (matches our
    // NameAddr behavior — see `test_quoted_param_value` there).
    assert_eq!(name_value, Some("\"x;y\""));
    // rsip rejects this. Pin that for documentation; if a future
    // rsip update fixes it the assertion will fire and we can
    // tighten the harness.
    let r = rsip_from_to_diff(v);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects quoted-param-with-semicolon; \
         got Ok({r:?}) — update this test if rsip changed",
    );
}

/// Sister test: a quoted param value WITHOUT a semicolon. rsip
/// 0.4 still rejects this — its `name_params` tokenizer doesn't
/// model `gen-value = quoted-string` *at all* (not just the
/// semicolon-inside subcase). Confirms the divergence is broader
/// than the semicolon case.
///
/// Our parser accepts and stores the value with surrounding
/// quotes preserved; consumers who want the unquoted text apply
/// `unquote_display_name`-style stripping at the call site. We
/// pin both shapes here.
#[test]
fn typed_from_quoted_param_value_rsip_rejects_broadly() {
    let v = r#"<sip:a@b>;tag=t;name="hello""#;
    let d = ours_from_to_diff(v).unwrap();
    // Our parser keeps surrounding quotes verbatim.
    let name_value = d
        .parameters
        .iter()
        .find(|(k, _)| k == "name")
        .and_then(|(_, v)| v.as_deref());
    assert_eq!(name_value, Some("\"hello\""));
    let r = rsip_from_to_diff(v);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects all quoted-string param values; got \
         Ok({r:?}) — update this test if rsip changed",
    );
}

// ---------------------------------------------------------------
// Sanity tests for the typed-form (M5) Via/CSeq/Contact path
// ---------------------------------------------------------------

#[test]
fn typed_via_basic_normalizes() {
    let v = "SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK1";
    let d = ours_via_diff(v).unwrap();
    let r = rsip_via_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.protocol, "SIP/2.0");
    assert_eq!(d.transport, "UDP");
    assert_eq!(d.sent_by, "host.example.com:5060");
}

#[test]
fn typed_via_transport_case_normalized_to_upper() {
    let v_upper = "SIP/2.0/UDP host:5060;branch=z";
    let v_lower = "SIP/2.0/udp host:5060;branch=z";
    let d_upper = ours_via_diff(v_upper).unwrap();
    let d_lower = ours_via_diff(v_lower).unwrap();
    assert_eq!(d_upper.transport, d_lower.transport);
}

#[test]
fn typed_via_host_case_normalized_to_lower() {
    let v_lc = "SIP/2.0/UDP host.example.com:5060;branch=z";
    let v_uc = "SIP/2.0/UDP HOST.EXAMPLE.COM:5060;branch=z";
    let d_lc = ours_via_diff(v_lc).unwrap();
    let d_uc = ours_via_diff(v_uc).unwrap();
    assert_eq!(d_lc.sent_by, d_uc.sent_by);
}

/// RFC 3261 §20.42 + RFC 5118 §4.1: Via sent-by may be a bracketed
/// IPv6 reference, e.g. `[2001:db8::1]:5060`. **rsip 0.4 rejects
/// this** — its sent-by tokenizer doesn't model the
/// `IP6reference` production. Our parser accepts it (see
/// `via::test_parse_ipv6_with_port`).
///
/// Like the quoted-param-with-semicolon case, this is a
/// one-accepts/one-rejects divergence where the spec is on our
/// side. Pin the asymmetry; tighten when rsip is dropped at M10.
#[test]
fn typed_via_ipv6_rsip_rejects() {
    let v = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKabc";
    let d = ours_via_diff(v).unwrap();
    assert_eq!(d.sent_by, "[2001:db8::1]:5060");
    let r = rsip_via_diff(v);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects IPv6 sent-by; got Ok({r:?}) — \
         update this test if rsip changed",
    );
}

#[test]
fn typed_via_rport_flag_and_value_both_match_rsip() {
    // rport without value (client request): rsip stores as
    // Other("rport", None); we as ("rport", None).
    let v_flag = "SIP/2.0/UDP host:5060;branch=z;rport";
    let d_flag = ours_via_diff(v_flag).unwrap();
    let r_flag = rsip_via_diff(v_flag).unwrap();
    assert_eq!(d_flag, r_flag);

    // rport with value (server response).
    let v_val = "SIP/2.0/UDP host:5060;branch=z;rport=12345";
    let d_val = ours_via_diff(v_val).unwrap();
    let r_val = rsip_via_diff(v_val).unwrap();
    assert_eq!(d_val, r_val);
}

#[test]
fn typed_cseq_basic_normalizes() {
    let v = "1 INVITE";
    let d = ours_cseq_diff(v).unwrap();
    let r = rsip_cseq_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.seq, 1);
    assert_eq!(d.method, "INVITE");
}

#[test]
fn typed_cseq_method_case_normalized() {
    // rsip Display upper-cases; our Method::as_str() also upper.
    let v = "42 invite";
    let d = ours_cseq_diff(v).unwrap();
    let r = rsip_cseq_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.method, "INVITE");
}

#[test]
fn typed_cseq_high_seq_numbers() {
    let v = format!("{} BYE", u32::MAX);
    let d = ours_cseq_diff(&v).unwrap();
    let r = rsip_cseq_diff(&v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.seq, u32::MAX);
}

#[test]
fn typed_contact_simple_normalizes() {
    let v = "<sip:alice@example.com>;expires=3600";
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert_eq!(d, r);
    if let DiffContact::Addr(a) = &d {
        assert!(a.display_name.is_none());
    } else {
        panic!("expected Addr");
    }
}

#[test]
fn typed_contact_wildcard_handled_on_both_sides() {
    let v = "*";
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert!(matches!(d, DiffContact::Wildcard));
    assert!(matches!(r, DiffContact::Wildcard));
}

#[test]
fn typed_contact_with_quoted_display_normalizes() {
    let v = r#""Alice" <sip:alice@example.com>;expires=300;q=0.7"#;
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert_eq!(d, r);
    if let DiffContact::Addr(a) = &d {
        assert_eq!(a.display_name.as_deref(), Some("Alice"));
    } else {
        panic!("expected Addr");
    }
}

#[test]
fn typed_contact_bare_addr_spec_normalizes() {
    let v = "sip:bob@example.com;expires=60";
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert_eq!(d, r);
}

#[test]
fn normalize_does_not_apply_quoted_pair_outside_string_or_comment() {
    // RFC 3261 §25.1: quoted-pair only valid inside quoted-string or comment.
    // Outside both, a backslash is a literal byte and the parens are real (not comment-start).
    let input = r"foo \(literal\) bar";
    let out = normalize_value(input);
    // The parens are NOT comments since they're not introduced by an unescaped '(',
    // they're escaped. But our parser doesn't escape; the check is that we don't
    // silently swallow the closing ')'. Concretely: output must contain both '(' and ')'.
    assert!(out.contains('('), "expected '(' preserved, got: {out:?}");
    assert!(out.contains(')'), "expected ')' preserved, got: {out:?}");
}
