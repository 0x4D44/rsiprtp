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
    ours_from_to_diff, ours_to_diff, ours_to_to_diff, ours_via_diff, rsip_contact_diff,
    rsip_cseq_diff, rsip_from_to_diff, rsip_to_diff, rsip_to_to_diff, rsip_via_diff,
    unquote_display_name, DiffContact,
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

/// §3.1.2.2 "Valid use of the % escaping": escaped chars in user/
/// contact URIs.
///
/// **Divergence pinned (byte-perfect §A.1):** the canonical RFC 4475
/// `esc01` bytes line-fold the `Contact:` header — the URI sits on
/// the next line indented with two spaces, per RFC 3261 §7.3.1. rsip
/// 0.4's tokenizer rejects the SP-led continuation as a malformed
/// header line (the same wsinv/folding deficiency pinned by
/// `diff_rfc4475_wsinv_rsip_rejects`). Our parser correctly accepts
/// and merges the fold (see `framing::parse_header_block`'s folding
/// path).
///
/// The pre-Stage-A representative fixture had no folding so this was
/// a plain `assert_equivalent`; the byte-perfect §A.1 form exposes
/// the same rsip line-folding deficiency we already pin on wsinv.
/// When rsip is dropped at M10 this test should be retargeted to a
/// direct on-our-parser assertion.
#[test]
fn diff_rfc4475_esc01_rsip_rejects_folding() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/esc01.sip");
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_err(),
        "rsip 0.4 rejects RFC 4475 §3.1.2.2 esc01 (canonical bytes \
         line-fold the Contact header); got Ok({rs:?}) — update this \
         test if rsip changed",
    );
    let ours = OurMessage::parse(bytes);
    assert!(
        ours.is_ok(),
        "our parser must accept RFC 4475 §3.1.2.2 esc01; got \
         Err({ours:?})",
    );
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

/// §3.1.2.6 "Long values in header fields": exercises size-limit
/// path. Our defense-in-depth caps at 8192 per value; this fixture
/// sits well below that.
///
/// **Divergence pinned (byte-perfect §A.1):** the canonical RFC 4475
/// `longreq` bytes carry a Via-stack that includes entries with
/// interior whitespace around HCOLON (`V :  SIP/2.0/TCP …`,
/// `V  : SIP/2.0/TCP …`, `Via : …`, `Via  : …`) — RFC 3261 §25.1
/// `HCOLON = *( SP / HTAB ) ":" SWS` mandates acceptance of all of
/// these forms. rsip 0.4's tokenizer rejects them with the same
/// `failed to tokenize version` error pinned on wsinv (see
/// `diff_rfc4475_wsinv_rsip_rejects`). Our parser correctly accepts.
///
/// The pre-Stage-A representative fixture had a simpler Via-stack so
/// this was a plain `assert_equivalent`; the byte-perfect §A.1 form
/// exposes the same rsip HCOLON-whitespace deficiency we already pin
/// on wsinv. When rsip is dropped at M10 this test should be
/// retargeted to a direct on-our-parser assertion.
#[test]
fn diff_rfc4475_longreq_rsip_rejects_hcolon_whitespace() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/longreq.sip");
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_err(),
        "rsip 0.4 rejects RFC 4475 §3.1.2.6 longreq (canonical bytes \
         carry HCOLON-with-interior-whitespace forms in the Via \
         stack); got Ok({rs:?}) — update this test if rsip changed",
    );
    let ours = OurMessage::parse(bytes);
    assert!(
        ours.is_ok(),
        "our parser must accept RFC 4475 §3.1.2.6 longreq; got \
         Err({ours:?})",
    );
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

/// M11 fuzz finding #10: rsip 0.4 accepts `SIP/x.y` for arbitrary
/// `x.y` in the status line (`SIP/1.0`, `SIP/1.25`, etc.). RFC 3261
/// §7.1 mandates *exactly* `SIP/2.0` ("The current SIP version is
/// 'SIP/2.0'. The version is case-sensitive."). Our parser was
/// tightened in M11 to enforce that, so we correctly reject these.
///
/// Note rsip is *internally inconsistent* — an earlier M11 finding
/// showed it rejects `SIP/0` while still accepting `SIP/1.x`,
/// suggesting a numeric-range check that allows some forms. The
/// fuzz oracle's known-asymmetry skip (see
/// `parser_diff_oracle::assert_equivalent`) prevents libfuzzer from
/// rediscovering variants of this each run.
///
/// **Divergence pinned:** rsip accepts, ours rejects. When rsip is
/// dropped at M10 this test should be retargeted to a direct
/// on-our-parser rejection assertion.
#[test]
fn typed_status_line_sip1_x_version_rsip_accepts_we_reject() {
    let bytes = b"SIP/1.0 200 OK\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\
                  From: <sip:a>\r\nTo: <sip:b>\r\nVia: SIP/2.0/UDP h\r\n\
                  Content-Length: 0\r\n\r\n";
    let rs = rsip::SipMessage::try_from(&bytes[..]);
    assert!(
        rs.is_ok(),
        "rsip 0.4 accepts SIP/1.0 status lines; got Err({rs:?}) — \
         update this test if rsip stops accepting non-2.0 versions",
    );
    let ours = OurMessage::parse(bytes);
    assert!(
        ours.is_err(),
        "our parser must reject non-SIP/2.0 per RFC 3261 §7.1; \
         got Ok({ours:?})",
    );
}

/// M11 fuzz finding #11: rsip 0.4 silently strips a leading `\r\n`
/// from the body when the wire bytes contain a third CRLF immediately
/// after the `\r\n\r\n` headers/body separator. RFC 3261 §7.5 says
/// the body is exactly the bytes that follow the CRLF that terminates
/// the headers — a third CRLF is *part of the body*. Our parser
/// preserves the leading CRLF (correct); rsip drops it.
///
/// **Divergence pinned:** both accept; rsip's body is 2 bytes shorter
/// (the leading `\r\n` is gone). The fuzz oracle's known-asymmetry
/// skip (see `parser_diff_oracle::assert_equivalent` `(Ok, Ok)` arm)
/// prevents libfuzzer from rediscovering this every run. Update this
/// test if rsip stops stripping leading body CRLFs.
#[test]
fn body_leading_crlf_rsip_strips_we_preserve() {
    // Reproduces M11 fuzz finding #11. The trigger: a response with
    // no `Content-Length` header where the bytes immediately after
    // the `\r\n\r\n` headers/body separator begin with another `\r\n`.
    // rsip 0.4 silently strips that leading `\r\n` (drops 2 bytes off
    // the front of the body); our parser preserves it. RFC 3261 §7.5
    // says the body is *exactly* the bytes that follow the separator
    // — a third CRLF belongs to the body.
    let bytes = b"SIP/2.0 200 OK\r\n\r\n\r\nHi!";
    //                              ^^^^ headers/body separator
    //                                   ^^^^ leading CRLF of body
    //                                       ^^^ body content
    let rs = rsip_to_diff(bytes).expect("rsip should accept");
    let ours = ours_to_diff(bytes).expect("ours should accept");
    assert_eq!(
        ours.body, b"\r\nHi!",
        "ours preserves leading CRLF in body (RFC 3261 §7.5)",
    );
    assert_eq!(
        rs.body, b"Hi!",
        "rsip 0.4 strips the leading CRLF — update this test if rsip \
         stops stripping leading body CRLFs",
    );
    assert!(
        rs.body.len() < ours.body.len(),
        "rsip body must be strictly shorter than ours (the divergence \
         we're pinning); got rsip={:?} ours={:?}",
        rs.body,
        ours.body,
    );
}

/// M11 fuzz finding #13: rsip 0.4 silently swallows a bare LF
/// (without preceding CR) inside the Reason-Phrase, consuming
/// arbitrary text on the following line as part of the reason. RFC
/// 3261 §7.2 BNF mandates `Status-Line = SIP-Version SP Status-Code
/// SP Reason-Phrase CRLF` and `Reason-Phrase = *(reserved /
/// unreserved / escaped / UTF8-NONASCII / UTF8-CONT / SP / HTAB)` —
/// explicitly **not** including LF. The line terminator is CRLF
/// only.
///
/// On a wire input like `b"SIP/2.0 202 \nNotAHeader\r\n\r\n\xac "`,
/// rsip frames it as `Response { status: 202, reason: "\nNotAHeader",
/// headers: [], body: [0xAC, 0x20] }` — silently absorbing the bare
/// LF + bogus header text into the reason phrase. Our parser
/// correctly rejects: it recognizes the bare LF (or CRLF after the
/// trailing SP) as the end of the status line and then sees
/// `NotAHeader` as a malformed header line, surfacing
/// `Invalid header: missing ':' in header: NotAHeader`.
///
/// **Divergence pinned:** rsip accepts, ours rejects. The visible
/// "missing ':'" error from our parser is downstream of the real
/// rsip-side issue (bare-LF-as-part-of-reason). The fuzz oracle's
/// `(Ok, Err)` arm carries a `"missing ':'"` skip (see
/// `parser_diff_oracle::assert_equivalent`) to keep libfuzzer from
/// rediscovering variants of this every run. Update this test if
/// rsip stops absorbing bare LFs into the reason phrase.
#[test]
fn header_missing_colon_rsip_accepts_we_reject() {
    // The bare LF before "NotAHeader" is the trigger: rsip 0.4 eats
    // it as part of the reason phrase, our parser correctly treats
    // CR/LF as the line terminator per RFC 3261 §7.2. M11 fuzz
    // finding #13. Update this test if rsip stops swallowing bare
    // LFs in the status line.
    let bytes = b"SIP/2.0 202 \nNotAHeader\r\n\r\n\xac ";
    let rs = oracle::rsip_to_diff(bytes);
    let ours = oracle::ours_to_diff(bytes);
    assert!(rs.is_ok(), "rsip should accept (its real behavior)");
    let err = ours.expect_err("ours should reject");
    assert!(
        err.contains("missing ':'"),
        "ours error should mention missing colon (proxy for the \
         bare-LF-into-reason rsip bug); got: {err}",
    );
}

/// M11 round-trip oracle finding (round-trip #1): RFC 3261 §25.1's
/// `Reason-Phrase` grammar excludes CTL bytes (`%x00-1F / %x7F`)
/// other than HTAB. The parser previously accepted bare CR / NUL /
/// other CTL bytes that survived the framing layer (i.e. when not
/// recognised as line terminators); the serializer emitted them
/// verbatim onto the start line; the re-parse then broke because
/// the round-tripped bytes shifted framing. The round-trip oracle
/// caught this on the first run.
///
/// Fix: `parse_status_line` now rejects the full §25.1-disallowed
/// byte set. Companion to pin #13 — same RFC clause, different
/// detection surface (round-trip oracle vs. differential oracle).
///
/// **Divergence pinned:** rsip accepts, ours rejects. The fuzz
/// oracle's `(Ok, Err)` arm carries a
/// `"reason phrase contains forbidden control byte"` skip to keep
/// libfuzzer from rediscovering this every run. Update if rsip
/// tightens its tokenizer to match the §25.1 grammar.
#[test]
fn status_line_reason_ctl_byte_rsip_accepts_we_reject() {
    // Bare CR in the reason phrase. Survives `find_separator` (no
    // `\r\n`) and `split_first_line` (no `\r\n`, no bare `\n`), so
    // it reaches `parse_status_line`. RFC 3261 §25.1 disallows it.
    let bytes: &[u8] = b"SIP/2.0 200 ab\rcd\r\n\r\n";
    let rs = oracle::rsip_to_diff(bytes);
    let ours = oracle::ours_to_diff(bytes);
    assert!(
        rs.is_ok(),
        "rsip should accept (lenient §25.1): {:?}",
        rs.err()
    );
    let err = ours.expect_err("ours should reject CTL byte in reason");
    assert!(
        err.contains("reason phrase contains forbidden control byte"),
        "ours error should mention CTL byte in reason; got: {err}",
    );
}

/// M11 fuzz finding #14: a NUL byte (`0x00`) inside a header NAME
/// token in the header section. rsip 0.4's nom-based tokenizer
/// rejects it with a `Tokenizer error`; our parser accepts per the
/// M2-A pinned permissive policy (see
/// `crates/rsiprtp/src/sip/parser/framing.rs` ::
/// `test_header_with_embedded_nul_pinned_accepted`). RFC 3261 §7.3
/// does not strictly forbid NUL in header text, and §25.1 OCTET
/// grammar admits any byte; the rsip tokenizer is the narrower side
/// here.
///
/// Empirically rsip 0.4 accepts NUL inside a header *value*
/// (e.g. `Foo: a\0b`), inside the reason phrase, and inside the
/// body — so this pin uses NUL inside the header *name* token,
/// which is the position where rsip's tokenizer surfaces the
/// asymmetry as a `Tokenizer error` divergence (the original fuzz
/// finding's failing seeds matched this shape).
///
/// **Divergence pinned:** ours accepts, rsip rejects. This sits in
/// the same general category as findings #12 (status-line lenience)
/// and #13 (bare LF in Reason-Phrase): rsip's tokenizer is narrower
/// than RFC 3261 / our parser for non-printable bytes in the header
/// section. The fuzz oracle's `(Err, Ok)` arm now carries a
/// principled heuristic (any non-printable byte in the header
/// section combined with a rsip Tokenizer-class error) that catches
/// this whole category without needing per-error-string skips. See
/// `parser_diff_oracle::assert_equivalent`. Update this test if
/// rsip broadens its accepted character set (e.g. moves to a
/// byte-level OCTET tokenizer).
#[test]
fn header_section_contains_nul_rsip_rejects_we_accept() {
    // RFC 3261 §7.3 doesn't strictly forbid NUL bytes in header
    // section text; §25.1 OCTET grammar permits any byte. rsip 0.4's
    // tokenizer is narrower (rejects NUL inside the header NAME
    // token); we accept per M2-A's documented permissive policy. M11
    // fuzz finding #14. Update if rsip broadens its accepted
    // character set.
    let mut bytes = b"SIP/2.0 200 OK\r\nFo".to_vec();
    bytes.push(0); // NUL inside header NAME
    bytes.extend_from_slice(b"o: bar\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n");
    bytes.extend_from_slice(b"From: <sip:a>\r\nTo: <sip:b>\r\nVia: SIP/2.0/UDP h\r\n");
    bytes.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    let rs = oracle::rsip_to_diff(&bytes);
    let ours = oracle::ours_to_diff(&bytes);
    assert!(rs.is_err(), "rsip should reject NUL in header NAME");
    let rs_err = rs.unwrap_err();
    assert!(
        rs_err.contains("Tokenizer error"),
        "rsip rejection should be Tokenizer-class (the heuristic skip \
         in parser_diff_oracle keys off this); got: {rs_err}",
    );
    assert!(
        ours.is_ok(),
        "we accept per OCTET grammar / M2-A permissive policy",
    );
}

/// M11 fuzz finding #12, closed: status lines that omit the SP
/// between Status-Code and Reason-Phrase when the reason is empty
/// (e.g. `"SIP/2.0 202\r\n"`). RFC 3261 §7.2 BNF
/// (`Status-Line = SIP-Version SP Status-Code SP Reason-Phrase
/// CRLF`) requires the SP — both SPs are mandatory. rsip 0.4
/// always rejected this; our parser previously stayed lenient via
/// `splitn(3, ' ')` (the third part defaulted to `""`), surfacing
/// as a one-accepts/one-rejects asymmetry. We tightened
/// `parse_status_line` to require the SP per the BNF (see the unit
/// test `test_status_line_missing_sp_after_code_rejects`), so both
/// parsers now reject and the asymmetry is closed.
///
/// History: previously a `(Err, Ok)` divergence pin
/// (`status_line_no_reason_sp_rsip_rejects_we_accept`) plus a
/// matching skip in `parser_diff_oracle`. After the framing
/// tightening, this is a both-reject case. The oracle's
/// `Tokenizer error + high-bit byte` skip is also retired — see
/// the `(Err, Ok)` arm in `parser_diff_oracle::assert_equivalent`.
#[test]
fn status_line_missing_sp_after_code_both_reject() {
    // RFC 3261 §7.2 BNF requires two SPs in Status-Line:
    // `Status-Line = SIP-Version SP Status-Code SP Reason-Phrase CRLF`
    // Previously rsip rejected this and ours accepted (M11 fuzz finding
    // #12); we tightened parse_status_line to match RFC strictly. Both
    // now reject — symmetric, no asymmetry to pin.
    let bytes = b"SIP/2.0 202\r\nCall-ID: x\r\nCSeq: 1 INVITE\r\n\
                  From: <sip:a>\r\nTo: <sip:b>\r\nVia: SIP/2.0/UDP h\r\n\
                  Content-Length: 0\r\n\r\n";
    assert_both_reject("status_line_missing_sp_after_code", bytes);
}

/// M11 fuzz finding #6: a bare LF in the start-line region (LF not
/// immediately preceded by CR, appearing before the first `\r\n`)
/// trips two mutually amplifying non-RFC behaviors and produces a
/// `(Ok, Ok)` divergence where both parsers accept the same status
/// code but disagree on framing.
///
/// The wire shape is:
/// `SIP/2.0 202 \n\n6.55554\r\n4:::::::::::*\r\n[13 body bytes]`.
/// Note there is **no** `\r\n\r\n` anywhere — only an LFLF after the
/// status line and single CRLFs separating the two header-like lines.
///
/// **rsip 0.4**: its status-line tokenizer (`response::Tokenizer`) is
/// `version SP status_code <reason via take_until("\r\n")> tag("\r\n")`.
/// `take_until("\r\n")` silently absorbs bare LFs — so the reason is
/// `"\n\n6.55554"` and the first `\r\n` after `6.55554` terminates
/// the status line. The header section is then `4:::::::::::*`
/// followed by a single CRLF, which the alt-fallback
/// `take_until("\r\n") + tag("\r\n")` consumes. rsip ends up with
/// one header `("4", "::::::::::*")` and a 13-byte body. RFC 3261
/// §7.2 BNF excludes LF from `Reason-Phrase`; rsip is non-strict.
/// Same family as M11 finding #13 (pinned via
/// `header_missing_colon_rsip_accepts_we_reject`).
///
/// **Our parser**: `framing::find_separator` prefers `\r\n\r\n` but
/// falls back to `\n\n` (deliberate compatibility leniency, pinned
/// by `framing::test_split_message_lf_only_fallback`). With no
/// `\r\n\r\n` in the input, we split at the LFLF immediately after
/// the status line. Header block is empty; body is the remaining 37
/// bytes — including `6.55554\r\n4:::::::::::*\r\n` which, viewed
/// as ASCII, looks like header lines. RFC 3261 §7.5 says the body
/// is what follows CRLFCRLF; our LFLF fallback is non-strict.
///
/// **Divergence pinned**: both accept; same status (202); different
/// framing (rsip 1 hdr / 13 body, ours 0 hdr / 37 body). The fuzz
/// oracle's `(Ok, Ok)` arm carries a `has_bare_lf_in_start_line`
/// skip that catches this whole family without enumerating wire
/// shapes (any bare LF before the first `\r\n` is the trigger).
/// When rsip is dropped at M10, this skip can be retired together
/// with the pin and the framing-side LFLF fallback can be
/// reconsidered (closing the divergence on our side too).
///
/// Update this test if rsip stops absorbing bare LFs in the
/// start-line region or if we tighten `find_separator` to reject
/// the LFLF fallback.
#[test]
fn body_starts_with_header_like_line_rsip_misinterprets() {
    // The trigger: a bare LF in the start-line region. Here the LFLF
    // immediately after `SIP/2.0 202 ` is what flips the framing on
    // our side; the SAME bytes are what rsip silently absorbs into
    // its reason phrase. M11 fuzz finding #6.
    let bytes: &[u8] = b"SIP/2.0 202 \n\n6.55554\r\n4:::::::::::*\r\n\x00\x00\x00z*4(\r\n@\nTT";
    let rs = oracle::rsip_to_diff(bytes).expect("rsip should accept");
    let ours = oracle::ours_to_diff(bytes).expect("ours should accept");
    // Same status, different framing.
    assert_eq!(rs.kind, ours.kind, "both parsers see Response 202");
    assert_eq!(
        rs.headers.len(),
        1,
        "rsip absorbs bare-LF prefix into reason and parses one header",
    );
    assert_eq!(rs.headers[0].0, "4", "rsip's single header is name=\"4\"",);
    assert_eq!(rs.body.len(), 13, "rsip's body is 13 bytes after CRLFCRLF");
    assert!(
        ours.headers.is_empty(),
        "ours splits at the LFLF after the status line, no headers",
    );
    assert_eq!(
        ours.body.len(),
        37,
        "ours's body is the prefix + the 13 trailing bytes (24 + 13)",
    );
    // Sanity: ours's body END must equal rsip's body (the same 13
    // trailing bytes). The 24-byte prefix is what rsip absorbed.
    assert_eq!(
        &ours.body[ours.body.len() - rs.body.len()..],
        &rs.body[..],
        "ours's body trails with the same 13 bytes rsip sees as body",
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

/// M11 fuzz finding #16 (run-#6 triage): rsip 0.4 silently absorbs a
/// bare LF inside a *header value*, consuming the following line's
/// bytes as part of the value. Same rsip-side bug class as finding
/// #13 (`header_missing_colon_rsip_accepts_we_reject`), which pins
/// the same behavior in the **reason-phrase** position; this pin
/// covers the **header-value** position. Future-proof: if rsip fixes
/// one tokenizer site but not the other, the unfixed site is still
/// caught.
///
/// On wire `b"SIP/2.0 200 OK\r\n6.~: 5\r-\n!S-*\x01\x0c~~~*\x0b* S54\r\n\r\n"`,
/// rsip frames it as a single header
/// `("6.~", "5\r-\n!S-*\u{1}\u{c}~~~*\u{b}* S54")` — bare CR and
/// bare LF and control bytes are silently absorbed into the value.
/// Our parser treats the bare LF as a line terminator (per
/// `str::lines` semantics; RFC 3261 §7.3 says CRLF terminates a
/// header), splits there, and surfaces the orphan continuation
/// `!S-*...` as a malformed header line — `Invalid header: missing
/// ':'`. Same downstream error string as pin #13, so the existing
/// oracle `(Ok, Err)` skip already catches the class; this test is
/// a regression guard for the specific position.
///
/// **Divergence pinned:** rsip accepts, ours rejects. Update if rsip
/// stops absorbing bare LFs inside header values.
#[test]
fn header_value_with_bare_lf_rsip_accepts_we_reject() {
    let bytes = b"SIP/2.0 200 OK\r\n6.~: 5\r-\n!S-*\x01\x0c~~~*\x0b* S54\r\n\r\n";
    let rs = oracle::rsip_to_diff(bytes);
    let ours = oracle::ours_to_diff(bytes);
    assert!(rs.is_ok(), "rsip should accept (its real behavior)");
    let err = ours.expect_err("ours should reject");
    assert!(
        err.contains("missing ':'"),
        "ours error should mention missing colon (proxy for the \
         bare-LF-into-value rsip bug); got: {err}",
    );
}

/// M11 fuzz finding #17 (run-#6 triage): the LFLF-separator
/// asymmetry — rsip rejects what we accept.
///
/// Our parser's `framing::find_separator` accepts a bare `\n\n` as a
/// header/body separator when no `\r\n\r\n` is present (deliberate
/// M2-A compatibility leniency, pinned by
/// `framing::test_split_message_lf_only_fallback`). rsip 0.4 has no
/// such fallback: when the wire lacks `\r\n\r\n`, rsip's nom-based
/// tokenizer treats the entire input as a header section and fails
/// on whatever can't be tokenized as SIP header syntax — typically
/// the bytes that we'd surface as the body.
///
/// Trigger: any `SIP/2.0 ... \n\n <bytes that don't tokenize as
/// headers>` shape. The body bytes are incidental — what matters is
/// LFLF being our recognized separator but not rsip's. The original
/// run-#6 finding's "sustained 0xb8/0xf8 bytes" was incidental: the
/// fuzzer landed on high-bit bytes because those are the cheapest
/// way to make rsip's tokenizer fail past the LFLF position. Any
/// non-tokenizer-friendly bytes would trigger the same shape.
///
/// **Divergence pinned:** rsip rejects (Tokenizer error), ours
/// accepts. The principled tokenizer-narrowness heuristic in
/// `parser_diff_oracle::assert_equivalent` misses this because it
/// scopes `header_section` via the same LFLF-fallback splitter — so
/// the "header section" the heuristic sees is pure ASCII (`SIP/2.0
/// 200 OK`) with no unusual bytes. The oracle now carries a separate
/// LFLF-asymmetry skip in the `(Err, Ok)` arm. Update both this
/// pin and the skip if our parser stops accepting the LFLF
/// fallback, or if rsip starts accepting it.
#[test]
fn lflf_separator_only_rsip_rejects_we_accept() {
    // Minimal trigger: SIP response, LFLF separator (no CRLFCRLF),
    // body bytes that don't tokenize as headers.
    let bytes = b"SIP/2.0 200 OK\n\n\xb8\xb8\xb8";
    let rs = oracle::rsip_to_diff(bytes);
    let ours = oracle::ours_to_diff(bytes);
    let rs_err = rs.expect_err("rsip should reject (no CRLFCRLF and high-bit body)");
    assert!(
        rs_err.contains("Tokenizer error"),
        "rsip rejection should be Tokenizer-class (the new LFLF \
         skip in parser_diff_oracle keys off this); got: {rs_err}",
    );
    let ours = ours.expect("ours should accept (LFLF fallback per M2-A)");
    assert_eq!(
        ours.body, b"\xb8\xb8\xb8",
        "ours surfaces the post-LFLF bytes as body",
    );
    // Sanity: the wire bytes have no CRLFCRLF, only LFLF.
    assert!(
        !bytes.windows(4).any(|w| w == b"\r\n\r\n"),
        "trigger requires no CRLFCRLF",
    );
    assert!(
        bytes.windows(2).any(|w| w == b"\n\n"),
        "trigger requires LFLF",
    );
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

/// RFC 3261 §10.2.2 permits `Contact: *;expires=0` (wildcard with
/// parameters — the canonical REGISTER unbinding shape). Our
/// parser accepts and exposes `expires() == Some(0)` on a
/// typed `Wildcard { params: [...] }` variant. rsip 0.4 does NOT
/// model the wildcard at the typed level — instead it parses the
/// `*` as a literal `Domain("*")` host of an addr-spec URI, then
/// attaches the params to that fake addr. Both parsers "accept",
/// but the structural shape diverges. Pinned 9th rsip-side
/// deficiency: if rsip 0.4 is fixed to recognize the wildcard
/// shape (either as a dedicated typed variant or as a parse
/// rejection that defers to untyped), this assertion fires.
#[test]
fn typed_contact_wildcard_with_params_rsip_misclassifies() {
    use rsip::headers::untyped::{ToTypedHeader, UntypedHeader};
    let v = "*;expires=0";
    // Ours: wildcard variant with expires=0 in params.
    let ours = ours_contact_diff(v).unwrap();
    assert!(
        matches!(ours, DiffContact::Wildcard),
        "ours produced non-wildcard for `*;expires=0`: {ours:?}",
    );
    // rsip: typed-Contact accepts but classifies the `*` as a
    // domain-host. Verify that misclassification persists in 0.4
    // so a future rsip fix fires this pin.
    let untyped = rsip::headers::Contact::new(v);
    let rsip_typed = untyped.typed().expect("rsip 0.4 accepts `*;expires=0`");
    let rsip_host = rsip_typed.uri.host_with_port.host.to_string();
    assert_eq!(
        rsip_host, "*",
        "rsip 0.4 unexpectedly stopped misclassifying `*` as a Domain host: \
         host now = {rsip_host:?}; the wildcard-with-params divergence may be \
         fixed and this pin can be retired",
    );
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
