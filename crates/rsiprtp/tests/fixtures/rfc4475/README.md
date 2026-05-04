# RFC 4475 fixtures

[RFC 4475](https://datatracker.ietf.org/doc/html/rfc4475) ("Session
Initiation Protocol (SIP) Torture Test Messages") defines a corpus of
intentionally-stressful SIP messages designed to exercise parser
corners. These fixtures are *representative* messages constructed per
the categories in §3 ("Valid Messages") and §4 ("Invalid Messages") —
each fixture exercises the same parser corner the RFC §3.1 paragraph
describes, not necessarily the byte-perfect example from the RFC body.

Each `.sip` file contains literal CRLF-terminated bytes and ends with
a `\r\n\r\n` body separator. The fixtures themselves are the
authoritative artifacts; if regeneration is ever needed, consult RFC
4475 directly.

| File | Description | RFC § |
|---|---|---|
| `wsinv.sip` | Short tortuous INVITE: quoted display names with embedded SP / quoted-pairs, parameter-name-only forms, exotic interior whitespace, and folded headers. (Pinned divergence — rsip 0.4 rejects the whole message; see `diff_rfc4475_wsinv_rsip_rejects`.) | §3.1.1 |
| `esc01.sip` | Valid `%HH` escapes throughout user, contact, and URI parameter portions. | §3.1.2.2 |
| `escnull.sip` | Escaped NUL bytes (`%00`) in user portion of `Contact:` URIs. | §3.1.2.3 |
| `esc02.sip` | `%` characters in header *values* that are not `%HH` escape sequences. | §3.1.2.4 |
| `lwsdisp.sip` | Display name and `<addr-spec>` with no LWS between them (e.g. `"caller"<sip:caller@…>`). | §3.1.2.5 |
| `longreq.sip` | Long header values (~200-char display name and user portion) — exercises the value-length path within our 8192-byte defense-in-depth cap. | §3.1.2.6 |
| `dblreq.sip` | `Content-Length: 0` request with extra octets after the body (a complete second request). The extra bytes must be ignored. (Pinned divergence — rsip 0.4 captures the trailing bytes as the body; see `diff_rfc4475_dblreq_rsip_keeps_trailing`.) | §3.1.2.7 |
| `semiuri.sip` | Semicolons in URI user part (`sip:user;par=u%40example.net@example.com`). (Pinned divergence — rsip 0.4 rejects; see `diff_rfc4475_semiuri_rsip_rejects`. M6 also fixed a bug in our URI parser where `;` before `@` was treated as the params boundary.) | §3.1.2.8 |
| `transports.sip` | Multiple `Via:` lines covering UDP, TCP, SCTP, TLS, TLS-SCTP, and an unknown `TUNA` transport. (Pinned divergence — rsip 0.4's typed-Via rejects unknown transport tokens; see `diff_rfc4475_transports_rsip_rejects_unknown_transport`.) | §3.1.2.9 |
| `unreason.sip` | Unusual REGISTER request with multi-segment binding: quoted display name, multiple `Contact:` lines with `q=` and `expires=` parameters, an unknown extension parameter. | §3.1.2.10 |

The following §3 sub-sections are intentionally **omitted**:

- **§3.1.2.1 intmeth** (Wide range of valid characters in method
  token) — our `Method` enum is a closed set per RFC 3261 §7.1; we
  reject exotic method tokens like `!interesting-Method`. Skipped.
- **§3.1.2.11 noreason** (Unknown method) — same reason as §3.1.2.1.

## §4 Invalid Messages — `rfc4475_invalid/`

Lives in a sibling directory (`crates/rsiprtp/tests/fixtures/rfc4475_invalid/`)
to make the rejection-expectation explicit. Each fixture is asserted
to be rejected by **both** rsip 0.4 and our parser via
`assert_both_reject` in `parser_diff.rs`.

| File | Description | RFC § category |
|---|---|---|
| `badaspec_no_version.sip` | Request line missing the `SIP/2.0` SIP-Version token entirely. | §4 (badaspec) |
| `badaspec_garbage_start.sip` | Start line that is neither a valid request line nor a valid status line. | §4 (badaspec) |

The RFC 4475 §4 `ncl` test (negative `Content-Length`) was considered
and dropped: both parsers store header values as strings and only
validate the digits when bounding the body, which is a typed-form /
body-extraction concern rather than a tier-1 framing concern. The §4
ncl test really exercises tier-2 logic that this harness does not
cover.

## Pinned divergences from this milestone (M6)

| Test | Direction | Spec citation |
|---|---|---|
| `diff_rfc4475_wsinv_rsip_rejects` | rsip rejects, ours accepts | RFC 3261 §7.3.1 (line folding) + §25.1 (LWS in HCOLON / SEMI) |
| `diff_rfc4475_dblreq_rsip_keeps_trailing` | both accept; rsip captures trailing octets as body, ours truncates per Content-Length | RFC 3261 §18.3 / RFC 4475 §3.1.2.7 |
| `diff_rfc4475_semiuri_rsip_rejects` | rsip rejects, ours accepts | RFC 3261 §25.1 `user-unreserved` includes `;`; §19.1.1 grammar requires `@` to bound userinfo before params |
| `diff_rfc4475_transports_rsip_rejects_unknown_transport` | rsip's typed-Via rejects, ours accepts | RFC 3261 §20.42 `transport-param` `other-transport = token` |

Combined with the pre-M6 pins (`diff_handcrafted_invite_folded_subject`,
`typed_from_quoted_param_value_rsip_rejects_broadly`,
`typed_from_quoted_param_value_with_semicolon_rsip_rejects`,
`typed_via_ipv6_rsip_rejects`), the running rsip 0.4 spec-deficiency
count is **8 distinct types**. All are retargeted to direct
on-our-parser assertions when rsip is dropped from runtime deps at M10.

## Parser bug fixed in this milestone

`crates/rsiprtp/src/sip/uri.rs` — the URI parser's parameter-boundary
detection treated the *first* `;` as the user/host vs params boundary,
even when that `;` lay inside the userinfo (i.e., before the `@`). RFC
3261 §19.1.1 requires `@` to terminate userinfo before parameter
parsing begins. Surfaced by `wsinv.sip` and `semiuri.sip`; fixed by
restricting the `;` search to the substring after the `@` (or the
whole rest if there is no `@`).
