# handcrafted fixtures

Hand-curated SIP-message fixtures that exercise corners the
`mdsiprtp3/` corpus does not: compact-form headers, folded headers,
multi-`Via`, authentication challenges/responses, and the
REGISTER / ACK / CANCEL methods. These seed the differential-test
harness in `crates/rsiprtp/tests/parser_diff.rs` alongside the
`mdsiprtp3/` fixtures.

Each `.sip` file contains literal CRLF-terminated bytes (no LF-only
endings, no Windows autocrlf surprises — verified at write time).

| File | Description | Source |
|---|---|---|
| `register_with_contact.sip` | REGISTER request with `Contact: <sip:...>;expires=3600` and a `Authorization: Digest username=..., realm=..., ...` line. | RFC 3261 §10 (REGISTER shape) and §22.4 (digest response shape). |
| `invite_compact_via.sip` | INVITE using compact-form headers `v:` (Via), `f:` (From), `t:` (To), `i:` (Call-ID), `l:` (Content-Length). Same logical content as `mdsiprtp3/invite_with_via.sip` but compact-form. | RFC 3261 §20 (compact-form table). |
| `invite_folded_subject.sip` | INVITE with a `Subject:` header value broken across two lines via line folding (continuation begins with SP). | RFC 3261 §7.3.1 (line folding). |
| `response_407_with_proxy_authenticate.sip` | 407 Proxy Authentication Required with `Proxy-Authenticate: Digest realm=..., nonce=..., ...`. | RFC 3261 §22.3 (proxy-to-user authentication challenge). |
| `ack_for_2xx.sip` | ACK request for a 2xx response. Separate transaction from the INVITE (different CSeq method, separate branch). | RFC 3261 §13.2.2.4. |
| `cancel.sip` | CANCEL request matching an in-flight INVITE: same Call-ID and CSeq number as the INVITE, method `CANCEL`. | RFC 3261 §9.1. |
| `response_with_multi_via.sip` | 200 OK carrying two `Via:` headers in wire order (typical proxy-chain reversal: top-most Via was added by the proxy). | RFC 3261 §16.7. |

The harness `assert_equivalent` over each fixture asserts that
`rsip` and our parser produce equivalent `DiffMessage` representations
under the neutralization rules documented at the top of `parser_diff.rs`.
