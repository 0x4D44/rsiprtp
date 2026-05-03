# mdsiprtp3 fixtures

Raw SIP-message bytes extracted from `mdsiprtp3`'s `#[test]` blocks
(at `d:\language\mdsiprtp3\src\`). These seed the differential-test
harness in `crates/rsiprtp/tests/parser_diff.rs`.

mdsiprtp3 has 101 `#[test]` functions, but only the three listed
below contain a complete SIP-message bytes literal (`b"..."`).
Everything else tests sub-parsers (URIs, methods, single header
values) which the framing harness doesn't exercise.

| File | Source | Description |
|---|---|---|
| `invite_with_via.sip` | `mdsiprtp3/src/sip/message.rs:381` | RFC-3261-style INVITE with Via, From (with tag), To, Call-ID, CSeq, Max-Forwards, Content-Length: 0. The canonical request-side smoke test. |
| `response_200_ok.sip` | `mdsiprtp3/src/sip/message.rs:399` | 200 OK response paired with the above INVITE: same headers plus a To-tag. The canonical response-side smoke test. |
| `invite_with_body.sip` | `mdsiprtp3/src/transport/tcp.rs:371` | Minimal INVITE with `Content-Length: 5` and a 5-byte body `HELLO`. Exercises body framing. |

Bytes are exactly what the original `b"..."` literal contains
(trailing-backslash continuations swallow indentation per Rust
string-literal rules), including the trailing CRLF that terminates
the message.
