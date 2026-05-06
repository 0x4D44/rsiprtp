All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.4.0] — 2026-05-03

This release is the SIP parser rewrite. The third-party `rsip` 0.4
crate has been dropped from runtime dependencies; an in-tree parser at
`crates/rsiprtp/src/sip/parser/` is now authoritative for SIP message
framing, header recognition, typed-form structures, and URIs. The
`crate::sip` public API was redesigned to remove all `rsip::` type
leakage. A differential-test harness (`tests/parser_diff.rs`) asserts
behavioral parity with rsip 0.4 across a corpus of `mdsiprtp3`
fixtures, hand-curated SIP message shapes, and RFC 4475 torture
tests; eight known rsip 0.4 spec deficiencies are pinned with
regression-firing tests. A nightly fuzz target,
`sip_message_parse_diff`, runs both parsers on each input and panics
on any divergence.

### Added

- **In-tree SIP parser** at `crates/rsiprtp/src/sip/parser/` covering
  request/status-line framing, header folding and recognition, typed
  forms (`From`, `To`, `Via`, `CSeq`, `Contact`), and URI parsing.
  Two-tier model: tier 1 is eager framing into `Header` enum variants
  with raw `String` values; tier 2 is `.typed()`-on-demand parsing of
  complex headers. RFC 3261 ABNF compliance for header values
  (quoted strings, escape sequences, comments).
- **`impl FromStr for Method`** with case-insensitive parsing per RFC
  3261 §7.1, replacing the removed rsip bridge as the canonical way to
  reconstruct a `Method` from a string token. Lossless round-trip for
  all 14 method variants.
- **Differential-test harness** at `crates/rsiprtp/tests/parser_diff.rs`.
  Runs the in-tree parser and rsip 0.4 (dev-dep oracle) against the
  same input bytes and asserts a neutral `DiffMessage` representation
  matches. Corpus: `mdsiprtp3` fixtures, hand-curated golden cases,
  RFC 4475 torture tests, and the existing rsiprtp fuzz corpus. Eight
  known rsip 0.4 spec deficiencies are pinned with `assert!(rs.is_err())`
  regression-firing tests; see
  `crates/rsiprtp/tests/fixtures/rfc4475/README.md` for the running
  list.
- **`sip_message_parse_diff` fuzz target** in the root `fuzz/` crate.
  Runs the in-tree parser and rsip 0.4 against the same input bytes
  and panics on any divergence (parse-success structural mismatch or
  one-accepts-one-rejects). Used for the M11 overnight 8h campaign;
  see `fuzz/README.md` for launch instructions.

### Changed

- **`SipRequest::uri`**, **`from_uri`**, **`to_uri`**, **`contact_uri`**,
  **`from_tag_and_uri`**, and **`SipResponse::contact_uri`** now return
  `SipUri` (owned) instead of `rsip::Uri` (`&rsip::Uri` for `uri`,
  `Result<rsip::Uri>` / `Option<rsip::Uri>` for the others). The
  `Display` impl is identical, so call sites that did `.to_string()` on
  the old return value need no change. Test sites that asserted on
  `rsip::Uri`'s structural fields move to `SipUri`'s accessors.
- **Internal storage of `SipRequest` / `SipResponse` is now the in-tree
  parser type** (`parser::Request` / `parser::Response`). The wrapper
  layer no longer holds rsip types — accessors project from
  parser-native data. The public API contract is preserved.

### Removed

- **`rsip` dropped from runtime dependencies.** `rsip = "0.4"` remains in
  `[dev-dependencies]` indefinitely as the differential-test oracle for
  `tests/parser_diff.rs`. The library builds and runs without rsip;
  downstream consumers no longer pull rsip (or its transitive
  `syn 1` / `digest 0.9` / `sha2 0.9` / `uuid 0.8` chain) into their
  runtime tree.
- **`rsiprtp::sip::RsipUri`** re-export of `rsip::Uri`. The wrapper layer
  no longer leaks rsip types across its public boundary.
- **`SipRequest::inner()`** and **`SipResponse::inner()`** — the
  `&rsip::Request` / `&rsip::Response` escape hatches. They had zero
  callers inside `rsiprtp` and were the last public rsip-typed
  accessors.
- **`Method::to_rsip()`** and the **`impl From<&rsip::Method> for Method`**
  bridge. With the cutover to parser-native storage these no longer
  have any in-tree caller; the previous `method_to_rsip` shim is also
  gone. Callers that previously bridged from rsip to ours via
  `Method::from(&rsip_method)` now round-trip via the canonical
  method-name string with the new `Method::FromStr` impl.

### Security

- **Request-URI validated at framing time.** `parse_request_line` now
  runs the Request-URI through `SipUri::parse` and rejects any URI
  the owned-form decoder cannot accept (e.g. `http://`, malformed
  schemes). Previously the framer accepted any whitespace-bounded
  token, and `SipRequest::uri()` would panic downstream — an
  attacker-controlled DoS on the inbound path. Inputs that survive
  framing are now guaranteed to round-trip through `SipUri::parse`.

## [0.3.0] — 2026-05-02

### Removed

- **DTLS-SRTP stub** (`rsiprtp::srtp::dtls`). The module never contained a DTLS handshake — only fingerprint parsing, role enums, and a use-srtp-extension codec. SRTP key exchange is via SDES only. If DTLS-SRTP support arrives later it will be designed against an actual DTLS crate, not retrofitted onto these types.

## [0.2.0] — 2026-05-01

### Added

- SRTP and ICE/STUN/TURN types are now reachable through the published facade
  as `rsiprtp::srtp` and `rsiprtp::ice`.

### Changed

- **Workspace collapsed into a single publishable crate.** The eleven internal
  `rsiprtp-*` crates (core, sip, transaction, dialog, transport, sdp, rtp,
  srtp, ice, media, session) are now modules of the `rsiprtp` crate. Source
  layout is unchanged for end users — `rsiprtp::sip::…`, `rsiprtp::rtp::…`,
  etc. resolve as before.
- **Minimum supported Rust version is now 1.88** (previously 1.75). Required
  by `ropus 0.12` (typed runtime bitrate API used by the BitrateBridge) and
  the `time 0.3.47` transitive via `ezk-g722`. Downstream consumers upgrading
  from 0.1.x will need a newer toolchain.
- Minor clippy / MSRV idiom cleanups under stable rustc (`is_multiple_of`,
  `Duration::abs_diff`, `collapsible-match`).

### Removed

- **`opus` feature flag** — Opus codec is now built in. `ropus` is pure-Rust
  and was already unconditionally enabled by `rsiprtp-session`; the flag had
  no off-state and is gone.
- **`dtls` feature flag** and the optional `openssl` dependency. The
  DTLS-SRTP framing types remain in `rsiprtp::srtp`; the handshake itself is
  not yet implemented, so there was nothing for `openssl` to gate.
- Unused `crossbeam` and `dasp` dependencies.
- Heavyweight baresip / Asterisk integration test fixtures from the published
  tarball (`package.exclude`). The framework stays in the repository for
  local use.

### Fixed

- `RegistrationManager::needs_refresh` no longer panics on Windows hosts
  within roughly twelve minutes of system boot. The check used unchecked
  `Instant` subtraction; it now uses saturating arithmetic.
- `generate_tag()` no longer produces duplicate tags on macOS under load.
  The previous implementation seeded from `SystemTime`, whose resolution on
  macOS is too coarse to distinguish back-to-back calls; it now draws from
  `rand::thread_rng()`.

[Unreleased]: https://github.com/0x4D44/rsiprtp/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/0x4D44/rsiprtp/releases/tag/v0.4.0
[0.3.0]: https://github.com/0x4D44/rsiprtp/releases/tag/v0.3.0
[0.2.0]: https://github.com/0x4D44/rsiprtp/releases/tag/v0.2.0
