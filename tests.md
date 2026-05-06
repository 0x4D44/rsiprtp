# rsiprtp test suites

This is a single-page index of every test suite, fuzz target, and quality
gate that ships with the repo. Each entry tells you what it covers, how
to run it, and where the source lives. The standard test bar
(`cargo test --workspace --exclude gabby`) runs everything in the
**Built-in** column below; everything else is opt-in.

## Quick reference

| Suite | Command | Built-in? | Approximate runtime |
|---|---|---|---|
| Unit tests | `cargo test -p rsiprtp --lib` | yes | 2–5 s |
| Doc tests | `cargo test -p rsiprtp --doc` | yes | 5–10 s |
| Integration tests | `cargo test -p rsiprtp --tests` | yes | 15–25 s |
| Property-based tests (proptest) | `cargo test -p rsiprtp --test 'proptest_*'` | yes (via `--tests`) | <1 s |
| Allocation budget regression | `cargo test -p rsiprtp --test allocations_sip_parse` | yes | <1 s |
| Round-trip oracles (static) | `cargo test -p rsiprtp --test parser_roundtrip --test sdp_roundtrip --test builder_roundtrip` | yes | <1 s |
| Differential parser oracle | `cargo test -p rsiprtp --test parser_diff` | yes | <1 s |
| Asterisk integration | `cargo test -p rsiprtp --test asterisk_integration` | no — needs Docker | varies |
| baresip integration | `cargo test -p rsiprtp --test baresip_integration -- --include-ignored --test-threads=1` | no — needs `baresip` binary | minutes |
| Fuzz (libFuzzer) | `cargo +nightly fuzz run <target>` | no — needs nightly + cargo-fuzz | unbounded |
| Overnight fuzz rotation | `pwsh fuzz_overnight.ps1` | no | configurable (default 8 h) |
| Coverage report | `cargo llvm-cov` | no — needs `cargo-llvm-cov` | 60–120 s |
| Full test bar with HTML report | `cargo run --release -p full_test` | no — wraps the above | 3–5 min |

The workspace excludes `gabby` from default builds (it depends on the
Vosk native library); see `crates/gabby/scripts/setup_windows.ps1` and
the project `CLAUDE.md` for how to build it.

---

## 1. Unit tests

In-source `#[test]` and `#[cfg(test)] mod tests { ... }` blocks under
`crates/rsiprtp/src/`. Cover the leaf data structures and Sans-IO state
machines (transactions, dialog FSM, SDP negotiation, RTP framing, codec
adapters, ICE/STUN, SRTP key derivation, etc.).

Run:

```sh
cargo test -p rsiprtp --lib
```

Single test by name:

```sh
cargo test -p rsiprtp --lib transaction::invite_client::tests::test_name
```

## 2. Doc tests

Runnable code examples in `///` rustdoc comments. Used to keep the
public-API examples accurate (and as a tiny smoke test that the code
samples in `README.md`-style docstrings still compile).

```sh
cargo test -p rsiprtp --doc
```

The full test bar (`full_test`) runs `cargo doc --no-deps -D warnings`
as a separate stage to catch broken intra-doc links — that is **not**
the same as `--doc`.

## 3. Integration tests

One Cargo test binary per file under `crates/rsiprtp/tests/`. Each is
self-contained — Cargo gives them their own `target/.../deps/` binary
and a fresh process. Group by purpose:

### 3.1 SIP / call-flow integration

| File | What it exercises |
|---|---|
| `tests/integration_basic_calls.rs` | INVITE / 200 / ACK / BYE end-to-end at the transaction + dialog + transport layers |
| `tests/integration_advanced.rs` | CANCEL, re-INVITE, UPDATE, digest auth, complex dialog scenarios |
| `tests/integration_resilience.rs` | Packet loss, retransmits, transaction timeouts, recovery |
| `tests/stack_to_stack.rs` | Two production stacks talking to each other in-process — no transports mocked |
| `tests/concurrency_safety.rs` | Thread safety of shared session state under concurrent operations |
| `tests/security_input_validation.rs` | Buffer boundaries, integer overflow, NUL/CRLF injection, malformed-input handling |
| `tests/fault_handling.rs` | Network failure + resource-exhaustion error paths |
| `tests/prack.rs` | RFC 3262 PRACK — three transport-less Sans-IO scenarios |
| `tests/session_timers.rs` | RFC 4028 session timers — six Sans-IO scenarios driving `CallManager` |
| `tests/register_auth_e2e.rs` | REGISTER + MD5 digest auth against an in-process mock registrar (no Docker required) |
| `tests/ice_basic.rs` | End-to-end ICE wiring oracle — STUN connectivity checks on loopback, then real socket traffic |

### 3.2 Codec / media bridges

| File | What it exercises |
|---|---|
| `tests/bitrate_bridge_remb.rs` | REMB → `CongestionController` → `BitrateBridge` → `OpusCodec` end-to-end |
| `tests/rtcp_drives_bridge.rs` | Same path but wired through `MediaSession::handle_rtcp` (full call-layer surface) |

### 3.3 Round-trip oracles

These are the load-bearing correctness oracles. Each oracle module
lives in a subdirectory so Cargo's per-`.rs`-binary discovery skips it,
then the same module is reached via `#[path]` from both a static-fixture
driver under `tests/` and a libFuzzer target under `fuzz/`. One
oracle, two drivers — no duplication.

| Driver | Oracle module | Fuzz target |
|---|---|---|
| `tests/parser_roundtrip.rs` | `tests/parser_roundtrip_oracle/mod.rs` | `fuzz/fuzz_targets/sip_message_roundtrip.rs` |
| `tests/sdp_roundtrip.rs` | `tests/sdp_roundtrip_oracle/mod.rs` | `fuzz/fuzz_targets/sdp_session_roundtrip.rs` |
| `tests/parser_diff.rs` | `tests/parser_diff_oracle/mod.rs` | `fuzz/fuzz_targets/sip_message_parse_diff.rs` (planned) |
| `tests/builder_roundtrip.rs` | (inline) | — |

The parser round-trip oracle asserts `Message::parse ∘ Message::to_bytes`
is a fixed point after one normalization pass (compact → long header
names, stale `Content-Length` → real length, fold collapse). The SDP
oracle is the same shape on `SessionDescription::parse ∘ to_string`.
The differential oracle (`parser_diff`) compares the in-tree parser
against `rsip 0.4` (kept as a dev-dep for exactly this purpose) on a
shared corpus, with explicit pinning of every known rsip 0.4 deficiency.
The builder round-trip closes the Tier-2 gap: build typed → serialize
→ parse → read typed → assert agreement.

### 3.4 Property-based tests (proptest) — landed 2026-05-06

Three test files generate **structurally-valid** SIP/SDP inputs and
feed them to the existing round-trip oracles. Complementary to the
libFuzzer targets — proptest exercises the *valid* corner of the
input space that bit-mutation rarely reaches, and shrinks failures to
minimal reproducers.

| File | Properties | Header(s) covered |
|---|---|---|
| `tests/proptest_sip_message.rs` | 1 (256 cases) | Whole-message Tier-1 round-trip |
| `tests/proptest_sip_typed.rs` | 13 (256 cases each) | `SipUri`, `Via`, `From`, `To`, `Contact`, `CSeq` |
| `tests/proptest_sdp_session.rs` | 2 (256 + 64 cases) | `SessionDescription` via `SdpBuilder` |

Soak the properties with more cases:

```sh
RSIPRTP_PROPTEST_CASES=1000000 cargo test --release -p rsiprtp --test proptest_sip_message
```

Per-track soak knobs (each test reads its own env var via the same
helper). Failure persistence files
(`<test>.proptest-regressions`) are written to `tests/` on failure
and are gitignored. Design and findings:

- HLDs: `wrk_docs/2026.05.06 - HLD - proptest *.md`
- Journal: `wrk_journals/2026.05.05 - JRN - proptest property-based tests.md`

### 3.5 Allocation budget regression

`tests/allocations_sip_parse.rs` uses `stats_alloc` as a scoped global
allocator (one test binary, no leakage to production code or sibling
tests) to lock in per-INVITE allocation counts. If the parser's
allocation footprint regresses past a fixture's measured baseline + a
small headroom, the test fails and points at the offending fixture.

### 3.6 Coverage instantiation tests

`tests/coverage_instantiations.rs` exists to ensure generic and
trait-impl code paths the production code can reach are also reached
from tests, so coverage tooling produces a fair number. Pure
maintenance test — never assert a behaviour, only call.

### 3.7 Fixture corpora

| Path | Source | Used by |
|---|---|---|
| `tests/fixtures/handcrafted/` | curated by us | round-trip + diff oracles |
| `tests/fixtures/rfc4475/` | RFC 4475 valid section | round-trip + diff oracles |
| `tests/fixtures/rfc4475_invalid/` | RFC 4475 invalid section | parse-rejection tests |
| `tests/fixtures/mdsiprtp3/` | corpus from the predecessor parser, retained as a regression |  diff oracle |
| `tests/fixtures/sdp/` | SDP fixtures | SDP round-trip oracle + Track C proptest minimal-shape sanity |

## 4. External-dependency integration tests

These are **not** part of the standard test bar; they require infrastructure that CI may or may not have.

### 4.1 Asterisk (Docker)

`tests/asterisk_integration.rs` registers and places calls against a
real Asterisk PBX over UDP/SIP. Bring up the container first:

```sh
docker compose -f docker/docker-compose.yml up -d
cargo test -p rsiprtp --test asterisk_integration
docker compose -f docker/docker-compose.yml down
```

The compose file builds an Asterisk image from `docker/asterisk/` and
exposes `5060/udp`, `5060/tcp`, and a small RTP range. Test users:
`1001/test1001`, `1002/test1002`, etc. (defined in `pjsip.conf`).

CI does not depend on this — the equivalent flow is covered by
`register_auth_e2e.rs` (in-process mock registrar) for the digest-auth
path.

### 4.2 baresip

`tests/baresip_integration.rs` and `tests/baresip_integration/`
exercise our stack against the `baresip` reference SIP UA. Scenarios
are organised by capability: `basic_call.rs`, `call_hold.rs`,
`call_transfer.rs`, `codec_nego.rs`, `dtmf.rs`,
`endpoint_to_endpoint.rs`, `error_recovery.rs`, `media_audio.rs`,
`registration.rs`. Most are gated behind `#[ignore]` because they need
the `baresip` binary on `PATH`.

```sh
# Framework smoke (always runs)
cargo test -p rsiprtp --test baresip_integration -- --test-threads=1

# Full suite (requires baresip)
cargo test -p rsiprtp --test baresip_integration -- --include-ignored --test-threads=1
```

`--test-threads=1` is required: each scenario binds well-known UDP
ports.

### 4.3 Gabby

`crates/gabby/tests/media_branch_coverage.rs` is gabby's own test;
build gabby first (`cargo build -p gabby`, requires `VOSK_LIB_DIR` on
Windows). Not part of the default workspace test run.

## 5. Fuzz tests

The `fuzz/` directory is a standalone cargo-fuzz crate with **29 fuzz
targets** spanning every parser and binary-format codec we own. Build
all targets:

```sh
cargo +nightly fuzz build
```

Run a single target:

```sh
cargo +nightly fuzz run sip_message_roundtrip
```

Categories:

| Category | Targets |
|---|---|
| SIP parsing | `sip_message`, `sip_message_roundtrip`, `sip_uri`, `sip_via`, `sip_via_typed`, `sip_contact`, `sip_name_addr`, `sip_cseq`, `sip_digest` |
| SDP | `sdp_session`, `sdp_session_roundtrip` |
| RTP / RTCP | `rtp_packet`, `rtcp_header`, `rtcp_sr`, `rtcp_rr`, `rtcp_pli`, `rtcp_nack`, `rtcp_remb`, `rtcp_fir`, `rtcp_compound`, `dtmf_event` |
| Audio codecs | `g711_decode`, `g722_decode`, `opus_decode` |
| Media | `jitter_push` |
| ICE | `ice_candidate` |
| SRTP / SRTCP | `srtp_sdes`, `srtp_unprotect`, `srtcp_unprotect` |

Corpus and crash artifacts live under `fuzz/corpus/` and
`fuzz/artifacts/` (both gitignored via `target/`). Per-target seed
corpora are seeded from the integration-test fixtures the first time a
target runs.

### Overnight fuzz rotation

`fuzz_overnight.ps1` drives a round-robin rotation across a configured
target list, with a global wall-clock budget (default 8 h), per-target
slice cap (default 30 min), heartbeat logging, and crash-pause
behaviour (the script blocks on a crash and waits for the supervisor
to touch a `RESUME` sentinel — wall-clock pause time does **not** eat
the budget).

```pwsh
pwsh fuzz_overnight.ps1                              # 8 h default
pwsh fuzz_overnight.ps1 -BudgetSeconds 14400         # 4 h
pwsh fuzz_overnight.ps1 -Targets @('sip_message_roundtrip','sip_via_typed')
```

Logs land under `wrk_journals/fuzz_logs/`; crash triage scratch under
`wrk_journals/fuzz_triage/`. Both are gitignored.

## 6. Quality gates (lint, format, supply chain)

Run as part of the full test bar; can also run individually.

```sh
cargo fmt --check                              # formatting
cargo clippy --workspace -- -D warnings        # lints, warnings as errors
cargo deny check                               # license + advisory + supply-chain
cargo doc --workspace --no-deps                # docs build clean (intra-doc links)
```

`deny.toml` lives at the repo root and is the source of truth for the
supply-chain policy.

## 7. Coverage

Line + region coverage via `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov                   # one-time
cargo llvm-cov                                 # workspace-wide
cargo llvm-cov --html                          # HTML report under target/llvm-cov/html/
cargo llvm-cov --test-threads=1                # if a parallel-test ordering bug is suspected
```

Coverage runs `cargo test --workspace --exclude gabby` under the
hood, so everything in §1–§3 contributes (plus the proptest cases at
their default 256 — bumping `RSIPRTP_PROPTEST_CASES` does not change
which lines get covered, only how many times).

## 8. `full_test` runner

`tools/full_test/` is the one-button "did everything pass?" runner.
It orchestrates seven stages and emits a self-contained HTML report
under `crates/rsiprtp/tests/results/`:

1. `cargo fmt --check`
2. `cargo clippy --workspace -- -D warnings`
3. `cargo deny check`
4. `cargo build --locked --workspace --exclude gabby`
5. `cargo test --workspace --exclude gabby --test-threads=1`
6. `cargo doc --workspace --no-deps`
7. `cargo llvm-cov` (skipped if `cargo-llvm-cov` not installed)

```sh
cargo run --release -p full_test               # all 7 stages
cargo run --release -p full_test -- --help     # see skip flags
cargo run --release -p full_test -- --skip-coverage --skip-supply
```

The HTML report bundles per-suite test lists, durations, failure
output tails, and the coverage summary into a single file you can
open in a browser or attach to a PR.

## 9. Layout summary

```
crates/rsiprtp/
├── src/                                  # production code with #[cfg(test)] mod tests
└── tests/                                # one cargo test binary per .rs file
    ├── parser_roundtrip_oracle/          # shared oracle module (also used by fuzz/)
    ├── parser_diff_oracle/               # shared oracle module (also used by fuzz/)
    ├── sdp_roundtrip_oracle/             # shared oracle module (also used by fuzz/)
    ├── proptest_sip_message.rs           # property test — Track A
    ├── proptest_sip_typed.rs             # property test — Track B
    ├── proptest_sdp_session.rs           # property test — Track C
    ├── allocations_sip_parse.rs          # parser-allocation budget regression
    ├── parser_roundtrip.rs               # static round-trip oracle driver
    ├── parser_diff.rs                    # differential parser oracle driver
    ├── sdp_roundtrip.rs                  # static SDP round-trip oracle driver
    ├── builder_roundtrip.rs              # builder typed round-trip oracle
    ├── integration_*.rs                  # call-flow integration suites
    ├── stack_to_stack.rs, ice_basic.rs, prack.rs, session_timers.rs, register_auth_e2e.rs
    ├── bitrate_bridge_remb.rs, rtcp_drives_bridge.rs
    ├── concurrency_safety.rs, security_input_validation.rs, fault_handling.rs
    ├── coverage_instantiations.rs        # coverage-shaping instantiations
    ├── asterisk_integration.rs           # Docker-required
    ├── baresip_integration.rs + baresip_integration/
    │   ├── framework/                    # baresip harness
    │   ├── scenarios/                    # per-capability scenarios
    │   └── fixtures/                     # baresip-side fixtures
    ├── fixtures/                         # SIP/SDP corpora — see §3.7
    └── results/                          # full_test HTML reports (gitignored)

fuzz/
├── fuzz_targets/                         # 29 libFuzzer targets — see §5
├── corpus/                               # seed corpora (gitignored)
└── artifacts/                            # crash artifacts (gitignored)

tools/full_test/                          # full_test runner — see §8
fuzz_overnight.ps1                        # overnight fuzz rotation — see §5
docker/docker-compose.yml + docker/asterisk/  # Asterisk integration — see §4.1
```

## 10. Adding a test

Pick the right tool for the question you're asking:

| Question | Tool |
|---|---|
| "Does this leaf data structure / function behave correctly?" | unit test (`#[cfg(test)] mod tests` next to the code) |
| "Does this multi-component flow work end-to-end without external deps?" | integration test under `crates/rsiprtp/tests/` |
| "Does this generic invariant hold across the *space* of valid inputs?" | proptest property under `tests/proptest_*.rs` |
| "Does the parser tolerate adversarial bytes without panicking?" | libFuzzer target under `fuzz/fuzz_targets/` |
| "Is this allocation budget regression-protected?" | extend `tests/allocations_sip_parse.rs` |
| "Does my code interoperate with a real SIP UA?" | scenario under `tests/baresip_integration/scenarios/` (or extend `asterisk_integration.rs`) |
| "Does this round-trip property hold on every fixture *and* on fuzzed bytes?" | static driver + oracle module under `tests/<oracle>/`, then add a libFuzzer target that uses the same module via `#[path]` |

When in doubt, look at how an existing test in the same category is
wired up — the patterns are consistent (e.g., every shared oracle
module follows the `parser_roundtrip_oracle/mod.rs` pattern).

## See also

- `CLAUDE.md` — project instructions including build / lint / test commands.
- `ARCHITECTURE.md` — high-level architecture including the Sans-IO model that makes most integration tests transport-less.
- `wrk_docs/` — design docs (HLDs) for every major test infrastructure landing.
- `wrk_journals/` — per-task journals with findings, deviations, and follow-ups.
