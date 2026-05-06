//! Allocation-count regression test for `SipMessage::parse`.
//!
//! The in-tree parser at `src/sip/parser/` replaced the `rsip = "0.4"`
//! dependency in the M1–M9 rewrite (HLD: 2026-05-03). One of the
//! advertised wins of that rewrite was a sharp drop in per-INVITE
//! allocations. This test locks in those gains: every fixture has a
//! measured baseline plus a small headroom; if the parser starts
//! allocating beyond that budget, the assertion fires and points at
//! the offending fixture.
//!
//! ## Methodology
//!
//! The `#[global_allocator]` declaration here is **scoped to this
//! test binary only** — each Rust integration test under `tests/`
//! compiles to its own binary, so neither production code nor any
//! sibling test sees `StatsAlloc`.
//!
//! `Region::new` snapshots the allocator counters; the `change()`
//! delta after parsing is what we assert against. Fixtures are
//! pulled in via `include_bytes!` so file I/O is not part of the
//! measurement.
//!
//! ## Why a single `#[test]` for all fixtures
//!
//! `StatsAlloc` counters are process-wide, not thread-local. If each
//! fixture were its own `#[test]`, cargo's default scheduler would
//! run them on multiple threads concurrently, and any sibling
//! thread's allocations would land inside another test's `Region`
//! window and inflate its count. We saw ~40% flakiness with four
//! parallel `#[test]` functions even with a measurement mutex —
//! the mutex serializes the *measurement* but not the *threads*. So
//! the budget assertions live in a single `#[test]` that walks the
//! fixtures sequentially, accumulating per-fixture failures into one
//! diagnostic message.
//!
//! ## What we assert on
//!
//! Only `stats.allocations` (the count). `bytes_allocated` is
//! sensitive to the exact `String`/`Vec` growth path the parser
//! takes and is more brittle in the face of harmless internal
//! tweaks; the count is what we actually care about for "did the
//! parser regress?".
//!
//! ## Modes of operation
//!
//! There are two budget sets per fixture:
//!
//! - `*_BUDGET` — measured under plain `cargo test`.
//! - `*_BUDGET_UNDER_COVERAGE` — measured under `cargo llvm-cov`,
//!   which is how stage 7 of `tools/full_test` runs us.
//!
//! At runtime, `invite_allocation_budgets` picks one of the two by
//! checking `LLVM_PROFILE_FILE`. Both sets are real assertions —
//! there is no skip path. The earlier (now-removed) skip silently
//! disabled this oracle in the test-bar pipeline; see the HLD
//! `wrk_docs/2026.05.06 - HLD - alloc budget under coverage.md` for
//! why we chose runtime detection over `cfg(coverage)`.
//!
//! ## Refreshing the budgets
//!
//! Both budgets must be refreshed together when the parser is
//! intentionally re-tuned. Run **both** of these and update **both**
//! constant families:
//!
//! ```text
//! # No-coverage baseline (updates *_BUDGET):
//! cargo test -p rsiprtp --test allocations_sip_parse \
//!     -- --ignored --nocapture discover_baselines
//!
//! # Under-coverage baseline (updates *_BUDGET_UNDER_COVERAGE).
//! # `--no-cfg-coverage` mirrors stage 7 of the test bar at
//! # `tools/full_test/src/main.rs` — measure the *exact* config
//! # that runs in CI, not a slightly different llvm-cov mode:
//! cargo llvm-cov test -p rsiprtp --test allocations_sip_parse \
//!     --no-cfg-coverage -- --ignored --nocapture discover_baselines
//! ```
//!
//! For each fixture, apply
//! `max(measured + 4 + spread, ceil(measured * 1.15))` to set the
//! budget. On Windows MSVC + cargo-llvm-cov 0.8.5 today, the two
//! budgets coincide because the coverage runtime emits static
//! counters that don't allocate; on a future toolchain the
//! under-coverage value may shift (HLD §6 R1). If the under-coverage
//! ratio diverges sharply (more than ~5x the no-coverage value),
//! suspect a coverage-tool change rather than a parser regression.
//!
//! A maintainer who refreshes only one of the two will get a sharp
//! failure on the next test bar run — the failure message names the
//! out-of-budget constant, which makes "you forgot to refresh the
//! other one" the obvious diagnosis.
//!
//! ## Known limitation: stale `LLVM_PROFILE_FILE`
//!
//! A developer with a stale `LLVM_PROFILE_FILE` exported in their
//! shell (e.g. left over from a prior `cargo llvm-cov` run) will
//! select the under-coverage budget under plain `cargo test`. The
//! oracle still fires — it's just slightly looser than intended in
//! that one shell session. We accept this rather than add
//! belt-and-braces secondary detection (HLD §1).

use rsiprtp::sip::SipMessage;
use stats_alloc::{Region, Stats, StatsAlloc, INSTRUMENTED_SYSTEM};
use std::alloc::System;
use std::sync::Mutex;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Belt-and-braces serialization of the measurement window. The
/// budget assertions all live in one `#[test]` (so cargo cannot
/// schedule them in parallel), but `discover_baselines` runs as a
/// separate `#[ignore]`d test and could be invoked alongside the
/// budget test via `--include-ignored`. The lock keeps that path
/// honest as well.
static MEASURE_LOCK: Mutex<()> = Mutex::new(());

/// Parse `bytes` once inside an instrumented region and return the
/// allocator delta. We assert on `Stats::allocations`, which is a
/// monotonic counter — dropping `parsed` before sampling does not
/// change that number. The explicit drop is kept for symmetry so any
/// future assertion on net memory (`bytes_allocated`) measures a
/// fully-released parse, not a parse plus retained owned strings.
fn count_parse_allocs(bytes: &[u8]) -> Stats {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let region = Region::new(GLOBAL);
    let parsed = SipMessage::parse(bytes).expect("fixture must parse");
    drop(parsed);
    region.change()
}

const FIXTURE_INVITE_WITH_VIA: &[u8] = include_bytes!("fixtures/mdsiprtp3/invite_with_via.sip");
const FIXTURE_INVITE_WITH_BODY: &[u8] = include_bytes!("fixtures/mdsiprtp3/invite_with_body.sip");
const FIXTURE_INVITE_COMPACT_VIA: &[u8] =
    include_bytes!("fixtures/handcrafted/invite_compact_via.sip");
// RFC 4475 §3.1.1.1 "longreq" — long URI, long display names, long tag and
// branch parameters. Stress-tests the parser's behavior on outsized header
// values; a regression here typically means the parser started allocating
// proportionally to header-value length (e.g. extra `String::from` per
// quoted-string segment). Worth its own budget for that reason.
const FIXTURE_INVITE_LONGREQ: &[u8] = include_bytes!("fixtures/rfc4475/longreq.sip");

// ---------------------------------------------------------------
// Budget constants. Two parallel sets per fixture:
//
//   *_BUDGET                  — measured under plain `cargo test`.
//   *_BUDGET_UNDER_COVERAGE   — measured under `cargo llvm-cov`,
//                               which is how stage 7 of the test bar
//                               (`tools/full_test`) runs us.
//
// The two-tier scheme exists because coverage instrumentation may
// inject heap activity for `__llvm_profile_*` counters on covered
// branches; the count is platform-dependent (effectively zero
// inflation on Windows MSVC + cargo-llvm-cov 0.8.5 today, but other
// toolchains may differ). Asserting only the `cargo test` budget
// would silently disable the oracle under stage 7; asserting only
// the loosest of the two would let no-coverage regressions slip.
// Mode is picked at the call site via `under_coverage_instrumentation()`.
//
// Formula for both: max(measured + 4 + spread, ceil(measured * 1.15)),
// where `spread = max - min` over N=5 consecutive measurement runs.
// The +4 floor keeps tiny fixtures from asserting on a literally-zero
// headroom; the 1.15x multiplier allows for harmless refactors (e.g.
// one extra `String::from` for a header parameter); `spread` absorbs
// run-to-run measurement noise.
// ---------------------------------------------------------------

/// Measured 2026-05-06: 42 allocations. Budget 49 = ceil(42 * 1.15).
const TYPICAL_INVITE_ALLOC_BUDGET: usize = 49;

/// Measured 2026-05-06 under coverage (median of N=5, spread=0):
/// 42 allocations. Budget 49 = ceil(42 * 1.15).
/// (Today coincides with the no-coverage budget — Windows MSVC +
/// cargo-llvm-cov 0.8.5 emits static counters that don't allocate.
/// Kept as a separate constant so the contract survives a toolchain
/// bump that changes that assumption.)
const TYPICAL_INVITE_ALLOC_BUDGET_UNDER_COVERAGE: usize = 49;

/// Measured 2026-05-06: 13 allocations. Budget 17 = 13 + 4 (the +4
/// floor — 1.15x would only buy us 2 extra slots, which isn't enough
/// headroom for harmless tweaks on a 4-line fixture).
const BODY_INVITE_ALLOC_BUDGET: usize = 17;

/// Measured 2026-05-06 under coverage (median of N=5, spread=0):
/// 13 allocations. Budget 17 = 13 + 4 (floor; same rationale as
/// the no-coverage budget).
const BODY_INVITE_ALLOC_BUDGET_UNDER_COVERAGE: usize = 17;

/// Measured 2026-05-06: 42 allocations. Budget 49 = ceil(42 * 1.15).
const COMPACT_INVITE_ALLOC_BUDGET: usize = 49;

/// Measured 2026-05-06 under coverage (median of N=5, spread=0):
/// 42 allocations. Budget 49 = ceil(42 * 1.15).
const COMPACT_INVITE_ALLOC_BUDGET_UNDER_COVERAGE: usize = 49;

/// Measured 2026-05-06 (byte-perfect RFC 4475 §A.1): 224 allocations
/// on the canonical "longreq" fixture. Budget 258 = ceil(224 * 1.15).
/// The fixture grew from 1007 → 3515 bytes when Stage A swapped to
/// byte-perfect §A.1 bytes (it now carries a full SDP body plus the
/// long-Via stack), so the previous 47-allocation baseline against
/// the representative form is gone. The real point of this budget
/// isn't its absolute value — it's that parsing the huge-header
/// message stays sub-linear in header-value length.
const LONGREQ_INVITE_ALLOC_BUDGET: usize = 258;

/// Measured 2026-05-06 under coverage (median of N=5, spread=0):
/// 224 allocations. Budget 258 = ceil(224 * 1.15).
const LONGREQ_INVITE_ALLOC_BUDGET_UNDER_COVERAGE: usize = 258;

struct BudgetCase {
    name: &'static str,
    fixture_path: &'static str,
    bytes: &'static [u8],
    budget: usize,
    budget_under_coverage: usize,
    constant_name: &'static str,
    constant_name_under_coverage: &'static str,
}

const BUDGET_CASES: &[BudgetCase] = &[
    BudgetCase {
        name: "invite_with_via.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/mdsiprtp3/invite_with_via.sip",
        bytes: FIXTURE_INVITE_WITH_VIA,
        budget: TYPICAL_INVITE_ALLOC_BUDGET,
        budget_under_coverage: TYPICAL_INVITE_ALLOC_BUDGET_UNDER_COVERAGE,
        constant_name: "TYPICAL_INVITE_ALLOC_BUDGET",
        constant_name_under_coverage: "TYPICAL_INVITE_ALLOC_BUDGET_UNDER_COVERAGE",
    },
    BudgetCase {
        name: "invite_with_body.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/mdsiprtp3/invite_with_body.sip",
        bytes: FIXTURE_INVITE_WITH_BODY,
        budget: BODY_INVITE_ALLOC_BUDGET,
        budget_under_coverage: BODY_INVITE_ALLOC_BUDGET_UNDER_COVERAGE,
        constant_name: "BODY_INVITE_ALLOC_BUDGET",
        constant_name_under_coverage: "BODY_INVITE_ALLOC_BUDGET_UNDER_COVERAGE",
    },
    BudgetCase {
        name: "invite_compact_via.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/handcrafted/invite_compact_via.sip",
        bytes: FIXTURE_INVITE_COMPACT_VIA,
        budget: COMPACT_INVITE_ALLOC_BUDGET,
        budget_under_coverage: COMPACT_INVITE_ALLOC_BUDGET_UNDER_COVERAGE,
        constant_name: "COMPACT_INVITE_ALLOC_BUDGET",
        constant_name_under_coverage: "COMPACT_INVITE_ALLOC_BUDGET_UNDER_COVERAGE",
    },
    BudgetCase {
        name: "rfc4475/longreq.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/rfc4475/longreq.sip",
        bytes: FIXTURE_INVITE_LONGREQ,
        budget: LONGREQ_INVITE_ALLOC_BUDGET,
        budget_under_coverage: LONGREQ_INVITE_ALLOC_BUDGET_UNDER_COVERAGE,
        constant_name: "LONGREQ_INVITE_ALLOC_BUDGET",
        constant_name_under_coverage: "LONGREQ_INVITE_ALLOC_BUDGET_UNDER_COVERAGE",
    },
];

// ---------------------------------------------------------------
// Manual diagnostic — print allocation counts for each fixture.
// Marked `#[ignore]` so it doesn't run by default. Single test
// services both refresh paths; pick the invocation that matches
// the budget set you need to update. See module docstring
// "Refreshing the budgets" for the full recipe.
//
//   # *_BUDGET (no-coverage):
//   cargo test -p rsiprtp --test allocations_sip_parse \
//       -- --ignored --nocapture discover_baselines
//
//   # *_BUDGET_UNDER_COVERAGE (mirrors test-bar stage 7):
//   cargo llvm-cov test -p rsiprtp --test allocations_sip_parse \
//       --no-cfg-coverage -- --ignored --nocapture discover_baselines
// ---------------------------------------------------------------

#[test]
#[ignore]
fn discover_baselines() {
    for case in BUDGET_CASES {
        let stats = count_parse_allocs(case.bytes);
        eprintln!(
            "{:32} allocs={:4}  reallocs={:4}  bytes={:6}",
            case.name, stats.allocations, stats.reallocations, stats.bytes_allocated,
        );
    }
}

/// Returns true when the test process is running under coverage
/// instrumentation. We detect via `LLVM_PROFILE_FILE`, which
/// `cargo-llvm-cov` sets for every test process it spawns.
///
/// HLD `wrk_docs/2026.05.06 - HLD - alloc budget under coverage.md` §1
/// considered alternatives (`#[cfg(coverage)]`, RUSTFLAGS sniffing) and
/// chose this for one decisive reason: our test bar
/// (`tools/full_test/src/main.rs`) invokes `cargo llvm-cov ...
/// --no-cfg-coverage`, which suppresses `cfg(coverage)` in the path
/// that matters most. `LLVM_PROFILE_FILE` is the only signal that's
/// reliably set by our pipeline.
fn under_coverage_instrumentation() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

/// All fixture budgets are checked in a single `#[test]` so cargo
/// cannot schedule them on different threads — see the module-level
/// "Why a single `#[test]`" note. Per-fixture failures are
/// accumulated and reported together so a multi-fixture regression
/// surfaces all the affected budgets in one go, not just the first.
///
/// We pick one of two budget sets per fixture based on whether
/// `LLVM_PROFILE_FILE` is set (i.e. whether we're under coverage).
/// Both sets are real assertions — there is no skip path. See the
/// module docstring's "Refreshing the budgets" section for how to
/// re-baseline either set.
#[test]
fn invite_allocation_budgets() {
    let under_cov = under_coverage_instrumentation();
    eprintln!(
        "invite_allocation_budgets: mode={}",
        if under_cov {
            "under-coverage (asserting *_BUDGET_UNDER_COVERAGE)"
        } else {
            "no-coverage (asserting *_BUDGET)"
        },
    );

    let mut failures: Vec<String> = Vec::new();

    for case in BUDGET_CASES {
        let stats = count_parse_allocs(case.bytes);
        let (budget, constant) = if under_cov {
            (
                case.budget_under_coverage,
                case.constant_name_under_coverage,
            )
        } else {
            (case.budget, case.constant_name)
        };
        if stats.allocations > budget {
            let refresh_cmd = if under_cov {
                "cargo llvm-cov test -p rsiprtp --test allocations_sip_parse \
                 --no-cfg-coverage -- --ignored --nocapture discover_baselines"
            } else {
                "cargo test -p rsiprtp --test allocations_sip_parse -- \
                 --ignored --nocapture discover_baselines"
            };
            failures.push(format!(
                "  {} ({}): SipMessage::parse allocated {} times; budget is {}. \
                 If this regression is intentional, refresh the baseline via \
                 `{}` and update {}.",
                case.name, case.fixture_path, stats.allocations, budget, refresh_cmd, constant,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "SIP INVITE parser allocation budget(s) exceeded:\n{}",
        failures.join("\n"),
    );
}
