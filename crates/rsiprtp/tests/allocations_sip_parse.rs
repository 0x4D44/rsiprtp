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
//! ## Refreshing the budget
//!
//! When the parser is intentionally re-tuned and the budget needs
//! updating, run:
//!
//! ```text
//! cargo test -p rsiprtp --test allocations_sip_parse \
//!     -- --ignored --nocapture discover_baselines
//! ```
//!
//! and update the `*_BUDGET` constants below.

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
// Budget constants. Formula: max(measured + 4, ceil(measured * 1.15)),
// capped at measured * 1.5. The +4 floor keeps tiny fixtures from
// asserting on a literally-zero headroom; the 1.15x multiplier
// allows for harmless refactors (e.g. one extra `String::from`
// for a header parameter); the 1.5x cap keeps regressions from
// hiding behind a generous budget.
// ---------------------------------------------------------------

/// Measured 2026-05-06: 42 allocations. Budget 49 = ceil(42 * 1.15).
const TYPICAL_INVITE_ALLOC_BUDGET: usize = 49;

/// Measured 2026-05-06: 13 allocations. Budget 17 = 13 + 4 (the +4
/// floor — 1.15x would only buy us 2 extra slots, which isn't enough
/// headroom for harmless tweaks on a 4-line fixture).
const BODY_INVITE_ALLOC_BUDGET: usize = 17;

/// Measured 2026-05-06: 42 allocations. Budget 49 = ceil(42 * 1.15).
const COMPACT_INVITE_ALLOC_BUDGET: usize = 49;

/// Measured 2026-05-06 (byte-perfect RFC 4475 §A.1): 224 allocations
/// on the canonical "longreq" fixture. Budget 258 = ceil(224 * 1.15).
/// The fixture grew from 1007 → 3515 bytes when Stage A swapped to
/// byte-perfect §A.1 bytes (it now carries a full SDP body plus the
/// long-Via stack), so the previous 47-allocation baseline against
/// the representative form is gone. The real point of this budget
/// isn't its absolute value — it's that parsing the huge-header
/// message stays sub-linear in header-value length.
const LONGREQ_INVITE_ALLOC_BUDGET: usize = 258;

struct BudgetCase {
    name: &'static str,
    fixture_path: &'static str,
    bytes: &'static [u8],
    budget: usize,
    constant_name: &'static str,
}

const BUDGET_CASES: &[BudgetCase] = &[
    BudgetCase {
        name: "invite_with_via.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/mdsiprtp3/invite_with_via.sip",
        bytes: FIXTURE_INVITE_WITH_VIA,
        budget: TYPICAL_INVITE_ALLOC_BUDGET,
        constant_name: "TYPICAL_INVITE_ALLOC_BUDGET",
    },
    BudgetCase {
        name: "invite_with_body.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/mdsiprtp3/invite_with_body.sip",
        bytes: FIXTURE_INVITE_WITH_BODY,
        budget: BODY_INVITE_ALLOC_BUDGET,
        constant_name: "BODY_INVITE_ALLOC_BUDGET",
    },
    BudgetCase {
        name: "invite_compact_via.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/handcrafted/invite_compact_via.sip",
        bytes: FIXTURE_INVITE_COMPACT_VIA,
        budget: COMPACT_INVITE_ALLOC_BUDGET,
        constant_name: "COMPACT_INVITE_ALLOC_BUDGET",
    },
    BudgetCase {
        name: "rfc4475/longreq.sip",
        fixture_path: "crates/rsiprtp/tests/fixtures/rfc4475/longreq.sip",
        bytes: FIXTURE_INVITE_LONGREQ,
        budget: LONGREQ_INVITE_ALLOC_BUDGET,
        constant_name: "LONGREQ_INVITE_ALLOC_BUDGET",
    },
];

// ---------------------------------------------------------------
// Manual diagnostic — print allocation counts for each fixture.
// Marked `#[ignore]` so it doesn't run by default. Use to refresh
// the budget constants when the parser is intentionally re-tuned:
//   cargo test -p rsiprtp --test allocations_sip_parse \
//       -- --ignored --nocapture discover_baselines
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

/// All fixture budgets are checked in a single `#[test]` so cargo
/// cannot schedule them on different threads — see the module-level
/// "Why a single `#[test]`" note. Per-fixture failures are
/// accumulated and reported together so a multi-fixture regression
/// surfaces all the affected budgets in one go, not just the first.
#[test]
fn invite_allocation_budgets() {
    // Skip under `cargo llvm-cov`: coverage instrumentation injects heap
    // activity for `__llvm_profile_*` counters on every covered branch,
    // which inflates allocation counts ~5x and busts these tight budgets
    // without indicating a real parser regression. `LLVM_PROFILE_FILE` is
    // set by cargo-llvm-cov for every test process it spawns.
    if std::env::var_os("LLVM_PROFILE_FILE").is_some() {
        eprintln!("skipping allocation budget test under llvm-cov instrumentation");
        return;
    }

    let mut failures: Vec<String> = Vec::new();

    for case in BUDGET_CASES {
        let stats = count_parse_allocs(case.bytes);
        if stats.allocations > case.budget {
            failures.push(format!(
                "  {} ({}): SipMessage::parse allocated {} times; budget is {}. \
                 If this regression is intentional, refresh the baseline via \
                 `cargo test -p rsiprtp --test allocations_sip_parse -- \
                 --ignored --nocapture discover_baselines` and update {}.",
                case.name, case.fixture_path, stats.allocations, case.budget, case.constant_name,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "SIP INVITE parser allocation budget(s) exceeded:\n{}",
        failures.join("\n"),
    );
}
