# M11 — Overnight differential fuzz campaign

Per HLD §M11 ("Overnight fuzz campaign on `sip_message_parse_diff`
≥8h"), the rewrite's exit gate is a clean 8-hour fuzz run with **zero
divergences** between the in-tree `crate::sip::parser` and `rsip` 0.4
under the same neutral `DiffMessage` representation that
`tests/parser_diff.rs` uses today.

This document is the launch checklist. The campaign runs unattended;
findings (if any) get triaged in the morning per the M5 pinning
pattern.

## Prerequisites

- **Nightly Rust toolchain.** `cargo-fuzz` only works on nightly.
  ```bash
  rustup toolchain install nightly
  ```
- **`cargo-fuzz`** ≥ 0.13.
  ```bash
  cargo install cargo-fuzz
  ```
- **Windows MSVC only:** the fuzz binary dynamically links
  `clang_rt.asan_dynamic-x86_64.dll`. Add the MSVC clang_rt directory
  to `PATH` before launch:
  ```powershell
  $env:PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64;" + $env:PATH
  ```
  Adjust the path to match your installed VS edition / MSVC version
  (search for the DLL name to find it).
- **Disk:** the corpus accumulates in
  `crates/rsiprtp/fuzz/corpus/sip_message_parse_diff/`. Allow ~500 MB
  headroom; an 8h run typically produces a few thousand new corpus
  entries.

## Verifying the build before launch

From `crates/rsiprtp`:

```bash
cargo +nightly fuzz build sip_message_parse_diff
```

Should finish with `Finished release profile [optimized + debuginfo]`.
If the build fails, fix it first — do not start an 8h campaign on a
broken target.

## Launch — full 8h campaign

From `crates/rsiprtp`:

```bash
cargo +nightly fuzz run sip_message_parse_diff -- \
  -max_total_time=28800 \
  -workers=4 \
  -jobs=4 \
  -timeout=10 \
  -rss_limit_mb=512
```

Flags explained:

| flag                  | meaning                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------- |
| `-max_total_time=28800` | Run for 8 hours (28800 seconds), then stop cleanly.                                                |
| `-workers=4`          | Spawn 4 worker processes that fuzz in parallel.                                                      |
| `-jobs=4`             | Allow up to 4 concurrent jobs (matches workers).                                                     |
| `-timeout=10`         | Kill any input that takes more than 10 seconds — flags pathological-perf inputs as crashes.          |
| `-rss_limit_mb=512`   | Cap each worker's RSS at 512 MB. A worker exceeding this is treated as a crash.                      |

Tune `-workers` / `-jobs` to match your machine's cores; on a 16-core
box, 8/8 is fine.

## What "success" looks like

After 8 hours the campaign exits with something like:

```
Done 12345678 runs in 28800 second(s)
```

and **no entries** under
`crates/rsiprtp/fuzz/artifacts/sip_message_parse_diff/`. That is the
M11 exit gate per HLD §"Exit criteria" point 4.

## Interpreting findings

Per HLD §M11 expectations:

> with ~22 fixtures the harness has already surfaced 8 rsip 0.4 spec
> deficiencies. M11's overnight fuzz against the same harness should
> anticipate a high volume of rsip-side rejection divergences; the
> operator is triaging and pinning rsip-side bugs per the M5 pattern,
> not chasing our-parser bugs.

Each crash artifact lives at
`crates/rsiprtp/fuzz/artifacts/sip_message_parse_diff/crash-<hash>`.

To reproduce a single finding:

```bash
cargo +nightly fuzz run sip_message_parse_diff -- \
  artifacts/sip_message_parse_diff/crash-<hash>
```

The panic message identifies the divergence kind:

| message                                                  | meaning                                                                                                                                                                                                                                                |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `DIVERGENCE on parse-success`                            | both parsers accepted but produced different `DiffMessage`s. This is the highest-priority bug shape — investigate which parser is wrong against RFC 3261 / RFC 4475.                                                                                  |
| `rsip accepted but ours rejected`                        | `rsip` 0.4 accepted a message we rejected. Triage: if our rejection is RFC-correct, **pin** by adding a fixture to `tests/fixtures/rfc4475/` (or wherever it fits) and asserting `assert!(rs.is_ok())` + `assert!(ours.is_err())` per the M5 pattern. |
| `ours accepted but rsip rejected`                        | Expected to be the bulk of findings. Triage: confirm our acceptance is RFC-correct, then pin per the M5 pattern (asserts `rsip` rejects, our parser accepts). 8 such pins already exist in `tests/parser_diff.rs`.                                    |
| `TYPED-FROM DIVERGENCE` / `TYPED-VIA DIVERGENCE` / etc.   | Tier-1 framing matched but the typed-form parse diverged. Same triage protocol as above, scoped to the typed accessor.                                                                                                                                |

After pinning a divergence, **add the input to the seed corpus** at
`crates/rsiprtp/fuzz/corpus/sip_message_parse_diff/` so future runs
hit it deterministically. libFuzzer will mutate around it and find
adjacent shapes.

After triage, **delete the crash artifact** so the next run starts
clean:

```bash
rm crates/rsiprtp/fuzz/artifacts/sip_message_parse_diff/crash-<hash>
```

## Resuming after a crash

libFuzzer halts the run on the first crash. To resume:

1. Triage the crash (above).
2. Pin it (add a fixture + the asymmetric assertion) so it stops
   firing.
3. Delete the artifact.
4. Re-launch with the same command above. The corpus survives — only
   the artifacts dir held the failed input. Reduce
   `-max_total_time` to the remaining budget if you want to honour
   the 8h ceiling.

## Where artifacts live

| path                                                        | purpose                                                                                                  |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `crates/rsiprtp/fuzz/corpus/sip_message_parse_diff/`        | Mutating corpus. libFuzzer grows this in place. **Gitignored** — does not get committed.                  |
| `crates/rsiprtp/fuzz/artifacts/sip_message_parse_diff/`     | Crash and timeout reproductions. **Gitignored** — triage and delete after pinning.                       |
| `crates/rsiprtp/fuzz/target/`                               | Build artifacts (separate from the main `target/` dir). Safe to `cargo clean` between campaigns.         |

## Post-campaign cleanup

After a clean 8h run:

1. Delete the artifacts dir (should already be empty if run was clean):
   ```bash
   rm -rf crates/rsiprtp/fuzz/artifacts/sip_message_parse_diff/
   ```
2. **Keep** the corpus — it's the seed for any future fuzz work and
   the integration test at `tests/parser_diff.rs::diff_fuzz_corpus`
   reads from it.
3. Update `wrk_docs/journals/` with the run summary and runtime stats.
4. Mark M11 done in the parser-rewrite tracker.

## Reference

- HLD: [`wrk_docs/2026.05.03 - HLD - sip-parser-rewrite.md`](../../../wrk_docs/2026.05.03%20-%20HLD%20-%20sip-parser-rewrite.md)
- Oracle module: [`tests/parser_diff_oracle/mod.rs`](../tests/parser_diff_oracle/mod.rs)
- Integration test driver: [`tests/parser_diff.rs`](../tests/parser_diff.rs)
- Existing pinned divergences (8 as of M6): see the `*_rsip_rejects` /
  `*_rsip_keeps_*` test names in `tests/parser_diff.rs`.
