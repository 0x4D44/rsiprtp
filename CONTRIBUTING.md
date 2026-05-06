# Contributing

`rsiprtp` is a personal project. It's shared in the hope it's a useful
base — fork it, vendor it, or take pieces from it. The dual MIT /
Apache-2.0 licence is set up to make that frictionless.

I make no commitment to triage issues, review PRs, or respond to bug
reports. If you need any of those, please fork.

## If you do send a PR

Welcome, but not guaranteed any attention. To make one easier to land:

- Atomic commits, imperative subject lines.
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test --workspace --exclude gabby` all clean.
- No `unwrap()` / `expect()` in library code outside of tests.
- Sans-IO core stays Sans-IO — transactions and dialogs are pure state
  machines that emit actions; no `tokio::spawn` inside them.
- Tests for behavioural changes.

For vulnerabilities, see [SECURITY.md](SECURITY.md) — please don't file
public issues.
