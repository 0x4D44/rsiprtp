# Contributing to rsiprtp

Thanks for your interest in contributing! `rsiprtp` is a single-maintainer
project, so review bandwidth is limited — but pull requests, issues, and RFC
discussions are all welcome.

## Quick start

```bash
git clone https://github.com/0x4D44/rsiprtp
cd rsiprtp
cargo build                # builds the SIP/RTP stack (gabby is excluded by default)
cargo test --workspace --exclude gabby
```

`gabby` is the example Voice AI agent and requires Vosk/Ollama/Piper. See
`crates/gabby/scripts/` if you want to run it.

## Making changes

1. Fork the repo and branch off `main`.
2. Keep commits atomic — one logical change per commit, imperative subject
   line ("Add foo", not "Added foo").
3. Open a PR against `main`. The PR template covers what's expected.

## Code style

- **Formatting:** `cargo fmt` — CI enforces `cargo fmt --check`.
- **Lints:** `cargo clippy --all-targets -- -D warnings` must pass.
- **Tests:** add or update tests for behavioural changes. Coverage gating is
  enforced in CI.
- **Sans-IO:** core state machines (transactions, dialogs) are pure state
  machines that emit actions. Don't reach for `tokio::spawn` inside them —
  keep I/O at the edges.
- **No `unwrap()` / `expect()` in library code** outside of tests and `lib.rs`
  initialization. Errors propagate via `Result`.

## Testing

- Unit tests live alongside the code they test (`#[cfg(test)] mod tests`).
- Integration tests for the SIP stack against a real UA (baresip) live under
  `crates/rsiprtp/tests/baresip_integration.rs`. They're gated behind
  `--include-ignored` because they need network access and the baresip binary.
- `docker compose -f docker/docker-compose.yml up -d` brings up an Asterisk
  server for end-to-end testing.

## Reviews

Expect a few rounds. If a PR sits without comment for more than two weeks,
ping it.

## Security issues

Don't file public issues for vulnerabilities — see
[SECURITY.md](SECURITY.md) for the private reporting channel.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be kind.
