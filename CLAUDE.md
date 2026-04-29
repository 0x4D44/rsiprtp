# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**rsiprtp** is a production-ready, modular SIP/RTP communications stack in Rust. **Gabby** is a Voice AI agent application built on top of it that accepts SIP calls and converses using Vosk (STT), Ollama (LLM), and Piper (TTS).

## Build Commands

```bash
# Build the SIP/RTP stack (gabby is excluded from default-members because
# it requires the Vosk native library)
cargo build

# Build everything including gabby (requires VOSK_LIB_DIR on Windows)
cargo build --workspace

# Build gabby explicitly on Windows (requires VOSK_LIB_DIR set)
cargo build -p gabby

# Run tests
cargo test --workspace

# Run tests for a specific crate
cargo test -p rsiprtp-transaction

# Run a single test
cargo test -p rsiprtp-transaction test_name

# Linting and formatting
cargo clippy --workspace -- -D warnings
cargo fmt --check

# Code coverage
cargo llvm-cov
```

## Integration Testing

Integration tests use baresip (or Asterisk via Docker):

```bash
# Start Asterisk container
docker compose -f docker/docker-compose.yml up -d

# Run baresip integration tests (framework only)
cargo test --package rsiprtp --test baresip_integration -- --test-threads=1

# Run baresip integration tests including ignored tests
cargo test --package rsiprtp --test baresip_integration -- --include-ignored --test-threads=1
```

## Running Gabby

```bash
# Linux: run setup script first
cd crates/gabby && ./scripts/setup.sh

# Windows: run PowerShell setup
cd crates\gabby && .\scripts\setup_windows.ps1

# Start Ollama in separate terminal
ollama serve
ollama pull llama3.2:3b

# Run gabby
cargo run --release -p gabby
```

Gabby listens on UDP 5060 (SIP) and 10000-20000 (RTP). Call `sip:gabby@<ip>:5060`.

## Architecture

### Sans-IO Pattern

Core state machines (transactions, dialogs) use the **Sans-IO** pattern - they are pure state machines that emit actions to be executed by the caller, rather than performing I/O directly. This makes them deterministic and easy to test.

Example: `rsiprtp-transaction` state machines receive events (timer fired, message received) and return actions (send message, set timer) without touching the network.

### Crate Dependency Layers

```
rsiprtp (facade)
    ├── rsiprtp-session    (high-level call management)
    │       ├── rsiprtp-dialog     (INVITE dialog state)
    │       ├── rsiprtp-transaction (RFC 3261 transactions, Sans-IO)
    │       └── rsiprtp-sdp        (SDP parsing/negotiation)
    ├── rsiprtp-transport  (UDP/TCP/TLS, DNS resolution)
    ├── rsiprtp-rtp        (RTP packets, RTCP, DTMF)
    ├── rsiprtp-srtp       (SRTP encryption, DTLS)
    ├── rsiprtp-ice        (ICE, STUN, TURN)
    ├── rsiprtp-media      (G.711/G.722 codecs, jitter buffer, mixer)
    ├── rsiprtp-sip        (SIP parsing via rsip, auth)
    └── rsiprtp-core       (common types, errors, config)
```

### Gabby Pipeline

```
SIP/RTP → G.711 decode → 8k→16k resample → Vosk STT → Ollama LLM → Piper TTS → resample → G.711 encode → RTP
```

## Key Types

- `CallManager` / `RegistrationManager` (`rsiprtp-session`): High-level session management
- `TransactionManager` (`rsiprtp-transaction`): Routes SIP messages to transactions
- `InviteClientTransaction` / `InviteServerTransaction`: INVITE transaction state machines
- `DialogManager` (`rsiprtp-dialog`): Tracks INVITE dialog state
- `RtpSession` (`rsiprtp-rtp`): RTP send/receive with sequence/timestamp handling
- `JitterBuffer` (`rsiprtp-media`): Adaptive playout buffer

## Windows Notes

Gabby requires Vosk which needs special setup on Windows:
- Run `crates\gabby\scripts\setup_windows.ps1`
- Set `VOSK_LIB_DIR` to the folder containing `libvosk.lib`
- Ensure `vosk.dll` directory is on `PATH`

To build the stack without Gabby on Windows: `cargo build --workspace --exclude gabby`
