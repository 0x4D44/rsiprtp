# mdsiprtp & Gabby

**A modular, production-ready SIP/RTP stack for Rust, featuring a Voice AI agent.**

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)

## Project Overview

This repository hosts a comprehensive SIP/RTP communications stack written in Rust, along with a reference implementation of a Voice AI agent.

### Key Components

1.  **mdsiprtp**: The core library. A layered, modular stack designed for building high-performance VoIP applications like voicemail systems, call bridges, and AI assistants. It features a **Sans-IO** architecture for core state machines, making it deterministic and easy to test.
2.  **Gabby** (`crates/gabby`): A standalone Voice AI agent application. It accepts SIP calls and engages in natural conversation using offline Speech-to-Text (Vosk), local LLM inference (Ollama), and Neural Text-to-Speech (Piper).

## Features

*   **SIP/RTP Stack (`mdsiprtp`)**:
    *   **Modular Design**: Split into crates for SIP parsing, transactions, dialogs, SDP, RTP, and media handling.
    *   **Sans-IO Architecture**: Core logic is decoupled from network I/O, allowing for flexible integration with any async runtime (Tokio used by default).
    *   **RFC Compliance**: Implements RFC 3261 (SIP), RFC 3550 (RTP), RFC 4566 (SDP), and related standards.
    *   **Media Processing**: G.711 codec support, adaptive jitter buffer, and audio mixing.
    *   **Transport**: UDP, TCP, and TLS support.

*   **Voice AI Agent (`Gabby`)**:
    *   **Offline First**: Runs entirely locally (except for optional external LLM APIs if configured).
    *   **Real-time Interaction**: Low-latency pipeline for STT -> LLM -> TTS.
    *   **Voice Activity Detection (VAD)**: Smart interruption and silence detection.

## Getting Started

### Prerequisites

*   **Rust**: Version 1.70 or later.
*   **Docker**: Required for running integration tests (Asterisk container).
*   **Gabby Requirements**: Linux (x86_64/aarch64) is recommended for `libvosk` compatibility. 4GB+ RAM for local LLM inference.

### Building the Project

```bash
cargo build --workspace
```

On Windows, you can either build the library without `gabby`, or install the Vosk Windows binaries and set `VOSK_LIB_DIR` to build `gabby` (see `crates/gabby/README.md`):

```bash
cargo build -p mdsiprtp
# or: cargo build --workspace --exclude gabby

# With Vosk installed on Windows:
# cargo build -p gabby
```

### Running Gabby (Voice AI Agent)

1.  **Install Dependencies**:
    Gabby requires model files for speech recognition and synthesis. Use the provided setup script:
    ```bash
    cd crates/gabby
    ./scripts/setup.sh
    ```

2.  **Start Ollama**:
    Gabby uses Ollama for the LLM backend. Start it in a separate terminal:
    ```bash
    ollama serve
    # Ensure the default model is available
    ollama pull llama3.2:3b
    ```

3.  **Run the Agent**:
    ```bash
    cargo run --release -p gabby
    ```
    Gabby will listen on `0.0.0.0:5060` (SIP) and `10000-20000` (RTP). You can call it using a softphone (e.g., Linphone) at `sip:gabby@<your-ip>:5060`.

### Integration Testing

The project includes an integration test suite that runs against a real Asterisk server.

```bash
# 1. Start the Asterisk infrastructure
docker compose -f docker/docker-compose.yml up -d

# 2. Run integration tests
cargo test --test integration_*
```

## Architecture

The `mdsiprtp` stack is organized into the following crates:

*   `mdsiprtp-core`: Common types, errors, and configuration.
*   `mdsiprtp-sip`: SIP message parsing and building (wraps `rsip`).
*   `mdsiprtp-transaction`: RFC 3261 transaction state machines (Sans-IO).
*   `mdsiprtp-dialog`: INVITE dialog management.
*   `mdsiprtp-transport`: Network transport (UDP/TCP/TLS) and DNS resolution.
*   `mdsiprtp-sdp`: SDP parsing and negotiation.
*   `mdsiprtp-rtp`: RTP packet handling and RTCP generation.
*   `mdsiprtp-media`: Audio codecs, jitter buffer, and mixing.
*   `mdsiprtp-session`: High-level call session management.

## Contributing

1.  **Tests**: Please ensure all tests pass before submitting changes.
    *   Unit tests: `cargo test`
    *   Linting: `cargo clippy`
    *   Formatting: `cargo fmt`
2.  **Coverage**: We aim for high test coverage. 

## License

This project is licensed under the MIT License.
