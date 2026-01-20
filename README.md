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
    *   **Media Processing**: G.711/G.722 codec support, adaptive jitter buffer, and audio mixing.
    *   **Transport**: UDP, TCP, and TLS support.
    *   **Security**: SRTP encryption, DTLS key exchange, ICE/STUN/TURN for NAT traversal.

*   **Voice AI Agent (`Gabby`)**:
    *   **Offline First**: Runs entirely locally (except for optional external LLM APIs if configured).
    *   **Real-time Interaction**: Low-latency pipeline for STT -> LLM -> TTS.
    *   **Voice Activity Detection (VAD)**: Smart interruption and silence detection.

## Architecture

### Crate Structure

The `mdsiprtp` stack is organized into layered crates with clear responsibilities:

```mermaid
graph TB
    subgraph "Application Layer"
        GABBY[gabby<br/><i>Voice AI Agent</i>]
        APP[Your Application]
    end

    subgraph "Facade"
        MDSIPRTP[mdsiprtp<br/><i>Unified API</i>]
    end

    subgraph "Session Layer"
        SESSION[mdsiprtp-session<br/><i>Call & Registration Management</i>]
        DIALOG[mdsiprtp-dialog<br/><i>INVITE Dialog State</i>]
    end

    subgraph "Transaction Layer"
        TRANSACTION[mdsiprtp-transaction<br/><i>RFC 3261 State Machines</i><br/><b>Sans-IO</b>]
    end

    subgraph "Signaling"
        SIP[mdsiprtp-sip<br/><i>SIP Parsing & Auth</i>]
        SDP[mdsiprtp-sdp<br/><i>SDP Negotiation</i>]
    end

    subgraph "Media Layer"
        RTP[mdsiprtp-rtp<br/><i>RTP/RTCP/DTMF</i>]
        SRTP[mdsiprtp-srtp<br/><i>SRTP & DTLS</i>]
        MEDIA[mdsiprtp-media<br/><i>Codecs & Jitter Buffer</i>]
    end

    subgraph "Network Layer"
        TRANSPORT[mdsiprtp-transport<br/><i>UDP/TCP/TLS</i>]
        ICE[mdsiprtp-ice<br/><i>ICE/STUN/TURN</i>]
    end

    subgraph "Foundation"
        CORE[mdsiprtp-core<br/><i>Types & Errors</i>]
    end

    GABBY --> MDSIPRTP
    APP --> MDSIPRTP
    MDSIPRTP --> SESSION
    MDSIPRTP --> MEDIA
    MDSIPRTP --> RTP
    SESSION --> DIALOG
    SESSION --> TRANSACTION
    SESSION --> SDP
    DIALOG --> SIP
    TRANSACTION --> SIP
    RTP --> SRTP
    TRANSPORT --> CORE
    ICE --> CORE
    SIP --> CORE
    MEDIA --> CORE
```

### Sans-IO Pattern

The transaction and dialog layers use the **Sans-IO** pattern. State machines receive events and return actions without performing I/O directly. This makes them deterministic, easily testable, and runtime-agnostic.

```mermaid
sequenceDiagram
    participant App as Application
    participant SM as State Machine<br/>(Sans-IO)
    participant Net as Network

    App->>SM: Event: MessageReceived(INVITE)
    SM-->>App: Action: SendResponse(100 Trying)
    SM-->>App: Action: SetTimer(Timer::T1, 500ms)
    App->>Net: Send 100 Trying
    App->>App: Schedule Timer

    Note over App,Net: Timer fires...

    App->>SM: Event: TimerFired(T1)
    SM-->>App: Action: SendResponse(100 Trying)
    SM-->>App: Action: SetTimer(Timer::T1, 1000ms)
```

### SIP Call Flow

A typical SIP INVITE call establishment:

```mermaid
sequenceDiagram
    participant Caller as Caller (UAC)
    participant Stack as mdsiprtp
    participant Callee as Callee (UAS)

    Caller->>Stack: INVITE (SDP Offer)
    Stack->>Stack: Create Server Transaction
    Stack->>Caller: 100 Trying
    Stack->>Stack: Create Dialog

    Stack->>Callee: Notify: Incoming Call
    Callee->>Stack: Accept Call

    Stack->>Caller: 200 OK (SDP Answer)
    Caller->>Stack: ACK

    Note over Caller,Callee: Media Session Established<br/>RTP Audio Flows

    rect rgb(240, 240, 240)
        Caller->>Stack: RTP Audio
        Stack->>Stack: Decode → Jitter Buffer → Process
        Stack->>Callee: Decoded Audio

        Callee->>Stack: Audio Response
        Stack->>Stack: Encode → Packetize
        Stack->>Caller: RTP Audio
    end

    Callee->>Stack: Hang Up
    Stack->>Caller: BYE
    Caller->>Stack: 200 OK
    Stack->>Stack: Terminate Dialog
```

### Gabby Voice Pipeline

Gabby processes audio through a real-time pipeline:

```mermaid
flowchart LR
    subgraph Input["Incoming Audio"]
        SIP_IN[SIP/RTP]
        DECODE[G.711 Decode]
        RESAMPLE_UP[8kHz → 16kHz]
    end

    subgraph Processing["AI Processing"]
        VAD[Voice Activity<br/>Detection]
        STT[Vosk STT]
        LLM[Ollama LLM]
        TTS[Piper TTS]
    end

    subgraph Output["Outgoing Audio"]
        RESAMPLE_DOWN[22kHz → 8kHz]
        ENCODE[G.711 Encode]
        SIP_OUT[SIP/RTP]
    end

    SIP_IN --> DECODE --> RESAMPLE_UP --> VAD
    VAD --> STT
    STT -->|transcript| LLM
    LLM -->|response| TTS
    TTS --> RESAMPLE_DOWN --> ENCODE --> SIP_OUT

    style VAD fill:#f9f,stroke:#333
    style STT fill:#bbf,stroke:#333
    style LLM fill:#bfb,stroke:#333
    style TTS fill:#fbb,stroke:#333
```

### Component Interactions

How the major components interact during a call:

```mermaid
flowchart TB
    subgraph External["External"]
        PHONE[SIP Phone]
        OLLAMA[Ollama Server]
    end

    subgraph Gabby["Gabby Application"]
        SERVER[SIP Server]
        CALL[Call Handler]
        PIPELINE[Audio Pipeline]
    end

    subgraph mdsiprtp["mdsiprtp Stack"]
        SESS[Session Manager]
        TRANS[Transaction Layer]
        MEDIA_PROC[Media Processor]
        JITTER[Jitter Buffer]
        CODEC[G.711 Codec]
    end

    PHONE <-->|SIP/UDP:5060| SERVER
    PHONE <-->|RTP/UDP:10000+| MEDIA_PROC

    SERVER --> SESS
    SESS --> TRANS
    SESS --> CALL

    CALL --> PIPELINE
    PIPELINE <--> OLLAMA
    PIPELINE --> MEDIA_PROC

    MEDIA_PROC --> JITTER
    JITTER --> CODEC
    CODEC --> PIPELINE
```

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

## Network Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 5060 | UDP/TCP | SIP signaling |
| 10000-20000 | UDP | RTP media streams |

## Contributing

1.  **Tests**: Please ensure all tests pass before submitting changes.
    *   Unit tests: `cargo test`
    *   Linting: `cargo clippy`
    *   Formatting: `cargo fmt`
2.  **Coverage**: We aim for high test coverage.

## License

This project is licensed under the MIT License.
