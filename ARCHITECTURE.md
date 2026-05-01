# rsiprtp Architecture

This document is for contributors and curious users who want to understand how
`rsiprtp` is put together. If you just want to use the library, the top-level
[README](README.md) and the [API docs on docs.rs](https://docs.rs/rsiprtp) are
the better starting point.

The stack is organized as a single crate with layered internal modules.
Lower layers are pure data and state machines; higher layers add I/O,
scheduling, and convenience. Common types are re-exported flat through
`rsiprtp::prelude` for convenience, but every module is also reachable
directly (e.g. `rsiprtp::rtp`, `rsiprtp::srtp`, `rsiprtp::ice`).

## Module layering

```mermaid
graph TB
    subgraph "Application Layer"
        GABBY[gabby<br/><i>Voice AI Agent</i>]
        APP[Your Application]
    end

    subgraph "Crate"
        CRATE[rsiprtp<br/><i>Single published crate</i>]
    end

    subgraph "Session Layer"
        SESSION[rsiprtp::session<br/><i>Call & Registration Management</i>]
        DIALOG[rsiprtp::dialog<br/><i>INVITE Dialog State</i>]
    end

    subgraph "Transaction Layer"
        TRANSACTION[rsiprtp::transaction<br/><i>RFC 3261 State Machines</i><br/><b>Sans-IO</b>]
    end

    subgraph "Signaling"
        SIP[rsiprtp::sip<br/><i>SIP Parsing & Auth</i>]
        SDP[rsiprtp::sdp<br/><i>SDP Negotiation</i>]
    end

    subgraph "Media Layer"
        RTP[rsiprtp::rtp<br/><i>RTP/RTCP/DTMF</i>]
        SRTP[rsiprtp::srtp<br/><i>SRTP & DTLS framing</i>]
        MEDIA[rsiprtp::media<br/><i>Codecs & Jitter Buffer</i>]
    end

    subgraph "Network Layer"
        TRANSPORT[rsiprtp::transport<br/><i>UDP/TCP/TLS</i>]
        ICE[rsiprtp::ice<br/><i>ICE/STUN/TURN</i>]
    end

    subgraph "Foundation"
        CORE[rsiprtp::core<br/><i>Types & Errors</i>]
    end

    GABBY --> CRATE
    APP --> CRATE
    CRATE --> SESSION
    CRATE --> MEDIA
    CRATE --> RTP
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

Responsibilities by module:

- **`rsiprtp::core`** — shared types, error enum, configuration. The
  foundation other modules build on.
- **`rsiprtp::sip`** — SIP message parsing and building (wraps the `rsip`
  crate), digest authentication helpers, header generators (`Call-ID`, `tag`,
  `branch`).
- **`rsiprtp::transaction`** — RFC 3261 transaction state machines: INVITE
  client, INVITE server, non-INVITE client, non-INVITE server. **Sans-IO**:
  no sockets, no timers, no async runtime — just `Event` in, `Action` out.
- **`rsiprtp::dialog`** — INVITE dialog state, `DialogId`, route-set tracking.
- **`rsiprtp::sdp`** — SDP grammar (RFC 4566), offer/answer negotiation
  (RFC 3264), an SDP builder for outbound offers/answers.
- **`rsiprtp::transport`** — UDP, TCP, and TLS transports on top of Tokio,
  plus DNS resolution.
- **`rsiprtp::rtp`** — RTP packet encoding/decoding, RTCP sender and receiver
  reports, RFC 4733 DTMF events, an `RtpSession` that owns sequence and
  timestamp state.
- **`rsiprtp::srtp`** — SRTP encryption/decryption with SDES key exchange,
  plus DTLS-SRTP framing types (the DTLS handshake itself is not yet
  implemented).
- **`rsiprtp::ice`** — ICE, STUN, and TURN building blocks. Reachable as a
  module today; not yet integrated into the high-level call flow.
- **`rsiprtp::media`** — audio codecs (G.711, G.722, Opus), an adaptive
  jitter buffer, and helpers for resampling/mixing.
- **`rsiprtp::session`** — high-level `CallManager` and `RegistrationManager`
  that compose the layers below into something usable.

## The Sans-IO pattern

The transaction and dialog layers do not perform I/O. They are deterministic
state machines: feed them events, get back actions. The caller is responsible
for executing those actions (sending bytes on a socket, scheduling a timer,
delivering messages to higher layers).

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

Why this matters:

- **Determinism.** A given input sequence produces the same output sequence
  every time. Bug reproductions are trivial: replay the event log.
- **Testability.** Unit tests don't need sockets, timers, or async. They feed
  events, assert on actions, and run in microseconds.
- **Runtime independence.** The state machines compile and run anywhere. The
  `rsiprtp::session` layer happens to use Tokio, but that's a choice made
  above the Sans-IO core, not baked in.
- **Composability.** The same transaction module can drive a UDP UA, a TCP
  proxy, or an in-memory simulator.

## SIP call establishment

A typical UA-to-UA INVITE flow as orchestrated by `CallManager`:

```mermaid
sequenceDiagram
    participant Caller as Caller (UAC)
    participant Stack as rsiprtp
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

## Companion: gabby

[`crates/gabby`](crates/gabby) is a Voice AI agent that uses `rsiprtp` as its
SIP/RTP stack. It is not part of the published library — it depends on native
libraries (Vosk) that don't fit a `cargo install` workflow — but it is a
useful end-to-end demonstration of how the pieces fit together.

### Voice pipeline

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

### Component interactions during a call

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

    subgraph rsiprtp["rsiprtp Stack"]
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

The voice pipeline lives entirely in `gabby`. From `rsiprtp`'s point of view,
gabby is just another consumer: it asks the session layer for incoming RTP
frames, hands back outgoing RTP frames, and handles signaling events.

## Network ports (gabby defaults)

| Port          | Protocol | Purpose            |
|---------------|----------|--------------------|
| 5060          | UDP/TCP  | SIP signaling      |
| 10000-20000   | UDP      | RTP media streams  |

These are gabby's defaults. The `rsiprtp` library itself does not bind any
ports until you configure a `ManagerConfig` and start a transport.

## Further reading

- [README.md](README.md) — public-facing overview and quick start
- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow
- [docs.rs/rsiprtp](https://docs.rs/rsiprtp) — generated API documentation
- `crates/rsiprtp/src/<module>/mod.rs` — each module has a module-level doc
  comment describing its scope and types
