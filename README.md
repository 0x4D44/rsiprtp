# rsiprtp

[![Crates.io](https://img.shields.io/crates/v/rsiprtp.svg)](https://crates.io/crates/rsiprtp)
[![docs.rs](https://img.shields.io/docsrs/rsiprtp)](https://docs.rs/rsiprtp)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/rustc-1.75+-orange.svg)](#installation)

> A modular SIP/RTP communications stack for Rust. Built around Sans-IO state
> machines for transactions and dialogs, with batteries-included transports,
> media, and high-level call management for VoIP, telephony, and AI voice
> agents.

## Status

`rsiprtp` is **pre-1.0**. The public API will change between minor releases
until 1.0. It is suitable for prototyping and serious internal use today, but
pin an exact version before depending on it from production code.

## Features

**Signaling**
- SIP message parsing and building (RFC 3261), digest authentication
- Sans-IO transaction state machines (INVITE / non-INVITE, client and server)
- INVITE dialog management
- SDP offer/answer negotiation (RFC 3264) and SDP construction

**Media**
- RTP send/receive with sequence and timestamp handling, RTCP SR/RR
- DTMF (RFC 4733) events
- G.711 (PCMU/PCMA), G.722, and Opus codecs
- Adaptive jitter buffer with playout decisions

**Transport and security**
- UDP, TCP, and TLS transports built on Tokio
- SRTP encryption with SDES key exchange (DTLS-SRTP framing types are
  present, but the DTLS handshake itself is not yet implemented)
- ICE / STUN / TURN modules for NAT traversal (in-progress, not yet wired
  into `CallManager` — see [What's not included](#whats-not-included-yet))

**Architecture**
- Single crate organized into focused modules with a flat `prelude` import
  surface
- Sans-IO core: deterministic, runtime-agnostic, and easy to test

## Quick example

```rust,ignore
use rsiprtp::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = ManagerConfig {
        local_sip_addr: "0.0.0.0".to_string(),
        local_rtp_addr: "0.0.0.0".to_string(),
        rtp_port_range: (10_000, 20_000),
        call_config: CallConfig::default(),
    };
    let mut manager = CallManager::new(config);

    // Place an outbound call. The returned CallId identifies the call in
    // subsequent events emitted by the manager.
    let call_id = manager.create_call("sip:bob@example.com".to_string());
    println!("created call {}", call_id.0);

    // In a real application you would now drive the manager from a SIP
    // transport, pump it through `manager.poll()` style APIs, and react to
    // `ManagerEvent`s. See `crates/rsiprtp/examples/` for end-to-end flows
    // including registration, INVITE, and BYE against a live Asterisk.

    Ok(())
}
```

Worked examples in `crates/rsiprtp/examples/`:

- `basic_call.rs` — REGISTER + INVITE + BYE against an Asterisk server
- `voicemail.rs` — answer a call and record audio
- `ai_bridge.rs` — bridge a SIP call into an external audio pipeline

## Installation

```toml
[dependencies]
rsiprtp = "0.2"
tokio   = { version = "1", features = ["full"] }
```

MSRV: **Rust 1.75**.

## What's not included (yet)

`rsiprtp` focuses on UA-side SIP and RTP. The following are intentionally
out of scope or not yet implemented:

- SIP **REGISTER server** / location service (the client side is supported)
- **SUBSCRIBE / NOTIFY**, presence, dialog event package, BLF
- **MESSAGE** / SIMPLE instant messaging
- **REFER** and call transfer flows
- **SIP over WebSocket** (RFC 7118)
- **MSRP** for messaging
- **PUBLISH** (RFC 3903)
- **B2BUA / proxy / registrar** functionality — this is a UA stack, not a server
- ICE/STUN/TURN integration end-to-end through `CallManager` (the lower-level
  crates exist; high-level glue is still in progress)
- Video codecs and FEC — audio is the current focus

If you need any of these, please open an issue describing the use case before
building on top of `rsiprtp`.

## Architecture

`rsiprtp` is a single crate organized into modules layered from foundations
(`rsiprtp::core`) up through transport, media, transactions, dialogs, and
finally a session layer with `CallManager` and `RegistrationManager`. The
pieces most consumers want are re-exported flat via `rsiprtp::prelude::*`,
but every module is also reachable directly (e.g. `rsiprtp::rtp`,
`rsiprtp::srtp`, `rsiprtp::ice`).

For diagrams of the module graph, the Sans-IO event/action loop, and a
typical INVITE call flow, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Companion: gabby

[`gabby`](crates/gabby) is a Voice AI agent built on top of `rsiprtp`. It
accepts SIP calls and converses using Vosk (speech-to-text), a local Ollama
LLM, and Piper (text-to-speech). It lives in the same workspace as a
demonstration of what `rsiprtp` can do, but it is **not published to
crates.io** because it depends on native libraries (`libvosk`). Treat it as a
worked example rather than part of the public API.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for
the development workflow, lint/test expectations, and PR guidelines, and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating. Security
issues should follow [SECURITY.md](SECURITY.md).
