# rsiprtp

[![Crates.io](https://img.shields.io/crates/v/rsiprtp.svg)](https://crates.io/crates/rsiprtp)
[![docs.rs](https://img.shields.io/docsrs/rsiprtp)](https://docs.rs/rsiprtp)
[![CI](https://github.com/0x4D44/rsiprtp/actions/workflows/ci.yml/badge.svg)](https://github.com/0x4D44/rsiprtp/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/rustc-1.88+-orange.svg)](#installation)

> An audio-focused SIP user-agent stack for Rust, built around **Sans-IO**
> state machines (pure logic that emits actions instead of doing network I/O)
> for transactions and dialogs, with batteries-included transports, media,
> and high-level call management for VoIP, telephony, and AI voice agents.
>
> Targets traditional SIP / VoIP. **Not a WebRTC stack** — see [Scope](#scope).

## Features

**Signaling**
- SIP message parsing and building (RFC 3261)
- Digest authentication, including SHA-256 (RFC 7616)
- Sans-IO transaction state machines — all four of RFC 3261 §17 (INVITE
  client / server, non-INVITE client / server) with the full timer set
- INVITE dialog management with route sets, early dialogs, and target refresh
- SDP offer/answer negotiation (RFC 3264) and SDP construction
- Call hold / resume via re-INVITE with direction changes (`sendrecv` ↔
  `sendonly` / `inactive`)
- Blind and attended call transfer (REFER, RFC 3515; Replaces, RFC 3891)
- PRACK / 100rel reliable provisional responses (RFC 3262)
- UPDATE method (RFC 3311) for in-dialog refresh
- Session timers (RFC 4028) — both refresher (UPDATE / re-INVITE) and
  non-refresher (BYE on peer silence) paths
- Registration with digest challenge handling and periodic refresh

**Media**
- RTP send/receive with sequence and timestamp handling
- RTCP SR / RR / SDES / BYE / APP, with `rtcp-mux` support (RFC 5761)
- DTMF (RFC 4733) telephone-event
- G.711 (PCMU/PCMA), G.722, and Opus codecs (Opus inband FEC supported)
- Adaptive jitter buffer with reorder, duplicate, and late-arrival detection
- N-way mixer with active-speaker tracking for conference scenarios

**Transport and security**
- UDP, TCP, and TLS transports built on Tokio
- RFC 3263 SIP URI resolution (NAPTR / SRV / A) via [`SipResolver`]
- SRTP encryption with SDES key exchange (RFC 3711 + RFC 4568)
- ICE / STUN / TURN (RFC 8445 / 5389 / 5766), with an `IceSession` helper
  that gathers candidates and runs connectivity checks alongside
  `CallManager`. Host and server-reflexive candidates are supported;
  TURN relay candidates (the `TurnClient` exists in `ice::turn` but is
  not wired into `IceSession`), trickle ICE, ICE restart, IPv6
  dual-stack interop, symmetric-NAT peer-reflexive (prflx) discovery,
  and RFC 7675 consent-freshness keepalives are not yet implemented.

[`SipResolver`]: https://docs.rs/rsiprtp/latest/rsiprtp/transport/struct.SipResolver.html

**Architecture**
- Single crate organized into focused modules with a flat `prelude`
  import surface
- Sans-IO core: deterministic, runtime-agnostic, and easy to test

## Installation

```sh
cargo add rsiprtp
cargo add tokio --features full
```

Or directly in `Cargo.toml`:

```toml
[dependencies]
rsiprtp = "0.3"
tokio   = { version = "1", features = ["full"] }
```

MSRV: **Rust 1.88**.

## Examples

Worked end-to-end programs live in
[`crates/rsiprtp/examples/`](crates/rsiprtp/examples):

- [`basic_call.rs`](crates/rsiprtp/examples/basic_call.rs) — REGISTER + INVITE +
  BYE against a live Asterisk server, including digest auth and RTP media.
- [`voicemail.rs`](crates/rsiprtp/examples/voicemail.rs) — answer an inbound
  call and record the caller's audio to a WAV file.
- [`ai_bridge.rs`](crates/rsiprtp/examples/ai_bridge.rs) — bridge a SIP call
  into an external audio pipeline (the same shape `gabby` uses).
- [`ice_call.rs`](crates/rsiprtp/examples/ice_call.rs) — two `CallManager`s
  on loopback driving an `IceSession` through a full gather / offer /
  answer / connectivity-check / probe flow.
- [`session_timers.rs`](crates/rsiprtp/examples/session_timers.rs) — the
  PRACK / UPDATE / session-timer choreography (RFC 3262 / 3311 / 4028)
  showing how `tick` / `next_deadline` / `drain_outbound_requests`
  thread into a `tokio::select!` event loop.

Run one with environment configuration, for example:

```sh
SIP_SERVER=192.168.1.10 SIP_USER=1001 SIP_PASS=secret SIP_DEST='*43' \
  cargo run --example basic_call
```

A minimal API sketch — the manager is constructed with a `ManagerConfig`
and driven from your transport, emitting `ManagerEvent`s you react to:

```rust,ignore
use rsiprtp::prelude::*;

let config = ManagerConfig {
    local_sip_addr: "0.0.0.0:5060".to_string(), // IP:port
    local_rtp_addr: "0.0.0.0".to_string(),      // IP only
    rtp_port_range: (10_000, 20_000),
    call_config: CallConfig::default(),
};
let mut manager = CallManager::new(config);
let call_id = manager.create_call("sip:bob@example.com".to_string());
// `call_id` identifies the call in subsequent `ManagerEvent`s.
// Pump SIP messages into the manager and react to emitted events from your transport loop.
```

See the examples above for the surrounding transport, event loop, and
SDP/RTP plumbing.

## Architecture

`rsiprtp` is a single crate organized into modules layered from foundations
up through transport, media, transactions, dialogs, and finally a session
layer. The pieces most consumers want are re-exported flat via
`rsiprtp::prelude::*`, but every module is also reachable directly.

```text
Session     │ session, dialog          (CallManager, RegistrationManager, INVITE dialogs)
Transaction │ transaction              (RFC 3261 state machines, Sans-IO)
Signaling   │ sip, sdp                 (message parsing & digest auth; offer/answer)
Media       │ rtp, srtp, media         (RTP/RTCP/DTMF, SRTP-SDES, codecs, jitter buffer)
Network     │ transport, ice           (UDP/TCP/TLS + DNS; ICE/STUN/TURN building blocks)
Foundation  │ core                     (shared types, errors, configuration)
```

For the full module graph, the Sans-IO event/action loop, and a typical
INVITE call flow, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Scope

`rsiprtp` is a **user-agent (UA) stack** focused on placing and answering
audio calls over traditional SIP. The following are deliberately out of
scope or not yet implemented; if you need any of these, please open an
issue first:

- **WebRTC interop.** No DTLS-SRTP. SRTP is reachable via SDES key
  exchange (RFC 4568), which works against SIP carriers but not against browsers.
- **Server roles**: REGISTER server / location service, B2BUA, proxy, registrar.
- **Event packages**: SUBSCRIBE / NOTIFY / PUBLISH carry method-level message
  support only — no event-state machines, presence, BLF, or MWI.
- **MESSAGE / SIMPLE / MSRP** messaging.
- **SIP over WebSocket** (RFC 7118).
- **Video codecs** and FEC (RED / ULPFEC / RTX).

## Status

`rsiprtp` is **pre-1.0**: the public API may change between minor releases
until 1.0. It is suitable for prototyping and serious internal use today —
pin an exact version before depending on it from production code.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Companion: gabby

[`gabby`](crates/gabby) is a Voice AI agent built on top of `rsiprtp`. It
accepts SIP calls and converses using Vosk (speech-to-text), a local Ollama
LLM, and Piper (text-to-speech). It lives in the same workspace as a
demonstration of what `rsiprtp` can do, but it is **not published to
crates.io** because it depends on native libraries (`libvosk`). Treat it as
a worked example rather than part of the public API.

## Acknowledgments

`rsiprtp` is built on excellent work in the Rust ecosystem, including:
[`rsip`](https://crates.io/crates/rsip) for SIP message parsing,
[`tokio`](https://crates.io/crates/tokio) and
[`rustls`](https://crates.io/crates/rustls) for async transport and TLS,
[`hickory-resolver`](https://crates.io/crates/hickory-resolver) for DNS,
[`ropus`](https://crates.io/crates/ropus),
[`ezk-g722`](https://crates.io/crates/ezk-g722), and
[`audio-codec-algorithms`](https://crates.io/crates/audio-codec-algorithms)
for codecs.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
for the development workflow, lint/test expectations, and PR guidelines,
and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before participating.
Security issues should follow [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
