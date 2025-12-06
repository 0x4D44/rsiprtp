# Ralph Wiggum Prompt for mdsiprtp Implementation

## Usage

```bash
/ralph-wiggum:ralph-loop "$(cat RALPH_PROMPT.md)" --max-iterations 50 --completion-promise "ALL PHASE 1 TESTS PASS"
```

---

## TASK: Implement Phase 1 MVP of mdsiprtp SIP/RTP Stack

You are implementing a Rust SIP/RTP stack for voicemail and AI agent applications. The workspace structure already exists at `/home/md/language/mdsiprtp/` with stub crates.

### COMPLETION CRITERIA (ALL must be true to finish)

1. `cargo build` compiles with zero errors and zero warnings
2. `cargo test --workspace` passes ALL tests
3. A basic SIP REGISTER transaction works end-to-end
4. A basic SIP INVITE/200 OK/ACK/BYE call flow works
5. RTP audio can be sent and received with G.711 codec
6. The jitter buffer correctly handles packet reordering

### CURRENT STATE

Check the current state by running:
- `cargo build 2>&1` - see compilation status
- `cargo test --workspace 2>&1` - see test status
- `git status` - see what's been modified
- `git diff --stat` - see scope of changes

### IMPLEMENTATION ORDER (follow strictly)

#### Step 1: mdsiprtp-sip (SIP Message Wrapper)
File: `crates/mdsiprtp-sip/src/message.rs`

Implement:
- `SipMessage` enum wrapping `rsip::SipMessage`
- `SipRequest` wrapper with convenience methods: `method()`, `uri()`, `call_id()`, `from_tag()`, `to_tag()`, `via_branch()`, `cseq()`
- `SipResponse` wrapper with: `status_code()`, `is_provisional()`, `is_success()`, `is_failure()`
- Builder patterns for creating requests/responses
- Unit tests for parsing and building messages

#### Step 2: mdsiprtp-transaction (Sans-IO State Machines)
Files: `crates/mdsiprtp-transaction/src/`

Implement:
- `timer.rs`: Timer structs (T1, T2, T4, TimerA through TimerK) with RFC 3261 defaults
- `client/invite.rs`: INVITE client transaction FSM (Calling → Proceeding → Completed → Terminated)
- `client/non_invite.rs`: Non-INVITE client transaction FSM
- `server/invite.rs`: INVITE server transaction FSM
- `server/non_invite.rs`: Non-INVITE server transaction FSM
- `manager.rs`: TransactionManager that tracks active transactions
- Use typestate pattern for compile-time state enforcement
- Sans-IO design: `handle_input()`, `handle_timeout()`, `poll_transmit()`, `poll_event()`
- Unit tests for ALL state transitions

#### Step 3: mdsiprtp-dialog (Dialog Management)
Files: `crates/mdsiprtp-dialog/src/`

Implement:
- `state.rs`: DialogId (Call-ID + local-tag + remote-tag), DialogState enum
- `invite.rs`: INVITE dialog FSM (Initial → Early → Confirmed → Terminated)
- `manager.rs`: DialogManager tracking active dialogs
- Route set handling from Record-Route headers
- Remote target updates from Contact headers
- Unit tests for dialog lifecycle

#### Step 4: mdsiprtp-transport (UDP Transport)
Files: `crates/mdsiprtp-transport/src/`

Implement:
- `traits.rs`: `Transport` trait with `send()`, `recv()`, `local_addr()`
- `udp.rs`: `UdpTransport` using tokio::net::UdpSocket
- Proper message framing (SIP messages are text, delimited by Content-Length)
- Integration test that sends/receives SIP message over localhost UDP

#### Step 5: mdsiprtp-sdp (SDP Parsing)
Files: `crates/mdsiprtp-sdp/src/`

Implement:
- `parser.rs`: Parse SDP from bytes (v=, o=, s=, c=, t=, m=, a= lines)
- `builder.rs`: Build SDP string from struct
- `SessionDescription` struct with media descriptions
- `MediaDescription` struct with codec info
- `negotiation.rs`: Simple offer/answer (select first matching codec)
- Unit tests for parsing real SDP examples

#### Step 6: mdsiprtp-rtp (RTP Packets)
Files: `crates/mdsiprtp-rtp/src/`

Implement:
- `packet.rs`: RTP header parsing (V, P, X, CC, M, PT, seq, timestamp, SSRC)
- `packet.rs`: RTP packet building
- `session.rs`: RtpSession with SSRC management, sequence numbering, timestamp generation
- Unit tests for packet round-trip

#### Step 7: mdsiprtp-media (G.711 + Jitter Buffer)
Files: `crates/mdsiprtp-media/src/`

Implement:
- `codec/g711.rs`: G.711 μ-law encoder/decoder using audio-codec-algorithms crate
- `codec/mod.rs`: `Codec` trait with `encode()` and `decode()` methods
- `jitter.rs`: Adaptive jitter buffer with:
  - Packet insertion by sequence number
  - Reordering handling
  - Target delay estimation
  - `get_frame()` returning Play/Expand/Conceal decision
- Unit tests for codec roundtrip
- Unit tests for jitter buffer with simulated packet loss/reorder

#### Step 8: mdsiprtp-session (Call Management)
Files: `crates/mdsiprtp-session/src/`

Implement:
- `call.rs`: `Call` struct representing an active call
- `manager.rs`: `CallManager` orchestrating transports, transactions, dialogs, media
- High-level API: `register()`, `invite()`, `answer()`, `hangup()`
- Event emission via channels
- Integration test for REGISTER flow
- Integration test for basic call flow

### CODING STANDARDS

1. **TDD**: Write tests FIRST, then implement to make them pass
2. **No warnings**: Fix all clippy and compiler warnings
3. **Documentation**: Add doc comments to all public items
4. **Error handling**: Use the error types from mdsiprtp-core, no unwrap() in library code
5. **Async**: Use tokio for all async code
6. **Logging**: Use tracing for debug logging

### VALIDATION COMMANDS

After each implementation step, run:
```bash
cargo build --workspace 2>&1
cargo test --workspace 2>&1
cargo clippy --workspace 2>&1
```

Fix any errors before proceeding to the next step.

### REFERENCE MATERIALS

- Plan file: `/home/md/.claude/plans/zazzy-dazzling-deer.md`
- RFC 3261 (SIP): Transaction state machines in Section 17
- RFC 3550 (RTP): Packet format in Section 5
- RFC 4566 (SDP): Session description format

### PROGRESS TRACKING

After completing each step, update the TODO comment at the top of each file from:
```rust
// TODO: Implement X
```
to:
```rust
// DONE: Implemented X
```

### WHEN STUCK

If a test fails repeatedly:
1. Read the error message carefully
2. Add debug tracing to understand the failure
3. Simplify the test case
4. Check if the implementation matches RFC requirements

If compilation fails:
1. Fix one error at a time, starting from the top
2. Check import paths and module structure
3. Ensure workspace dependencies are correct

### SUCCESS OUTPUT

When complete, running `cargo test --workspace` should output something like:
```
running X tests
test result: ok. X passed; 0 failed; 0 ignored
```

And running `cargo build --workspace` should output:
```
Finished `dev` profile [unoptimized + debuginfo] target(s)
```

With ZERO warnings.

---

**START NOW**: Check current state with `cargo build` and `cargo test`, then begin with Step 1.
