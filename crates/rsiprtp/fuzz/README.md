# rsiprtp fuzz targets

[cargo-fuzz] harness for the SIP message parser. This is a separate
workspace so it doesn't pull libFuzzer / sanitizer-instrumented builds
into the main `rsiprtp` workspace.

## Targets

| target              | entry point                   | what it covers                                                                                  |
| ------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------- |
| `sip_message_parse` | `rsiprtp::sip::SipMessage::parse` | full SIP request/response wire parser, plus the typed-header accessors in `sip/{message,headers,uri}.rs` |

The harness round-trips every successful parse via `to_bytes()` and walks
the cheap accessors (`method`, `uri`, `cseq`, `via_branch`, `from_tag`,
`to_tag`, `call_id`, `body`, `content_type`, response status helpers).

## Prerequisites

- Nightly toolchain: `rustup toolchain install nightly`.
- `cargo install cargo-fuzz` (already installed if you see `cargo fuzz`
  in `cargo --list`).
- **Windows MSVC only**: the fuzz binary is built with AddressSanitizer
  by default and dynamically links `clang_rt.asan_dynamic-x86_64.dll`
  from the Visual Studio MSVC toolchain. Add that directory to `PATH`
  before running, e.g.

  ```powershell
  $env:PATH = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64;" + $env:PATH
  ```

  (path varies by VS edition / version — search for `clang_rt.asan_dynamic-x86_64.dll`).

## Build

```bash
cargo +nightly fuzz build sip_message_parse --fuzz-dir crates/rsiprtp/fuzz
```

## Run

Time-limited smoke run (20 seconds):

```bash
cargo +nightly fuzz run sip_message_parse --fuzz-dir crates/rsiprtp/fuzz -- -max_total_time=20
```

Full run with multiple workers and a 1 GiB RSS cap:

```bash
cargo +nightly fuzz run sip_message_parse --fuzz-dir crates/rsiprtp/fuzz -- \
    -workers=4 -jobs=4 -rss_limit_mb=1024
```

Reproduce a finding from `artifacts/sip_message_parse/`:

```bash
cargo +nightly fuzz run sip_message_parse --fuzz-dir crates/rsiprtp/fuzz -- \
    artifacts/sip_message_parse/crash-<hash>
```

Minimize a finding:

```bash
cargo +nightly fuzz tmin sip_message_parse --fuzz-dir crates/rsiprtp/fuzz \
    artifacts/sip_message_parse/crash-<hash>
```

## Corpus

Seed inputs live in `corpus/sip_message_parse/`:

- `invite.txt` — RFC 3261 §24.2 INVITE example.
- `200_ok.txt` — matching 200 OK response.
- `register_auth.txt` — REGISTER carrying a Digest `Authorization` header.

All seeds use CRLF line endings (SIP wire format). The `corpus/` and
`artifacts/` directories are gitignored — libFuzzer grows the corpus in
place during runs.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
