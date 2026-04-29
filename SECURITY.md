# Security Policy

## Reporting a Vulnerability

`rsiprtp` is a SIP/RTP stack — bugs here can have real network-security
consequences. Please report vulnerabilities **privately** via
[GitHub Security Advisories](https://github.com/0x4D44/rsiprtp/security/advisories/new)
rather than opening a public issue.

Include in your report, where possible:

- A description of the issue and its impact (DoS? RCE? Information disclosure?).
- A reproduction or proof-of-concept (a `.pcap`, a unit test, or a code snippet).
- The affected `rsiprtp` version and Rust toolchain.
- Any suggested mitigation or fix.

I'll acknowledge receipt within 7 days and aim to give a status update within
30 days. Once a fix is ready we'll coordinate disclosure (CVE assignment if
appropriate, advisory publication, and a patched release).

## Scope

Covered:

- The published `rsiprtp` crate and its internal `rsiprtp-*` workspace
  members.
- The SIP message parser, transport layers (UDP/TCP/TLS), transaction and
  dialog state machines, RTP/RTCP/SRTP, ICE/STUN/TURN, and audio codecs
  shipped under this workspace.

Out of scope:

- Vulnerabilities in upstream dependencies (please report to the dep's maintainer
  and we'll bump once a fix lands).
- Configuration mistakes by users — e.g., binding the SIP listener to a public
  IP with no authentication, disabling TLS verification, etc.
- The unpublished `gabby` example application (it bundles Vosk/Ollama/Piper
  and isn't a supported library surface).

## Supported Versions

Pre-1.0: only the latest 0.x release receives security fixes. Once 1.0 ships,
this section will be updated with a real support window.
