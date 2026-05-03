# Security Policy

## Status of this project

`rsiprtp` is shared as a **community base** — a working SIP/RTP stack that
others can fork, vendor, or take pieces from for their own projects. It is
**not a supported product**. There is no SLA, no security team, and no
guarantee that any given report will result in a fix or release on a
particular timeline.

If you are deploying SIP/RTP on a network you care about, please assume you
are taking ownership of the code you ship, including any security issues in
it. The most reliable path to a fix you can rely on is to maintain your own
fork (or vendored copy) and patch in place.

## Reporting a Vulnerability

If you find something, I'd still like to know — both so I can fix it here
and so other people pulling from this repo can pick up the fix.

Please report **privately** via
[GitHub Security Advisories](https://github.com/0x4D44/rsiprtp/security/advisories/new)
rather than opening a public issue.

Helpful things to include:

- A description of the issue and its impact (DoS? RCE? Information disclosure?).
- A reproduction or proof-of-concept (a `.pcap`, a unit test, or a code snippet).
- The affected commit or `rsiprtp` version.
- Any suggested mitigation or fix — patches very welcome.

I'll respond when I can. Best-effort, no promises on timing.

## Scope

If you're reporting an issue, the parts of the workspace most useful to hear
about are:

- The SIP message parser and transport layers (UDP/TCP/TLS).
- Transaction and dialog state machines.
- RTP/RTCP/SRTP and ICE/STUN/TURN.
- The audio codecs shipped here.

Out of scope:

- Upstream dependencies — please report to the dep's maintainer.
- Configuration mistakes (binding to a public IP with no auth, disabling TLS
  verification, etc.).
- The unpublished `gabby` example application.

## Supported Versions

None, in the formal sense. Fixes land on `main`; downstream users are
expected to pull and rebuild.
