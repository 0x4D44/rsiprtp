#![no_main]

//! Fuzz the SIP message parser entry point.
//!
//! `SipMessage::parse` is the funnel every UDP/TCP/TLS-borne SIP datagram
//! flows through before any session-layer logic runs, so a panic here is a
//! remote DoS primitive. After a successful parse we also exercise the
//! cheap accessors so the fuzzer covers our wrapper code in
//! `crates/rsiprtp/src/sip/{message,headers,uri}.rs`, not just `rsip`'s
//! tokenizer.

use libfuzzer_sys::fuzz_target;
use rsiprtp::sip::SipMessage;

fuzz_target!(|data: &[u8]| {
    let Ok(msg) = SipMessage::parse(data) else {
        return;
    };

    // Round-trip: re-serializing parsed input must not panic.
    let _ = msg.to_bytes();

    match &msg {
        SipMessage::Request(req) => {
            let _ = req.method();
            let _ = req.uri();
            let _ = req.call_id();
            let _ = req.from_tag();
            let _ = req.from_uri();
            let _ = req.to_tag();
            let _ = req.to_uri();
            let _ = req.via_branch();
            let _ = req.cseq();
            let _ = req.cseq_method();
            let _ = req.contact_uri();
            let _ = req.content_type();
            let _ = req.body();
        }
        SipMessage::Response(resp) => {
            let _ = resp.status_code();
            let _ = resp.reason();
            let _ = resp.is_provisional();
            let _ = resp.is_success();
            let _ = resp.is_failure();
            let _ = resp.call_id();
            let _ = resp.from_tag();
            let _ = resp.to_tag();
            let _ = resp.via_branch();
            let _ = resp.cseq();
            let _ = resp.cseq_method();
            let _ = resp.contact_uri();
            let _ = resp.content_type();
            let _ = resp.body();
        }
    }
});
