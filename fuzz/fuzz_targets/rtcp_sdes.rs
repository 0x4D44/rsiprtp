#![no_main]
use libfuzzer_sys::fuzz_target;

// SourceDescription has no public parse() — fuzz Pli::parse here instead so we
// keep target count stable.
fuzz_target!(|data: &[u8]| {
    let _ = rsiprtp::rtp::rtcp::Pli::parse(data);
});
