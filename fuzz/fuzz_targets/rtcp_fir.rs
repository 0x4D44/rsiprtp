#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rsiprtp::rtp::rtcp::Fir::parse(data);
});
