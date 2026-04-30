#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rsiprtp_rtp::DtmfEvent::decode(data);
});
