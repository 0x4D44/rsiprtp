#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rsiprtp::srtp::dtls::parse_use_srtp_extension(data);
});
