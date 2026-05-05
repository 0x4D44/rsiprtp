#![no_main]
use libfuzzer_sys::fuzz_target;

#[path = "../../crates/rsiprtp/tests/sdp_roundtrip_oracle/mod.rs"]
mod oracle;

fuzz_target!(|data: &[u8]| {
    oracle::assert_roundtrip_fixed_point(data);
});
