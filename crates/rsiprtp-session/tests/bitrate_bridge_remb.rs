//! Integration test: REMB bytes → CongestionController → BitrateBridge → OpusCodec.
//!
//! This is the codec-focused integration test from the bitrate-bridge HLD
//! (`wrk_docs/2026.04.29 - HLD - CongestionController to codec bitrate bridge.md`,
//! § Tests, "Integration" subsection). It wires together real REMB on-the-wire
//! bytes (round-tripped through `Remb::parse`/`build`), the AIMD
//! `CongestionController`, the `BitrateBridge` hysteresis filter, and a real
//! `OpusCodec`. No mocks.

use std::time::Instant;

use rsiprtp_media::{Bitrate, OpusCodec, OpusConfig};
use rsiprtp_rtp::rtcp::Remb;
use rsiprtp_rtp::session::CongestionController;
use rsiprtp_session::BitrateBridge;

#[test]
fn remb_drives_opus_bitrate_through_bridge() {
    // 1. Build CC (defaults: 500 kbps initial, 50 kbps min, 5 Mbps max),
    //    BitrateBridge, and OpusCodec started at 96 kbps. The REMB target
    //    below is 64 kbps, so the bridge applies a real DROP — matching the
    //    HLD wording about the encoder's operating point falling.
    let mut cc = CongestionController::default();
    let mut bridge = BitrateBridge::new();
    let mut codec = OpusCodec::with_config(OpusConfig {
        bitrate: Bitrate::Bits(96_000),
        ..OpusConfig::default()
    })
    .expect("opus codec construction");

    assert_eq!(
        codec.bitrate(),
        Bitrate::Bits(96_000),
        "test starts the codec at 96 kbps so the REMB-driven 64 kbps target is a real drop"
    );

    // 2. Encode one frame and record the encoder's configured bitrate plus
    //    the encoded byte size as physical evidence of the operating point.
    //
    //    The HLD references `effective_bitrate_bps()` here, but that getter
    //    was deliberately dropped during the sibling Opus HLD's review (the
    //    contract for when ropus populates it isn't testable). We use the
    //    configured `bitrate()` getter plus the encoded frame size — the
    //    latter is the actual physical evidence that the encoder's operating
    //    point changed.
    let pcm: Vec<i16> = (0..codec.samples_per_frame())
        .map(|i| ((i as f32 * 0.1).sin() * 16_000.0) as i16)
        .collect();
    let encoded_initial = codec.encode(&pcm).expect("initial encode");
    let initial_bitrate = codec.bitrate();
    let initial_bytes = encoded_initial.len();

    // 3. Build a Remb with bitrate = 64_000 (above CC's 50 kbps floor),
    //    serialise to bytes, then round-trip through `Remb::parse` to prove
    //    we're consuming on-the-wire bytes (not the in-memory struct).
    let outbound_remb = Remb::new(0xDEAD_BEEF, 64_000, vec![0xCAFE_F00D]);
    let bytes = outbound_remb.build();
    let parsed = Remb::parse(&bytes).expect("REMB round-trip");
    // REMB encodes bitrate as mantissa * 2^exp; small values like 64_000 fit
    // in the 18-bit mantissa with exp=0, so the round-trip is exact.
    assert_eq!(parsed.bitrate, 64_000);

    // 4. Feed the parsed REMB into the CC. Default target is 500 kbps; 64 kbps
    //    is well under the 90 %-of-target threshold, so on_remb reduces the
    //    target. 64 kbps > 50 kbps min, so no clamp.
    cc.on_remb(parsed.bitrate);
    assert_eq!(cc.target_bitrate(), 64_000);

    // 5. Poll the bridge — first poll always applies regardless of hysteresis.
    let applied = bridge
        .poll(cc.target_bitrate(), &mut codec, Instant::now())
        .expect("bridge poll");
    assert!(applied, "first poll must apply");

    // 6. Encode another frame and record the post-bridge operating point.
    let encoded_after = codec.encode(&pcm).expect("post-bridge encode");
    let after_bitrate = codec.bitrate();
    let after_bytes = encoded_after.len();

    // 7. Assert the encoder is now configured at the REMB-driven target.
    assert_eq!(
        after_bitrate,
        Bitrate::Bits(64_000),
        "bridge should have set the encoder to 64 kbps (was {initial_bitrate:?})"
    );

    // 8. Physical-reality check on the encoded bytes.
    //
    //    The HLD step 5 says "assert effective_bitrate_bps() has dropped
    //    relative to step 2." We exercise an actual drop here: codec starts
    //    at 96 kbps, REMB drives the target to 64 kbps, so the encoded frame
    //    must shrink. For a 20 ms frame the expected delta is on the order of
    //    80 bytes; we assert >= 20 to keep a safety margin while still
    //    catching regressions in the wrong direction.
    assert!(
        after_bytes < initial_bytes,
        "encoded frame did not shrink after bitrate drop: initial={initial_bytes}, after={after_bytes} \
         (initial bitrate {initial_bitrate:?}, after {after_bitrate:?})"
    );
    assert!(
        initial_bytes - after_bytes >= 20,
        "encoded frame shrinkage too small to attribute to bitrate change: \
         initial={}, after={}, delta={}",
        initial_bytes,
        after_bytes,
        initial_bytes - after_bytes
    );
}
