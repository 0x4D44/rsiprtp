//! Integration test: REMB bytes → MediaSession::handle_rtcp →
//! CongestionController → BitrateBridge → SessionCodec encoder rate.
//!
//! This is the production-wiring integration test from the bitrate-bridge
//! production-wiring HLD (`wrk_docs/2026.04.30 - HLD - Production wiring for
//! the bitrate bridge.md`, § Tests, "Integration" subsection). The sibling
//! test `bitrate_bridge_remb.rs` exercises the bridge wired against a bare
//! `OpusCodec`; this one wires the full call-layer surface end-to-end:
//! the inbound REMB bytes go through `MediaSession::handle_rtcp` and
//! `MediaSession::tick`, and the proof of adaptation is the encoded payload
//! shrinking on a subsequent `MediaSession::encode_audio` call.

use std::time::Instant;

use rsiprtp::rtp::rtcp::{Remb, RtcpCompound, RtcpPacket};
use rsiprtp::sdp::negotiation::Codec;
use rsiprtp::session::call::MediaSession;

#[test]
fn remb_drives_opus_through_media_session() {
    // 1. Build an Opus Codec entry as it would arrive from SDP negotiation
    //    (RTP `a=rtpmap:111 opus/48000/2`).
    let codec = Codec::new(111, "opus", 48_000).with_channels(2);

    // 2. Construct MediaSession; Opus starts at 32 kbps via
    //    OpusConfig::fullband_speech() (RFC 7587 § 7).
    let mut media = MediaSession::for_negotiated(0x1234_5678, &codec, 0)
        .expect("opus MediaSession construction");

    // 3. Encode one frame at the codec's 32 kbps starting rate.
    //    Opus 48 kHz × 20 ms = 960 samples per frame.
    let samples_per_frame = 960;
    let pcm: Vec<i16> = (0..samples_per_frame)
        .map(|i| ((i as f32 * 0.1).sin() * 16_000.0) as i16)
        .collect();
    let initial_pkt = media.encode_audio(&pcm, false).expect("initial encode");
    let initial_bytes = initial_pkt.payload.len();

    // 4. Build a compound RTCP containing a REMB at 16 kbps. This is below
    //    the codec's 32 kbps starting rate AND below 0.9 × 32_000 = 28_800,
    //    so cc.on_remb actually reduces the target. 16 kbps > 6 kbps min,
    //    so no clamp on the way in.
    let remb = Remb::new(0xDEAD_BEEF, 16_000, vec![0xCAFE_F00D]);
    let compound = RtcpCompound {
        packets: vec![RtcpPacket::Remb(remb)],
    };
    let bytes = compound.build();

    // 5. Hand bytes to MediaSession; this parses + routes REMB into the
    //    private CongestionController.
    media.handle_rtcp(&bytes).expect("handle_rtcp");

    // 6. Tick to drive the BitrateBridge (first poll always applies, ignoring
    //    hysteresis) so the codec's encoder rate is updated.
    media.tick(Instant::now());

    // 7. Encode another frame; assert the encoded payload SHRUNK. The byte
    //    delta is the proof that adaptation reached the encoder end-to-end.
    let after_pkt = media.encode_audio(&pcm, false).expect("post-bridge encode");
    let after_bytes = after_pkt.payload.len();

    assert!(
        after_bytes < initial_bytes,
        "expected encoded frame to shrink: initial={initial_bytes}, after={after_bytes}"
    );
    assert!(
        initial_bytes - after_bytes >= 20,
        "encoded frame shrinkage too small to attribute to bitrate change: \
         initial={initial_bytes}, after={after_bytes}, delta={}",
        initial_bytes - after_bytes
    );
}

#[test]
fn fixed_rate_codec_handles_rtcp_without_panic() {
    // PCMU is fixed-rate: MediaSession::for_negotiated should leave
    // `adaptive` as None, and the RTCP / tick paths must be no-ops apart
    // from parsing. This guards against regressions where the RTCP path
    // accidentally tries to mutate a non-existent `adaptive`.
    let mut media = MediaSession::for_negotiated(0x4242_4242, &Codec::pcmu(), 0)
        .expect("PCMU MediaSession construction");

    // Build a compound containing a REMB. Even though PCMU can't act on it,
    // handle_rtcp must still parse cleanly and return Ok(()).
    let remb = Remb::new(0xDEAD_BEEF, 16_000, vec![0xCAFE_F00D]);
    let compound = RtcpCompound {
        packets: vec![RtcpPacket::Remb(remb)],
    };
    let bytes = compound.build();

    media
        .handle_rtcp(&bytes)
        .expect("PCMU handle_rtcp must succeed even with REMB present");
    media.tick(Instant::now());

    // Encode one G.711 mu-law frame: 8 kHz × 20 ms = 160 PCM samples,
    // which produces 160 mu-law bytes (1:1 sample-to-byte ratio).
    let pcm: Vec<i16> = (0..160)
        .map(|i| ((i as f32 * 0.1).sin() * 16_000.0) as i16)
        .collect();
    let pkt = media.encode_audio(&pcm, false).expect("PCMU encode");
    assert_eq!(
        pkt.payload.len(),
        160,
        "G.711 mu-law frame should be 160 bytes for 160 PCM samples"
    );
}
