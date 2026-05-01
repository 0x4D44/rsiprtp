//! Hysteresis filter bridging a `u64` target bitrate to an adaptive codec.
//!
//! [`BitrateBridge`] is a Sans-IO style filter sitting between any source of
//! target-bitrate values (today: `crate::rtp::CongestionController`, tomorrow
//! potentially RFC 8888 transport-wide CC) and any codec implementing
//! [`AdaptiveBitrate`]. It does not perform I/O and does not own a clock —
//! callers inject `now: Instant` so tests can drive time deterministically.
//!
//! # Behaviour
//!
//! On `poll`, the bridge applies the new target if **either**
//!
//! - it is the first call since construction, or
//! - the relative change vs the last *applied* value clears `rel_threshold`
//!   **and** at least `min_interval` has elapsed since the last apply.
//!
//! Otherwise the call is suppressed and the codec is not touched.
//!
//! Defaults are 5 % relative change and 200 ms minimum interval. They are not
//! tunable through the public API by design: if real REMB traces show jitter
//! or laggy adaptation, retune the constants here before exposing them.
//!
//! # Example
//!
//! ```rust,ignore
//! use std::time::Instant;
//! use rsiprtp::session::BitrateBridge;
//!
//! let mut bridge = BitrateBridge::new();
//! let applied = bridge.poll(cc.target_bitrate(), &mut codec, Instant::now())?;
//! if applied {
//!     tracing::debug!("encoder bitrate updated");
//! }
//! ```
//!
//! See `wrk_docs/2026.04.29 - HLD - CongestionController to codec bitrate bridge.md`.

use std::time::{Duration, Instant};

use crate::media::AdaptiveBitrate;

/// Default minimum interval between applied bitrate updates.
const DEFAULT_MIN_INTERVAL: Duration = Duration::from_millis(200);

/// Default minimum relative change (5 %) needed to apply an update.
const DEFAULT_REL_THRESHOLD: f32 = 0.05;

/// Hysteresis filter that pumps a `u64` target bitrate into an
/// [`AdaptiveBitrate`] codec, suppressing churn from REMB jitter.
///
/// See the module-level documentation for behaviour and rationale.
pub struct BitrateBridge {
    /// Last bitrate (bps) actually written to the codec.
    last_applied_bps: Option<u32>,
    /// `Instant` at which `last_applied_bps` was written.
    last_applied_at: Option<Instant>,
    /// Minimum elapsed time between applied updates.
    min_interval: Duration,
    /// Minimum relative change vs `last_applied_bps` needed to apply.
    rel_threshold: f32,
}

impl BitrateBridge {
    /// Construct a bridge with the default hysteresis (200 ms / 5 %).
    pub fn new() -> Self {
        Self {
            last_applied_bps: None,
            last_applied_at: None,
            min_interval: DEFAULT_MIN_INTERVAL,
            rel_threshold: DEFAULT_REL_THRESHOLD,
        }
    }

    /// Push `target_bps` into `codec` if the change clears both the relative
    /// threshold and the minimum interval. Returns `Ok(true)` if the codec was
    /// updated, `Ok(false)` if the update was suppressed by hysteresis.
    ///
    /// `target_bps` is saturating-cast from `u64` to `u32`. Callers that care
    /// about a sane range (e.g. the upstream `CongestionController`) should
    /// clamp at the source; the bridge does not.
    ///
    /// If `codec.set_target_bitrate_bps` returns an error, the bridge's
    /// internal state is **not** updated — the next `poll` will see the same
    /// baseline as before the failed call.
    pub fn poll(
        &mut self,
        target_bps: u64,
        codec: &mut dyn AdaptiveBitrate,
        now: Instant,
    ) -> Result<bool, String> {
        let new_bps: u32 = target_bps.min(u32::MAX as u64) as u32;

        let should_apply = match self.last_applied_bps {
            None => true,
            Some(0) => true,
            Some(last) => {
                let abs_delta = new_bps.abs_diff(last) as f32;
                let rel_delta = abs_delta / last as f32;
                let elapsed = self
                    .last_applied_at
                    .map(|t| now.duration_since(t))
                    .unwrap_or(Duration::ZERO);
                rel_delta >= self.rel_threshold && elapsed >= self.min_interval
            }
        };

        if !should_apply {
            return Ok(false);
        }

        codec.set_target_bitrate_bps(new_bps)?;
        self.last_applied_bps = Some(new_bps);
        self.last_applied_at = Some(now);
        Ok(true)
    }
}

impl Default for BitrateBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test stand-in for an adaptive codec.
    struct MockAdaptive {
        last_set: Option<u32>,
        force_err: bool,
    }

    impl MockAdaptive {
        fn new() -> Self {
            Self {
                last_set: None,
                force_err: false,
            }
        }
    }

    impl AdaptiveBitrate for MockAdaptive {
        fn set_target_bitrate_bps(&mut self, bps: u32) -> Result<(), String> {
            if self.force_err {
                return Err("forced".to_string());
            }
            self.last_set = Some(bps);
            Ok(())
        }
    }

    #[test]
    fn applies_first_update() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        let applied = bridge.poll(100_000, &mut mock, t0).unwrap();

        assert!(applied);
        assert_eq!(mock.last_set, Some(100_000));
    }

    #[test]
    fn suppresses_subthreshold_change() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        bridge.poll(100_000, &mut mock, t0).unwrap();
        let applied = bridge
            .poll(102_000, &mut mock, t0 + Duration::from_secs(1))
            .unwrap();

        assert!(!applied);
        assert_eq!(mock.last_set, Some(100_000));
    }

    #[test]
    fn applies_supra_threshold_change() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        bridge.poll(100_000, &mut mock, t0).unwrap();
        let applied = bridge
            .poll(110_000, &mut mock, t0 + Duration::from_secs(1))
            .unwrap();

        assert!(applied);
        assert_eq!(mock.last_set, Some(110_000));
    }

    #[test]
    fn respects_min_interval() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        bridge.poll(100_000, &mut mock, t0).unwrap();

        let too_soon = bridge
            .poll(200_000, &mut mock, t0 + Duration::from_millis(50))
            .unwrap();
        assert!(!too_soon);
        assert_eq!(mock.last_set, Some(100_000));

        let ok_now = bridge
            .poll(200_000, &mut mock, t0 + Duration::from_millis(250))
            .unwrap();
        assert!(ok_now);
        assert_eq!(mock.last_set, Some(200_000));
    }

    #[test]
    fn monotonic_through_repeated_updates() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        // First applies unconditionally; each subsequent value is a >5 %
        // change vs the prior applied baseline.
        let values = [120_000_u64, 80_000, 90_000, 150_000];
        for (i, v) in values.iter().enumerate() {
            let now = t0 + Duration::from_secs(i as u64);
            let applied = bridge.poll(*v, &mut mock, now).unwrap();
            assert!(applied, "expected apply at step {i} (value={v})");
        }

        assert_eq!(mock.last_set, Some(150_000));
    }

    #[test]
    fn surfaces_codec_error() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive {
            last_set: None,
            force_err: true,
        };
        let t0 = Instant::now();

        let err = bridge.poll(100_000, &mut mock, t0).unwrap_err();
        assert_eq!(err, "forced");
        assert_eq!(mock.last_set, None);

        // Clear the forced error: the bridge must still treat the next call
        // as a first-call (state unchanged across the failure).
        mock.force_err = false;
        let applied = bridge
            .poll(100_000, &mut mock, t0 + Duration::from_secs(1))
            .unwrap();
        assert!(applied);
        assert_eq!(mock.last_set, Some(100_000));
    }

    #[test]
    fn defensive_zero_baseline_applies() {
        // After a first poll with target 0, the bridge stores Some(0).
        // The next poll must apply via the defensive `last == 0` branch
        // rather than dividing by zero in the relative-threshold check.
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        // First poll establishes Some(0) baseline.
        let applied = bridge.poll(0, &mut mock, t0).unwrap();
        assert!(applied);
        assert_eq!(mock.last_set, Some(0));

        // Second poll, well within min_interval, must still apply because
        // of the defensive zero guard (no rel-threshold math).
        let applied = bridge
            .poll(50_000, &mut mock, t0 + Duration::from_millis(10))
            .unwrap();
        assert!(applied);
        assert_eq!(mock.last_set, Some(50_000));
    }

    #[test]
    fn slow_drift_eventually_applies() {
        let mut bridge = BitrateBridge::new();
        let mut mock = MockAdaptive::new();
        let t0 = Instant::now();

        // Baseline.
        bridge.poll(100_000, &mut mock, t0).unwrap();

        // Each step is ~2 % over the *previous polled value* — sub-threshold
        // when measured pairwise. But the bridge measures vs the last
        // *applied* baseline (100_000), so cumulative drift past 105_000
        // crosses the gate.
        let drifts = [
            (102_000_u64, Duration::from_millis(250), false),
            (104_040, Duration::from_millis(500), false),
            (106_120, Duration::from_millis(750), true),
            (108_242, Duration::from_millis(1000), false),
        ];

        for (value, dt, expect_applied) in drifts {
            let applied = bridge.poll(value, &mut mock, t0 + dt).unwrap();
            assert_eq!(
                applied, expect_applied,
                "value={value} dt={dt:?} expected_applied={expect_applied}"
            );
        }

        // The first poll above 105_000 (i.e. 106_120) flipped to applied.
        assert_eq!(mock.last_set, Some(106_120));
    }
}
