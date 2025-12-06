//! SIP timer abstractions per RFC 3261 Section 17.
//!
//! The SIP transaction layer uses several timers:
//! - T1: RTT estimate (default 500ms)
//! - T2: Maximum retransmit interval for non-INVITE (default 4s)
//! - T4: Maximum network transit time (default 5s)
//! - Timer A-K: Transaction-specific timers built from T1/T2/T4

use std::time::Duration;

/// RFC 3261 timer values.
#[derive(Debug, Clone, Copy)]
pub struct TimerValues {
    /// T1: RTT estimate (default 500ms).
    pub t1: Duration,
    /// T2: Maximum retransmit interval for non-INVITE (default 4s).
    pub t2: Duration,
    /// T4: Maximum network transit time (default 5s).
    pub t4: Duration,
}

impl Default for TimerValues {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
        }
    }
}

impl TimerValues {
    /// Create timer values with custom T1.
    pub fn with_t1(t1_ms: u64) -> Self {
        Self {
            t1: Duration::from_millis(t1_ms),
            ..Default::default()
        }
    }

    /// Timer A: INVITE retransmit for unreliable transport (initially T1).
    pub fn timer_a(&self) -> Duration {
        self.t1
    }

    /// Timer B: INVITE transaction timeout (64 * T1).
    pub fn timer_b(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer C: Proxy INVITE transaction timeout (> 3 minutes).
    pub fn timer_c(&self) -> Duration {
        Duration::from_secs(180) + Duration::from_secs(1)
    }

    /// Timer D: Wait time in Completed state for unreliable transport (> 32s).
    pub fn timer_d(&self) -> Duration {
        Duration::from_secs(32) + Duration::from_secs(1)
    }

    /// Timer E: Non-INVITE retransmit for unreliable transport (initially T1).
    pub fn timer_e(&self) -> Duration {
        self.t1
    }

    /// Timer F: Non-INVITE transaction timeout (64 * T1).
    pub fn timer_f(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer G: INVITE response retransmit (initially T1).
    pub fn timer_g(&self) -> Duration {
        self.t1
    }

    /// Timer H: Wait for ACK timeout (64 * T1).
    pub fn timer_h(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer I: Wait in Confirmed state for unreliable transport (T4).
    pub fn timer_i(&self) -> Duration {
        self.t4
    }

    /// Timer J: Wait in Completed state for non-INVITE (64 * T1 for unreliable, 0 for reliable).
    pub fn timer_j(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            self.t1 * 64
        }
    }

    /// Timer K: Wait in Completed state for client non-INVITE (T4 for unreliable, 0 for reliable).
    pub fn timer_k(&self, reliable: bool) -> Duration {
        if reliable {
            Duration::ZERO
        } else {
            self.t4
        }
    }

    /// Calculate next retransmit interval with exponential backoff.
    /// Doubles the interval up to T2.
    pub fn next_retransmit(&self, current: Duration) -> Duration {
        let doubled = current * 2;
        std::cmp::min(doubled, self.t2)
    }
}

/// Timer identifier for transaction state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Timer {
    /// Timer A: INVITE request retransmit.
    A,
    /// Timer B: INVITE transaction timeout.
    B,
    /// Timer C: Proxy INVITE transaction timeout.
    C,
    /// Timer D: Wait time in Completed state.
    D,
    /// Timer E: Non-INVITE request retransmit.
    E,
    /// Timer F: Non-INVITE transaction timeout.
    F,
    /// Timer G: INVITE response retransmit.
    G,
    /// Timer H: Wait for ACK receipt.
    H,
    /// Timer I: Wait in Confirmed state.
    I,
    /// Timer J: Wait in Completed state (non-INVITE server).
    J,
    /// Timer K: Wait in Completed state (non-INVITE client).
    K,
}

impl std::fmt::Display for Timer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Timer::A => write!(f, "Timer A"),
            Timer::B => write!(f, "Timer B"),
            Timer::C => write!(f, "Timer C"),
            Timer::D => write!(f, "Timer D"),
            Timer::E => write!(f, "Timer E"),
            Timer::F => write!(f, "Timer F"),
            Timer::G => write!(f, "Timer G"),
            Timer::H => write!(f, "Timer H"),
            Timer::I => write!(f, "Timer I"),
            Timer::J => write!(f, "Timer J"),
            Timer::K => write!(f, "Timer K"),
        }
    }
}

/// An active timer with its deadline.
#[derive(Debug, Clone, Copy)]
pub struct ActiveTimer {
    /// Which timer this is.
    pub timer: Timer,
    /// When the timer fires (absolute time in microseconds from some epoch).
    pub deadline_us: u64,
}

impl ActiveTimer {
    /// Create a new active timer.
    pub fn new(timer: Timer, deadline_us: u64) -> Self {
        Self { timer, deadline_us }
    }

    /// Check if this timer has expired.
    pub fn is_expired(&self, now_us: u64) -> bool {
        now_us >= self.deadline_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TimerValues tests
    #[test]
    fn test_default_timers() {
        let tv = TimerValues::default();
        assert_eq!(tv.t1, Duration::from_millis(500));
        assert_eq!(tv.t2, Duration::from_secs(4));
        assert_eq!(tv.t4, Duration::from_secs(5));
    }

    #[test]
    fn test_with_t1() {
        let tv = TimerValues::with_t1(250);
        assert_eq!(tv.t1, Duration::from_millis(250));
        // T2 and T4 should still be default
        assert_eq!(tv.t2, Duration::from_secs(4));
        assert_eq!(tv.t4, Duration::from_secs(5));
    }

    #[test]
    fn test_timer_a() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_a(), Duration::from_millis(500));

        let tv_custom = TimerValues::with_t1(100);
        assert_eq!(tv_custom.timer_a(), Duration::from_millis(100));
    }

    #[test]
    fn test_timer_b() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_b(), Duration::from_secs(32)); // 64 * 500ms

        let tv_custom = TimerValues::with_t1(250);
        assert_eq!(tv_custom.timer_b(), Duration::from_millis(16000)); // 64 * 250ms
    }

    #[test]
    fn test_timer_c() {
        let tv = TimerValues::default();
        // > 3 minutes
        assert!(tv.timer_c() > Duration::from_secs(180));
        assert_eq!(tv.timer_c(), Duration::from_secs(181));
    }

    #[test]
    fn test_timer_d() {
        let tv = TimerValues::default();
        // > 32 seconds
        assert!(tv.timer_d() > Duration::from_secs(32));
        assert_eq!(tv.timer_d(), Duration::from_secs(33));
    }

    #[test]
    fn test_timer_e() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_e(), Duration::from_millis(500));

        let tv_custom = TimerValues::with_t1(200);
        assert_eq!(tv_custom.timer_e(), Duration::from_millis(200));
    }

    #[test]
    fn test_timer_f() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_f(), Duration::from_secs(32));
    }

    #[test]
    fn test_timer_g() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_g(), Duration::from_millis(500));
    }

    #[test]
    fn test_timer_h() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_h(), Duration::from_secs(32)); // 64 * 500ms
    }

    #[test]
    fn test_timer_i() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_i(), Duration::from_secs(5)); // T4
    }

    #[test]
    fn test_timer_j() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_j(true), Duration::ZERO);
        assert_eq!(tv.timer_j(false), Duration::from_secs(32)); // 64 * T1
    }

    #[test]
    fn test_timer_k_reliable() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_k(true), Duration::ZERO);
        assert_eq!(tv.timer_k(false), Duration::from_secs(5)); // T4
    }

    #[test]
    fn test_retransmit_backoff() {
        let tv = TimerValues::default();
        let t1 = tv.t1;
        let t2 = tv.next_retransmit(t1);
        assert_eq!(t2, Duration::from_millis(1000));
        let t3 = tv.next_retransmit(t2);
        assert_eq!(t3, Duration::from_millis(2000));
        let t4 = tv.next_retransmit(t3);
        assert_eq!(t4, Duration::from_millis(4000)); // capped at T2
        let t5 = tv.next_retransmit(t4);
        assert_eq!(t5, Duration::from_millis(4000)); // stays at T2
    }

    #[test]
    fn test_retransmit_immediately_capped() {
        let tv = TimerValues::default();
        // If current is already >= T2, should stay at T2
        let current = Duration::from_secs(10);
        assert_eq!(tv.next_retransmit(current), Duration::from_secs(4));
    }

    #[test]
    fn test_timer_values_debug() {
        let tv = TimerValues::default();
        let debug = format!("{:?}", tv);
        assert!(debug.contains("TimerValues"));
    }

    #[test]
    fn test_timer_values_clone() {
        let tv = TimerValues::default();
        let cloned = tv;
        assert_eq!(cloned.t1, tv.t1);
        assert_eq!(cloned.t2, tv.t2);
    }

    // Timer enum tests
    #[test]
    fn test_timer_debug() {
        assert!(format!("{:?}", Timer::A).contains("A"));
        assert!(format!("{:?}", Timer::B).contains("B"));
    }

    #[test]
    fn test_timer_clone() {
        let t = Timer::A;
        let cloned = t;
        assert_eq!(t, cloned);
    }

    #[test]
    fn test_timer_eq() {
        assert_eq!(Timer::A, Timer::A);
        assert_ne!(Timer::A, Timer::B);
    }

    #[test]
    fn test_timer_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Timer::A);
        set.insert(Timer::B);
        set.insert(Timer::A); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_timer_display() {
        assert_eq!(Timer::A.to_string(), "Timer A");
        assert_eq!(Timer::B.to_string(), "Timer B");
        assert_eq!(Timer::C.to_string(), "Timer C");
        assert_eq!(Timer::D.to_string(), "Timer D");
        assert_eq!(Timer::E.to_string(), "Timer E");
        assert_eq!(Timer::F.to_string(), "Timer F");
        assert_eq!(Timer::G.to_string(), "Timer G");
        assert_eq!(Timer::H.to_string(), "Timer H");
        assert_eq!(Timer::I.to_string(), "Timer I");
        assert_eq!(Timer::J.to_string(), "Timer J");
        assert_eq!(Timer::K.to_string(), "Timer K");
    }

    // ActiveTimer tests
    #[test]
    fn test_active_timer_new() {
        let timer = ActiveTimer::new(Timer::A, 1000000);
        assert_eq!(timer.timer, Timer::A);
        assert_eq!(timer.deadline_us, 1000000);
    }

    #[test]
    fn test_active_timer_is_expired() {
        let timer = ActiveTimer::new(Timer::B, 1000);

        // Not expired yet
        assert!(!timer.is_expired(500));
        assert!(!timer.is_expired(999));

        // Exactly at deadline - considered expired
        assert!(timer.is_expired(1000));

        // Past deadline
        assert!(timer.is_expired(1001));
        assert!(timer.is_expired(2000));
    }

    #[test]
    fn test_active_timer_debug() {
        let timer = ActiveTimer::new(Timer::A, 12345);
        let debug = format!("{:?}", timer);
        assert!(debug.contains("ActiveTimer"));
        assert!(debug.contains("12345"));
    }

    #[test]
    fn test_active_timer_clone() {
        let timer = ActiveTimer::new(Timer::C, 5000);
        let cloned = timer;
        assert_eq!(cloned.timer, timer.timer);
        assert_eq!(cloned.deadline_us, timer.deadline_us);
    }
}
