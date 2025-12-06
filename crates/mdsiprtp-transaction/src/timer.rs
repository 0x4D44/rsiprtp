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

    #[test]
    fn test_default_timers() {
        let tv = TimerValues::default();
        assert_eq!(tv.t1, Duration::from_millis(500));
        assert_eq!(tv.t2, Duration::from_secs(4));
        assert_eq!(tv.t4, Duration::from_secs(5));
    }

    #[test]
    fn test_timer_b() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_b(), Duration::from_secs(32));
    }

    #[test]
    fn test_timer_f() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_f(), Duration::from_secs(32));
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
    fn test_timer_k_reliable() {
        let tv = TimerValues::default();
        assert_eq!(tv.timer_k(true), Duration::ZERO);
        assert_eq!(tv.timer_k(false), Duration::from_secs(5));
    }
}
