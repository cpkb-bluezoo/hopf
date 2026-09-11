// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Round-trip time estimation (RFC 9002 section 5 / Appendix A.7).

use std::time::Duration;

/// RFC 9002 section 6.2.2: RTT assumed before any real sample exists.
pub const K_INITIAL_RTT: Duration = Duration::from_millis(333);

/// Round-trip time estimator. Times are supplied by the caller.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    latest_rtt: Duration,
    smoothed_rtt: Duration,
    rttvar: Duration,
    min_rtt: Duration,
    has_sample: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    /// Create an estimator with no RTT sample yet (RFC 9002 Appendix A.4).
    pub fn new() -> Self {
        Self {
            latest_rtt: Duration::ZERO,
            smoothed_rtt: K_INITIAL_RTT,
            rttvar: K_INITIAL_RTT / 2,
            min_rtt: Duration::ZERO,
            has_sample: false,
        }
    }

    /// Record a new RTT sample (RFC 9002 Appendix A.7 `UpdateRtt`).
    pub fn on_rtt_sample(
        &mut self,
        latest_rtt: Duration,
        ack_delay: Duration,
        max_ack_delay: Duration,
        handshake_confirmed: bool,
    ) {
        self.latest_rtt = latest_rtt;

        if !self.has_sample {
            self.min_rtt = latest_rtt;
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            self.has_sample = true;
            return;
        }

        self.min_rtt = self.min_rtt.min(latest_rtt);
        let ack_delay = if handshake_confirmed {
            ack_delay.min(max_ack_delay)
        } else {
            ack_delay
        };

        let mut adjusted_rtt = latest_rtt;
        if latest_rtt >= self.min_rtt + ack_delay {
            adjusted_rtt = latest_rtt - ack_delay;
        }

        // Integer millis arithmetic matches Gumdrop / RFC pseudocode.
        let rttvar_ms = self.rttvar.as_millis() as u64;
        let smoothed_ms = self.smoothed_rtt.as_millis() as u64;
        let adjusted_ms = adjusted_rtt.as_millis() as u64;
        let diff = smoothed_ms.abs_diff(adjusted_ms);
        self.rttvar = Duration::from_millis((3 * rttvar_ms + diff) / 4);
        self.smoothed_rtt = Duration::from_millis((7 * smoothed_ms + adjusted_ms) / 8);
    }

    /// Most recent RTT sample.
    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    /// Smoothed RTT estimate.
    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    /// RTT variation.
    pub fn rtt_var(&self) -> Duration {
        self.rttvar
    }

    /// Minimum RTT observed (zero if no sample yet).
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Whether at least one RTT sample has been recorded.
    pub fn has_rtt_sample(&self) -> bool {
        self.has_sample
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_uses_initial_rtt() {
        let e = RttEstimator::new();
        assert!(!e.has_rtt_sample());
        assert_eq!(e.smoothed_rtt(), K_INITIAL_RTT);
        assert_eq!(e.rtt_var(), K_INITIAL_RTT / 2);
    }

    #[test]
    fn first_sample_sets_all_fields_directly() {
        let mut e = RttEstimator::new();
        e.on_rtt_sample(
            Duration::from_millis(100),
            Duration::from_millis(5),
            Duration::from_millis(25),
            false,
        );
        assert!(e.has_rtt_sample());
        assert_eq!(e.latest_rtt(), Duration::from_millis(100));
        assert_eq!(e.smoothed_rtt(), Duration::from_millis(100));
        assert_eq!(e.rtt_var(), Duration::from_millis(50));
        assert_eq!(e.min_rtt(), Duration::from_millis(100));
    }

    #[test]
    fn second_sample_matches_update_rtt_formula() {
        let mut e = RttEstimator::new();
        e.on_rtt_sample(
            Duration::from_millis(100),
            Duration::from_millis(5),
            Duration::from_millis(25),
            false,
        );
        e.on_rtt_sample(
            Duration::from_millis(150),
            Duration::from_millis(10),
            Duration::from_millis(25),
            false,
        );
        assert_eq!(e.min_rtt(), Duration::from_millis(100));
        assert_eq!(e.rtt_var(), Duration::from_millis(47));
        assert_eq!(e.smoothed_rtt(), Duration::from_millis(105));
        assert_eq!(e.latest_rtt(), Duration::from_millis(150));
    }

    #[test]
    fn ack_delay_unclamped_before_handshake_confirmed() {
        let mut e = RttEstimator::new();
        e.on_rtt_sample(
            Duration::from_millis(50),
            Duration::ZERO,
            Duration::from_millis(10),
            false,
        );
        e.on_rtt_sample(
            Duration::from_millis(100),
            Duration::from_millis(40),
            Duration::from_millis(10),
            false,
        );
        assert_eq!(e.rtt_var(), Duration::from_millis(21));
        assert_eq!(e.smoothed_rtt(), Duration::from_millis(51));
    }

    #[test]
    fn ack_delay_clamped_after_handshake_confirmed() {
        let mut e = RttEstimator::new();
        e.on_rtt_sample(
            Duration::from_millis(50),
            Duration::ZERO,
            Duration::from_millis(10),
            false,
        );
        e.on_rtt_sample(
            Duration::from_millis(100),
            Duration::from_millis(40),
            Duration::from_millis(10),
            true,
        );
        assert_eq!(e.rtt_var(), Duration::from_millis(28));
        assert_eq!(e.smoothed_rtt(), Duration::from_millis(55));
    }

    #[test]
    fn implausible_adjustment_leaves_latest_rtt_unchanged() {
        let mut e = RttEstimator::new();
        e.on_rtt_sample(
            Duration::from_millis(50),
            Duration::ZERO,
            Duration::from_millis(100),
            false,
        );
        e.on_rtt_sample(
            Duration::from_millis(55),
            Duration::from_millis(20),
            Duration::from_millis(100),
            false,
        );
        assert_eq!(e.rtt_var(), Duration::from_millis(20));
        assert_eq!(e.smoothed_rtt(), Duration::from_millis(50));
    }

    #[test]
    fn min_rtt_ignores_ack_delay() {
        let mut e = RttEstimator::new();
        e.on_rtt_sample(
            Duration::from_millis(200),
            Duration::ZERO,
            Duration::from_millis(100),
            false,
        );
        e.on_rtt_sample(
            Duration::from_millis(50),
            Duration::from_millis(40),
            Duration::from_millis(100),
            false,
        );
        assert_eq!(e.min_rtt(), Duration::from_millis(50));
    }
}
