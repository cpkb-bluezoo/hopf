// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Generic retry/backoff policy (issue #344).
//!
//! [`RetryPolicy`] computes exponential-backoff delays (with optional
//! jitter) and a bound on how long to keep going, generalizing the shape
//! already proven out by `hopf-amqp`'s connection-recovery backoff.
//! [`RetryState`] tracks one operation's attempts against a policy;
//! [`Retryable`] lets a protocol crate plug in its own classification of
//! what counts as worth retrying at all (a 4xx SMTP reply vs a 5xx one, an
//! AMQP connection drop vs a protocol error, ...) without this module
//! needing to know anything about any specific protocol.
//!
//! This module deliberately does not own any actual timer — computing
//! "how long to wait" is decoupled from "how to wait." Feed the returned
//! [`Duration`] into [`crate::ConnHandle::schedule_timer`] or
//! [`crate::Runtime::pick_worker`]`().schedule_timer(...)` rather than
//! blocking a thread on it.

use std::time::{Duration, Instant};

/// How long to keep retrying: by attempt count, by elapsed wall-clock time
/// since the first attempt, both, or neither (unlimited).
#[derive(Debug, Clone, Copy)]
pub enum RetryBound {
    /// Never give up.
    Unlimited,
    /// Stop after this many attempts.
    MaxAttempts(u32),
    /// Stop once this much time has passed since the first attempt.
    MaxElapsed(Duration),
    /// Stop when either bound is hit, whichever comes first.
    Both {
        /// Attempt-count bound.
        max_attempts: u32,
        /// Elapsed-time bound.
        max_elapsed: Duration,
    },
}

/// Exponential backoff with optional jitter and a give-up bound.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    initial_delay: Duration,
    max_delay: Duration,
    multiplier: f64,
    jitter: f64,
    bound: RetryBound,
}

impl RetryPolicy {
    /// 1s initial delay, doubling each attempt, capped at 30s, no jitter,
    /// unlimited attempts/time.
    pub fn exponential_backoff() -> Self {
        Self {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: 0.0,
            bound: RetryBound::Unlimited,
        }
    }

    /// Delay before the first retry attempt (default 1s).
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Cap on the backoff delay (default 30s).
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Growth factor applied to the delay each attempt (default 2.0 —
    /// doubling). Values `<= 1.0` are treated as 1.0 (fixed delay).
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier.max(1.0);
        self
    }

    /// Randomly vary the computed delay by up to `±fraction` (clamped to
    /// `[0.0, 1.0]`) — spreads out retries from many operations that
    /// failed at the same moment instead of having them all wake up and
    /// retry in lockstep. Default 0.0 (no jitter).
    pub fn with_jitter(mut self, fraction: f64) -> Self {
        self.jitter = fraction.clamp(0.0, 1.0);
        self
    }

    /// Stop after `attempts` consecutive failed attempts.
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.bound = match self.bound {
            RetryBound::MaxElapsed(max_elapsed) | RetryBound::Both { max_elapsed, .. } => {
                RetryBound::Both {
                    max_attempts: attempts,
                    max_elapsed,
                }
            }
            _ => RetryBound::MaxAttempts(attempts),
        };
        self
    }

    /// Stop once `max_elapsed` has passed since the first attempt.
    pub fn with_max_elapsed(mut self, max_elapsed: Duration) -> Self {
        self.bound = match self.bound {
            RetryBound::MaxAttempts(max_attempts) | RetryBound::Both { max_attempts, .. } => {
                RetryBound::Both {
                    max_attempts,
                    max_elapsed,
                }
            }
            _ => RetryBound::MaxElapsed(max_elapsed),
        };
        self
    }

    /// Never give up (the default) — clears any bound set by
    /// [`Self::with_max_attempts`]/[`Self::with_max_elapsed`].
    pub fn unlimited(mut self) -> Self {
        self.bound = RetryBound::Unlimited;
        self
    }

    /// Backoff delay before retry attempt number `attempt` (1-indexed),
    /// with jitter applied: `min(initial_delay * multiplier^(attempt-1),
    /// max_delay)`, then randomized by up to `±jitter`.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        apply_jitter(self.raw_delay_for_attempt(attempt), self.jitter)
    }

    fn raw_delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(1024) as i32;
        let scale = self.multiplier.powi(exponent);
        let millis = (self.initial_delay.as_millis() as f64) * scale;
        let capped = millis.min(self.max_delay.as_millis() as f64).max(0.0);
        Duration::from_millis(capped as u64)
    }

    /// Begin tracking a new operation's attempts against this policy.
    pub fn start(&self) -> RetryState {
        RetryState {
            policy: self.clone(),
            attempt: 0,
            started: Instant::now(),
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::exponential_backoff()
    }
}

fn apply_jitter(base: Duration, jitter: f64) -> Duration {
    if jitter <= 0.0 {
        return base;
    }
    let mut buf = [0u8; 8];
    let _ = getrandom::getrandom(&mut buf);
    let r = u64::from_le_bytes(buf);
    let unit = (r as f64) / (u64::MAX as f64); // [0.0, 1.0]
    let factor = 1.0 + jitter * (unit * 2.0 - 1.0); // [1-jitter, 1+jitter]
    let millis = (base.as_millis() as f64 * factor).max(0.0);
    Duration::from_millis(millis as u64)
}

/// Something a caller can classify as worth retrying or not — implemented
/// by each protocol crate for its own error/reply type (SMTP for reply
/// codes, generic I/O for `io::ErrorKind`, ...). `hopf-core` never needs
/// to know what any of these mean; it only asks the question.
pub trait Retryable {
    /// Whether this outcome is worth retrying at all, independent of
    /// whatever budget (attempts/elapsed time) remains.
    fn is_retryable(&self) -> bool;
}

/// Tracks one operation's attempts against a [`RetryPolicy`].
#[derive(Debug, Clone)]
pub struct RetryState {
    policy: RetryPolicy,
    attempt: u32,
    started: Instant,
}

impl RetryState {
    /// Number of attempts recorded so far (0 before the first failure).
    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Wall-clock time since this state was created ([`RetryPolicy::start`]).
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Record a failed attempt and return the delay before the next one —
    /// `None` once the policy's bound (attempt count and/or elapsed time)
    /// has been reached, meaning the caller should give up.
    pub fn next_delay(&mut self) -> Option<Duration> {
        let next_attempt = self.attempt + 1;
        let attempts_ok = match self.policy.bound {
            RetryBound::MaxAttempts(max) => next_attempt <= max,
            RetryBound::Both { max_attempts, .. } => next_attempt <= max_attempts,
            _ => true,
        };
        if !attempts_ok {
            return None;
        }
        let elapsed_ok = match self.policy.bound {
            RetryBound::MaxElapsed(max) => self.started.elapsed() < max,
            RetryBound::Both { max_elapsed, .. } => self.started.elapsed() < max_elapsed,
            _ => true,
        };
        if !elapsed_ok {
            return None;
        }
        self.attempt = next_attempt;
        Some(self.policy.delay_for_attempt(next_attempt))
    }

    /// Combine an outcome's own [`Retryable`] classification with this
    /// state's remaining budget: only consults (and advances)
    /// [`Self::next_delay`] when `outcome` itself says it's worth retrying
    /// at all — a permanent failure never consumes an attempt.
    pub fn should_retry<E: Retryable>(&mut self, outcome: &E) -> Option<Duration> {
        if !outcome.is_retryable() {
            return None;
        }
        self.next_delay()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_for_attempt_doubles_and_caps_with_no_jitter() {
        let p = RetryPolicy::exponential_backoff();
        assert_eq!(p.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(p.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(p.delay_for_attempt(3), Duration::from_secs(4));
        assert_eq!(p.delay_for_attempt(4), Duration::from_secs(8));
        assert_eq!(p.delay_for_attempt(5), Duration::from_secs(16));
        assert_eq!(p.delay_for_attempt(6), Duration::from_secs(30)); // 32s capped
        assert_eq!(p.delay_for_attempt(50), Duration::from_secs(30)); // stays capped
    }

    #[test]
    fn custom_initial_delay_and_multiplier_are_honored() {
        let p = RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(100))
            .with_max_delay(Duration::from_secs(2))
            .with_multiplier(2.0);
        assert_eq!(p.delay_for_attempt(1), Duration::from_millis(100));
        assert_eq!(p.delay_for_attempt(2), Duration::from_millis(200));
        assert_eq!(p.delay_for_attempt(5), Duration::from_millis(1600));
        assert_eq!(p.delay_for_attempt(6), Duration::from_secs(2)); // 3.2s capped
    }

    #[test]
    fn jitter_stays_within_the_configured_fraction() {
        let p = RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_secs(10))
            .with_max_delay(Duration::from_secs(10))
            .with_jitter(0.2);
        let base = 10_000u128;
        for _ in 0..200 {
            let d = p.delay_for_attempt(1).as_millis();
            assert!(
                d >= base * 8 / 10 && d <= base * 12 / 10,
                "delay {d}ms outside ±20% of {base}ms"
            );
        }
    }

    #[test]
    fn max_attempts_bound_stops_after_the_configured_count() {
        let p = RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(1))
            .with_max_attempts(3);
        let mut state = p.start();
        assert!(state.next_delay().is_some()); // attempt 1
        assert!(state.next_delay().is_some()); // attempt 2
        assert!(state.next_delay().is_some()); // attempt 3
        assert!(state.next_delay().is_none(), "should give up after 3 attempts");
        assert_eq!(state.attempt(), 3);
    }

    #[test]
    fn max_elapsed_bound_stops_once_the_window_has_passed() {
        let p = RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(1))
            .with_max_elapsed(Duration::from_millis(30));
        let mut state = p.start();
        assert!(state.next_delay().is_some(), "window just started");
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            state.next_delay().is_none(),
            "should give up once max_elapsed has passed"
        );
    }

    #[test]
    fn both_bound_stops_on_whichever_limit_is_hit_first() {
        let p = RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(1))
            .with_max_attempts(100)
            .with_max_elapsed(Duration::from_millis(30));
        let mut state = p.start();
        assert!(state.next_delay().is_some());
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            state.next_delay().is_none(),
            "elapsed bound should win even though attempts is nowhere near 100"
        );
    }

    #[test]
    fn unlimited_after_max_attempts_clears_the_bound() {
        let p = RetryPolicy::exponential_backoff()
            .with_initial_delay(Duration::from_millis(1))
            .with_max_attempts(1)
            .unlimited();
        let mut state = p.start();
        for _ in 0..10 {
            assert!(state.next_delay().is_some());
        }
    }

    struct Classified(bool);

    impl Retryable for Classified {
        fn is_retryable(&self) -> bool {
            self.0
        }
    }

    #[test]
    fn should_retry_does_not_consume_a_budget_attempt_when_not_retryable() {
        let p = RetryPolicy::exponential_backoff().with_initial_delay(Duration::from_millis(1));
        let mut state = p.start();
        assert!(state.should_retry(&Classified(false)).is_none());
        assert_eq!(state.attempt(), 0, "a non-retryable outcome must not consume an attempt");
        assert!(state.should_retry(&Classified(true)).is_some());
        assert_eq!(state.attempt(), 1);
    }
}
