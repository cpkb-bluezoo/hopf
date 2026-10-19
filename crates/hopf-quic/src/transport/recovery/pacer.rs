// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Send pacing (RFC 9002 section 7.7): a token bucket that spreads stream
//! data over the round trip instead of releasing a whole congestion
//! window in one burst.
//!
//! Credit accrues at the pacing rate, 1.25 times the congestion window per
//! smoothed round trip (twice during slow start). From idle a burst of up
//! to the initial window may leave at once; while data is in flight credit
//! is capped at one datagram plus one timer tick's worth, so at the rates
//! where pacing matters each wake-up releases a datagram or two rather than
//! a batch, while a fast path is not held to the wake-up frequency. Nothing
//! is paced before the first RTT sample.

use std::time::{Duration, Instant};

/// The finest interval the driver's timer can be relied on for: one tick
/// of credit may accrue beyond a single datagram while data is in flight.
const TIMER_TICK: Duration = Duration::from_millis(1);

/// Token-bucket pacer for stream data.
#[derive(Debug)]
pub struct Pacer {
    max_datagram_size: u64,
    initial_window: u64,
    /// Bytes that may leave now.
    credit: u64,
    /// When credit was last accrued.
    last_refill: Option<Instant>,
    /// When enough credit for the datagram last refused will exist.
    deadline: Option<Instant>,
}

impl Pacer {
    /// Create a pacer with a full idle burst available.
    pub fn new(max_datagram_size: usize, initial_window: u64) -> Self {
        Self {
            max_datagram_size: max_datagram_size.max(1) as u64,
            initial_window,
            credit: initial_window,
            last_refill: None,
            deadline: None,
        }
    }

    /// Pacing rate in bytes per second.
    fn rate(congestion_window: u64, smoothed_rtt: Duration, slow_start: bool) -> f64 {
        let factor = if slow_start { 2.0 } else { 1.25 };
        let rtt = smoothed_rtt.max(Duration::from_millis(1)).as_secs_f64();
        (congestion_window as f64 * factor / rtt).max(1.0)
    }

    /// Whether `bytes` may leave at `now`. Credit for the time since the
    /// last call accrues first, at the current rate; from idle the full
    /// initial-window burst is granted. When the answer is no, the moment
    /// enough credit will exist is recorded as [`Self::deadline`].
    // Each argument is one independent input to the rate or the cap.
    #[allow(clippy::too_many_arguments)]
    pub fn allow(
        &mut self,
        now: Instant,
        bytes: usize,
        congestion_window: u64,
        smoothed_rtt: Duration,
        slow_start: bool,
        bytes_in_flight: u64,
        has_rtt_sample: bool,
    ) -> bool {
        if !has_rtt_sample {
            self.deadline = None;
            return true;
        }
        let rate = Self::rate(congestion_window, smoothed_rtt, slow_start);
        if bytes_in_flight == 0 {
            // From idle: a burst of up to the initial window.
            self.credit = self.credit.max(self.initial_window);
        } else if let Some(last) = self.last_refill {
            // In flight: accrue, but never above one datagram plus one
            // timer tick of credit, so releases stay small at the rates
            // where pacing matters.
            let accrued = (rate * now.saturating_duration_since(last).as_secs_f64()) as u64;
            let cap = self.max_datagram_size + (rate * TIMER_TICK.as_secs_f64()) as u64;
            self.credit = (self.credit + accrued).min(cap.max(self.credit));
        }
        self.last_refill = Some(now);
        if self.credit >= bytes as u64 {
            self.deadline = None;
            return true;
        }
        let missing = (bytes as u64 - self.credit) as f64;
        self.deadline = Some(now + Duration::from_secs_f64(missing / rate));
        false
    }

    /// Charge a datagram that left.
    pub fn on_sent(&mut self, bytes: usize) {
        self.credit = self.credit.saturating_sub(bytes as u64);
    }

    /// When the datagram last refused may leave, if one was refused.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MDS: usize = 1200;
    const IW: u64 = 12_000;
    const RTT: Duration = Duration::from_millis(100);

    /// From idle a whole initial window leaves at once, then the next
    /// datagram waits for credit at the slow-start rate.
    #[test]
    fn idle_burst_then_spacing() {
        let now = Instant::now();
        let mut p = Pacer::new(MDS, IW);
        let mut in_flight = 0u64;
        let mut sent = 0;
        while p.allow(now, MDS, 120_000, RTT, true, in_flight, true) {
            p.on_sent(MDS);
            in_flight += MDS as u64;
            sent += 1;
        }
        assert_eq!(sent, 10, "burst of one initial window");
        // Rate 2 x 120000 / 0.1 s = 2.4 MB/s: a datagram every 0.5 ms.
        let deadline = p.deadline().expect("deadline");
        assert!(deadline > now && deadline <= now + Duration::from_millis(1), "{:?}", deadline - now);
        assert!(!p.allow(now + Duration::from_micros(100), MDS, 120_000, RTT, true, in_flight, true));
        assert!(p.allow(now + Duration::from_millis(1), MDS, 120_000, RTT, true, in_flight, true));
    }

    /// While data is in flight, however long the wake-up took, at most
    /// one datagram plus one timer tick's worth is released: at 2.4 MB/s
    /// that is 1200 + 2400 bytes, three datagrams.
    #[test]
    fn in_flight_releases_stay_small() {
        let now = Instant::now();
        let mut p = Pacer::new(MDS, IW);
        while p.allow(now, MDS, 120_000, RTT, true, 1, true) {
            p.on_sent(MDS);
        }
        let late = now + Duration::from_millis(50);
        let mut released = 0;
        while p.allow(late, MDS, 120_000, RTT, true, 12_000, true) {
            p.on_sent(MDS);
            released += 1;
        }
        assert_eq!(released, 3);
        // At a tenth of the rate a late wake-up releases just one.
        let mut slow = Pacer::new(MDS, IW);
        while slow.allow(now, MDS, 12_000, RTT, true, 1, true) {
            slow.on_sent(MDS);
        }
        let mut released = 0;
        while slow.allow(late, MDS, 12_000, RTT, true, 12_000, true) {
            slow.on_sent(MDS);
            released += 1;
        }
        assert_eq!(released, 1);
    }

    /// Nothing is paced before the first RTT sample.
    #[test]
    fn unpaced_without_an_rtt_sample() {
        let now = Instant::now();
        let mut p = Pacer::new(MDS, IW);
        for _ in 0..100 {
            assert!(p.allow(now, MDS, 12_000, RTT, true, 50_000, false));
            p.on_sent(MDS);
        }
        assert!(p.deadline().is_none());
    }

    /// Congestion avoidance paces at 1.25 windows per round trip.
    #[test]
    fn congestion_avoidance_rate() {
        let now = Instant::now();
        let mut p = Pacer::new(MDS, IW);
        p.on_sent(IW as usize);
        assert!(!p.allow(now, MDS, 120_000, RTT, false, 1, true));
        // 1.25 x 120000 / 0.1 s = 1.5 MB/s: 1200 bytes take 0.8 ms.
        let wait = p.deadline().unwrap() - now;
        assert!(wait > Duration::from_micros(700) && wait < Duration::from_micros(900), "{wait:?}");
    }
}
