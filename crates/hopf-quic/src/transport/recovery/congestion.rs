// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! NewReno congestion control (RFC 9002 section 7 / Appendix B).

use std::time::Instant;

/// RFC 9002 section 7.3.2: window halved on entering recovery.
pub const K_LOSS_REDUCTION_FACTOR: f64 = 0.5;

/// RFC 9002 section 7.2: floor on the initial window.
const INITIAL_WINDOW_FLOOR: u64 = 14_720;

/// NewReno congestion controller (no ECN).
#[derive(Debug)]
pub struct CongestionController {
    max_datagram_size: usize,
    minimum_window: u64,
    congestion_window: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    /// `None` means not in a recovery period.
    congestion_recovery_start: Option<Instant>,
}

impl CongestionController {
    /// Create with the RFC 9002 section 7.2 initial window.
    pub fn new(max_datagram_size: usize) -> Self {
        let max_datagram_size = max_datagram_size.max(1);
        let minimum_window = 2 * max_datagram_size as u64;
        let congestion_window = (10 * max_datagram_size as u64)
            .min((2 * max_datagram_size as u64).max(INITIAL_WINDOW_FLOOR));
        Self {
            max_datagram_size,
            minimum_window,
            congestion_window,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            congestion_recovery_start: None,
        }
    }

    /// Whether `bytes` more may be sent without exceeding the congestion window.
    pub fn can_send(&self, bytes: usize) -> bool {
        self.bytes_in_flight + bytes as u64 <= self.congestion_window
    }

    /// Record that an in-flight packet was sent (Appendix B.4).
    pub fn on_packet_sent(&mut self, sent_bytes: usize) {
        self.bytes_in_flight += sent_bytes as u64;
    }

    /// Remove bytes from flight without ACK/loss (Appendix B.9).
    pub fn remove_from_bytes_in_flight(&mut self, sent_bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_bytes as u64);
    }

    /// Record that an in-flight packet was acknowledged (Appendix B.5).
    pub fn on_packet_acked(
        &mut self,
        sent_time: Instant,
        sent_bytes: usize,
        app_or_flow_control_limited: bool,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_bytes as u64);
        if app_or_flow_control_limited {
            return;
        }
        if self.in_congestion_recovery(sent_time) {
            return;
        }
        if self.congestion_window < self.ssthresh {
            self.congestion_window += sent_bytes as u64;
        } else {
            self.congestion_window +=
                (self.max_datagram_size as u64 * sent_bytes as u64) / self.congestion_window.max(1);
        }
    }

    /// Enter recovery on a congestion event (Appendix B.6).
    pub fn on_congestion_event(&mut self, sent_time: Instant, now: Instant) {
        if self.in_congestion_recovery(sent_time) {
            return;
        }
        self.congestion_recovery_start = Some(now);
        self.ssthresh = (self.congestion_window as f64 * K_LOSS_REDUCTION_FACTOR) as u64;
        self.congestion_window = self.ssthresh.max(self.minimum_window);
    }

    fn in_congestion_recovery(&self, sent_time: Instant) -> bool {
        match self.congestion_recovery_start {
            Some(start) => sent_time <= start,
            None => false,
        }
    }

    /// Persistent congestion: drop to the minimum window (section 7.6).
    pub fn on_persistent_congestion(&mut self) {
        self.congestion_window = self.minimum_window;
        self.congestion_recovery_start = None;
    }

    /// Reset path congestion state (RFC 9000 §9.4); leave bytes in flight.
    pub fn reset(&mut self) {
        self.congestion_window = (10 * self.max_datagram_size as u64)
            .min((2 * self.max_datagram_size as u64).max(INITIAL_WINDOW_FLOOR));
        self.ssthresh = u64::MAX;
        self.congestion_recovery_start = None;
    }

    /// Current congestion window in bytes.
    pub fn congestion_window(&self) -> u64 {
        self.congestion_window
    }

    /// Current bytes in flight.
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// Slow-start threshold (`u64::MAX` if still infinite).
    pub fn ssthresh(&self) -> u64 {
        self.ssthresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    #[test]
    fn initial_window_is_bounded_by_floor_and_ten_times_datagram() {
        assert_eq!(CongestionController::new(1200).congestion_window(), 12_000);
        assert_eq!(CongestionController::new(1500).congestion_window(), 14_720);
    }

    #[test]
    fn can_send_respects_window() {
        let mut cc = CongestionController::new(1200);
        assert!(cc.can_send(12_000));
        assert!(!cc.can_send(12_001));
        cc.on_packet_sent(5000);
        assert!(cc.can_send(7000));
        assert!(!cc.can_send(7001));
        assert_eq!(cc.bytes_in_flight(), 5000);
    }

    #[test]
    fn slow_start_grows_by_acked_bytes() {
        let mut cc = CongestionController::new(1200);
        cc.on_packet_sent(1000);
        cc.on_packet_acked(t(100), 1000, false);
        assert_eq!(cc.congestion_window(), 13_000);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn congestion_avoidance_grows_additively() {
        let mut cc = CongestionController::new(1200);
        let base = Instant::now();
        let t100 = base + Duration::from_millis(100);
        let t200 = base + Duration::from_millis(200);
        let t300 = base + Duration::from_millis(300);
        cc.on_congestion_event(t100, t200);
        cc.on_packet_sent(1000);
        cc.on_packet_acked(t300, 1000, false);
        assert_eq!(cc.congestion_window(), 6200);
    }

    #[test]
    fn acked_packet_during_recovery_does_not_grow_window() {
        let mut cc = CongestionController::new(1200);
        let base = Instant::now();
        cc.on_packet_sent(1000);
        cc.on_congestion_event(
            base + Duration::from_millis(100),
            base + Duration::from_millis(200),
        );
        cc.on_packet_acked(base + Duration::from_millis(150), 1000, false);
        assert_eq!(cc.congestion_window(), 6000);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn app_or_flow_control_limited_does_not_grow_window() {
        let mut cc = CongestionController::new(1200);
        cc.on_packet_sent(1000);
        cc.on_packet_acked(t(100), 1000, true);
        assert_eq!(cc.congestion_window(), 12_000);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn congestion_event_halves_window_and_ignores_repeats_within_recovery() {
        let mut cc = CongestionController::new(1200);
        let base = Instant::now();
        cc.on_congestion_event(
            base + Duration::from_millis(100),
            base + Duration::from_millis(200),
        );
        assert_eq!(cc.congestion_window(), 6000);
        assert_eq!(cc.ssthresh(), 6000);
        cc.on_congestion_event(
            base + Duration::from_millis(150),
            base + Duration::from_millis(250),
        );
        assert_eq!(cc.congestion_window(), 6000);
        cc.on_congestion_event(
            base + Duration::from_millis(250),
            base + Duration::from_millis(300),
        );
        assert_eq!(cc.congestion_window(), 3000);
        assert_eq!(cc.ssthresh(), 3000);
    }

    #[test]
    fn minimum_window_floor() {
        let mut cc = CongestionController::new(1200);
        let base = Instant::now();
        cc.on_congestion_event(
            base + Duration::from_millis(100),
            base + Duration::from_millis(200),
        );
        cc.on_congestion_event(
            base + Duration::from_millis(250),
            base + Duration::from_millis(300),
        );
        cc.on_congestion_event(
            base + Duration::from_millis(350),
            base + Duration::from_millis(400),
        );
        assert_eq!(cc.congestion_window(), 2400);
    }

    #[test]
    fn persistent_congestion_drops_to_minimum_window() {
        let mut cc = CongestionController::new(1200);
        cc.on_persistent_congestion();
        assert_eq!(cc.congestion_window(), 2400);
    }

    #[test]
    fn persistent_congestion_clears_recovery_state_allowing_immediate_growth() {
        let mut cc = CongestionController::new(1200);
        let base = Instant::now();
        cc.on_congestion_event(
            base + Duration::from_millis(100),
            base + Duration::from_millis(200),
        );
        cc.on_persistent_congestion();
        cc.on_packet_sent(1000);
        cc.on_packet_acked(base + Duration::from_millis(50), 1000, false);
        assert_eq!(cc.congestion_window(), 3400);
    }
}
