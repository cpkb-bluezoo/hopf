// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Congestion control: NewReno (RFC 9002 section 7 / Appendix B) and
//! CUBIC (RFC 9438), with HyStart++ (RFC 9406) in the slow start they share.

use std::time::{Duration, Instant};

/// RFC 9002 section 7.3.2: window halved on entering recovery.
pub const K_LOSS_REDUCTION_FACTOR: f64 = 0.5;

/// RFC 9002 section 7.2: floor on the initial window.
const INITIAL_WINDOW_FLOOR: u64 = 14_720;

/// RFC 9438 section 5: the cubic scaling constant.
const CUBIC_C: f64 = 0.4;
/// RFC 9438 section 4.6: the window kept on a congestion event.
const CUBIC_BETA: f64 = 0.7;
/// RFC 9438 section 4.3: Reno-friendly additive increase per round trip.
const CUBIC_ALPHA: f64 = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);

/// RFC 9406 section 4.2 constants.
const HS_MIN_RTT_THRESH: Duration = Duration::from_millis(4);
const HS_MAX_RTT_THRESH: Duration = Duration::from_millis(16);
const HS_MIN_RTT_DIVISOR: u32 = 8;
const HS_N_RTT_SAMPLE: u32 = 8;
const HS_CSS_GROWTH_DIVISOR: u64 = 4;
const HS_CSS_ROUNDS: u32 = 5;

/// RFC 9438 state, in units of the maximum datagram size.
#[derive(Debug, Default)]
struct Cubic {
    /// Window at the last congestion event (after fast convergence).
    w_max: f64,
    /// Seconds for the cube to return to `w_max`.
    k: f64,
    /// Start of the current congestion avoidance stage.
    epoch_start: Option<Instant>,
    /// Reno-friendly window estimate.
    w_est: f64,
}

/// RFC 9406 slow start state.
#[derive(Debug)]
struct HyStart {
    /// When the current round began; `None` until the first acknowledgement.
    round_start: Option<Instant>,
    samples_in_round: u32,
    current_round_min_rtt: Duration,
    last_round_min_rtt: Option<Duration>,
    /// In conservative slow start.
    css: bool,
    css_baseline_min_rtt: Duration,
    css_rounds: u32,
}

impl HyStart {
    fn new() -> Self {
        Self {
            round_start: None,
            samples_in_round: 0,
            current_round_min_rtt: Duration::MAX,
            last_round_min_rtt: None,
            css: false,
            css_baseline_min_rtt: Duration::MAX,
            css_rounds: 0,
        }
    }
}

/// Which congestion control algorithm a connection runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionAlgorithm {
    /// RFC 9002 section 7 NewReno.
    NewReno,
    /// RFC 9438 CUBIC with RFC 9406 HyStart++ (the default).
    #[default]
    Cubic,
}

impl std::str::FromStr for CongestionAlgorithm {
    type Err = String;

    /// Parse `"newreno"` or `"cubic"` (any case); anything else is rejected.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "newreno" | "reno" => Ok(Self::NewReno),
            "cubic" => Ok(Self::Cubic),
            other => Err(format!("unknown congestion control algorithm: {other}")),
        }
    }
}

/// Congestion controller (no ECN): NewReno or CUBIC, sharing one slow
/// start with HyStart++.
#[derive(Debug)]
pub struct CongestionController {
    algorithm: CongestionAlgorithm,
    max_datagram_size: usize,
    minimum_window: u64,
    congestion_window: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    /// `None` means not in a recovery period.
    congestion_recovery_start: Option<Instant>,
    cubic: Cubic,
    hystart: HyStart,
}

impl CongestionController {
    /// Create with the RFC 9002 section 7.2 initial window, running
    /// `algorithm`.
    pub fn with_algorithm(max_datagram_size: usize, algorithm: CongestionAlgorithm) -> Self {
        let mut cc = Self::new(max_datagram_size);
        cc.algorithm = algorithm;
        cc
    }

    /// The algorithm in use.
    pub fn algorithm(&self) -> CongestionAlgorithm {
        self.algorithm
    }

    /// CUBIC's W_max: the window at the last congestion event (after fast
    /// convergence), `None` for NewReno or before any event.
    pub fn cubic_w_max(&self) -> Option<u64> {
        match self.algorithm {
            CongestionAlgorithm::Cubic if self.cubic.w_max > 0.0 => {
                Some((self.cubic.w_max * self.max_datagram_size as f64).round() as u64)
            }
            _ => None,
        }
    }

    /// Feed a round-trip time sample (RFC 9406: HyStart++ watches the
    /// per-round minimum).
    pub fn on_rtt_sample(&mut self, latest_rtt: Duration) {
        let hs = &mut self.hystart;
        hs.samples_in_round += 1;
        hs.current_round_min_rtt = hs.current_round_min_rtt.min(latest_rtt);
    }

    fn mss(&self) -> f64 {
        self.max_datagram_size as f64
    }

    /// Slow start with HyStart++ (RFC 9406): grow by the acknowledged
    /// bytes (a quarter of them in conservative slow start), and at the end
    /// of each round compare its minimum RTT with the last round's.
    fn slow_start_on_ack(&mut self, sent_time: Instant, sent_bytes: usize, now: Instant) {
        let growth = if self.hystart.css {
            sent_bytes as u64 / HS_CSS_GROWTH_DIVISOR
        } else {
            sent_bytes as u64
        };
        self.congestion_window += growth;
        let round_over = self.hystart.round_start.is_none_or(|start| sent_time >= start);
        if !round_over {
            return;
        }
        let mut exit_slow_start = false;
        let hs = &mut self.hystart;
        if hs.samples_in_round >= HS_N_RTT_SAMPLE {
            if let Some(last) = hs.last_round_min_rtt {
                let thresh = (last / HS_MIN_RTT_DIVISOR).clamp(HS_MIN_RTT_THRESH, HS_MAX_RTT_THRESH);
                if hs.css {
                    if hs.current_round_min_rtt < hs.css_baseline_min_rtt {
                        // The delay was transient: back to standard slow start.
                        hs.css = false;
                    } else {
                        hs.css_rounds += 1;
                        exit_slow_start = hs.css_rounds >= HS_CSS_ROUNDS;
                    }
                } else if hs.current_round_min_rtt >= last + thresh {
                    hs.css = true;
                    hs.css_baseline_min_rtt = hs.current_round_min_rtt;
                    hs.css_rounds = 0;
                }
            }
            hs.last_round_min_rtt = Some(hs.current_round_min_rtt);
        }
        hs.current_round_min_rtt = Duration::MAX;
        hs.samples_in_round = 0;
        hs.round_start = Some(now);
        if exit_slow_start {
            // Exit slow start without waiting for a loss; congestion
            // avoidance grows from the window reached.
            self.ssthresh = self.congestion_window;
            let cwnd = self.congestion_window as f64 / self.mss();
            self.cubic.epoch_start = None;
            self.cubic.w_est = cwnd;
            if self.cubic.w_max == 0.0 {
                self.cubic.w_max = cwnd;
            }
        }
    }

    /// RFC 9438 sections 4.2 and 4.3: one acknowledgement in congestion
    /// avoidance moves the window towards W_cubic(t + RTT), never slower
    /// than the Reno-friendly estimate.
    fn cubic_on_ack(&mut self, sent_bytes: usize, now: Instant, smoothed_rtt: Duration) {
        let mss = self.mss();
        let cwnd = self.congestion_window as f64 / mss;
        let segs = sent_bytes as f64 / mss;
        let epoch = *self.cubic.epoch_start.get_or_insert(now);
        if self.cubic.w_max == 0.0 {
            // No loss yet (slow start ended by HyStart++): grow from here.
            self.cubic.w_max = cwnd;
            self.cubic.w_est = cwnd;
        }
        let t = now.saturating_duration_since(epoch).as_secs_f64();
        let w_cubic = |t: f64| CUBIC_C * (t - self.cubic.k).powi(3) + self.cubic.w_max;
        self.cubic.w_est += CUBIC_ALPHA * segs / cwnd;
        let new_cwnd = if self.cubic.w_est > w_cubic(t) {
            // Reno-friendly region.
            cwnd.max(self.cubic.w_est)
        } else {
            let target = w_cubic(t + smoothed_rtt.as_secs_f64()).clamp(cwnd, 1.5 * cwnd);
            cwnd + (target - cwnd) / cwnd * segs
        };
        self.congestion_window = (new_cwnd * mss) as u64;
    }

    /// The RFC 9002 section 7.2 initial window for a datagram size.
    pub fn initial_window(max_datagram_size: usize) -> u64 {
        let max_datagram_size = max_datagram_size.max(1) as u64;
        (10 * max_datagram_size).min((2 * max_datagram_size).max(INITIAL_WINDOW_FLOOR))
    }

    /// Whether the controller is in slow start (window below ssthresh).
    pub fn in_slow_start(&self) -> bool {
        self.congestion_window < self.ssthresh
    }

    /// Create with the RFC 9002 section 7.2 initial window.
    pub fn new(max_datagram_size: usize) -> Self {
        let max_datagram_size = max_datagram_size.max(1);
        let minimum_window = 2 * max_datagram_size as u64;
        let congestion_window = Self::initial_window(max_datagram_size);
        Self {
            algorithm: CongestionAlgorithm::NewReno,
            max_datagram_size,
            minimum_window,
            congestion_window,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            congestion_recovery_start: None,
            cubic: Cubic::default(),
            hystart: HyStart::new(),
        }
    }

    /// Open the window wide so a test can study another limit (flow
    /// control, pacing) without the congestion window in the way.
    #[cfg(test)]
    pub(crate) fn set_congestion_window_for_tests(&mut self, window: u64) {
        self.congestion_window = window;
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
        now: Instant,
        smoothed_rtt: Duration,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_bytes as u64);
        if app_or_flow_control_limited {
            return;
        }
        if self.in_congestion_recovery(sent_time) {
            return;
        }
        if self.congestion_window < self.ssthresh {
            self.slow_start_on_ack(sent_time, sent_bytes, now);
            return;
        }
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                self.congestion_window +=
                    (self.max_datagram_size as u64 * sent_bytes as u64) / self.congestion_window.max(1);
            }
            CongestionAlgorithm::Cubic => self.cubic_on_ack(sent_bytes, now, smoothed_rtt),
        }
    }

    /// Enter recovery on a congestion event (Appendix B.6).
    pub fn on_congestion_event(&mut self, sent_time: Instant, now: Instant) {
        if self.in_congestion_recovery(sent_time) {
            return;
        }
        self.congestion_recovery_start = Some(now);
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                self.ssthresh = (self.congestion_window as f64 * K_LOSS_REDUCTION_FACTOR) as u64;
                self.congestion_window = self.ssthresh.max(self.minimum_window);
            }
            CongestionAlgorithm::Cubic => {
                // RFC 9438 sections 4.6 and 4.7: keep beta of the window;
                // a loss before regaining the previous W_max lowers W_max
                // further (fast convergence).
                let mss = self.mss();
                let w = self.congestion_window as f64 / mss;
                self.cubic.w_max = if w < self.cubic.w_max { w * (1.0 + CUBIC_BETA) / 2.0 } else { w };
                self.ssthresh = ((self.congestion_window as f64 * CUBIC_BETA) as u64).max(self.minimum_window);
                self.congestion_window = self.ssthresh;
                let cwnd = self.congestion_window as f64 / mss;
                self.cubic.k = ((self.cubic.w_max - cwnd) / CUBIC_C).max(0.0).cbrt();
                // The cube is timed from the event: recovery lasts a round
                // trip, after which congestion avoidance follows it.
                self.cubic.epoch_start = Some(now);
                self.cubic.w_est = cwnd;
            }
        }
        // A loss ends slow start for HyStart++ too.
        self.hystart.css = false;
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
        self.congestion_window = Self::initial_window(self.max_datagram_size);
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

    fn t(ms: u64) -> Instant {
        Instant::now() + Duration::from_millis(ms)
    }

    /// A `now` after every sent time the NewReno tests use.
    fn far() -> Instant {
        Instant::now() + Duration::from_secs(10)
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
        cc.on_packet_acked(t(100), 1000, false, far(), Duration::from_millis(50));
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
        cc.on_packet_acked(t300, 1000, false, far(), Duration::from_millis(50));
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
        cc.on_packet_acked(base + Duration::from_millis(150), 1000, false, far(), Duration::from_millis(50));
        assert_eq!(cc.congestion_window(), 6000);
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn app_or_flow_control_limited_does_not_grow_window() {
        let mut cc = CongestionController::new(1200);
        cc.on_packet_sent(1000);
        cc.on_packet_acked(t(100), 1000, true, far(), Duration::from_millis(50));
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
        cc.on_packet_acked(base + Duration::from_millis(50), 1000, false, far(), Duration::from_millis(50));
        assert_eq!(cc.congestion_window(), 3400);
    }

    const MDS: usize = 1200;
    const SRTT: Duration = Duration::from_millis(50);

    fn cubic() -> CongestionController {
        CongestionController::with_algorithm(MDS, CongestionAlgorithm::Cubic)
    }

    /// Drive `n` acknowledgements of one datagram each at `now`.
    fn ack_n(cc: &mut CongestionController, n: usize, sent: Instant, now: Instant) {
        for _ in 0..n {
            cc.on_packet_sent(MDS);
            cc.on_packet_acked(sent, MDS, false, now, SRTT);
        }
    }

    /// RFC 9438 section 4.6: on loss the window is reduced to 0.7 of its
    /// size, not halved.
    #[test]
    fn cubic_reduces_the_window_to_seven_tenths_on_loss() {
        let mut cc = cubic();
        let base = Instant::now();
        cc.set_congestion_window_for_tests(100_000);
        cc.on_congestion_event(base, base + Duration::from_millis(1));
        assert_eq!(cc.congestion_window(), 70_000);
        assert_eq!(cc.ssthresh(), 70_000);
        assert_eq!(cc.cubic_w_max(), Some(100_000));
    }

    /// RFC 9438 section 4.2: in congestion avoidance the window follows
    /// W_cubic(t) = C (t - K)^3 + W_max: back at W_max after K seconds and
    /// growing past it along the cube from there.
    #[test]
    fn cubic_grows_along_the_cubic_curve_past_w_max() {
        let mut cc = cubic();
        let base = Instant::now();
        cc.set_congestion_window_for_tests(100_000);
        cc.on_congestion_event(base, base);
        // W_max = 83.33 MSS, K = cbrt(W_max (1 - 0.7) / 0.4) = 3.97 s.
        // One and a half seconds past K (plus the 50 ms RTT look-ahead)
        // the curve is at 0.4 x 1.55^3 + W_max = 84.8 MSS, 101 800 bytes.
        let later = base + Duration::from_millis(5470);
        ack_n(&mut cc, 2000, base + Duration::from_millis(10), later);
        let w = cc.congestion_window();
        assert!(w > 100_500 && w < 102_500, "window {w} not on the cubic curve (about 101 200)");
    }

    /// RFC 9438 section 4.3: the window never grows slower than Reno would
    /// (AIMD with alpha = 3 (1 - beta) / (1 + beta)).
    #[test]
    fn cubic_window_has_a_reno_friendly_floor() {
        let mut cc = cubic();
        let base = Instant::now();
        cc.set_congestion_window_for_tests(24_000);
        cc.on_congestion_event(base, base);
        assert_eq!(cc.congestion_window(), 16_800);
        // Right after the loss the cubic curve is flat (K = 2.47 s), so
        // 200 acknowledgements lift the window along the Reno-friendly
        // estimate: alpha per window of acknowledgements, W^2 = 14^2 +
        // 2 x 0.53 x 200, about 20.2 MSS or 24 200 bytes.
        let soon = base + Duration::from_millis(10);
        ack_n(&mut cc, 200, base + Duration::from_millis(1), soon);
        let w = cc.congestion_window();
        assert!(w > 23_000 && w < 26_000, "window {w} not on the Reno-friendly floor (about 24 200)");
    }

    /// RFC 9438 section 4.7: a loss before the window reaches the previous
    /// W_max lowers W_max further (fast convergence).
    #[test]
    fn cubic_fast_convergence_lowers_w_max() {
        let mut cc = cubic();
        let base = Instant::now();
        cc.set_congestion_window_for_tests(100_000);
        cc.on_congestion_event(base, base);
        cc.set_congestion_window_for_tests(70_000);
        cc.on_congestion_event(base + Duration::from_secs(1), base + Duration::from_secs(1));
        assert_eq!(cc.cubic_w_max(), Some(59_500), "W_max = 70 000 x (1 + 0.7) / 2");
        assert_eq!(cc.congestion_window(), 49_000);
    }

    /// One HyStart++ round: eight RTT samples around `min_rtt`, then an
    /// acknowledgement of a packet sent after the round began.
    fn hystart_round(cc: &mut CongestionController, min_rtt: Duration, at: &mut Instant) {
        for i in 0..8u32 {
            cc.on_rtt_sample(min_rtt + Duration::from_millis(u64::from(i % 3)));
        }
        let sent = *at + Duration::from_millis(1);
        *at += min_rtt + Duration::from_millis(5);
        cc.on_packet_sent(MDS);
        cc.on_packet_acked(sent, MDS, false, *at, min_rtt);
    }

    /// RFC 9406: a per-round minimum RTT rising by more than the threshold
    /// (last round's minimum / 8, clamped to 4..16 ms) makes slow start
    /// conservative, growing at a quarter of the rate, and five such
    /// rounds end it without a loss.
    #[test]
    fn hystart_rising_rtt_turns_slow_start_conservative_then_ends_it() {
        let mut cc = cubic();
        let mut at = Instant::now();
        assert!(cc.in_slow_start());
        hystart_round(&mut cc, Duration::from_millis(32), &mut at);
        let before = cc.congestion_window();
        ack_n(&mut cc, 1, at - Duration::from_millis(1), at);
        assert_eq!(cc.congestion_window(), before + MDS as u64, "standard slow start grows by the acknowledged bytes");
        // The minimum rises 5 ms a round, past the 4 ms threshold.
        hystart_round(&mut cc, Duration::from_millis(37), &mut at);
        let before = cc.congestion_window();
        ack_n(&mut cc, 1, at - Duration::from_millis(1), at);
        assert_eq!(cc.congestion_window(), before + MDS as u64 / 4, "conservative slow start grows at a quarter of the rate");
        assert!(cc.in_slow_start());
        for r in 0..5u64 {
            hystart_round(&mut cc, Duration::from_millis(37 + r), &mut at);
        }
        assert!(!cc.in_slow_start(), "slow start not ended after five conservative rounds");
        assert_eq!(cc.ssthresh(), cc.congestion_window());
    }

    /// RFC 9406 section 4.2: if the minimum RTT falls back below the level
    /// that started conservative slow start, standard slow start resumes.
    #[test]
    fn hystart_falling_rtt_resumes_standard_slow_start() {
        let mut cc = cubic();
        let mut at = Instant::now();
        hystart_round(&mut cc, Duration::from_millis(32), &mut at);
        hystart_round(&mut cc, Duration::from_millis(37), &mut at);
        let before = cc.congestion_window();
        ack_n(&mut cc, 1, at - Duration::from_millis(1), at);
        assert_eq!(cc.congestion_window(), before + MDS as u64 / 4);
        hystart_round(&mut cc, Duration::from_millis(31), &mut at);
        let before = cc.congestion_window();
        ack_n(&mut cc, 1, at - Duration::from_millis(1), at);
        assert_eq!(cc.congestion_window(), before + MDS as u64, "standard slow start did not resume");
        assert!(cc.in_slow_start());
    }
}
