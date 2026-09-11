// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-connection loss detection (RFC 9002 section 6 / Appendix A).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::transport::types::SpaceId;

use super::congestion::CongestionController;
use super::rtt::RttEstimator;
use super::sent_packet::{RecoverableFrame, SentPacket};

/// RFC 9002 §6.1.1: reordering tolerance in packets.
pub const K_PACKET_THRESHOLD: u64 = 3;

/// RFC 9002 §6.1.2: reordering tolerance in time (RTT multiplier).
pub const K_TIME_THRESHOLD: f64 = 9.0 / 8.0;

/// RFC 9002 Appendix A.2: timer granularity.
pub const K_GRANULARITY: Duration = Duration::from_millis(1);

/// RFC 9002 §7.6.1: persistent congestion duration multiplier.
pub const K_PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// Result of [`LossDetector::on_ack_received`].
#[derive(Debug)]
pub struct AckResult {
    /// Packets newly acknowledged by this ACK.
    pub newly_acked: Vec<SentPacket>,
    /// Packets newly declared lost while processing this ACK.
    pub newly_lost: Vec<SentPacket>,
}

/// Result of [`LossDetector::on_loss_detection_timeout`].
#[derive(Debug)]
pub struct TimeoutResult {
    /// Packets lost by time-threshold detection (empty if PTO).
    pub newly_lost: Vec<SentPacket>,
    /// Space the loss was detected in (`None` if PTO).
    pub loss_space: Option<SpaceId>,
    /// Space a probe should be sent in (`None` if time-threshold loss).
    pub probe_space: Option<SpaceId>,
}

#[derive(Debug)]
struct SpaceState {
    sent: BTreeMap<u64, SentPacket>,
    ack_eliciting_in_flight: usize,
    largest_acked: Option<u64>,
    time_of_last_ack_eliciting: Option<Instant>,
    loss_time: Option<Instant>,
}

impl SpaceState {
    fn new() -> Self {
        Self {
            sent: BTreeMap::new(),
            ack_eliciting_in_flight: 0,
            largest_acked: None,
            time_of_last_ack_eliciting: None,
            loss_time: None,
        }
    }
}

/// Loss detector driving one [`RttEstimator`] and one [`CongestionController`].
#[derive(Debug)]
pub struct LossDetector {
    spaces: [SpaceState; 3],
    rtt: RttEstimator,
    congestion: CongestionController,
    pto_count: u32,
    handshake_confirmed: bool,
    first_rtt_sample: Option<Instant>,
}

impl LossDetector {
    /// Create a loss detector.
    pub fn new(max_datagram_size: usize) -> Self {
        Self {
            spaces: [SpaceState::new(), SpaceState::new(), SpaceState::new()],
            rtt: RttEstimator::new(),
            congestion: CongestionController::new(max_datagram_size),
            pto_count: 0,
            handshake_confirmed: false,
            first_rtt_sample: None,
        }
    }

    /// RTT estimator.
    pub fn rtt(&self) -> &RttEstimator {
        &self.rtt
    }

    /// Congestion controller.
    pub fn congestion(&self) -> &CongestionController {
        &self.congestion
    }

    /// Mutable congestion controller (for `can_send` gating).
    pub fn congestion_mut(&mut self) -> &mut CongestionController {
        &mut self.congestion
    }

    /// Record that the handshake is confirmed (RFC 9001 §4.1.2).
    pub fn set_handshake_confirmed(&mut self, confirmed: bool) {
        self.handshake_confirmed = confirmed;
    }

    /// Whether the handshake is confirmed.
    pub fn handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    /// Record that a packet was sent (Appendix A.5 `OnPacketSent`).
    pub fn on_packet_sent(
        &mut self,
        space: SpaceId,
        packet_number: u64,
        now: Instant,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        frames: Vec<RecoverableFrame>,
    ) {
        let packet = SentPacket::new(
            packet_number,
            now,
            ack_eliciting,
            in_flight,
            sent_bytes,
            frames,
        );
        let sp = self.space_mut(space);
        if ack_eliciting && in_flight {
            sp.ack_eliciting_in_flight += 1;
        }
        if in_flight && ack_eliciting {
            sp.time_of_last_ack_eliciting = Some(now);
        }
        sp.sent.insert(packet_number, packet);
        if in_flight {
            self.congestion.on_packet_sent(sent_bytes);
        }
    }

    /// Process a received ACK frame (Appendix A.7 `OnAckReceived`).
    pub fn on_ack_received(
        &mut self,
        space: SpaceId,
        largest_acked: u64,
        ack_delay: Duration,
        ack_ranges: &[(u64, u64)],
        max_ack_delay: Duration,
        now: Instant,
        peer_address_validated: bool,
    ) -> AckResult {
        {
            let sp = self.space_mut(space);
            sp.largest_acked = Some(match sp.largest_acked {
                Some(cur) => cur.max(largest_acked),
                None => largest_acked,
            });
        }

        let newly_acked = self.detect_and_remove_acked(space, ack_ranges);
        if newly_acked.is_empty() {
            return AckResult {
                newly_acked,
                newly_lost: Vec::new(),
            };
        }

        let largest_newly_acked = newly_acked.last().unwrap();
        if largest_newly_acked.packet_number == largest_acked
            && newly_acked.iter().any(|p| p.ack_eliciting)
        {
            let sample = now.saturating_duration_since(largest_newly_acked.time_sent);
            self.rtt
                .on_rtt_sample(sample, ack_delay, max_ack_delay, self.handshake_confirmed);
            if self.first_rtt_sample.is_none() {
                self.first_rtt_sample = Some(now);
            }
        }

        let newly_lost = self.detect_and_remove_lost(space, now);
        self.on_packets_lost(&newly_lost, max_ack_delay, now);

        for acked in &newly_acked {
            if acked.in_flight {
                self.congestion
                    .on_packet_acked(acked.time_sent, acked.sent_bytes, false);
            }
        }

        if peer_address_validated {
            self.pto_count = 0;
        }

        AckResult {
            newly_acked,
            newly_lost,
        }
    }

    fn detect_and_remove_acked(
        &mut self,
        space: SpaceId,
        ack_ranges: &[(u64, u64)],
    ) -> Vec<SentPacket> {
        let sp = self.space_mut(space);
        let mut newly_acked = BTreeMap::new();
        for &(low, high) in ack_ranges {
            if low > high {
                continue;
            }
            let keys: Vec<u64> = sp.sent.range(low..=high).map(|(k, _)| *k).collect();
            for pn in keys {
                if let Some(packet) = sp.sent.remove(&pn) {
                    if packet.ack_eliciting && packet.in_flight {
                        sp.ack_eliciting_in_flight =
                            sp.ack_eliciting_in_flight.saturating_sub(1);
                    }
                    newly_acked.insert(pn, packet);
                }
            }
        }
        newly_acked.into_values().collect()
    }

    fn detect_and_remove_lost(&mut self, space: SpaceId, now: Instant) -> Vec<SentPacket> {
        let largest_acked = match self.space(space).largest_acked {
            Some(v) => v,
            None => return Vec::new(),
        };

        let latest = self.rtt.latest_rtt();
        let smoothed = self.rtt.smoothed_rtt();
        let base_ms = latest.max(smoothed).as_millis() as f64;
        let loss_delay =
            Duration::from_millis((K_TIME_THRESHOLD * base_ms).max(1.0) as u64).max(K_GRANULARITY);
        let lost_send_time = now.checked_sub(loss_delay);

        let sp = self.space_mut(space);
        sp.loss_time = None;

        let candidates: Vec<u64> = sp.sent.range(..=largest_acked).map(|(k, _)| *k).collect();
        let mut lost = Vec::new();
        for pn in candidates {
            let Some(packet) = sp.sent.get(&pn) else {
                continue;
            };
            let time_lost = lost_send_time
                .map(|t| packet.time_sent <= t)
                .unwrap_or(false);
            let packet_lost = largest_acked >= packet.packet_number + K_PACKET_THRESHOLD;
            if time_lost || packet_lost {
                let packet = sp.sent.remove(&pn).unwrap();
                if packet.ack_eliciting && packet.in_flight {
                    sp.ack_eliciting_in_flight = sp.ack_eliciting_in_flight.saturating_sub(1);
                }
                lost.push(packet);
            } else {
                let candidate = packet.time_sent + loss_delay;
                sp.loss_time = Some(match sp.loss_time {
                    Some(cur) => cur.min(candidate),
                    None => candidate,
                });
            }
        }
        lost
    }

    fn on_packets_lost(
        &mut self,
        lost: &[SentPacket],
        max_ack_delay: Duration,
        now: Instant,
    ) {
        if lost.is_empty() {
            return;
        }
        let mut sent_time_of_last_loss: Option<Instant> = None;
        for packet in lost {
            if packet.in_flight {
                self.congestion
                    .remove_from_bytes_in_flight(packet.sent_bytes);
                sent_time_of_last_loss = Some(match sent_time_of_last_loss {
                    Some(t) => t.max(packet.time_sent),
                    None => packet.time_sent,
                });
            }
        }
        if let Some(sent) = sent_time_of_last_loss {
            self.congestion.on_congestion_event(sent, now);
        }

        if self.first_rtt_sample.is_none() {
            return;
        }
        if self.is_in_persistent_congestion(lost, max_ack_delay) {
            self.congestion.on_persistent_congestion();
        }
    }

    fn is_in_persistent_congestion(
        &self,
        lost: &[SentPacket],
        max_ack_delay: Duration,
    ) -> bool {
        let Some(first_rtt) = self.first_rtt_sample else {
            return false;
        };
        let smoothed_ms = self.rtt.smoothed_rtt().as_millis() as u64;
        let rttvar_ms = self.rtt.rtt_var().as_millis() as u64;
        let gran_ms = K_GRANULARITY.as_millis() as u64;
        let max_ack_ms = max_ack_delay.as_millis() as u64;
        let duration_threshold = Duration::from_millis(
            (smoothed_ms + (4 * rttvar_ms).max(gran_ms) + max_ack_ms)
                * u64::from(K_PERSISTENT_CONGESTION_THRESHOLD),
        );

        let mut run_first_ack_eliciting: Option<&SentPacket> = None;
        let mut previous: Option<&SentPacket> = None;
        for packet in lost {
            if packet.time_sent <= first_rtt {
                run_first_ack_eliciting = None;
                previous = None;
                continue;
            }
            let continues_run = previous
                .map(|p| packet.packet_number == p.packet_number + 1)
                .unwrap_or(false);
            if !continues_run {
                run_first_ack_eliciting = None;
            }
            if packet.ack_eliciting {
                match run_first_ack_eliciting {
                    None => run_first_ack_eliciting = Some(packet),
                    Some(first) => {
                        if packet
                            .time_sent
                            .saturating_duration_since(first.time_sent)
                            >= duration_threshold
                        {
                            return true;
                        }
                    }
                }
            }
            previous = Some(packet);
        }
        false
    }

    /// When the loss detection timer should next fire (Appendix A.8).
    pub fn loss_detection_timeout(
        &self,
        server_at_anti_amplification_limit: bool,
        peer_address_validated: bool,
        has_handshake_keys: bool,
        max_ack_delay: Duration,
        now: Instant,
    ) -> Option<Instant> {
        if let Some(t) = self.earliest_loss_time() {
            return Some(t);
        }
        if server_at_anti_amplification_limit {
            return None;
        }
        if !self.has_ack_eliciting_in_flight() && peer_address_validated {
            return None;
        }
        self.pto_time_and_space(peer_address_validated, has_handshake_keys, max_ack_delay, now)
            .0
    }

    fn earliest_loss_time(&self) -> Option<Instant> {
        self.spaces
            .iter()
            .filter_map(|s| s.loss_time)
            .min()
    }

    fn earliest_loss_space(&self) -> SpaceId {
        let mut best: Option<(Instant, SpaceId)> = None;
        for (i, sp) in self.spaces.iter().enumerate() {
            if let Some(t) = sp.loss_time {
                let space = index_to_space(i);
                best = Some(match best {
                    Some((cur, s)) if t >= cur => (cur, s),
                    _ => (t, space),
                });
            }
        }
        best.map(|(_, s)| s).unwrap_or(SpaceId::Initial)
    }

    fn has_ack_eliciting_in_flight(&self) -> bool {
        self.spaces.iter().any(|s| s.ack_eliciting_in_flight > 0)
    }

    fn has_ack_eliciting_in_flight_space(&self, space: SpaceId) -> bool {
        self.space(space).ack_eliciting_in_flight > 0
    }

    fn pto_time_and_space(
        &self,
        _peer_address_validated: bool,
        has_handshake_keys: bool,
        max_ack_delay: Duration,
        now: Instant,
    ) -> (Option<Instant>, SpaceId) {
        let smoothed_ms = self.rtt.smoothed_rtt().as_millis() as u64;
        let rttvar_ms = self.rtt.rtt_var().as_millis() as u64;
        let gran_ms = K_GRANULARITY.as_millis() as u64;
        let base_ms = smoothed_ms + (4 * rttvar_ms).max(gran_ms);
        let duration = Duration::from_millis(base_ms << self.pto_count.min(16));

        if !self.has_ack_eliciting_in_flight() {
            let space = if has_handshake_keys {
                SpaceId::Handshake
            } else {
                SpaceId::Initial
            };
            return (Some(now + duration), space);
        }

        let mut pto_timeout: Option<Instant> = None;
        let mut pto_space = SpaceId::Initial;
        for space in [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data] {
            if !self.has_ack_eliciting_in_flight_space(space) {
                continue;
            }
            let mut level_duration = duration;
            if space == SpaceId::Data {
                if !self.handshake_confirmed {
                    return (pto_timeout, pto_space);
                }
                level_duration += max_ack_delay * (1u32 << self.pto_count.min(16));
            }
            let Some(last) = self.space(space).time_of_last_ack_eliciting else {
                continue;
            };
            let candidate = last + level_duration;
            if pto_timeout.map(|t| candidate < t).unwrap_or(true) {
                pto_timeout = Some(candidate);
                pto_space = space;
            }
        }
        (pto_timeout, pto_space)
    }

    /// Handle loss detection timer expiry (Appendix A.9).
    pub fn on_loss_detection_timeout(
        &mut self,
        peer_address_validated: bool,
        has_handshake_keys: bool,
        max_ack_delay: Duration,
        now: Instant,
    ) -> TimeoutResult {
        if self.earliest_loss_time().is_some() {
            let space = self.earliest_loss_space();
            let lost = self.detect_and_remove_lost(space, now);
            self.on_packets_lost(&lost, max_ack_delay, now);
            return TimeoutResult {
                newly_lost: lost,
                loss_space: Some(space),
                probe_space: None,
            };
        }

        let (_, probe_space) =
            self.pto_time_and_space(peer_address_validated, has_handshake_keys, max_ack_delay, now);
        self.pto_count = self.pto_count.saturating_add(1);
        TimeoutResult {
            newly_lost: Vec::new(),
            loss_space: None,
            probe_space: Some(probe_space),
        }
    }

    /// Discard all tracked state for a packet number space (Appendix A.11).
    pub fn discard_packet_number_space(&mut self, space: SpaceId) {
        let sp = self.space_mut(space);
        let in_flight: Vec<usize> = sp
            .sent
            .values()
            .filter(|p| p.in_flight)
            .map(|p| p.sent_bytes)
            .collect();
        sp.sent.clear();
        sp.ack_eliciting_in_flight = 0;
        sp.time_of_last_ack_eliciting = None;
        sp.loss_time = None;
        for bytes in in_flight {
            self.congestion.remove_from_bytes_in_flight(bytes);
        }
        self.pto_count = 0;
    }

    fn space(&self, id: SpaceId) -> &SpaceState {
        &self.spaces[space_index(id)]
    }

    fn space_mut(&mut self, id: SpaceId) -> &mut SpaceState {
        &mut self.spaces[space_index(id)]
    }
}

fn space_index(id: SpaceId) -> usize {
    match id {
        SpaceId::Initial => 0,
        SpaceId::Handshake => 1,
        SpaceId::Data => 2,
    }
}

fn index_to_space(i: usize) -> SpaceId {
    match i {
        0 => SpaceId::Initial,
        1 => SpaceId::Handshake,
        _ => SpaceId::Data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Instant {
        Instant::now()
    }

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    #[test]
    fn on_packet_sent_tracks_bytes_in_flight() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.on_packet_sent(SpaceId::Data, 0, at(b, 100), true, true, 500, vec![]);
        assert_eq!(d.congestion().bytes_in_flight(), 500);
    }

    #[test]
    fn ack_acknowledges_packet_and_takes_rtt_sample() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.on_packet_sent(SpaceId::Data, 0, at(b, 100), true, true, 500, vec![]);
        let result = d.on_ack_received(
            SpaceId::Data,
            0,
            Duration::ZERO,
            &[(0, 0)],
            Duration::from_millis(25),
            at(b, 150),
            true,
        );
        assert_eq!(result.newly_acked.len(), 1);
        assert_eq!(result.newly_acked[0].packet_number, 0);
        assert!(result.newly_lost.is_empty());
        assert_eq!(d.rtt().latest_rtt(), Duration::from_millis(50));
        assert_eq!(d.congestion().bytes_in_flight(), 0);
    }

    #[test]
    fn packet_threshold_loss_detection() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.on_packet_sent(SpaceId::Initial, 0, at(b, 0), true, true, 50, vec![]);
        d.on_ack_received(
            SpaceId::Initial,
            0,
            Duration::ZERO,
            &[(0, 0)],
            Duration::from_millis(25),
            at(b, 200),
            true,
        );

        d.on_packet_sent(SpaceId::Data, 0, at(b, 1000), true, true, 100, vec![]);
        d.on_packet_sent(SpaceId::Data, 1, at(b, 1000), true, true, 100, vec![]);
        d.on_packet_sent(SpaceId::Data, 2, at(b, 1000), true, true, 100, vec![]);
        d.on_packet_sent(SpaceId::Data, 3, at(b, 1005), true, true, 100, vec![]);

        let result = d.on_ack_received(
            SpaceId::Data,
            3,
            Duration::ZERO,
            &[(3, 3)],
            Duration::from_millis(25),
            at(b, 1010),
            true,
        );
        assert_eq!(result.newly_acked.len(), 1);
        assert_eq!(result.newly_lost.len(), 1);
        assert_eq!(result.newly_lost[0].packet_number, 0);
    }

    #[test]
    fn time_threshold_loss_detection() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.on_packet_sent(SpaceId::Initial, 0, at(b, 0), true, true, 50, vec![]);
        d.on_ack_received(
            SpaceId::Initial,
            0,
            Duration::ZERO,
            &[(0, 0)],
            Duration::from_millis(25),
            at(b, 50),
            true,
        );

        d.on_packet_sent(SpaceId::Data, 0, at(b, 1000), true, true, 100, vec![]);
        d.on_packet_sent(SpaceId::Data, 1, at(b, 1000), true, true, 100, vec![]);
        d.on_packet_sent(SpaceId::Data, 2, at(b, 1300), true, true, 100, vec![]);

        let result = d.on_ack_received(
            SpaceId::Data,
            2,
            Duration::ZERO,
            &[(2, 2)],
            Duration::from_millis(25),
            at(b, 1350),
            true,
        );
        assert_eq!(result.newly_acked.len(), 1);
        assert_eq!(result.newly_lost.len(), 2);
        let lost_pns: Vec<u64> = result.newly_lost.iter().map(|p| p.packet_number).collect();
        assert!(lost_pns.contains(&0));
        assert!(lost_pns.contains(&1));
    }

    #[test]
    fn no_timeout_when_nothing_ack_eliciting_in_flight() {
        let d = LossDetector::new(1200);
        let b = base();
        assert!(d
            .loss_detection_timeout(false, true, true, Duration::from_millis(25), at(b, 1000))
            .is_none());
    }

    #[test]
    fn pto_timeout_computation_and_backoff() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.set_handshake_confirmed(true);
        d.on_packet_sent(SpaceId::Data, 0, at(b, 1000), true, true, 100, vec![]);

        let first = d
            .loss_detection_timeout(false, true, true, Duration::from_millis(25), at(b, 1000))
            .unwrap();
        assert_eq!(first, at(b, 2022));

        let result =
            d.on_loss_detection_timeout(true, true, Duration::from_millis(25), at(b, 2022));
        assert!(result.newly_lost.is_empty());
        assert_eq!(result.probe_space, Some(SpaceId::Data));

        let second = d
            .loss_detection_timeout(false, true, true, Duration::from_millis(25), at(b, 2022))
            .unwrap();
        assert_eq!(second, at(b, 3044));
    }

    #[test]
    fn discard_packet_number_space_clears_state() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.on_packet_sent(SpaceId::Initial, 0, at(b, 1000), true, true, 300, vec![]);
        assert_eq!(d.congestion().bytes_in_flight(), 300);
        d.discard_packet_number_space(SpaceId::Initial);
        assert_eq!(d.congestion().bytes_in_flight(), 0);
        let result = d.on_ack_received(
            SpaceId::Initial,
            0,
            Duration::ZERO,
            &[(0, 0)],
            Duration::from_millis(25),
            at(b, 1100),
            true,
        );
        assert!(result.newly_acked.is_empty());
    }

    #[test]
    fn loss_detection_timeout_notifies_congestion_controller() {
        let mut d = LossDetector::new(1200);
        let b = base();
        d.on_packet_sent(SpaceId::Initial, 0, at(b, 0), true, true, 50, vec![]);
        d.on_ack_received(
            SpaceId::Initial,
            0,
            Duration::ZERO,
            &[(0, 0)],
            Duration::from_millis(25),
            at(b, 200),
            true,
        );

        d.on_packet_sent(SpaceId::Data, 0, at(b, 1000), true, true, 100, vec![]);
        d.on_packet_sent(SpaceId::Data, 1, at(b, 1050), false, true, 50, vec![]);
        d.on_ack_received(
            SpaceId::Data,
            1,
            Duration::ZERO,
            &[(1, 1)],
            Duration::from_millis(25),
            at(b, 1100),
            true,
        );

        let result =
            d.on_loss_detection_timeout(true, true, Duration::from_millis(25), at(b, 1300));
        assert_eq!(result.newly_lost.len(), 1);
        // Initial ACK grew the window by 50 (unlike Gumdrop's millis-0
        // InCongestionRecovery quirk), then pn1's ACK grew by another 50:
        // 12000+50+50=12100, halved on loss -> 6050.
        assert_eq!(d.congestion().congestion_window(), 6050);
    }
}
