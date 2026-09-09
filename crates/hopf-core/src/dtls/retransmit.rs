// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS flight-based retransmission (RFC 9147 §5.7's timeout-and-retransmit
//! model — RFC 9147 doesn't mandate specific backoff values; this follows
//! DTLS 1.2's well-established RFC 6347 §4.2.4.1 guidance: start at 1s,
//! double on each retransmit, cap at 60s). No ACK-message support (RFC 9147
//! §7) — a real peer's ACKs, if any, are simply not consumed; recovery is
//! blind retransmit-on-timeout only, which RFC 9147 permits (ACK is a
//! SHOULD-implement optimization on top of, not a replacement for, this).
//!
//! Owns only the *bytes* of the last-sent flight and the backoff schedule —
//! arming/cancelling the actual wall-clock timer is the caller's job (the
//! reactor/connection pump), signalled through
//! [`crate::dtls::engine::DtlsRecordSink::arm_retransmit_timer`], the same
//! separation this crate's engines already use for every other timer
//! (`crypto-migration-plan.md`'s Engine design: reactive stimuli in,
//! sink-requested timers armed by the caller).

use std::time::Duration;

const INITIAL_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Retransmit attempts before giving up on the peer entirely — roughly
/// matches DTLS 1.2 implementation practice (1+2+4+8+16+32 = 63s of total
/// waiting before failing the handshake).
const MAX_RETRANSMITS: u32 = 6;

/// What to do after a retransmit timer fires.
pub enum RetransmitOutcome {
    /// Resend these exact bytes and re-arm the timer for the new (doubled) timeout.
    Resend(Vec<u8>),
    /// Retry budget exhausted — fail the handshake.
    GiveUp,
}

/// One direction's flight-retransmit state.
#[derive(Default)]
pub struct RetransmitState {
    /// Raw wire bytes of the last-sent, not-yet-superseded flight. Empty
    /// means nothing outstanding (either nothing sent yet, or the peer's
    /// response already arrived and progressed the handshake).
    flight: Vec<u8>,
    timeout: Option<Duration>,
    retransmit_count: u32,
}

impl RetransmitState {
    /// Fresh state, nothing buffered.
    pub fn new() -> Self {
        Self::default()
    }

    /// A new flight was just sent — buffer it and reset the backoff
    /// schedule. Caller should arm a timer for [`Self::current_timeout`]
    /// right after calling this.
    pub fn on_flight_sent(&mut self, wire: Vec<u8>) {
        self.flight = wire;
        self.timeout = Some(INITIAL_TIMEOUT);
        self.retransmit_count = 0;
    }

    /// The handshake advanced (the peer's expected response arrived and was
    /// processed) — nothing left to retransmit. Caller should cancel any
    /// armed timer.
    pub fn on_progress(&mut self) {
        self.flight.clear();
        self.timeout = None;
    }

    /// Current backoff duration a caller should arm the next timer for —
    /// `None` when nothing is outstanding (timer should stay cancelled).
    pub fn current_timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The reactor's armed timer fired. Returns `None` if nothing was
    /// actually outstanding (a stale/already-cancelled timer firing late —
    /// the caller should just ignore it, not treat it as an error).
    pub fn on_timer_fired(&mut self) -> Option<RetransmitOutcome> {
        if self.flight.is_empty() {
            return None;
        }
        self.retransmit_count += 1;
        if self.retransmit_count > MAX_RETRANSMITS {
            self.flight.clear();
            self.timeout = None;
            return Some(RetransmitOutcome::GiveUp);
        }
        let next = self
            .timeout
            .unwrap_or(INITIAL_TIMEOUT)
            .saturating_mul(2)
            .min(MAX_TIMEOUT);
        self.timeout = Some(next);
        Some(RetransmitOutcome::Resend(self.flight.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_timer_needed_before_anything_is_sent() {
        let state = RetransmitState::new();
        assert_eq!(state.current_timeout(), None);
    }

    #[test]
    fn backoff_doubles_on_each_retransmit_and_caps() {
        let mut state = RetransmitState::new();
        state.on_flight_sent(b"flight1".to_vec());
        assert_eq!(state.current_timeout(), Some(Duration::from_secs(1)));

        let mut last = Duration::from_secs(1);
        for _ in 0..3 {
            match state.on_timer_fired() {
                Some(RetransmitOutcome::Resend(bytes)) => assert_eq!(bytes, b"flight1"),
                _ => panic!("expected a resend"),
            }
            let now = state.current_timeout().unwrap();
            assert_eq!(now, last * 2);
            last = now;
        }
    }

    #[test]
    fn progress_cancels_pending_retransmission() {
        let mut state = RetransmitState::new();
        state.on_flight_sent(b"flight1".to_vec());
        state.on_progress();
        assert_eq!(state.current_timeout(), None);
        assert!(state.on_timer_fired().is_none(), "a stale timer must be a no-op after progress");
    }

    #[test]
    fn gives_up_after_max_retransmits() {
        let mut state = RetransmitState::new();
        state.on_flight_sent(b"flight1".to_vec());
        for _ in 0..MAX_RETRANSMITS {
            assert!(matches!(state.on_timer_fired(), Some(RetransmitOutcome::Resend(_))));
        }
        assert!(matches!(state.on_timer_fired(), Some(RetransmitOutcome::GiveUp)));
    }

    #[test]
    fn a_new_flight_resets_the_backoff() {
        let mut state = RetransmitState::new();
        state.on_flight_sent(b"flight1".to_vec());
        state.on_timer_fired();
        state.on_timer_fired();
        assert!(state.current_timeout().unwrap() > Duration::from_secs(1));
        state.on_flight_sent(b"flight2".to_vec());
        assert_eq!(state.current_timeout(), Some(Duration::from_secs(1)));
    }
}
