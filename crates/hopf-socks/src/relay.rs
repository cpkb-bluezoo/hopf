// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The bidirectional byte relay shared by every SOCKS command that ends in
//! two established connections forwarding to each other — CONNECT (client
//! ↔ dialed target) and BIND (client ↔ accepted peer) alike.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::ConnHandle;

use crate::metrics::SocksServerMetrics;

/// Activity/lifecycle tracking for one established relay, independent of
/// how the two connections it forwards between came to exist.
///
/// Both legs' `disconnected()` (and, for the leg still mid-setup when the
/// other vanishes, an ordinary handler-initiated `close()`) can observe
/// the end of the same session — `established`/`released` together ensure
/// [`Self::release_once`] only ever decrements the active-relay counter
/// for a session that actually got as far as [`Self::mark_established`],
/// and only once. Without the `established` gate, a session that never
/// got that far (e.g. the client disconnects while a CONNECT dial or a
/// BIND accept-wait is still in flight, and the losing side's own cleanup
/// path closes the connection) would still reach a teardown callback and
/// decrement a counter it never incremented — an unsigned underflow, not
/// just an off-by-one.
pub(crate) struct RelayActivity {
    /// Set by traffic in either direction; cleared and checked by the
    /// self-rearming idle timer armed in [`arm_idle_timer`].
    activity: AtomicBool,
    /// Set exactly once, by [`Self::mark_established`].
    established: AtomicBool,
    /// Guards the active-relay counter decrement.
    released: AtomicBool,
}

impl RelayActivity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            activity: AtomicBool::new(false),
            established: AtomicBool::new(false),
            released: AtomicBool::new(false),
        })
    }

    fn mark(&self) {
        self.activity.store(true, Ordering::Release);
    }

    /// Call exactly once, when both legs are actually up and relaying —
    /// increments the active-relay counter and arms
    /// [`Self::release_once`] to eventually decrement it.
    pub(crate) fn mark_established(&self, metrics: &SocksServerMetrics) {
        self.established.store(true, Ordering::Release);
        SocksServerMetrics::add(&metrics.active_relays, 1);
    }

    /// Decrement the active-relay counter exactly once, for a relay that
    /// reached [`Self::mark_established`] — however many teardown paths
    /// end up observing its end. A no-op for a session that never got
    /// that far.
    pub(crate) fn release_once(&self, metrics: &SocksServerMetrics) {
        if self.established.load(Ordering::Acquire) && !self.released.swap(true, Ordering::AcqRel) {
            metrics.active_relays.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Forward one chunk of traffic to `to`, marking activity and adding to
/// `counter` — the two legs of a relay call this symmetrically (client
/// forwards to the other leg's handle with the "upstream" counter, the
/// other leg forwards back with the "downstream" counter), so which
/// counter/direction is which is entirely up to the caller.
pub(crate) fn forward(activity: &RelayActivity, to: &ConnHandle, counter: &AtomicU64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    activity.mark();
    SocksServerMetrics::add(counter, data.len() as u64);
    to.send(data.to_vec());
}

/// Arm (or re-arm) the self-rearming relay idle timer: fires after
/// `timeout`, and either finds activity since the last tick (clears the
/// flag and reschedules) or finds none (closes both legs and stops).
pub(crate) fn arm_idle_timer(activity: Arc<RelayActivity>, a: ConnHandle, b: ConnHandle, timeout: Duration) {
    let activity2 = Arc::clone(&activity);
    let a2 = a.clone();
    let b2 = b.clone();
    // The returned `TimerHandle` is deliberately not retained: there is
    // nothing to cancel it for (a closed connection makes `close()` here a
    // harmless no-op, and letting one superseded tick fire is cheaper than
    // threading a handle through both legs' teardown paths).
    let _ = a.schedule_timer(
        timeout,
        Box::new(move || {
            if activity2.activity.swap(false, Ordering::AcqRel) {
                arm_idle_timer(activity2, a2, b2, timeout);
            } else {
                a2.close();
                b2.close();
            }
        }),
    );
}
