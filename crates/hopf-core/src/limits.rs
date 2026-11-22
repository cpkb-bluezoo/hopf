// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! How many connections a listener has open: in total, and from one address.
//!
//! A listener's accept rate limit bounds how fast connections arrive, not how
//! many are open at once, and a client that connects and stays quiet costs a
//! connection's buffers for as long as it likes. These limits bound the number.
//! A connection that would exceed one is accepted and closed at once, as the
//! peer lists and the rate limit do, and the listener's telemetry hook is told.
//!
//! Each accepted connection holds a [`ConnectionSlot`], which gives its place back
//! when the connection is dropped, whatever ended it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Which limit refused a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The listener has as many connections open as it may.
    Total,
    /// The peer's address has as many as it may.
    PerAddress,
}

impl Refused {
    /// The reason, as the telemetry hook is told.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Total => "connection limit",
            Self::PerAddress => "per-address connection limit",
        }
    }
}

#[derive(Default)]
struct Counts {
    total: usize,
    by_address: HashMap<IpAddr, usize>,
}

/// The connections a listener has open, and what it allows.
pub(crate) struct ConnectionLimiter {
    max: Option<usize>,
    per_address: Option<usize>,
    counts: Mutex<Counts>,
}

impl ConnectionLimiter {
    /// A limiter, or `None` if neither limit is set (nothing to count).
    pub(crate) fn new(max: Option<usize>, per_address: Option<usize>) -> Option<Arc<Self>> {
        (max.is_some() || per_address.is_some()).then(|| {
            Arc::new(Self {
                max,
                per_address,
                counts: Mutex::new(Counts::default()),
            })
        })
    }

    /// Take a place for a connection from `peer`, if the limits allow one.
    pub(crate) fn try_acquire(self: &Arc<Self>, peer: IpAddr) -> Result<ConnectionSlot, Refused> {
        // An IPv4 client reached over a dual-stack socket is one address, not two.
        let peer = peer.to_canonical();
        let mut counts = self.counts.lock().unwrap();
        if self.max.is_some_and(|m| counts.total >= m) {
            return Err(Refused::Total);
        }
        let held = counts.by_address.get(&peer).copied().unwrap_or(0);
        if self.per_address.is_some_and(|m| held >= m) {
            return Err(Refused::PerAddress);
        }
        counts.total += 1;
        *counts.by_address.entry(peer).or_insert(0) += 1;
        Ok(ConnectionSlot {
            limiter: Arc::clone(self),
            peer,
        })
    }

    #[cfg(test)]
    fn open(&self) -> usize {
        self.counts.lock().unwrap().total
    }
}

/// A connection's place under its listener's limits, held for as long as the
/// connection is: dropping it gives the place back.
pub struct ConnectionSlot {
    limiter: Arc<ConnectionLimiter>,
    peer: IpAddr,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut counts = self.limiter.counts.lock().unwrap();
        counts.total = counts.total.saturating_sub(1);
        if let Some(n) = counts.by_address.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                counts.by_address.remove(&self.peer);
            }
        }
    }
}

impl std::fmt::Debug for ConnectionSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectionSlot({})", self.peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn no_limits_means_nothing_is_counted() {
        assert!(ConnectionLimiter::new(None, None).is_none());
    }

    #[test]
    fn the_total_is_held_to_and_a_place_is_given_back_when_a_slot_is_dropped() {
        let l = ConnectionLimiter::new(Some(2), None).unwrap();
        let a = l.try_acquire(ip("192.0.2.1")).unwrap();
        let _b = l.try_acquire(ip("192.0.2.2")).unwrap();
        assert_eq!(l.try_acquire(ip("192.0.2.3")).unwrap_err(), Refused::Total);
        drop(a);
        assert_eq!(l.open(), 1);
        assert!(l.try_acquire(ip("192.0.2.3")).is_ok());
    }

    #[test]
    fn an_address_is_held_to_its_own_limit_and_others_are_not_affected() {
        let l = ConnectionLimiter::new(None, Some(2)).unwrap();
        let _a = l.try_acquire(ip("192.0.2.1")).unwrap();
        let b = l.try_acquire(ip("192.0.2.1")).unwrap();
        assert_eq!(l.try_acquire(ip("192.0.2.1")).unwrap_err(), Refused::PerAddress);
        let _other = l.try_acquire(ip("192.0.2.9")).unwrap();
        drop(b);
        assert!(l.try_acquire(ip("192.0.2.1")).is_ok());
    }

    #[test]
    fn both_limits_apply_and_the_total_is_said_first() {
        let l = ConnectionLimiter::new(Some(2), Some(1)).unwrap();
        let _a = l.try_acquire(ip("192.0.2.1")).unwrap();
        assert_eq!(l.try_acquire(ip("192.0.2.1")).unwrap_err(), Refused::PerAddress);
        let _b = l.try_acquire(ip("192.0.2.2")).unwrap();
        assert_eq!(l.try_acquire(ip("192.0.2.3")).unwrap_err(), Refused::Total);
    }

    #[test]
    fn an_ipv4_peer_on_a_dual_stack_socket_is_one_address() {
        let l = ConnectionLimiter::new(None, Some(1)).unwrap();
        let _a = l.try_acquire(ip("192.0.2.1")).unwrap();
        assert_eq!(l.try_acquire(ip("::ffff:192.0.2.1")).unwrap_err(), Refused::PerAddress);
    }

    #[test]
    fn the_counts_return_to_nothing_when_every_slot_is_dropped() {
        let l = ConnectionLimiter::new(Some(100), Some(100)).unwrap();
        let slots: Vec<_> = (0..50).map(|i| l.try_acquire(ip(&format!("192.0.2.{}", i % 5))).unwrap()).collect();
        drop(slots);
        assert_eq!(l.open(), 0);
        assert!(l.counts.lock().unwrap().by_address.is_empty(), "no entry is left behind");
    }
}
