// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-server encrypted-transport capability cache.
//!
//! Today a server's wire transport is a fixed, static choice: whatever
//! `add_server`/`add_server_dot`/`add_server_doq`/`add_server_doh` was
//! called with, and that mapping never changes at runtime. Dynamic
//! transport selection (choosing DoQ/DoT/DoH over plain UDP/TCP for a
//! server added the plain way, and adapting when a server's support
//! changes) needs somewhere to record what's currently known about a
//! given server's support for each encrypted transport. This module is
//! that registry — a pure in-memory cache with no I/O of its own; nothing
//! here decides *when* to probe a server or *which* transport to prefer
//! (that's for the discovery and selection logic built on top of it).
//!
//! This cache only ever applies to servers added via the plain
//! `add_server` family ("auto" mode) — a server pinned to a specific
//! transport via `add_server_dot`/`add_server_doq`/`add_server_doh` never
//! consults or populates it, so an explicit pin can never be silently
//! overridden by cached or discovered data for that address.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An encrypted DNS wire transport a server might support, beyond plain
/// UDP/TCP.
///
/// Each variant is only ever constructed by
/// [`ServerTransport::encrypted_transport`](super::ServerTransport::encrypted_transport)'s
/// own feature-gated match arm in production code — e.g. `Doq` is dead
/// outside a build with the `doq` feature enabled. This module's own
/// tests construct all three regardless of which features are on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum EncryptedTransport {
    /// DNS-over-QUIC (RFC 9250).
    #[cfg_attr(not(any(test, feature = "doq")), allow(dead_code))]
    Doq,
    /// DNS-over-TLS (RFC 7858).
    #[cfg_attr(not(any(test, feature = "dot")), allow(dead_code))]
    Dot,
    /// DNS-over-HTTPS (RFC 8484).
    #[cfg_attr(not(any(test, feature = "doh")), allow(dead_code))]
    Doh,
}

/// How much evidence backs a recorded transport capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Confidence {
    /// Seeded prior knowledge, never confirmed by an actual query or
    /// discovery result against this specific server — carries no
    /// evidence it was ever true for *this* deployment, so it's demoted
    /// on the very first failure, with no benefit of the doubt.
    Provisional,
    /// Backed by a real successful query or an authenticated discovery
    /// result — tolerates one isolated transient failure before
    /// demoting, since a single blip shouldn't discard confirmed-good
    /// information.
    Confirmed,
}

/// Long TTL for a confirmed-working entry: there's no urgency to
/// re-establish something that's already working, but a re-check
/// eventually happens rather than trusting a confirmation forever.
const CONFIRMED_TTL: Duration = Duration::from_secs(24 * 3600);

/// Long TTL for a confirmed-absent entry, matching [`CONFIRMED_TTL`] —
/// operators do occasionally roll out encrypted support later, so this
/// shouldn't be permanent either, but there's equally no urgency to
/// re-check a server that's already given a definitive negative answer.
const ABSENT_TTL: Duration = Duration::from_secs(24 * 3600);

/// A confirmed entry survives this many *consecutive* failures before
/// being evicted — one isolated transient failure is tolerated, the next
/// one in a row is not. A provisional entry gets none of this tolerance
/// (see [`Confidence::Provisional`]).
///
/// Only [`TransportCapabilityCache::record_failure`] reads this — with
/// none of the `dot`/`doq`/`doh` features enabled, nothing can ever
/// construct a [`ConfiguredServer`](super::ConfiguredServer) with an
/// encrypted transport, so that demotion path is unreachable from
/// production code (still exercised directly by this module's own tests).
#[cfg_attr(not(any(test, feature = "dot", feature = "doq", feature = "doh")), allow(dead_code))]
const CONFIRMED_FAILURE_TOLERANCE: u32 = 1;

struct TransportRecord {
    confidence: Confidence,
    recorded_at: Instant,
    #[cfg_attr(not(any(test, feature = "dot", feature = "doq", feature = "doh")), allow(dead_code))]
    consecutive_failures: u32,
}

impl TransportRecord {
    fn is_expired(&self) -> bool {
        matches!(self.confidence, Confidence::Confirmed) && self.recorded_at.elapsed() >= CONFIRMED_TTL
    }
}

struct Inner {
    transports: HashMap<(SocketAddr, EncryptedTransport), TransportRecord>,
    absent: HashMap<SocketAddr, Instant>,
}

/// Per-server encrypted-transport capability registry (see this module's
/// own documentation for scope). Cheap to share: wrap in an [`std::sync::Arc`]
/// the same way [`crate::cache::DnsCache`] is shared across a resolver.
pub(crate) struct TransportCapabilityCache {
    inner: Mutex<Inner>,
}

impl TransportCapabilityCache {
    /// Create an empty cache.
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                transports: HashMap::new(),
                absent: HashMap::new(),
            }),
        }
    }

    /// Seed a transport as provisionally supported by `server` — prior
    /// knowledge (e.g. "Cloudflare supports DoQ") that has never been
    /// confirmed against this specific deployment. A pre-existing entry
    /// for the same `(server, transport)` pair is left untouched: seeding
    /// must never downgrade a confirmed entry back to provisional.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn seed_provisional(&self, server: SocketAddr, transport: EncryptedTransport) {
        let mut g = self.inner.lock().unwrap();
        g.transports.entry((server, transport)).or_insert_with(|| TransportRecord {
            confidence: Confidence::Provisional,
            recorded_at: Instant::now(),
            consecutive_failures: 0,
        });
    }

    /// Record that `transport` just succeeded against `server` — promotes
    /// (or refreshes) it to confirmed-working and resets its failure
    /// count, since a fresh success is exactly the evidence that clears
    /// an isolated prior failure.
    pub(crate) fn record_success(&self, server: SocketAddr, transport: EncryptedTransport) {
        let mut g = self.inner.lock().unwrap();
        g.transports.insert(
            (server, transport),
            TransportRecord {
                confidence: Confidence::Confirmed,
                recorded_at: Instant::now(),
                consecutive_failures: 0,
            },
        );
        // A server that just answered over an encrypted transport is
        // demonstrably not confirmed-absent any more.
        g.absent.remove(&server);
    }

    /// Record that `transport` just failed against `server`. A
    /// provisional entry is evicted outright; a confirmed entry tolerates
    /// [`CONFIRMED_FAILURE_TOLERANCE`] consecutive failures before also
    /// being evicted. A nonexistent entry is a no-op — there's nothing to
    /// demote.
    ///
    /// Only reachable from production code once one of the `dot`/`doq`/
    /// `doh` features is enabled — see [`CONFIRMED_FAILURE_TOLERANCE`]'s
    /// own doc comment for why.
    #[cfg_attr(not(any(test, feature = "dot", feature = "doq", feature = "doh")), allow(dead_code))]
    pub(crate) fn record_failure(&self, server: SocketAddr, transport: EncryptedTransport) {
        let mut g = self.inner.lock().unwrap();
        let key = (server, transport);
        let Some(record) = g.transports.get_mut(&key) else {
            return;
        };
        match record.confidence {
            Confidence::Provisional => {
                g.transports.remove(&key);
            }
            Confidence::Confirmed => {
                record.consecutive_failures += 1;
                if record.consecutive_failures > CONFIRMED_FAILURE_TOLERANCE {
                    g.transports.remove(&key);
                }
            }
        }
    }

    /// Record that `server` answers ordinary DNS but has explicitly told
    /// us (via discovery) that it offers nothing beyond plain UDP/TCP.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn record_confirmed_absent(&self, server: SocketAddr) {
        let mut g = self.inner.lock().unwrap();
        g.absent.insert(server, Instant::now());
        g.transports.retain(|(addr, _), _| *addr != server);
    }

    /// Has `server` given a definitive "nothing beyond plain DNS" answer
    /// that hasn't yet gone stale?
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_confirmed_absent(&self, server: SocketAddr) -> bool {
        let mut g = self.inner.lock().unwrap();
        match g.absent.get(&server) {
            Some(recorded_at) if recorded_at.elapsed() < ABSENT_TTL => true,
            Some(_) => {
                g.absent.remove(&server);
                false
            }
            None => false,
        }
    }

    /// Every transport (confirmed or provisional) currently known for
    /// `server`, with no ordering guarantee — the priority order among
    /// them is a transport-selection concern, not this cache's.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn known_transports(&self, server: SocketAddr) -> Vec<EncryptedTransport> {
        let mut g = self.inner.lock().unwrap();
        let expired: Vec<_> = g
            .transports
            .iter()
            .filter(|(k, v)| k.0 == server && v.is_expired())
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            g.transports.remove(&key);
        }
        g.transports
            .keys()
            .filter(|(addr, _)| *addr == server)
            .map(|(_, transport)| *transport)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    #[test]
    fn seed_provisional_is_visible_via_known_transports() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Doq);
        assert_eq!(cache.known_transports(addr()), vec![EncryptedTransport::Doq]);
    }

    #[test]
    fn seeding_never_downgrades_an_already_confirmed_entry() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doq);
        cache.seed_provisional(addr(), EncryptedTransport::Doq);
        // A single failure would evict a provisional entry outright but
        // is tolerated for a confirmed one — this proves seeding didn't
        // quietly downgrade the confirmed entry underneath it.
        cache.record_failure(addr(), EncryptedTransport::Doq);
        assert_eq!(cache.known_transports(addr()), vec![EncryptedTransport::Doq]);
    }

    #[test]
    fn provisional_entry_is_evicted_immediately_on_first_failure() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Dot);
        cache.record_failure(addr(), EncryptedTransport::Dot);
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn confirmed_entry_tolerates_one_isolated_failure() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doh);
        cache.record_failure(addr(), EncryptedTransport::Doh);
        assert_eq!(
            cache.known_transports(addr()),
            vec![EncryptedTransport::Doh],
            "an isolated failure must not discard confirmed-good information"
        );
    }

    #[test]
    fn confirmed_entry_is_evicted_on_a_second_consecutive_failure() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doh);
        cache.record_failure(addr(), EncryptedTransport::Doh);
        cache.record_failure(addr(), EncryptedTransport::Doh);
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn a_fresh_success_resets_the_failure_count() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doh);
        cache.record_failure(addr(), EncryptedTransport::Doh);
        // Confirmed again — the earlier isolated failure must not carry
        // over and combine with a later one to cause eviction.
        cache.record_success(addr(), EncryptedTransport::Doh);
        cache.record_failure(addr(), EncryptedTransport::Doh);
        assert_eq!(cache.known_transports(addr()), vec![EncryptedTransport::Doh]);
    }

    #[test]
    fn record_failure_on_an_unknown_entry_is_a_no_op() {
        let cache = TransportCapabilityCache::new();
        cache.record_failure(addr(), EncryptedTransport::Doq); // must not panic
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn confirmed_absent_is_reported_until_it_expires() {
        let cache = TransportCapabilityCache::new();
        assert!(!cache.is_confirmed_absent(addr()));
        cache.record_confirmed_absent(addr());
        assert!(cache.is_confirmed_absent(addr()));
    }

    #[test]
    fn a_success_clears_a_prior_confirmed_absent_record() {
        let cache = TransportCapabilityCache::new();
        cache.record_confirmed_absent(addr());
        assert!(cache.is_confirmed_absent(addr()));
        cache.record_success(addr(), EncryptedTransport::Doq);
        assert!(!cache.is_confirmed_absent(addr()));
    }

    #[test]
    fn confirmed_absent_evicts_any_previously_known_transports() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Doq);
        cache.record_confirmed_absent(addr());
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn entries_for_different_servers_are_independent() {
        let other: SocketAddr = "127.0.0.2:53".parse().unwrap();
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doq);
        assert!(cache.known_transports(other).is_empty());
        assert!(!cache.is_confirmed_absent(other));
    }
}
