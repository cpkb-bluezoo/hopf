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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// An encrypted DNS wire transport a server might support, beyond plain
/// UDP/TCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum EncryptedTransport {
    /// DNS-over-QUIC (RFC 9250).
    Doq,
    /// DNS-over-TLS (RFC 7858).
    Dot,
    /// DNS-over-HTTPS (RFC 8484).
    Doh,
}

/// Everything transport selection needs to actually dial a known
/// transport, beyond just "this server supports it" — an entry with no
/// endpoint details would be useless information to select, since there'd
/// be nowhere to send the query. Recorded alongside the confidence level
/// itself, both because a seeded entry (well-known public resolvers) and a
/// discovered one (RFC 9462 DDR) each know their own dial target, and
/// because a server can change which address/hostname its encrypted
/// transport is reachable at independently of losing support for it
/// entirely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EndpointDetails {
    /// Where to actually dial — often the same address as the plain
    /// server, but not necessarily (an RFC 9462 DDR answer may advertise a
    /// different one via `ipv4hint`/`ipv6hint`).
    pub(crate) target: SocketAddr,
    /// TLS/QUIC server name to present and validate the endpoint's
    /// certificate against.
    pub(crate) sni: String,
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
    details: EndpointDetails,
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
    pub(crate) fn seed_provisional(&self, server: SocketAddr, transport: EncryptedTransport, details: EndpointDetails) {
        let mut g = self.inner.lock().unwrap();
        g.transports.entry((server, transport)).or_insert_with(|| TransportRecord {
            confidence: Confidence::Provisional,
            recorded_at: Instant::now(),
            consecutive_failures: 0,
            details,
        });
    }

    /// Record that `transport` just succeeded against `server` — promotes
    /// (or refreshes) it to confirmed-working and resets its failure
    /// count, since a fresh success is exactly the evidence that clears
    /// an isolated prior failure. `details` replaces whatever was recorded
    /// before, in case the endpoint moved since the last confirmation.
    pub(crate) fn record_success(&self, server: SocketAddr, transport: EncryptedTransport, details: EndpointDetails) {
        let mut g = self.inner.lock().unwrap();
        g.transports.insert(
            (server, transport),
            TransportRecord {
                confidence: Confidence::Confirmed,
                recorded_at: Instant::now(),
                consecutive_failures: 0,
                details,
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
    /// `server`, with no ordering guarantee — for the priority-ordered
    /// lookup transport selection actually uses, see [`Self::best_known`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn known_transports(&self, server: SocketAddr) -> Vec<EncryptedTransport> {
        let mut g = self.inner.lock().unwrap();
        expire(&mut g, server);
        g.transports
            .keys()
            .filter(|(addr, _)| *addr == server)
            .map(|(_, transport)| *transport)
            .collect()
    }

    /// The highest-priority transport (confirmed or provisional) known for
    /// `server`, in `priority` order, along with what's needed to actually
    /// dial it — `priority` is the caller's own ordered list of
    /// transports it's both willing to prefer *and* actually able to dial
    /// in this build (e.g. skipping DoQ entirely when the `doq` feature
    /// isn't enabled). `None` means the cache has nothing for `server`
    /// among the transports offered, and the caller should fall back to
    /// plain UDP/TCP.
    #[cfg_attr(not(any(feature = "dot", feature = "doq")), allow(dead_code))]
    pub(crate) fn best_known(&self, server: SocketAddr, priority: &[EncryptedTransport]) -> Option<(EncryptedTransport, EndpointDetails)> {
        let mut g = self.inner.lock().unwrap();
        expire(&mut g, server);
        priority
            .iter()
            .find_map(|transport| g.transports.get(&(server, *transport)).map(|record| (*transport, record.details.clone())))
    }

    /// Seed every encrypted transport [`KNOWN_PUBLIC_RESOLVERS`] has on
    /// record for `addr` — a no-op if `addr` isn't on that list. Safe to
    /// call unconditionally for every server added the plain way: a
    /// pre-existing confirmed entry is never downgraded (see
    /// [`Self::seed_provisional`]'s own doc comment).
    pub(crate) fn seed_known_public_resolver(&self, addr: SocketAddr) {
        if let Some((_, transports, sni)) = KNOWN_PUBLIC_RESOLVERS.iter().find(|(ip, _, _)| *ip == addr.ip()) {
            for transport in *transports {
                let details = EndpointDetails {
                    target: SocketAddr::new(addr.ip(), default_port(*transport)),
                    sni: sni.to_string(),
                };
                self.seed_provisional(addr, *transport, details);
            }
        }
    }
}

/// Evict every expired entry for `server` from `g.transports` — shared by
/// [`TransportCapabilityCache::known_transports`] and
/// [`TransportCapabilityCache::best_known`] so both apply the same lazy
/// TTL expiry.
fn expire(g: &mut Inner, server: SocketAddr) {
    let expired: Vec<_> = g
        .transports
        .iter()
        .filter(|(k, v)| k.0 == server && v.is_expired())
        .map(|(k, _)| *k)
        .collect();
    for key in expired {
        g.transports.remove(&key);
    }
}

/// Standard port for a transport when nothing more specific is known —
/// used to fill in [`EndpointDetails::target`] for a seeded well-known
/// resolver, which (unlike an RFC 9462 DDR answer) never carries its own
/// port hint, and by RFC 9462 DDR discovery itself when a candidate's own
/// SVCB record has no explicit port SvcParam.
#[cfg_attr(not(any(feature = "dot", feature = "doq", feature = "doh")), allow(dead_code))]
pub(crate) fn default_port(transport: EncryptedTransport) -> u16 {
    match transport {
        EncryptedTransport::Dot | EncryptedTransport::Doq => 853,
        EncryptedTransport::Doh => 443,
    }
}

/// Well-known public resolvers whose encrypted-transport support is
/// public, documented knowledge (e.g. Cloudflare and Quad9 both support
/// DNS-over-QUIC, but Google's public resolver doesn't) — keyed by IP
/// address alone (any port), matching the granularity `add_server`/
/// `add_server_str` are called with.
///
/// This table drifts out of date over time: an operator can add, drop, or
/// change encrypted-transport support at any point without telling anyone
/// consuming this list. That's an accepted, unavoidable cost of a
/// hardcoded table, not a bug — every entry is seeded as
/// [`Confidence::Provisional`], demoted on the very first real failure
/// with no benefit of the doubt, and RFC 9462 discovery (tracked
/// separately) is the self-updating alternative for every server not on
/// this short list.
const KNOWN_PUBLIC_RESOLVERS: &[(IpAddr, &[EncryptedTransport], &str)] = &[
    // Cloudflare: DoT/DoQ on 853, DoH on 443, all under cloudflare-dns.com.
    (
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "cloudflare-dns.com",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "cloudflare-dns.com",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "cloudflare-dns.com",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "cloudflare-dns.com",
    ),
    // Quad9: DoT/DoQ on 853, DoH on 443, all under dns.quad9.net.
    (
        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.quad9.net",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.quad9.net",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.quad9.net",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009)),
        &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.quad9.net",
    ),
    // Google Public DNS: DoT on 853, DoH on 443, under dns.google — no DoQ.
    (
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        &[EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.google",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        &[EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.google",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        &[EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.google",
    ),
    (
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
        &[EncryptedTransport::Dot, EncryptedTransport::Doh],
        "dns.google",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:53".parse().unwrap()
    }

    /// A placeholder [`EndpointDetails`] for tests that only care about
    /// whether/how a transport is tracked, not where it dials.
    fn details() -> EndpointDetails {
        EndpointDetails {
            target: "127.0.0.1:853".parse().unwrap(),
            sni: "resolver.example".to_string(),
        }
    }

    #[test]
    fn seed_provisional_is_visible_via_known_transports() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Doq, details());
        assert_eq!(cache.known_transports(addr()), vec![EncryptedTransport::Doq]);
    }

    #[test]
    fn seeding_never_downgrades_an_already_confirmed_entry() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doq, details());
        cache.seed_provisional(addr(), EncryptedTransport::Doq, details());
        // A single failure would evict a provisional entry outright but
        // is tolerated for a confirmed one — this proves seeding didn't
        // quietly downgrade the confirmed entry underneath it.
        cache.record_failure(addr(), EncryptedTransport::Doq);
        assert_eq!(cache.known_transports(addr()), vec![EncryptedTransport::Doq]);
    }

    #[test]
    fn provisional_entry_is_evicted_immediately_on_first_failure() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Dot, details());
        cache.record_failure(addr(), EncryptedTransport::Dot);
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn confirmed_entry_tolerates_one_isolated_failure() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doh, details());
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
        cache.record_success(addr(), EncryptedTransport::Doh, details());
        cache.record_failure(addr(), EncryptedTransport::Doh);
        cache.record_failure(addr(), EncryptedTransport::Doh);
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn a_fresh_success_resets_the_failure_count() {
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doh, details());
        cache.record_failure(addr(), EncryptedTransport::Doh);
        // Confirmed again — the earlier isolated failure must not carry
        // over and combine with a later one to cause eviction.
        cache.record_success(addr(), EncryptedTransport::Doh, details());
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
        cache.record_success(addr(), EncryptedTransport::Doq, details());
        assert!(!cache.is_confirmed_absent(addr()));
    }

    #[test]
    fn confirmed_absent_evicts_any_previously_known_transports() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Doq, details());
        cache.record_confirmed_absent(addr());
        assert!(cache.known_transports(addr()).is_empty());
    }

    #[test]
    fn entries_for_different_servers_are_independent() {
        let other: SocketAddr = "127.0.0.2:53".parse().unwrap();
        let cache = TransportCapabilityCache::new();
        cache.record_success(addr(), EncryptedTransport::Doq, details());
        assert!(cache.known_transports(other).is_empty());
        assert!(!cache.is_confirmed_absent(other));
    }

    #[test]
    fn best_known_prefers_the_first_priority_match() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Dot, details());
        cache.seed_provisional(addr(), EncryptedTransport::Doh, details());
        let priority = [EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh];
        let (transport, _) = cache.best_known(addr(), &priority).unwrap();
        assert_eq!(transport, EncryptedTransport::Dot, "Doq isn't known here, so Dot is the highest-priority match");
    }

    #[test]
    fn best_known_returns_the_matching_endpoint_details() {
        let cache = TransportCapabilityCache::new();
        let target: SocketAddr = "198.51.100.9:853".parse().unwrap();
        cache.seed_provisional(
            addr(),
            EncryptedTransport::Dot,
            EndpointDetails {
                target,
                sni: "dot.example".to_string(),
            },
        );
        let (_, found) = cache.best_known(addr(), &[EncryptedTransport::Dot]).unwrap();
        assert_eq!(found.target, target);
        assert_eq!(found.sni, "dot.example");
    }

    #[test]
    fn best_known_is_none_when_nothing_in_priority_is_known() {
        let cache = TransportCapabilityCache::new();
        cache.seed_provisional(addr(), EncryptedTransport::Doh, details());
        assert!(cache.best_known(addr(), &[EncryptedTransport::Doq, EncryptedTransport::Dot]).is_none());
    }

    #[test]
    fn best_known_is_none_for_a_server_with_no_entries_at_all() {
        let cache = TransportCapabilityCache::new();
        assert!(cache.best_known(addr(), &[EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh]).is_none());
    }

    #[test]
    fn seeds_cloudflare_with_doq_dot_and_doh() {
        let cache = TransportCapabilityCache::new();
        let cloudflare: SocketAddr = "1.1.1.1:53".parse().unwrap();
        cache.seed_known_public_resolver(cloudflare);
        let mut got = cache.known_transports(cloudflare);
        got.sort_by_key(|t| format!("{t:?}"));
        let mut want = vec![EncryptedTransport::Doq, EncryptedTransport::Dot, EncryptedTransport::Doh];
        want.sort_by_key(|t| format!("{t:?}"));
        assert_eq!(got, want);
    }

    /// Regression test for issue #377: Google's public resolver is
    /// documented to support DoT/DoH but not DoQ — this must show up as a
    /// real difference in what's seeded, not the same table entry for
    /// every well-known resolver.
    #[test]
    fn seeds_google_without_doq() {
        let cache = TransportCapabilityCache::new();
        let google: SocketAddr = "8.8.8.8:53".parse().unwrap();
        cache.seed_known_public_resolver(google);
        let got = cache.known_transports(google);
        assert!(!got.contains(&EncryptedTransport::Doq), "Google's public resolver does not support DoQ");
        assert!(got.contains(&EncryptedTransport::Dot));
        assert!(got.contains(&EncryptedTransport::Doh));
    }

    #[test]
    fn seeds_quad9_ipv6_address_too() {
        let cache = TransportCapabilityCache::new();
        let quad9_v6: SocketAddr = "[2620:fe::fe]:53".parse().unwrap();
        cache.seed_known_public_resolver(quad9_v6);
        assert!(cache.known_transports(quad9_v6).contains(&EncryptedTransport::Doq));
    }

    #[test]
    fn seeding_an_address_not_on_the_list_is_a_no_op() {
        let cache = TransportCapabilityCache::new();
        // A TEST-NET-3 address (RFC 5737) — guaranteed not to be a
        // well-known public resolver.
        let unknown: SocketAddr = "203.0.113.1:53".parse().unwrap();
        cache.seed_known_public_resolver(unknown);
        assert!(cache.known_transports(unknown).is_empty());
    }

    #[test]
    fn seeding_a_known_resolver_ignores_the_port() {
        let cache = TransportCapabilityCache::new();
        let cloudflare_on_a_nonstandard_port: SocketAddr = "1.1.1.1:5353".parse().unwrap();
        cache.seed_known_public_resolver(cloudflare_on_a_nonstandard_port);
        assert!(!cache.known_transports(cloudflare_on_a_nonstandard_port).is_empty());
    }

    #[test]
    fn seeded_entries_carry_real_dial_details_not_placeholders() {
        let cache = TransportCapabilityCache::new();
        let cloudflare: SocketAddr = "1.1.1.1:53".parse().unwrap();
        cache.seed_known_public_resolver(cloudflare);
        let (transport, dot) = cache.best_known(cloudflare, &[EncryptedTransport::Dot]).unwrap();
        assert_eq!(transport, EncryptedTransport::Dot);
        assert_eq!(dot.sni, "cloudflare-dns.com");
        assert_eq!(dot.target, "1.1.1.1:853".parse().unwrap());

        let (_, doh) = cache.best_known(cloudflare, &[EncryptedTransport::Doh]).unwrap();
        assert_eq!(doh.sni, "cloudflare-dns.com");
        assert_eq!(doh.target, "1.1.1.1:443".parse().unwrap());
    }
}
