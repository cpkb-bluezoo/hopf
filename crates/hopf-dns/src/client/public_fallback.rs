// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Well-known public DNS fallbacks and IPv6 reachability.
//!
//! When the host has no configured resolver, [`fallback_servers`] supplies
//! Cloudflare, Quad9 and Google, each provider's IPv6 address interleaved
//! with its IPv4 one so that a dead address family cannot stack several
//! multi-second timeouts ahead of a working one. [`Ipv6Health`] decides, per
//! lookup, whether an IPv6 fallback is worth trying, from three separate
//! signals with separate, bounded memories:
//!
//! 1. **No route.** The host has no global IPv6 address or route (an
//!    immediate `ENETUNREACH` / `EHOSTUNREACH`, or only link-local
//!    addresses): every IPv6 fallback is skipped for [`NO_ROUTE_TTL`].
//! 2. **This address failed.** A timeout marks *that address* bad for
//!    [`ADDRESS_BAD_TTL`]; other IPv6 addresses stay eligible, so providers
//!    cover each other and probing rotates across them.
//! 3. **Path blackholed.** When IPv6 addresses of several providers have
//!    timed out and an IPv4 address answers, or when a hedged IPv4 attempt
//!    beats IPv6, IPv6 loses its head start for [`V4_PREFERRED_TTL`].
//!
//! While IPv6 is eligible it gets a short head start ([`HEDGE_DELAY`], the
//! RFC 8305 connection attempt delay) instead of the full query timeout: the
//! same query is then also sent to that provider's IPv4 address and the first
//! answer wins. None of this touches nameservers read from `resolv.conf`.
//!
//! All state transitions take the current time as an argument, so the
//! behaviour is deterministic under test.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

/// How long every IPv6 fallback is skipped after the host showed it has no
/// IPv6 route ("a few minutes": long enough that a corporate host pays the
/// probe cost rarely, short enough to notice a network change).
pub(crate) const NO_ROUTE_TTL: Duration = Duration::from_secs(300);
/// How long one IPv6 address that timed out is skipped.
pub(crate) const ADDRESS_BAD_TTL: Duration = Duration::from_secs(120);
/// How long IPv6 loses its head start once IPv4 has been seen to win.
pub(crate) const V4_PREFERRED_TTL: Duration = Duration::from_secs(300);
/// Head start IPv6 gets before the same query also goes to IPv4
/// (RFC 8305 section 5, the recommended connection attempt delay).
pub(crate) const HEDGE_DELAY: Duration = Duration::from_millis(250);
/// IPv6 timeouts older than this are not evidence of a blackholed path.
const TIMEOUT_WINDOW: Duration = Duration::from_secs(60);

/// A public DNS operator on the fallback list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Provider {
    Cloudflare,
    Quad9,
    Google,
}

/// Where a configured server sits on the well-known fallback list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WellKnown {
    pub(crate) provider: Provider,
    /// The provider's second address pair (`1.0.0.1` rather than `1.1.1.1`).
    pub(crate) secondary: bool,
}

/// The fallback list in the order servers are tried: provider order
/// Cloudflare, Quad9, Google (Google last, having no DNS over QUIC), each
/// address pair as IPv6 then IPv4, primaries before secondaries.
const TABLE: &[(&str, Provider, bool)] = &[
    ("2606:4700:4700::1111", Provider::Cloudflare, false),
    ("1.1.1.1", Provider::Cloudflare, false),
    ("2620:fe::fe", Provider::Quad9, false),
    ("9.9.9.9", Provider::Quad9, false),
    ("2001:4860:4860::8888", Provider::Google, false),
    ("8.8.8.8", Provider::Google, false),
    ("2606:4700:4700::1001", Provider::Cloudflare, true),
    ("1.0.0.1", Provider::Cloudflare, true),
    ("2620:fe::9", Provider::Quad9, true),
    ("149.112.112.112", Provider::Quad9, true),
    ("2001:4860:4860::8844", Provider::Google, true),
    ("8.8.4.4", Provider::Google, true),
];

/// The well-known public resolvers as servers, in trial order.
pub(crate) fn fallback_servers(port: u16) -> Vec<SocketAddr> {
    TABLE
        .iter()
        .map(|(ip, _, _)| SocketAddr::new(ip.parse().expect("table entries are valid addresses"), port))
        .collect()
}

/// Which well-known server `ip` is, if any.
pub(crate) fn classify(ip: IpAddr) -> Option<WellKnown> {
    TABLE
        .iter()
        .find(|(literal, _, _)| literal.parse::<IpAddr>().is_ok_and(|a| a == ip))
        .map(|&(_, provider, secondary)| WellKnown { provider, secondary })
}

/// Whether `addr` is a global unicast IPv6 address (2000::/3). Loopback,
/// link-local, unique-local and unspecified addresses are not: a host whose
/// only addresses are those has no route to the public IPv6 internet.
pub(crate) fn is_global_unicast(addr: Ipv6Addr) -> bool {
    addr.segments()[0] & 0xe000 == 0x2000
}

/// What a route probe toward an IPv6 destination says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    /// The host would source the traffic from a global address.
    Usable,
    /// No route, no global address, or IPv6 unavailable altogether.
    None,
}

/// Interpret a probe's outcome: `Ok(source address)` from a connected UDP
/// socket's `local_addr`, or the error the connect failed with.
pub(crate) fn classify_probe(result: io::Result<IpAddr>) -> Route {
    match result {
        Ok(IpAddr::V6(source)) if is_global_unicast(source) => Route::Usable,
        // A link-local, loopback or IPv4 source, or any failure to even
        // pick a source: nothing can reach the public IPv6 internet.
        _ => Route::None,
    }
}

/// A failure that means "this host cannot reach that network" rather than
/// "that server did not answer".
#[cfg_attr(not(any(feature = "dot", feature = "doq", feature = "doh")), allow(dead_code))]
pub(crate) fn is_unreachable(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable)
}

/// What to do with an IPv6 well-known server for this lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V6Decision {
    /// Don't try it; go straight to the next server.
    Skip,
    /// Try it, and if it has not answered within the delay also send the same
    /// query to the provider's IPv4 address.
    Attempt { hedge_after: Duration },
}

/// Bounded memory of IPv6 reachability for the well-known fallbacks.
#[derive(Debug, Default)]
pub(crate) struct Ipv6Health {
    no_route_until: Option<Instant>,
    bad_until: HashMap<IpAddr, Instant>,
    v4_preferred_until: Option<Instant>,
    recent_v6_timeouts: Vec<(Provider, Instant)>,
}

impl Ipv6Health {
    /// Decide whether to try IPv6 address `addr` (of `provider`) now.
    pub(crate) fn decide(&mut self, now: Instant, addr: IpAddr) -> V6Decision {
        self.prune(now);
        let skip = self.no_route_until.is_some_and(|t| now < t)
            || self.bad_until.get(&addr).is_some_and(|t| now < *t)
            || self.v4_preferred_until.is_some_and(|t| now < t);
        if skip {
            V6Decision::Skip
        } else {
            V6Decision::Attempt { hedge_after: HEDGE_DELAY }
        }
    }

    /// Drop memories that have expired.
    fn prune(&mut self, now: Instant) {
        self.bad_until.retain(|_, t| now < *t);
        self.recent_v6_timeouts.retain(|(_, at)| now.saturating_duration_since(*at) < TIMEOUT_WINDOW);
        if self.no_route_until.is_some_and(|t| now >= t) {
            self.no_route_until = None;
        }
        if self.v4_preferred_until.is_some_and(|t| now >= t) {
            self.v4_preferred_until = None;
        }
    }

    /// The host has no usable IPv6 route.
    pub(crate) fn record_no_route(&mut self, now: Instant) {
        self.no_route_until = Some(now + NO_ROUTE_TTL);
    }

    /// An IPv6 address of `provider` did not answer in time.
    pub(crate) fn record_v6_timeout(&mut self, now: Instant, addr: IpAddr, provider: Provider) {
        self.prune(now);
        self.bad_until.insert(addr, now + ADDRESS_BAD_TTL);
        self.recent_v6_timeouts.push((provider, now));
    }

    /// A well-known IPv4 address answered a query.
    pub(crate) fn record_v4_answer(&mut self, now: Instant) {
        self.prune(now);
        let mut providers: Vec<Provider> = self.recent_v6_timeouts.iter().map(|(p, _)| *p).collect();
        providers.sort_by_key(|p| *p as u8);
        providers.dedup();
        // One provider failing is one nameserver's problem; several
        // providers failing over IPv6 while IPv4 works is the path's.
        if providers.len() >= 2 {
            self.v4_preferred_until = Some(now + V4_PREFERRED_TTL);
        }
    }

    /// A hedged IPv4 attempt beat the IPv6 attempt it was racing.
    pub(crate) fn record_hedge_won_by_v4(&mut self, now: Instant) {
        self.v4_preferred_until = Some(now + V4_PREFERRED_TTL);
    }

    /// A well-known IPv6 address answered a query: IPv6 works from here.
    pub(crate) fn record_v6_answer(&mut self, _now: Instant, addr: IpAddr) {
        self.bad_until.remove(&addr);
        self.v4_preferred_until = None;
        self.no_route_until = None;
        self.recent_v6_timeouts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn t0() -> Instant {
        Instant::now()
    }

    const CF6: &str = "2606:4700:4700::1111";
    const Q9_6: &str = "2620:fe::fe";
    const G6: &str = "2001:4860:4860::8888";

    fn attempt(d: V6Decision) -> bool {
        matches!(d, V6Decision::Attempt { .. })
    }

    // ---- the list ----

    /// Provider order Cloudflare, Quad9, Google, each pair IPv6 then IPv4,
    /// primaries first - so no family can stack several timeouts up front.
    #[test]
    fn the_fallback_list_interleaves_each_providers_families() {
        let got: Vec<String> = fallback_servers(53).iter().map(|s| s.ip().to_string()).collect();
        assert_eq!(
            got,
            [
                "2606:4700:4700::1111", "1.1.1.1",
                "2620:fe::fe", "9.9.9.9",
                "2001:4860:4860::8888", "8.8.8.8",
                "2606:4700:4700::1001", "1.0.0.1",
                "2620:fe::9", "149.112.112.112",
                "2001:4860:4860::8844", "8.8.4.4",
            ]
        );
        assert!(fallback_servers(53).iter().all(|s| s.port() == 53));
        // Never two IPv6 addresses back to back.
        let servers = fallback_servers(53);
        assert!(servers.windows(2).all(|w| w[0].is_ipv4() || w[1].is_ipv4()));
    }

    #[test]
    fn every_listed_address_is_classified_and_others_are_not() {
        for s in fallback_servers(53) {
            assert!(classify(s.ip()).is_some(), "{s}");
        }
        let cf = classify(ip("1.1.1.1")).unwrap();
        assert_eq!((cf.provider, cf.secondary), (Provider::Cloudflare, false));
        let g2 = classify(ip("2001:4860:4860::8844")).unwrap();
        assert_eq!((g2.provider, g2.secondary), (Provider::Google, true));
        assert!(classify(ip("192.0.2.1")).is_none());
        assert!(classify(ip("2001:db8::1")).is_none());
    }

    // ---- routes ----

    #[test]
    fn only_2000_slash_3_counts_as_a_global_address() {
        assert!(is_global_unicast("2606:4700:4700::1111".parse().unwrap()));
        assert!(is_global_unicast("2a00:1450::1".parse().unwrap()));
        for not in ["::1", "::", "fe80::1", "fd00::1", "fc00::5", "ff02::1", "::ffff:1.2.3.4"] {
            assert!(!is_global_unicast(not.parse().unwrap()), "{not}");
        }
    }

    #[test]
    fn a_probe_with_a_global_source_is_usable_and_everything_else_is_no_route() {
        assert_eq!(classify_probe(Ok(ip("2001:db8::7").into_global_for_test())), Route::Usable);
        assert_eq!(classify_probe(Ok(ip("fe80::1"))), Route::None, "link-local only");
        assert_eq!(classify_probe(Ok(ip("::1"))), Route::None);
        assert_eq!(classify_probe(Ok(ip("192.0.2.1"))), Route::None, "not even IPv6");
        for kind in [io::ErrorKind::NetworkUnreachable, io::ErrorKind::HostUnreachable, io::ErrorKind::AddrNotAvailable, io::ErrorKind::Unsupported] {
            assert_eq!(classify_probe(Err(io::Error::from(kind))), Route::None, "{kind:?}");
        }
    }

    trait IntoGlobal {
        fn into_global_for_test(self) -> IpAddr;
    }
    impl IntoGlobal for IpAddr {
        /// 2001:db8::/32 is documentation space, outside 2000::/3's usual
        /// allocation but inside 2000::/3 itself - fine as a stand-in.
        fn into_global_for_test(self) -> IpAddr {
            self
        }
    }

    #[test]
    fn unreachable_errors_are_told_apart_from_timeouts() {
        assert!(is_unreachable(&io::Error::from(io::ErrorKind::NetworkUnreachable)));
        assert!(is_unreachable(&io::Error::from(io::ErrorKind::HostUnreachable)));
        assert!(!is_unreachable(&io::Error::from(io::ErrorKind::TimedOut)));
        assert!(!is_unreachable(&io::Error::from(io::ErrorKind::ConnectionRefused)));
    }

    // ---- signal 1: no route ----

    #[test]
    fn a_fresh_host_gets_the_head_start() {
        let mut h = Ipv6Health::default();
        assert_eq!(h.decide(t0(), ip(CF6)), V6Decision::Attempt { hedge_after: HEDGE_DELAY });
    }

    /// The corporate case: no route means every IPv6 fallback is skipped
    /// (instantly, no timeout paid), then tried again once the memory expires.
    #[test]
    fn no_route_skips_every_ipv6_fallback_for_a_bounded_time() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_no_route(now);
        for a in [CF6, Q9_6, G6] {
            assert_eq!(h.decide(now, ip(a)), V6Decision::Skip, "{a}");
            assert_eq!(h.decide(now + NO_ROUTE_TTL - Duration::from_secs(1), ip(a)), V6Decision::Skip);
        }
        assert!(attempt(h.decide(now + NO_ROUTE_TTL + Duration::from_secs(1), ip(CF6))), "a later network change is noticed");
    }

    // ---- signal 2: this address failed ----

    /// One provider's IPv6 timing out says nothing about the others: they
    /// stay eligible, so probing rotates across providers.
    #[test]
    fn a_timeout_marks_only_that_address_bad_and_only_for_a_while() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v6_timeout(now, ip(CF6), Provider::Cloudflare);
        assert_eq!(h.decide(now, ip(CF6)), V6Decision::Skip);
        assert!(attempt(h.decide(now, ip(Q9_6))), "Quad9's IPv6 is unaffected");
        assert!(attempt(h.decide(now, ip(G6))));
        assert!(attempt(h.decide(now + ADDRESS_BAD_TTL + Duration::from_secs(1), ip(CF6))), "eligible again");
    }

    #[test]
    fn a_timeout_is_not_a_no_route() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v6_timeout(now, ip(CF6), Provider::Cloudflare);
        assert!(attempt(h.decide(now, ip("2001:4860:4860::8844"))));
    }

    // ---- signal 3: blackholed path ----

    /// One provider timing out while IPv4 answers proves nothing about the
    /// path; two providers' IPv6 timing out and then IPv4 answering does.
    #[test]
    fn several_providers_timing_out_then_ipv4_answering_ends_the_head_start() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v6_timeout(now, ip(CF6), Provider::Cloudflare);
        h.record_v4_answer(now);
        assert!(attempt(h.decide(now, ip(Q9_6))), "one provider is not enough");

        h.record_v6_timeout(now, ip(Q9_6), Provider::Quad9);
        h.record_v4_answer(now);
        assert_eq!(h.decide(now, ip(G6)), V6Decision::Skip, "IPv6 loses its head start");
        assert!(attempt(h.decide(now + V4_PREFERRED_TTL + Duration::from_secs(1), ip(G6))), "and gets it back");
    }

    #[test]
    fn two_timeouts_from_the_same_provider_count_once() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v6_timeout(now, ip(CF6), Provider::Cloudflare);
        h.record_v6_timeout(now, ip("2606:4700:4700::1001"), Provider::Cloudflare);
        h.record_v4_answer(now);
        assert!(attempt(h.decide(now, ip(Q9_6))));
    }

    #[test]
    fn stale_timeouts_are_not_evidence() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v6_timeout(now, ip(CF6), Provider::Cloudflare);
        h.record_v6_timeout(now, ip(Q9_6), Provider::Quad9);
        let later = now + TIMEOUT_WINDOW + Duration::from_secs(5);
        h.record_v4_answer(later);
        assert!(attempt(h.decide(later, ip(G6))));
    }

    /// Losing a hedged race to IPv4 is direct evidence, so it needs no
    /// second provider.
    #[test]
    fn a_hedged_ipv4_win_ends_the_head_start_immediately() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_hedge_won_by_v4(now);
        assert_eq!(h.decide(now, ip(Q9_6)), V6Decision::Skip);
    }

    /// IPv6 answering proves the path: it must undo a prior preference so a
    /// recovered network is used at once.
    #[test]
    fn an_ipv6_answer_restores_the_head_start_and_forgives_the_address() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v6_timeout(now, ip(CF6), Provider::Cloudflare);
        h.record_hedge_won_by_v4(now);
        h.record_v6_answer(now, ip(CF6));
        assert!(attempt(h.decide(now, ip(CF6))));
    }

    /// An answer over IPv4 with no IPv6 timeouts at all (IPv6 was simply not
    /// tried) must not disable IPv6.
    #[test]
    fn an_ipv4_answer_alone_changes_nothing() {
        let now = t0();
        let mut h = Ipv6Health::default();
        h.record_v4_answer(now);
        assert!(attempt(h.decide(now, ip(CF6))));
    }
}
