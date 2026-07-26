// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! CIDR allow/deny and connection rate limiting for listen bindings.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// IPv4/IPv6 network prefix for ACL matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNet {
    /// Network address (host bits should be zero; matched with mask).
    pub addr: IpAddr,
    /// Prefix length.
    pub prefix: u8,
}

impl IpNet {
    /// Parse `"addr/prefix"` (e.g. `10.0.0.0/8`, `::1/128`).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_s, pref_s) = s.split_once('/')?;
        let addr: IpAddr = addr_s.parse().ok()?;
        let prefix: u8 = pref_s.parse().ok()?;
        Some(Self { addr, prefix })
    }

    /// True if `ip` is in this network.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                if self.prefix > 32 {
                    return false;
                }
                let mask = if self.prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(n) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                if self.prefix > 128 {
                    return false;
                }
                let n = u128::from(n);
                let a = u128::from(a);
                let mask = if self.prefix == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (n & mask) == (a & mask)
            }
            _ => false,
        }
    }
}

/// Peer ACL: optional allow list and deny list (deny wins).
#[derive(Debug, Clone, Default)]
pub struct PeerAcl {
    /// If non-empty, peer must match one entry.
    pub allow: Vec<IpNet>,
    /// If peer matches any entry, reject.
    pub deny: Vec<IpNet>,
}

impl PeerAcl {
    /// Empty ACL (allow all).
    pub fn open() -> Self {
        Self::default()
    }

    /// Evaluate peer address.
    pub fn allows(&self, peer: SocketAddr) -> bool {
        let ip = peer.ip();
        if self.deny.iter().any(|n| n.contains(ip)) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        self.allow.iter().any(|n| n.contains(ip))
    }
}

/// Simple token-bucket accept rate limit (per-source + optional global).
#[derive(Debug)]
pub struct AcceptRateLimit {
    /// Max accepts per window from one source IP.
    pub per_source: u32,
    /// Window length.
    pub window: Duration,
    /// Optional global accepts per window (`0` = unlimited).
    pub global: u32,
    inner: Mutex<RateState>,
}

#[derive(Debug, Default)]
struct RateState {
    global_count: u32,
    global_start: Option<Instant>,
    sources: HashMap<IpAddr, (u32, Instant)>,
    last_sweep: Option<Instant>,
}

impl Clone for AcceptRateLimit {
    fn clone(&self) -> Self {
        Self {
            per_source: self.per_source,
            window: self.window,
            global: self.global,
            inner: Mutex::new(RateState::default()),
        }
    }
}

impl AcceptRateLimit {
    /// Create a rate limiter.
    pub fn new(per_source: u32, window: Duration, global: u32) -> Self {
        Self {
            per_source,
            window,
            global,
            inner: Mutex::new(RateState::default()),
        }
    }

    /// Try to consume one accept slot for `peer`. Returns false if limited.
    pub fn try_acquire(&self, peer: SocketAddr) -> bool {
        let now = Instant::now();
        let ip = peer.ip();
        let mut g = self.inner.lock().unwrap();
        if self.global > 0 {
            match g.global_start {
                Some(start) if now.duration_since(start) < self.window => {
                    if g.global_count >= self.global {
                        return false;
                    }
                    g.global_count += 1;
                }
                _ => {
                    g.global_start = Some(now);
                    g.global_count = 1;
                }
            }
        }
        if self.per_source > 0 {
            // Sweep expired entries at most once per window, amortizing the
            // cost across every call in that window: without this, `sources`
            // is only ever inserted into and grows for the life of the
            // process, one entry per distinct source IP ever seen.
            let needs_sweep = match g.last_sweep {
                Some(last) => now.duration_since(last) >= self.window,
                None => true,
            };
            if needs_sweep {
                let window = self.window;
                g.sources
                    .retain(|_, (_, start)| now.duration_since(*start) < window);
                g.last_sweep = Some(now);
            }
            match g.sources.get_mut(&ip) {
                Some((count, start)) if now.duration_since(*start) < self.window => {
                    if *count >= self.per_source {
                        return false;
                    }
                    *count += 1;
                }
                _ => {
                    g.sources.insert(ip, (1, now));
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sa4(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::from(ip), port))
    }

    #[test]
    fn ipnet_parse_and_contains_v4() {
        let n = IpNet::parse("10.0.0.0/8").unwrap();
        assert!(n.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!n.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
        assert!(!n.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let all = IpNet::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        let host = IpNet::parse("192.0.2.1/32").unwrap();
        assert!(host.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!host.contains(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        assert!(IpNet::parse("bad").is_none());
        assert!(IpNet::parse("10.0.0.0/").is_none());
    }

    #[test]
    fn ipnet_v6_and_bad_prefix() {
        let n = IpNet::parse("2001:db8::/32").unwrap();
        assert!(n.contains(IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(!n.contains(IpAddr::V6("2001:db9::1".parse().unwrap())));
        let bad = IpNet {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix: 40,
        };
        assert!(!bad.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn peer_acl_deny_wins_and_allow_list() {
        let open = PeerAcl::open();
        assert!(open.allows(sa4([8, 8, 8, 8], 1)));

        let mut acl = PeerAcl::open();
        acl.allow.push(IpNet::parse("10.0.0.0/8").unwrap());
        assert!(acl.allows(sa4([10, 1, 0, 1], 80)));
        assert!(!acl.allows(sa4([11, 0, 0, 1], 80)));

        acl.deny.push(IpNet::parse("10.0.0.1/32").unwrap());
        assert!(!acl.allows(sa4([10, 0, 0, 1], 80)));
        assert!(acl.allows(sa4([10, 0, 0, 2], 80)));
    }

    #[test]
    fn rate_limit_per_source_and_global() {
        let lim = AcceptRateLimit::new(2, Duration::from_secs(60), 0);
        let a = sa4([1, 1, 1, 1], 1);
        let b = sa4([2, 2, 2, 2], 1);
        assert!(lim.try_acquire(a));
        assert!(lim.try_acquire(a));
        assert!(!lim.try_acquire(a));
        assert!(lim.try_acquire(b));

        let g = AcceptRateLimit::new(100, Duration::from_secs(60), 2);
        assert!(g.try_acquire(a));
        assert!(g.try_acquire(b));
        assert!(!g.try_acquire(a));
    }

    /// `sources` must not grow forever for the life of the process — once a
    /// source's window has elapsed, the next sweep (triggered by any call at
    /// least one window after the last sweep) prunes it, bounding memory to
    /// recently-active sources rather than every distinct IP ever seen.
    #[test]
    fn rate_limit_prunes_expired_sources_instead_of_growing_forever() {
        let window = Duration::from_millis(20);
        let lim = AcceptRateLimit::new(1, window, 0);

        for i in 0..50u8 {
            assert!(lim.try_acquire(sa4([10, 0, 0, i], 1)));
        }
        assert_eq!(lim.inner.lock().unwrap().sources.len(), 50);

        // Let every tracked entry's window expire, then make one more call
        // (from a source not in the map) far enough past the last sweep to
        // trigger a new sweep.
        std::thread::sleep(window * 2);
        assert!(lim.try_acquire(sa4([10, 0, 1, 0], 1)));

        // Only the source that triggered the sweep should remain — every
        // stale entry was pruned rather than sitting there indefinitely.
        assert_eq!(lim.inner.lock().unwrap().sources.len(), 1);
    }
}

