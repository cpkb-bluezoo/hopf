// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Limits on failed logins (issue #518).
//!
//! Without them a client can guess passwords as fast as the connection
//! carries `USER`/`PASS` pairs. [`LoginLimits`] holds the three defences:
//! a cap on failures per connection, a delay before each failure is answered,
//! and a lockout of a source address that keeps failing across connections.
//! [`LoginThrottle`] is the last one's memory, shared by every connection of
//! a server.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How hard the server makes it to guess a password. Set with
/// [`FtpConfig::with_login_limits`](crate::FtpConfig::with_login_limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginLimits {
    /// Failed logins one connection may make before it is closed with a 421.
    /// `0` means no limit. Default 3.
    pub max_failures_per_connection: u32,
    /// How long a failed login is left unanswered, and the connection's
    /// later commands held, so that each guess costs this much time. Zero
    /// answers at once. Default one second.
    pub failure_delay: Duration,
    /// Failures from one source address, within [`Self::lockout_window`],
    /// that lock the address out. `0` turns lockout off. Default 10.
    pub lockout_after: u32,
    /// How long a source's failures are remembered, counted from its first
    /// one. Default ten minutes.
    pub lockout_window: Duration,
    /// How long a locked-out source is turned away at connect. Default ten
    /// minutes.
    pub lockout_duration: Duration,
}

impl Default for LoginLimits {
    fn default() -> Self {
        Self {
            max_failures_per_connection: 3,
            failure_delay: Duration::from_secs(1),
            lockout_after: 10,
            lockout_window: Duration::from_secs(600),
            lockout_duration: Duration::from_secs(600),
        }
    }
}

impl LoginLimits {
    /// No limits at all: every guess is answered at once, forever.
    pub fn unlimited() -> Self {
        Self {
            max_failures_per_connection: 0,
            failure_delay: Duration::ZERO,
            lockout_after: 0,
            ..Self::default()
        }
    }
}

/// The most sources remembered at once. A source is only remembered after
/// failing a login, so this takes an attacker with this many addresses; past
/// it new sources go untracked rather than the server's memory growing.
const MAX_TRACKED: usize = 65_536;

struct Source {
    failures: u32,
    /// When the first of the remembered failures happened.
    since: Instant,
    locked_until: Option<Instant>,
}

/// Failed logins by source address, for lockout.
#[derive(Default)]
pub(crate) struct LoginThrottle {
    sources: Mutex<HashMap<IpAddr, Source>>,
}

/// What identifies a source: the address, except that an IPv6 host can use
/// any address in its /64, so all of those are one source.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        },
        v4 => v4,
    }
}

impl LoginThrottle {
    /// Is `ip` locked out at `now`?
    pub(crate) fn is_locked(&self, ip: IpAddr, now: Instant) -> bool {
        let mut sources = self.sources.lock().unwrap();
        let key = source_key(ip);
        match sources.get(&key).and_then(|s| s.locked_until) {
            Some(until) if now < until => true,
            Some(_) => {
                sources.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Note a failed login from `ip`; true if that locks the source out.
    pub(crate) fn record_failure(&self, ip: IpAddr, limits: &LoginLimits, now: Instant) -> bool {
        if limits.lockout_after == 0 {
            return false;
        }
        let mut sources = self.sources.lock().unwrap();
        let key = source_key(ip);
        if sources.len() >= MAX_TRACKED && !sources.contains_key(&key) {
            sources.retain(|_, s| match s.locked_until {
                Some(until) => now < until,
                None => now.duration_since(s.since) <= limits.lockout_window,
            });
            if sources.len() >= MAX_TRACKED {
                return false;
            }
        }
        let source = sources.entry(key).or_insert(Source { failures: 0, since: now, locked_until: None });
        if source.locked_until.is_some_and(|until| now < until) {
            return true;
        }
        if source.locked_until.is_some() || now.duration_since(source.since) > limits.lockout_window {
            *source = Source { failures: 0, since: now, locked_until: None };
        }
        source.failures += 1;
        if source.failures >= limits.lockout_after {
            source.locked_until = Some(now + limits.lockout_duration);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(after: u32) -> LoginLimits {
        LoginLimits {
            lockout_after: after,
            lockout_window: Duration::from_secs(60),
            lockout_duration: Duration::from_secs(300),
            ..LoginLimits::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn secs(base: Instant, s: u64) -> Instant {
        base + Duration::from_secs(s)
    }

    #[test]
    fn a_source_is_locked_out_by_the_failure_that_reaches_the_threshold() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(3), Instant::now());
        assert!(!t.record_failure(ip("192.0.2.1"), &l, now));
        assert!(!t.record_failure(ip("192.0.2.1"), &l, now));
        assert!(!t.is_locked(ip("192.0.2.1"), now));
        assert!(t.record_failure(ip("192.0.2.1"), &l, now), "the third failure locks it");
        assert!(t.is_locked(ip("192.0.2.1"), now));
    }

    #[test]
    fn the_lockout_ends_after_its_duration() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(1), Instant::now());
        assert!(t.record_failure(ip("192.0.2.1"), &l, now));
        assert!(t.is_locked(ip("192.0.2.1"), secs(now, 299)));
        assert!(!t.is_locked(ip("192.0.2.1"), secs(now, 300)));
        assert!(!t.record_failure(ip("192.0.2.1"), &limits(2), secs(now, 301)), "starts again from nothing");
    }

    #[test]
    fn failures_older_than_the_window_are_forgotten() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(3), Instant::now());
        t.record_failure(ip("192.0.2.1"), &l, now);
        t.record_failure(ip("192.0.2.1"), &l, secs(now, 30));
        // the window began at the first failure and has ended
        assert!(!t.record_failure(ip("192.0.2.1"), &l, secs(now, 61)));
        assert!(!t.record_failure(ip("192.0.2.1"), &l, secs(now, 62)));
        assert!(t.record_failure(ip("192.0.2.1"), &l, secs(now, 63)));
    }

    #[test]
    fn sources_are_independent() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(2), Instant::now());
        t.record_failure(ip("192.0.2.1"), &l, now);
        t.record_failure(ip("192.0.2.2"), &l, now);
        assert!(!t.is_locked(ip("192.0.2.1"), now) && !t.is_locked(ip("192.0.2.2"), now));
        assert!(t.record_failure(ip("192.0.2.1"), &l, now));
        assert!(!t.is_locked(ip("192.0.2.2"), now));
    }

    #[test]
    fn every_address_in_an_ipv6_64_is_one_source() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(2), Instant::now());
        t.record_failure(ip("2001:db8:1:2::1"), &l, now);
        assert!(t.record_failure(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), &l, now));
        assert!(t.is_locked(ip("2001:db8:1:2::99"), now));
        assert!(!t.is_locked(ip("2001:db8:1:3::1"), now), "another /64");
    }

    #[test]
    fn an_ipv4_mapped_address_is_the_ipv4_address() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(1), Instant::now());
        assert!(t.record_failure(ip("::ffff:192.0.2.7"), &l, now));
        assert!(t.is_locked(ip("192.0.2.7"), now));
    }

    #[test]
    fn a_threshold_of_zero_never_locks_anyone_out() {
        let t = LoginThrottle::default();
        let now = Instant::now();
        for _ in 0..100 {
            assert!(!t.record_failure(ip("192.0.2.1"), &limits(0), now));
        }
        assert!(!t.is_locked(ip("192.0.2.1"), now));
        assert!(t.sources.lock().unwrap().is_empty(), "and nothing is remembered");
    }

    #[test]
    fn a_failure_while_locked_out_does_not_extend_the_lockout() {
        let t = LoginThrottle::default();
        let (l, now) = (limits(1), Instant::now());
        t.record_failure(ip("192.0.2.1"), &l, now);
        assert!(t.record_failure(ip("192.0.2.1"), &l, secs(now, 200)));
        assert!(!t.is_locked(ip("192.0.2.1"), secs(now, 300)), "still ends 300 s after the first");
    }

    #[test]
    fn the_defaults_limit_guessing_and_unlimited_does_not() {
        let d = LoginLimits::default();
        assert!(d.max_failures_per_connection > 0 && !d.failure_delay.is_zero() && d.lockout_after > 0);
        let u = LoginLimits::unlimited();
        assert!(u.max_failures_per_connection == 0 && u.failure_delay.is_zero() && u.lockout_after == 0);
    }
}
