// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-resolver cache of which upstream servers are known *not* to support
//! RFC 10029 (DNS Multiple QTYPEs) — mirrors [`crate::cache::DnsCache`]'s
//! `Instant`-based TTL shape.
//!
//! A server that's never been tried, or that supports the mechanism, has
//! no entry at all: [`crate::client::DnsResolver::query_batch`] always
//! tries opportunistically by default, since attaching the option costs
//! nothing when it works. Only the negative case is cached, and only
//! temporarily, so a server whose support changes (or was probed while
//! temporarily misbehaving) gets re-tried later rather than written off
//! forever.
//!
//! Scoped to one [`crate::client::DnsResolver`] instance rather than a
//! process-wide global, matching this crate's existing no-statics style
//! (e.g. [`crate::cache::DnsCache`] is likewise always constructed per
//! resolver/shared explicitly via `Arc`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// RFC 10029 doesn't define a TTL for this kind of capability discovery; an
/// hour bounds how long a server that starts (or resumes) supporting the
/// option goes un-retried, without probing constantly.
const UNSUPPORTED_TTL: Duration = Duration::from_secs(60 * 60);

/// Per-resolver capability cache. Cheap to construct; typically one lives
/// inside a resolver's shared inner state.
#[derive(Default)]
pub struct MultiQTypeCache {
    unsupported_until: Mutex<HashMap<SocketAddr, Instant>>,
}

impl MultiQTypeCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `server` does not appear to support RFC 10029.
    pub fn mark_unsupported(&self, server: SocketAddr) {
        self.unsupported_until
            .lock()
            .unwrap()
            .insert(server, Instant::now() + UNSUPPORTED_TTL);
    }

    /// True if `server` was recently observed not to support RFC 10029 —
    /// i.e. attaching the `MQTYPE-Query` option to it should be skipped for
    /// now. Self-expiring: a stale entry is removed (not just ignored) the
    /// first time it's read past its TTL, so the map doesn't grow forever.
    pub fn is_known_unsupported(&self, server: SocketAddr) -> bool {
        let mut map = self.unsupported_until.lock().unwrap();
        match map.get(&server) {
            Some(&expiry) if Instant::now() < expiry => true,
            Some(_) => {
                map.remove(&server);
                false
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmarked_server_is_not_unsupported() {
        let cache = MultiQTypeCache::new();
        let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert!(!cache.is_known_unsupported(addr));
    }

    #[test]
    fn marked_server_is_unsupported_until_expiry() {
        let cache = MultiQTypeCache::new();
        let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
        cache.mark_unsupported(addr);
        assert!(cache.is_known_unsupported(addr));

        // A different server is unaffected.
        let other: SocketAddr = "127.0.0.1:54".parse().unwrap();
        assert!(!cache.is_known_unsupported(other));
    }
}
