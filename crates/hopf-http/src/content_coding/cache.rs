// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-origin record of which request-body codings a server accepts.
//!
//! HTTP has no request-side negotiation. A server may say which codings it
//! accepts in *requests* by sending `Accept-Encoding` on a response (RFC 9110
//! §12.5.3), and may reject a coded request with `415` plus `Accept-Encoding`.
//! The client records what it hears here and compresses a request body only
//! with a coding an origin has advertised - an origin nothing is known about
//! gets an uncompressed body.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::ContentCoding;

/// How long a learned capability is trusted.
const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);
/// Bound on remembered origins.
const MAX_ENTRIES: usize = 1024;

struct Entry {
    codings: Vec<ContentCoding>,
    expires: Instant,
}

/// Thread-safe capability cache, keyed by origin (host and port).
///
/// Share one between clients with `Arc`, the way [`AltSvcCache`](crate::AltSvcCache)
/// is shared.
pub struct ContentCodingCache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, u16), Entry>>,
}

impl Default for ContentCodingCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ContentCodingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentCodingCache").field("ttl", &self.ttl).finish_non_exhaustive()
    }
}

impl ContentCodingCache {
    /// Empty cache; entries live for one hour.
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }

    /// Empty cache with a custom entry lifetime.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn key(host: &str, port: u16) -> (String, u16) {
        (host.to_ascii_lowercase(), port)
    }

    /// Record the codings `host:port` accepts in requests. An empty list
    /// records "known to accept none" (identity only).
    pub fn put(&self, host: &str, port: u16, codings: Vec<ContentCoding>) {
        let mut m = self.entries.lock().unwrap();
        if m.len() >= MAX_ENTRIES {
            let now = Instant::now();
            m.retain(|_, e| e.expires > now);
            if m.len() >= MAX_ENTRIES {
                m.clear();
            }
        }
        m.insert(
            Self::key(host, port),
            Entry {
                codings,
                expires: Instant::now() + self.ttl,
            },
        );
    }

    /// The codings `host:port` is known to accept, or `None` if nothing is
    /// known (or what was known has expired).
    pub fn get(&self, host: &str, port: u16) -> Option<Vec<ContentCoding>> {
        let mut m = self.entries.lock().unwrap();
        let key = Self::key(host, port);
        match m.get(&key) {
            Some(e) if e.expires > Instant::now() => Some(e.codings.clone()),
            Some(_) => {
                m.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Forget an origin (for example after it rejected a coded request).
    pub fn forget(&self, host: &str, port: u16) {
        self.entries.lock().unwrap().remove(&Self::key(host, port));
    }
}
