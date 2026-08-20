// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 7838 Alt-Svc header parsing + discovery cache — the second tier of
//! automatic H3 negotiation in [`super::connect::connect_auto`], consulted
//! when a DNS HTTPS record (the first tier) didn't advertise `h3` support.
//!
//! Unlike the DNS HTTPS-record tier, Alt-Svc is only visible *after*
//! already connecting once (it's a response header, not something a client
//! can look up in advance) — [`AltSvcObservingHandler`] watches for it on
//! ordinary H1/H2 responses and feeds [`AltSvcCache`] so a *later*
//! connection attempt to the same origin can benefit.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg(feature = "h3")]
use crate::{ClientHandler, ClientHandlerFactory, ClientWriter, Headers};

/// RFC 7838 §3: default max-age assumed when an Alt-Svc entry omits the
/// `ma` parameter. Not RFC-mandated — a pragmatic 24-hour default.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(86400);

/// A parsed `h3` entry from an Alt-Svc header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvcH3Entry {
    /// The advertised host, or `None` for same-origin.
    pub host: Option<String>,
    /// The advertised port.
    pub port: u16,
    /// RFC 7838 §3 `ma` parameter, or [`DEFAULT_MAX_AGE`] if absent.
    pub max_age: Duration,
}

/// Parses the `h3` entry out of an Alt-Svc header value (RFC 7838 §3):
/// looks for `h3="[host]:port"`, with an optional trailing `; ma=NNN`.
/// Character-by-character, no regex. Returns `None` if no `h3` entry is
/// present or it's malformed.
pub fn parse_alt_svc_h3(value: &str) -> Option<AltSvcH3Entry> {
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }

        if i + 4 <= len && &bytes[i..i + 4] == b"h3=\"" {
            i += 4;
            let host_start = i;
            let mut colon_pos = None;
            while i < len && bytes[i] != b'"' {
                if bytes[i] == b':' {
                    colon_pos = Some(i);
                }
                i += 1;
            }
            let Some(colon_pos) = colon_pos else {
                return None;
            };
            if i >= len {
                return None;
            }
            let host_len = colon_pos - host_start;
            let host = if host_len > 0 {
                Some(value[host_start..colon_pos].to_string())
            } else {
                None
            };

            let mut port: u32 = 0;
            for &c in &bytes[colon_pos + 1..i] {
                if !c.is_ascii_digit() {
                    return None;
                }
                port = port * 10 + u32::from(c - b'0');
            }
            if port == 0 || port > 65535 {
                return None;
            }

            i += 1; // past closing quote
            let max_age = parse_trailing_max_age(value, i);

            return Some(AltSvcH3Entry {
                host,
                port: port as u16,
                max_age,
            });
        }

        while i < len && bytes[i] != b',' {
            i += 1;
        }
        if i < len {
            i += 1;
        }
    }

    None
}

/// Scans `; name=value` parameters following an Alt-Svc entry (starting at
/// `start`, just past the closing quote of the entry's value) for `ma`
/// (RFC 7838 §3), stopping at the next comma-separated entry or end of
/// string.
fn parse_trailing_max_age(value: &str, start: usize) -> Duration {
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut i = start;
    let mut max_age = DEFAULT_MAX_AGE;
    while i < len {
        while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i >= len || bytes[i] != b';' {
            break;
        }
        i += 1;
        while i < len && (bytes[i] == b' ' || bytes[i] == b'\t') {
            i += 1;
        }
        if i + 3 <= len && &bytes[i..i + 3] == b"ma=" {
            i += 3;
            let mut ma: u64 = 0;
            let mut any = false;
            while i < len && bytes[i].is_ascii_digit() {
                ma = ma * 10 + u64::from(bytes[i] - b'0');
                i += 1;
                any = true;
            }
            if any {
                max_age = Duration::from_secs(ma);
            }
        } else {
            while i < len && bytes[i] != b';' && bytes[i] != b',' {
                i += 1;
            }
        }
    }
    max_age
}

struct CacheEntry {
    h3_host: Option<String>,
    h3_port: u16,
    cached_at: Instant,
    max_age: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.cached_at + self.max_age
    }
}

/// A cached h3 alt-endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvcEntry {
    /// The advertised h3 host, or `None` for same-origin.
    pub h3_host: Option<String>,
    /// The advertised h3 port.
    pub h3_port: u16,
}

/// Discovery cache of h3 support seen via Alt-Svc response headers (RFC
/// 7838), keyed by origin `host:port`. Scoped to whatever owns it (e.g.
/// shared across [`super::connect::connect_auto`] calls via an `Arc`) —
/// matching this crate's existing no-statics style — rather than a
/// process-wide global.
#[derive(Default)]
pub struct AltSvcCache {
    inner: Mutex<HashMap<(String, u16), CacheEntry>>,
}

impl AltSvcCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `host:port` advertised h3 support, valid for `entry`'s
    /// max-age.
    pub fn put(&self, host: &str, port: u16, entry: &AltSvcH3Entry) {
        self.inner.lock().unwrap().insert(
            (host.to_ascii_lowercase(), port),
            CacheEntry {
                h3_host: entry.host.clone(),
                h3_port: entry.port,
                cached_at: Instant::now(),
                max_age: entry.max_age,
            },
        );
    }

    /// Returns the cached h3 entry for `host:port`, or `None` if absent or
    /// expired.
    pub fn get(&self, host: &str, port: u16) -> Option<AltSvcEntry> {
        let key = (host.to_ascii_lowercase(), port);
        let mut map = self.inner.lock().unwrap();
        match map.get(&key) {
            Some(e) if !e.is_expired() => Some(AltSvcEntry {
                h3_host: e.h3_host.clone(),
                h3_port: e.h3_port,
            }),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }
}

/// Wraps a [`ClientHandlerFactory`] to additionally watch every response
/// for an `Alt-Svc` header, feeding `cache` on a match — regardless of
/// whether the *current* connection acts on it. Used by
/// [`super::connect::connect_auto`]'s tier-3 (plain TCP) fallback so a
/// discovery made on one connection benefits the *next* connection attempt
/// to the same origin; it does not tear down/upgrade the connection it's
/// installed on.
#[cfg(feature = "h3")]
pub(crate) struct AltSvcObservingFactory {
    inner: std::sync::Arc<dyn ClientHandlerFactory>,
    cache: std::sync::Arc<AltSvcCache>,
    host: String,
    port: u16,
}

#[cfg(feature = "h3")]
impl AltSvcObservingFactory {
    pub(crate) fn new(
        inner: std::sync::Arc<dyn ClientHandlerFactory>,
        cache: std::sync::Arc<AltSvcCache>,
        host: String,
        port: u16,
    ) -> Self {
        Self { inner, cache, host, port }
    }
}

#[cfg(feature = "h3")]
impl ClientHandlerFactory for AltSvcObservingFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(AltSvcObservingHandler {
            inner: self.inner.create_handler(),
            cache: std::sync::Arc::clone(&self.cache),
            host: self.host.clone(),
            port: self.port,
        })
    }
}

#[cfg(feature = "h3")]
struct AltSvcObservingHandler {
    inner: Box<dyn ClientHandler>,
    cache: std::sync::Arc<AltSvcCache>,
    host: String,
    port: u16,
}

#[cfg(feature = "h3")]
impl ClientHandler for AltSvcObservingHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        self.inner.start(request);
    }

    fn informational_response(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.informational_response(request, headers);
    }

    fn switching_protocols(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.switching_protocols(request, headers);
    }

    fn response_headers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        if let Some(value) = headers.get("alt-svc") {
            if let Some(entry) = parse_alt_svc_h3(value) {
                self.cache.put(&self.host, self.port, &entry);
            }
        }
        self.inner.response_headers(request, headers);
    }

    fn start_response_body(&mut self, request: &mut dyn ClientWriter) {
        self.inner.start_response_body(request);
    }

    fn response_body_content(&mut self, request: &mut dyn ClientWriter, data: &[u8]) {
        self.inner.response_body_content(request, data);
    }

    fn end_response_body(&mut self, request: &mut dyn ClientWriter) {
        self.inner.end_response_body(request);
    }

    fn response_trailers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.response_trailers(request, headers);
    }

    fn response_complete(&mut self, request: &mut dyn ClientWriter) {
        self.inner.response_complete(request);
    }

    fn request_failed(&mut self, request: &mut dyn ClientWriter, err: &std::io::Error) {
        self.inner.request_failed(request, err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_h3_entry_with_default_max_age() {
        let entry = parse_alt_svc_h3("h3=\":443\"").unwrap();
        assert_eq!(entry.host, None);
        assert_eq!(entry.port, 443);
        assert_eq!(entry.max_age, DEFAULT_MAX_AGE);
    }

    #[test]
    fn parses_h3_entry_with_host_and_ma() {
        let entry = parse_alt_svc_h3("h3=\"alt.example:8443\"; ma=3600").unwrap();
        assert_eq!(entry.host.as_deref(), Some("alt.example"));
        assert_eq!(entry.port, 8443);
        assert_eq!(entry.max_age, Duration::from_secs(3600));
    }

    #[test]
    fn skips_non_h3_entries_to_find_h3() {
        let entry = parse_alt_svc_h3("h2=\":443\", h3=\":8443\"; ma=60").unwrap();
        assert_eq!(entry.port, 8443);
        assert_eq!(entry.max_age, Duration::from_secs(60));
    }

    #[test]
    fn no_h3_entry_returns_none() {
        assert_eq!(parse_alt_svc_h3("h2=\":443\""), None);
        assert_eq!(parse_alt_svc_h3("clear"), None);
        assert_eq!(parse_alt_svc_h3(""), None);
    }

    #[test]
    fn malformed_entries_return_none() {
        assert_eq!(parse_alt_svc_h3("h3=\":notaport\""), None);
        assert_eq!(parse_alt_svc_h3("h3=\"noport\""), None);
        assert_eq!(parse_alt_svc_h3("h3=\":0\""), None);
        assert_eq!(parse_alt_svc_h3("h3=\":99999\""), None);
    }

    #[test]
    fn cache_put_get_and_expiry() {
        let cache = AltSvcCache::new();
        assert_eq!(cache.get("example.test", 443), None);

        cache.put(
            "Example.Test",
            443,
            &AltSvcH3Entry { host: None, port: 8443, max_age: Duration::from_secs(60) },
        );
        // Lookup is case-insensitive on host.
        let got = cache.get("example.test", 443).unwrap();
        assert_eq!(got.h3_host, None);
        assert_eq!(got.h3_port, 8443);

        cache.put(
            "expired.test",
            443,
            &AltSvcH3Entry { host: None, port: 8443, max_age: Duration::from_secs(0) },
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("expired.test", 443), None);
    }
}
