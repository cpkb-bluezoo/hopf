// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::fmt;
use std::time::Duration;

use crate::headers::Headers;

/// A response `Cache-Control` value (RFC 9111 §5.2.2), built from
/// directives.
///
/// ```
/// use std::time::Duration;
/// use hopf_http::CacheControl;
///
/// let cc = CacheControl::new().public().max_age(Duration::from_secs(3600)).immutable();
/// assert_eq!(cc.to_string(), "public, max-age=3600, immutable");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheControl {
    public: bool,
    private: bool,
    no_cache: bool,
    no_store: bool,
    no_transform: bool,
    must_revalidate: bool,
    proxy_revalidate: bool,
    must_understand: bool,
    immutable: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    stale_while_revalidate: Option<u64>,
    stale_if_error: Option<u64>,
}

impl CacheControl {
    /// No directives.
    pub fn new() -> Self {
        Self::default()
    }

    /// `public`: a shared cache may store it even if it would not otherwise.
    pub fn public(mut self) -> Self {
        self.public = true;
        self
    }

    /// `private`: only the user agent's own cache may store it.
    pub fn private(mut self) -> Self {
        self.private = true;
        self
    }

    /// `no-cache`: a stored response must be revalidated before every reuse.
    pub fn no_cache(mut self) -> Self {
        self.no_cache = true;
        self
    }

    /// `no-store`: do not store any part of the request or response.
    pub fn no_store(mut self) -> Self {
        self.no_store = true;
        self
    }

    /// `no-transform`: intermediaries must not change the body. Also stops
    /// hopf's own [`ContentEncodingServerFactory`](crate::ContentEncodingServerFactory)
    /// compressing it.
    pub fn no_transform(mut self) -> Self {
        self.no_transform = true;
        self
    }

    /// `must-revalidate`: once stale, do not reuse without revalidating.
    pub fn must_revalidate(mut self) -> Self {
        self.must_revalidate = true;
        self
    }

    /// `proxy-revalidate`: `must-revalidate` for shared caches only.
    pub fn proxy_revalidate(mut self) -> Self {
        self.proxy_revalidate = true;
        self
    }

    /// `must-understand`: only store if the status code's semantics are
    /// understood.
    pub fn must_understand(mut self) -> Self {
        self.must_understand = true;
        self
    }

    /// `immutable` (RFC 8246): the response will not change while fresh, so
    /// a reload need not revalidate it.
    pub fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }

    /// `max-age`: fresh for this long. Sub-second parts are dropped.
    pub fn max_age(mut self, d: Duration) -> Self {
        self.max_age = Some(d.as_secs());
        self
    }

    /// `s-maxage`: like `max-age` but for shared caches, which it overrides.
    pub fn s_maxage(mut self, d: Duration) -> Self {
        self.s_maxage = Some(d.as_secs());
        self
    }

    /// `stale-while-revalidate` (RFC 5861).
    pub fn stale_while_revalidate(mut self, d: Duration) -> Self {
        self.stale_while_revalidate = Some(d.as_secs());
        self
    }

    /// `stale-if-error` (RFC 5861).
    pub fn stale_if_error(mut self, d: Duration) -> Self {
        self.stale_if_error = Some(d.as_secs());
        self
    }

    /// Whether no directive is set.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Set the `Cache-Control` field on `headers` (replacing any), unless
    /// there are no directives.
    pub fn apply(&self, headers: &mut Headers) {
        if !self.is_empty() {
            headers.set("Cache-Control", self.to_string());
        }
    }
}

impl fmt::Display for CacheControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut item = |f: &mut fmt::Formatter<'_>, s: String| -> fmt::Result {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            f.write_str(&s)
        };
        for (on, name) in [
            (self.public, "public"),
            (self.private, "private"),
            (self.no_cache, "no-cache"),
            (self.no_store, "no-store"),
            (self.no_transform, "no-transform"),
            (self.must_revalidate, "must-revalidate"),
            (self.proxy_revalidate, "proxy-revalidate"),
            (self.must_understand, "must-understand"),
        ] {
            if on {
                item(f, name.to_string())?;
            }
        }
        for (v, name) in [
            (self.max_age, "max-age"),
            (self.s_maxage, "s-maxage"),
            (self.stale_while_revalidate, "stale-while-revalidate"),
            (self.stale_if_error, "stale-if-error"),
        ] {
            if let Some(v) = v {
                item(f, format!("{name}={v}"))?;
            }
        }
        if self.immutable {
            item(f, "immutable".to_string())?;
        }
        Ok(())
    }
}
