// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Forwarder policies: resolver behaviour that the RFCs allow but do not
//! require, so each one is a hook a deployment can replace or turn off.
//!
//! * [`StalePolicy`] - RFC 8767 Serve-Stale.
//! * [`NxdomainCutPolicy`] - RFC 8020 "NXDOMAIN: there really is nothing
//!   underneath".
//! * [`MinimalAnyPolicy`](super::MinimalAnyPolicy) - RFC 8482 minimal `ANY`.
//!
//! All three are attached to a [`ForwarderHandler`](super::ForwarderHandler)
//! and, like the handler chain itself, take a closure where a policy is a
//! one-liner.

use std::time::Duration;

use crate::wire::DnsQuestion;

/// What a [`StalePolicy`] allows for one question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleTerms {
    /// The oldest an expired answer may be and still be served. The cache's
    /// own window ([`DnsCache::with_max_stale`](crate::DnsCache::with_max_stale))
    /// is an upper bound on this.
    pub max_age: Duration,
    /// TTL put on a stale answer. RFC 8767 §4 requires more than zero and
    /// recommends 30 seconds; this rate-limits clients that honour the TTL.
    pub answer_ttl: u32,
}

/// RFC 8767 §4's recommended stale TTL.
pub const RECOMMENDED_STALE_TTL: u32 = 30;

impl Default for StaleTerms {
    /// One day past expiry (the low end of RFC 8767 §5's suggested 1 to 3
    /// days) at the recommended 30-second TTL.
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(24 * 60 * 60),
            answer_ttl: RECOMMENDED_STALE_TTL,
        }
    }
}

/// Decides whether, and on what terms, an expired cache entry may answer a
/// question when the upstream cannot be reached (RFC 8767).
///
/// `None` means never for this question, so the client gets the failure. Any
/// `Fn(&DnsQuestion) -> Option<StaleTerms>` is a policy:
///
/// ```ignore
/// forwarder.with_stale_policy(|q: &DnsQuestion| {
///     // Never serve stale for the internal zone; a short window elsewhere.
///     (!q.name.ends_with(".corp.example")).then(|| StaleTerms {
///         max_age: Duration::from_secs(3600),
///         ..StaleTerms::default()
///     })
/// })
/// ```
pub trait StalePolicy: Send + Sync {
    /// The terms for `question`, or `None` to refuse stale answers for it.
    fn stale_terms(&self, question: &DnsQuestion) -> Option<StaleTerms>;
}

/// Serve stale on RFC 8767's recommended terms, or on the given ones (the
/// default).
#[derive(Debug, Clone, Copy, Default)]
pub struct ServeStale(pub StaleTerms);

/// Never serve stale: an unreachable upstream is a failure.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServeStaleDisabled;

impl StalePolicy for ServeStale {
    fn stale_terms(&self, _question: &DnsQuestion) -> Option<StaleTerms> {
        Some(self.0)
    }
}

impl StalePolicy for ServeStaleDisabled {
    fn stale_terms(&self, _question: &DnsQuestion) -> Option<StaleTerms> {
        None
    }
}

impl<F> StalePolicy for F
where
    F: Fn(&DnsQuestion) -> Option<StaleTerms> + Send + Sync,
{
    fn stale_terms(&self, question: &DnsQuestion) -> Option<StaleTerms> {
        self(question)
    }
}

/// Decides whether a cached NXDOMAIN answers queries for every name beneath it
/// (RFC 8020) without asking the upstream.
///
/// Split-horizon setups, where a name may exist internally beneath a name that
/// does not exist externally, should turn it off - at least for those zones.
/// Any `Fn(&DnsQuestion) -> bool` is a policy.
pub trait NxdomainCutPolicy: Send + Sync {
    /// `true` to synthesise NXDOMAIN for `question` from a cached ancestor.
    fn nxdomain_cut(&self, question: &DnsQuestion) -> bool;
}

/// Apply the NXDOMAIN cut everywhere (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct NxdomainCutEnabled;

/// Never infer non-existence from an ancestor.
#[derive(Debug, Clone, Copy, Default)]
pub struct NxdomainCutDisabled;

impl NxdomainCutPolicy for NxdomainCutEnabled {
    fn nxdomain_cut(&self, _question: &DnsQuestion) -> bool {
        true
    }
}

impl NxdomainCutPolicy for NxdomainCutDisabled {
    fn nxdomain_cut(&self, _question: &DnsQuestion) -> bool {
        false
    }
}

impl<F> NxdomainCutPolicy for F
where
    F: Fn(&DnsQuestion) -> bool + Send + Sync,
{
    fn nxdomain_cut(&self, question: &DnsQuestion) -> bool {
        self(question)
    }
}
