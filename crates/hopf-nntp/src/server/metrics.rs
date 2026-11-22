// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Counters for the NNTP server.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Server-wide NNTP counters.
#[derive(Debug, Default)]
pub struct NntpServerMetrics {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Commands received.
    pub commands: AtomicU64,
    /// Articles (or heads or bodies) sent.
    pub articles_retrieved: AtomicU64,
    /// Articles accepted by `POST`.
    pub articles_posted: AtomicU64,
    /// Successful authentications.
    pub auth_ok: AtomicU64,
    /// Failed authentications.
    pub auth_fail: AtomicU64,
    /// `STARTTLS` upgrades completed.
    pub starttls: AtomicU64,
}

impl NntpServerMetrics {
    /// A shared set of counters, all zero.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Adds `n` to `counter`.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}
