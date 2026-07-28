// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lightweight POP3 metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Server-wide POP3 counters.
#[derive(Debug, Default)]
pub struct Pop3ServerMetrics {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Successful authentications.
    pub auth_ok: AtomicU64,
    /// Failed authentications.
    pub auth_fail: AtomicU64,
    /// RETR commands completed.
    pub retr: AtomicU64,
    /// DELE marks applied.
    pub dele: AtomicU64,
    /// STLS upgrades completed.
    pub stls: AtomicU64,
}

impl Pop3ServerMetrics {
    /// Shared metrics handle.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}
