// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lightweight IMAP metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Server-wide IMAP counters.
#[derive(Debug, Default)]
pub struct ImapServerMetrics {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Successful authentications.
    pub auth_ok: AtomicU64,
    /// Failed authentications.
    pub auth_fail: AtomicU64,
    /// Tagged commands completed.
    pub commands: AtomicU64,
    /// STARTTLS upgrades completed.
    pub starttls: AtomicU64,
}

impl ImapServerMetrics {
    /// Shared metrics handle.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}
