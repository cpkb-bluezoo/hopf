// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lightweight SOCKS server metrics (atomic counters).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Server-wide SOCKS counters.
#[derive(Debug, Default)]
pub struct SocksServerMetrics {
    /// Control connections accepted.
    pub connections: AtomicU64,
    /// CONNECT requests received.
    pub connect_requests: AtomicU64,
    /// Relays currently active.
    pub active_relays: AtomicU64,
    /// Bytes relayed from client to target.
    pub bytes_upstream: AtomicU64,
    /// Bytes relayed from target to client.
    pub bytes_downstream: AtomicU64,
    /// Successful RFC 1929 authentications.
    pub auth_ok: AtomicU64,
    /// Failed RFC 1929 authentications.
    pub auth_fail: AtomicU64,
    /// Requests denied by the destination policy.
    pub destinations_blocked: AtomicU64,
}

impl SocksServerMetrics {
    /// Shared metrics handle.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}
