// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lightweight MQTT metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Server-wide MQTT counters.
#[derive(Debug, Default)]
pub struct MqttServerMetrics {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Successful CONNECT authorizations.
    pub auth_ok: AtomicU64,
    /// Failed CONNECT authorizations.
    pub auth_fail: AtomicU64,
    /// Client PUBLISH packets completed.
    pub publishes: AtomicU64,
    /// SUBSCRIBE packets processed.
    pub subscribes: AtomicU64,
}

impl MqttServerMetrics {
    /// Shared metrics handle.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}
