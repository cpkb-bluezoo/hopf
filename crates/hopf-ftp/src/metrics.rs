// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Lightweight FTP metrics (OTel-friendly counters).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Server-wide FTP counters.
#[derive(Debug, Default)]
pub struct FtpServerMetrics {
    /// Control connections accepted.
    pub connections: AtomicU64,
    /// Successful authentications.
    pub auth_ok: AtomicU64,
    /// Failed authentications.
    pub auth_fail: AtomicU64,
    /// Commands processed.
    pub commands: AtomicU64,
    /// Bytes sent on data connections.
    pub bytes_out: AtomicU64,
    /// Bytes received on data connections.
    pub bytes_in: AtomicU64,
    /// PASV listeners created.
    pub pasv_binds: AtomicU64,
}

impl FtpServerMetrics {
    /// Shared metrics handle.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Increment a counter.
    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }
}
