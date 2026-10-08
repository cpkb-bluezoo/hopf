// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-phase timeouts.

use std::time::Duration;

/// Timeouts applied at each phase of a client connection.
#[derive(Debug, Clone)]
pub struct NntpClientTimeouts {
    /// DNS resolution budget (ignored for literal IPs).
    pub dns: Duration,
    /// TCP connect budget.
    pub connect: Duration,
    /// Quiet-time budget for one command: reset on every reply line, so a
    /// long `LIST ACTIVE` or a big `ARTICLE` is not cut off while it flows.
    pub command: Duration,
}

impl Default for NntpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            command: Duration::from_secs(120),
        }
    }
}
