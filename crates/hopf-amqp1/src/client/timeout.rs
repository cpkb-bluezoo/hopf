// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-phase client timeouts.

use std::time::Duration;

/// Timeouts for the different phases of establishing and running an AMQP
/// 1.0 client connection.
#[derive(Debug, Clone, Copy)]
pub struct Amqp1ClientTimeouts {
    /// DNS resolution.
    pub dns: Duration,
    /// TCP (or TLS-wrapped TCP) connect.
    pub connect: Duration,
    /// SASL negotiation plus the AMQP `open` exchange.
    pub handshake: Duration,
    /// Idle timeout this client advertises in `open.idle-time-out` — the
    /// peer must see traffic from us at least this often, or it may close
    /// the connection (core spec 2.4.5).
    pub idle_time_out: Duration,
}

impl Default for Amqp1ClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(10),
            handshake: Duration::from_secs(10),
            idle_time_out: Duration::from_secs(60),
        }
    }
}
