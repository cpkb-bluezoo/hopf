// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-phase timeout configuration for the AMQP client.

use std::time::Duration;

/// Per-phase timeout configuration for [`super::facade::AmqpClient`].
#[derive(Debug, Clone)]
pub struct AmqpClientTimeouts {
    /// DNS resolution budget (default 5 s).
    pub dns: Duration,
    /// Connect budget: dial → TCP established (default 30 s).
    pub connect: Duration,
    /// How long to wait for `connection.open-ok` after starting the handshake (default 30 s).
    pub handshake: Duration,
    /// How long to wait for a heartbeat from the peer after we expect one (default 2× heartbeat interval, set at runtime; this is a floor of 10 s).
    pub heartbeat: Duration,
}

impl Default for AmqpClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            handshake: Duration::from_secs(30),
            heartbeat: Duration::from_secs(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let t = AmqpClientTimeouts::default();
        assert_eq!(t.dns, Duration::from_secs(5));
        assert_eq!(t.connect, Duration::from_secs(30));
        assert_eq!(t.handshake, Duration::from_secs(30));
    }
}
