// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Per-phase timeout configuration for the MQTT client.

use std::time::Duration;

/// Per-phase timeout configuration for [`super::facade::MqttClient`].
#[derive(Debug, Clone)]
pub struct MqttClientTimeouts {
    /// DNS resolution budget (default 5 s).
    pub dns: Duration,
    /// Connect budget: dial → TCP established (default 30 s).
    pub connect: Duration,
    /// How long to wait for CONNACK after sending CONNECT (default 30 s).
    pub connack: Duration,
    /// How long to wait for PINGRESP after sending PINGREQ before treating
    /// the connection as dead (MQTT doesn't mandate a value; default 10 s).
    pub pingresp: Duration,
}

impl Default for MqttClientTimeouts {
    fn default() -> Self {
        Self {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(30),
            connack: Duration::from_secs(30),
            pingresp: Duration::from_secs(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let t = MqttClientTimeouts::default();
        assert_eq!(t.dns, Duration::from_secs(5));
        assert_eq!(t.connect, Duration::from_secs(30));
        assert_eq!(t.connack, Duration::from_secs(30));
        assert_eq!(t.pingresp, Duration::from_secs(10));
    }
}
