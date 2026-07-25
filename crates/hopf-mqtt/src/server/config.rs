// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT server configuration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_auth::CredentialStore;

use crate::broker::BrokerState;
use crate::codec::DEFAULT_MAX_PACKET_SIZE;

/// Default window to wait for CONNECT after the TCP connection opens
/// (MQTT 3.1.1 §3.1: "If the Server does not receive a CONNECT Packet
/// within a reasonable amount of time... the Server SHOULD close").
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// MQTT server configuration.
pub struct MqttConfig {
    /// Listen address (default typically `0.0.0.0:1883`).
    pub listen: SocketAddr,
    /// Shared broker state (topics, retained messages, session registry).
    pub broker: Arc<BrokerState>,
    /// Credential store for CONNECT username/password. `None` accepts any
    /// CONNECT regardless of the username/password fields present.
    pub credentials: Option<Arc<dyn CredentialStore>>,
    /// Cap on a packet's Remaining Length.
    pub max_packet_size: u32,
    /// How long to wait for CONNECT before closing an idle new connection.
    pub connect_timeout: Duration,
}

impl MqttConfig {
    /// Plain (no auth) config sharing `broker` with every listener that uses it.
    pub fn new(listen: SocketAddr, broker: Arc<BrokerState>) -> Self {
        Self {
            listen,
            broker,
            credentials: None,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Require CONNECT username/password to match `store`.
    pub fn with_credentials(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.credentials = Some(store);
        self
    }

    /// Override the Remaining Length cap.
    pub fn with_max_packet_size(mut self, max_packet_size: u32) -> Self {
        self.max_packet_size = max_packet_size;
        self
    }

    /// Override the CONNECT wait window.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}
