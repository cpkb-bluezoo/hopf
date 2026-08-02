// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT server configuration.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_auth::CredentialStore;

use crate::server::broker::BrokerState;
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
    /// Credential store for CONNECT username/password.
    ///
    /// When [`Self::allow_anonymous`] is `false` (the default):
    /// - `Some(store)` — CONNECT must present matching username/password
    /// - `None` — every CONNECT is rejected (fail closed until credentials
    ///   or anonymous access are configured)
    ///
    /// When `allow_anonymous` is `true`, `None` accepts any CONNECT.
    pub credentials: Option<Arc<dyn CredentialStore>>,
    /// When `true`, CONNECT is accepted without username/password even if
    /// [`Self::credentials`] is `None`. Defaults to **`false`** — call
    /// [`Self::allow_anonymous`] explicitly for demo / trusted-network brokers.
    pub allow_anonymous: bool,
    /// Cap on a packet's Remaining Length.
    pub max_packet_size: u32,
    /// Cap on a PUBLISH payload, checked before any fan-out/spool work
    /// starts. Independent of `max_packet_size` so raising the general
    /// packet cap (e.g. for larger CONNECT properties) doesn't silently
    /// also raise how much a single PUBLISH can make the broker spool to
    /// disk per recipient. Default: same as `max_packet_size`.
    pub max_publish_payload: u32,
    /// How long to wait for CONNECT before closing an idle new connection.
    pub connect_timeout: Duration,
}

impl MqttConfig {
    /// Secure-by-default config: anonymous CONNECT is **denied** until
    /// [`Self::with_credentials`] or [`Self::allow_anonymous`] is used.
    pub fn new(listen: SocketAddr, broker: Arc<BrokerState>) -> Self {
        Self {
            listen,
            broker,
            credentials: None,
            allow_anonymous: false,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            max_publish_payload: DEFAULT_MAX_PACKET_SIZE,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Require CONNECT username/password to match `store`.
    pub fn with_credentials(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.credentials = Some(store);
        self
    }

    /// Allow CONNECT without credentials (explicit open-broker opt-in).
    pub fn allow_anonymous(mut self) -> Self {
        self.allow_anonymous = true;
        self
    }

    /// Override the Remaining Length cap.
    pub fn with_max_packet_size(mut self, max_packet_size: u32) -> Self {
        self.max_packet_size = max_packet_size;
        self
    }

    /// Override the PUBLISH payload cap.
    pub fn with_max_publish_payload(mut self, max_publish_payload: u32) -> Self {
        self.max_publish_payload = max_publish_payload;
        self
    }

    /// Override the CONNECT wait window.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}
