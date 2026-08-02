// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT broker and async client for Hopf (Gumdrop `mqtt` port).
//!
//! # Layout
//!
//! - [`codec`] — incremental push frame parser / encoder, varint, MQTT 5
//!   properties, streaming PUBLISH.
//! - [`server`] — `MqttConfig` / `MqttService` / `MqttControlHandler`, the
//!   staged CONNECT / PUBLISH / SUBSCRIBE handler SPI (`server::ConnectHandler`
//!   et al.), [`server::broker`] — topic tree (including `$share/...`),
//!   subscription index, retained store, Receive Maximum flow control,
//!   Session Expiry, offline QoS queues / QoS retransmission via
//!   [`server::store`], cross-reactor fan-out — and `server::ws` (feature
//!   `websocket`) — MQTT-over-WebSocket bridge sharing broker state with
//!   the TCP listener.
//! - [`client`] — async client facade, endpoint, and the consolidated
//!   `MqttClientDriver` callback trait (including enhanced AUTH).
//!
//! Deliberately still limited: QoS retry does not survive broker process
//! restarts (in-flight state is process-local even with
//! [`server::FileBackedMessageStore`]).

#![warn(missing_docs)]

pub mod client;
pub mod codec;
pub mod server;

#[cfg(all(test, feature = "integration"))]
mod integration;

/// Crate version string from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }
}
