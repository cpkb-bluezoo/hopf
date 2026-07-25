// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT broker and async client for Hopf (Gumdrop `mqtt` port).
//!
//! # Layout
//!
//! - [`codec`] — incremental push frame parser / encoder, varint, MQTT 5
//!   properties, streaming PUBLISH.
//! - [`broker`] — topic tree, subscription index, retained store,
//!   Receive Maximum flow control, Session Expiry, cross-reactor fan-out.
//! - [`server`] — `MqttConfig` / `MqttService` / `MqttControlHandler`, and
//!   the staged CONNECT handler SPI (`server::ConnectHandler`).
//! - [`client`] — async client facade, endpoint, and the consolidated
//!   `MqttClientDriver` callback trait.
//! - [`store`] — reserved for a future durable message store; retained
//!   messages already live in [`broker::RetainedStore`].
//! - [`ws`] (feature `websocket`) — MQTT-over-WebSocket bridge sharing
//!   broker state with the TCP listener.
//!
//! See the MQTT implementation plan for what's deliberately out of scope so
//! far: shared subscriptions, enhanced AUTH, topic aliases, will delay /
//! message expiry enforcement, durable offline queues, QoS retry across
//! reconnects, and file-backed message storage.

#![warn(missing_docs)]

pub mod broker;
pub mod client;
pub mod codec;
pub mod server;
mod store;

#[cfg(feature = "websocket")]
pub mod ws;

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
