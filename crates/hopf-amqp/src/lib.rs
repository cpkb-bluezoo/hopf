// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP 0-9-1 async client for Hopf (RabbitMQ).
//!
//! Client-only: dial a broker, publish opaque message bodies with basic
//! properties, and consume via push `basic.consume` deliveries or pull
//! `basic.get`. Also supports classic AMQP transactions (`tx.*`), channel
//! flow control, `basic.recover`, PLAIN / AMQPLAIN / EXTERNAL SASL
//! (auto-negotiated, or forced via [`client::AmqpClient::mechanism`]), and
//! automatic reconnection with topology/consumer replay via
//! [`client::AmqpRecoveringClient`]. There is no broker implementation in
//! this crate.
//!
//! # Layout
//!
//! - [`codec`] — frame encode/decode, field tables, basic properties, push parser
//! - [`client`] — facade, endpoint, Control / Driver SPI

#![warn(missing_docs)]

pub mod client;
pub mod codec;

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
