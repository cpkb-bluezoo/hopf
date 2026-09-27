// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AMQP **1.0** async client for Hopf.
//!
//! AMQP 1.0 (ISO/IEC 19464) shares only the four-byte `AMQP` magic with
//! AMQP 0-9-1 (see [`hopf_amqp`](https://docs.rs/hopf-amqp)); framing, the
//! type system, the connection/session/link model, and messaging semantics
//! are unrelated. This crate targets brokers that speak AMQP 1.0 natively
//! (RabbitMQ 4's native AMQP 1.0 support, ActiveMQ Artemis `amqp://`).
//!
//! Client-only: dial a broker, perform SASL and/or TLS as required, open a
//! connection/session, attach sender/receiver links, and send or receive
//! messages. There is no AMQP 1.0 broker/server implementation in this
//! crate.
//!
//! # Layout
//!
//! - [`codec`] — frame encode/decode, the AMQP 1.0 type system,
//!   performatives, SASL frame bodies, and message sections
//! - [`client`] — facade, endpoint, connection/session/link state,
//!   Driver / Control SPI

#![warn(missing_docs)]
// Performative/message-section encoders build their field list as one
// `.push()` call per spec-numbered field (see `codec::performative` and
// `codec::message`), deliberately one statement per field so the code reads
// against the spec's own field tables — collapsing that into a single
// `vec![...]` literal would trade that away for no benefit here.
#![allow(clippy::vec_init_then_push)]

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
