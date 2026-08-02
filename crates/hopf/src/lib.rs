// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Umbrella crate for the Hopf multi-protocol networking framework.
//!
//! Re-exports every `hopf-*` crate as a module. Depend on `hopf` with default
//! features for everything, or disable defaults and pick crates:
//!
//! ```toml
//! [dependencies]
//! hopf = "0.1"                                          # everything
//! # or:
//! hopf = { version = "0.1", default-features = false, features = ["http", "tls"] }
//! ```
//!
//! ```no_run
//! use hopf::core::{Runtime, RuntimeConfig};
//!
//! let rt = Runtime::start(RuntimeConfig::default()).unwrap();
//! # drop(rt);
//! ```
//!
//! | Module | Crate | Feature |
//! |--------|-------|---------|
//! | [`core`] | `hopf-core` | always |
//! | [`tls`] | `hopf-tls` | `tls` |
//! | [`auth`] | `hopf-auth` | `auth` |
//! | [`http`] | `hopf-http` | `http` (`h3` for HTTP/3) |
//! | [`quic`] | `hopf-quic` | `quic` |
//! | [`dns`] | `hopf-dns` | `dns` (`dns-server`, `dot`, `doq`, `doh`, `dnssec`) |
//! | [`webdav`] | `hopf-webdav` | `webdav` (`webdav-xattr`) |
//! | [`websocket`] | `hopf-websocket` | `websocket` |
//! | [`grpc`] | `hopf-grpc` | `grpc` |
//! | [`ftp`] | `hopf-ftp` | `ftp` |
//! | [`smtp`] | `hopf-smtp` | `smtp` |
//! | [`pop3`] | `hopf-pop3` | `pop3` |
//! | [`imap`] | `hopf-imap` | `imap` |
//! | [`mailbox`] | `hopf-mailbox` | `mailbox` |
//! | [`otel`] | `hopf-otel` | `otel` |
//! | [`mqtt`] | `hopf-mqtt` | `mqtt` (`mqtt-ws` for MQTT-over-WebSocket) |
//! | [`amqp`] | `hopf-amqp` | `amqp` |
//!
//! Documentation: <https://cpkb-bluezoo.github.io/hopf/>

#![warn(missing_docs)]

/// Thread-per-core Runtime, `Endpoint`, `ProtocolHandler`, Composition.
pub use hopf_core as core;

/// rustls integration: TCP TLS and STARTTLS.
#[cfg(feature = "tls")]
pub use hopf_tls as tls;

/// TrustPolicy / IdentityMaterial / SASL.
#[cfg(feature = "auth")]
pub use hopf_auth as auth;

/// HTTP/1.x, HTTP/2, and (feature `h3`) HTTP/3 Streams.
#[cfg(feature = "http")]
pub use hopf_http as http;

/// QUIC transport (quinn-proto + mio glue).
#[cfg(feature = "quic")]
pub use hopf_quic as quic;

/// DNS stub resolver and caching forwarder.
#[cfg(feature = "dns")]
pub use hopf_dns as dns;

/// RFC 4918 WebDAV filesystem handler.
#[cfg(feature = "webdav")]
pub use hopf_webdav as webdav;

/// RFC 6455 WebSocket framing and upgrade helpers.
#[cfg(feature = "websocket")]
pub use hopf_websocket as websocket;

/// Unary gRPC over HTTP Streams.
#[cfg(feature = "grpc")]
pub use hopf_grpc as grpc;

/// FTP / FTPS server and callback-driven client.
#[cfg(feature = "ftp")]
pub use hopf_ftp as ftp;

/// SMTP / SMTPS server, client, relay, and local delivery.
#[cfg(feature = "smtp")]
pub use hopf_smtp as smtp;

/// POP3 / POP3S server.
#[cfg(feature = "pop3")]
pub use hopf_pop3 as pop3;

/// IMAP4rev2 / IMAPS server and callback-driven client.
#[cfg(feature = "imap")]
pub use hopf_imap as imap;

/// mbox / Maildir++ mailbox storage SPI.
#[cfg(feature = "mailbox")]
pub use hopf_mailbox as mailbox;

/// OpenTelemetry OTLP/HTTP and JSONL exporters.
#[cfg(feature = "otel")]
pub use hopf_otel as otel;

/// MQTT broker and async client (feature `mqtt-ws` for MQTT-over-WebSocket).
#[cfg(feature = "mqtt")]
pub use hopf_mqtt as mqtt;

/// AMQP 0-9-1 async client (RabbitMQ).
#[cfg(feature = "amqp")]
pub use hopf_amqp as amqp;
