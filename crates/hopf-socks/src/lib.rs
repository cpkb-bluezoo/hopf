// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS proxy for Hopf: SOCKS4, SOCKS4a, and SOCKS5 (RFC 1928), built as a
//! peer crate to [`hopf_core`] (listener/connector infrastructure) and
//! [`hopf_dns`] (asynchronous target resolution).
//!
//! Currently implemented: version detection, SOCKS5 method negotiation
//! with RFC 1929 username/password authentication (see
//! [`SocksAuthenticator`]), and the CONNECT, BIND, and UDP ASSOCIATE
//! commands, server-side, plus CONNECT and BIND clients (see
//! [`SocksConnectHandler`] / [`socks_connect_config`] and
//! [`SocksBindHandler`] / [`socks_bind_config`]). UDP ASSOCIATE client
//! support is tracked separately.
//!
//! RFC 1961 GSSAPI authentication is a deliberate non-goal: it requires an
//! external Kerberos/GSSAPI dependency this crate does not take on. A
//! deployment needing GSSAPI-authenticated SOCKS should terminate TLS in
//! front of this proxy and use RFC 1929 username/password instead.
//!
//! UDP ASSOCIATE implements no RFC 1928 §7 fragment reassembly — only
//! standalone datagrams are forwarded, matching near-universal real-world
//! SOCKS5 server practice.

#![warn(missing_docs)]

mod auth;
mod bind;
mod client;
mod client_bind;
mod connect;
mod handler;
mod metrics;
mod policy;
mod relay;
mod service;
mod udp_associate;
mod udp_header;
mod wire;

pub use auth::SocksAuthenticator;
pub use bind::DEFAULT_BIND_ACCEPT_TIMEOUT;
pub use client::{
    socks_connect_config, SocksClientConfig, SocksClientVersion, SocksConnectHandler,
    DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
};
pub use client_bind::{socks_bind_config, SocksBindHandler};
pub use connect::DEFAULT_RELAY_IDLE_TIMEOUT;
pub use handler::{SocksConnectionHandlerFactory, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_RELAYS};
pub use metrics::SocksServerMetrics;
pub use policy::SocksPolicy;
pub use service::SocksService;
pub use udp_associate::DEFAULT_UDP_IDLE_TIMEOUT;
pub use wire::SocksAddress;

#[cfg(all(test, feature = "integration"))]
mod integration;
