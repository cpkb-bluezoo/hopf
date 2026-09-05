// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS proxy for Hopf: SOCKS4, SOCKS4a, and SOCKS5 (RFC 1928), built as a
//! peer crate to [`hopf_core`] (listener/connector infrastructure) and
//! [`hopf_dns`] (asynchronous target resolution).
//!
//! Currently implemented: version detection, SOCKS5 method negotiation
//! with RFC 1929 username/password authentication (see
//! [`SocksAuthenticator`]), and the CONNECT command, server-side. BIND,
//! UDP ASSOCIATE, and the client side are tracked separately.
//!
//! RFC 1961 GSSAPI authentication is a deliberate non-goal: it requires an
//! external Kerberos/GSSAPI dependency this crate does not take on. A
//! deployment needing GSSAPI-authenticated SOCKS should terminate TLS in
//! front of this proxy and use RFC 1929 username/password instead.

#![warn(missing_docs)]

mod auth;
mod bind;
mod connect;
mod handler;
mod metrics;
mod policy;
mod relay;
mod service;
mod wire;

pub use auth::SocksAuthenticator;
pub use bind::DEFAULT_BIND_ACCEPT_TIMEOUT;
pub use connect::DEFAULT_RELAY_IDLE_TIMEOUT;
pub use handler::SocksConnectionHandlerFactory;
pub use metrics::SocksServerMetrics;
pub use policy::SocksPolicy;
pub use service::SocksService;

#[cfg(all(test, feature = "integration"))]
mod integration;
