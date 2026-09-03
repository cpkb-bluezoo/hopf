// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MASQUE for Hopf: RFC 9298 (Proxying UDP in HTTP) and, eventually,
//! RFC 9484 (Proxying IP in HTTP) — built as a peer crate to
//! [`hopf_http`], the same way [`hopf_websocket`](../hopf_websocket)
//! layers WebSocket framing on top of it, via
//! [`hopf_http::ProtocolUpgradeHandler`].
//!
//! Currently implemented: the RFC 9298 CONNECT-UDP relay, server-side — see
//! [`ConnectUdpFactory`] — the RFC 9298 client (behind the `h3` feature) —
//! see [`connect_udp`](client::connect_udp) — the RFC 9484 CONNECT-IP
//! relay, server-side — see [`ConnectIpFactory`] — and the RFC 9484 client
//! (behind the `h3` feature) — see [`connect_ip`](ip_client::connect_ip).

#![warn(missing_docs)]

mod accept;
mod handler;
mod ip_capsule;
mod ip_handler;
mod ip_policy;
mod ip_relay;
mod ip_target;
mod percent;
mod policy;
mod relay;
mod target;

#[cfg(feature = "h3")]
mod client;
#[cfg(feature = "h3")]
mod ip_client;

pub use handler::{ConnectUdpFactory, DEFAULT_IDLE_TIMEOUT};
pub use ip_handler::ConnectIpFactory;
pub use ip_policy::ConnectIpPolicy;
pub use ip_relay::{ConnectIpHandler, ConnectIpHandlerFactory, ConnectIpSession};
pub use ip_target::{parse as parse_connect_ip_target, ConnectIpTarget, IpProto, IpTarget};
pub use policy::ConnectUdpPolicy;
pub use target::{parse as parse_connect_udp_target, ConnectUdpTarget};

#[cfg(feature = "h3")]
pub use client::{connect_udp, ConnectUdpEventHandler, ConnectUdpSession};
#[cfg(feature = "h3")]
pub use ip_client::{connect_ip, ConnectIpClientSession, ConnectIpEventHandler, RequestedAddress};

#[cfg(all(test, feature = "integration"))]
mod integration;
