// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MASQUE for Hopf: RFC 9298 (Proxying UDP in HTTP) and, eventually,
//! RFC 9484 (Proxying IP in HTTP) — built as a peer crate to
//! [`hopf_http`], the same way [`hopf_websocket`](../hopf_websocket)
//! layers WebSocket framing on top of it, via
//! [`hopf_http::ProtocolUpgradeHandler`].
//!
//! Currently implemented: the RFC 9298 CONNECT-UDP relay, server-side —
//! see [`ConnectUdpFactory`].

#![warn(missing_docs)]

mod handler;
mod policy;
mod relay;
mod target;

pub use handler::{ConnectUdpFactory, DEFAULT_IDLE_TIMEOUT};
pub use policy::ConnectUdpPolicy;
pub use target::{parse as parse_connect_udp_target, ConnectUdpTarget};

#[cfg(all(test, feature = "integration"))]
mod integration;
