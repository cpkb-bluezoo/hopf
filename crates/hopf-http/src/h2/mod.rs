// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 endpoints, frame utilities, and flow control (RFC 9113).
//!
//! # Cleartext (h2c) — prior-knowledge and Upgrade
//!
//! Use [`CleartextHttpEndpoint`] for plaintext TCP listeners. It auto-detects:
//!
//! - **Prior-knowledge** (`curl --http2-prior-knowledge`): client opens with
//!   the 24-byte connection preface; the dispatcher sniffs it before H1 parsing.
//! - **h2c Upgrade** (`curl --http2`): client sends an HTTP/1.1 request with
//!   `Upgrade: h2c`; the dispatcher responds with `101 Switching Protocols`
//!   and transitions to H2.
//! - **Plain HTTP/1.1**: falls back to [`crate::h1::H1Endpoint`].
//!
//! For TLS, use [`crate::dispatch::AlpnHttpEndpoint`] which routes via ALPN.
//!
//! # Client (H2 prior-knowledge dial)
//!
//! Use [`H2Endpoint::client`] with `secure = false` for cleartext H2 dials
//! or `secure = true` for TLS H2. The endpoint writes the client connection
//! preface and SETTINGS on connect, then starts a single request via
//! `ClientHandlerFactory`.
//!
//! # Client (h2c Upgrade dial)
//!
//! Use [`H2cUpgradeClientEndpoint`] to dial a peer that may not support
//! prior-knowledge H2: the request is sent as HTTP/1.1 with `Upgrade: h2c`,
//! promoting to H2 on a `101` response and falling back to plain HTTP/1.1
//! otherwise (server support for h2c Upgrade is optional).
//!
//! # Not yet implemented
//!
//! - **PUSH_PROMISE / server push** — `H2Endpoint` sends RST_STREAM for any
//!   server-push streams received as a client; server side rejects
//!   PUSH_PROMISE with GOAWAY per RFC 9113 §8.4.
//!   TODO: server push.
//! - **PRIORITY frames** are deprecated in RFC 9113 and silently ignored.
//!   TODO: priority (deprecated).

pub mod flow;
pub mod frame;
pub mod hpack;
pub mod parser;

pub(crate) mod base64url;
mod cleartext;
mod client_upgrade;
mod endpoint;
mod response;

pub use cleartext::CleartextHttpEndpoint;
pub use client_upgrade::H2cUpgradeClientEndpoint;
pub use endpoint::H2Endpoint;
pub use parser::{H2FrameHandler, H2Parser};
