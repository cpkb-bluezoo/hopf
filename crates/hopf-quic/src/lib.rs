// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC transport for Hopf (`quinn-proto` + mio UDP).
//!
//! HTTP/3 codecs live in [`hopf_http`] (feature `h3`), not here.
//! Each bidirectional QUIC stream is exposed as a [`QuicStreamEndpoint`]
//! implementing [`hopf_core::Endpoint`].

#![warn(missing_docs)]

mod config;
mod driver;
mod hooks;
mod runtime_ext;
mod stream;

pub use config::{
    client_config_for_certified_pem, client_config_for_pem_bytes, client_config_from_pem,
    server_config_from_pem, server_config_self_signed, QuicClientConfig, QuicConnectConfig,
    QuicListenConfig, QuicListenHooksConfig, QuicServerConfig,
};
pub use driver::{connect_quic, connect_quic_hooks, listen_quic, listen_quic_hooks, QuicDriverHandle};
pub use hooks::{ConnectionFactory, QuicConnApi, QuicConnection};
pub use runtime_ext::RuntimeQuicExt;
pub use stream::QuicStreamEndpoint;
pub use hopf_core::VERSION;

/// ALPN protocol identifier for HTTP/3.
pub const ALPN_H3: &[u8] = b"h3";
