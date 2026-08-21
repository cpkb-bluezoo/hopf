// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC transport for Hopf (`quinn-proto` + mio UDP).
//!
//! HTTP/3 codecs live in [`hopf_http`] (feature `h3`), not here.
//! Each bidirectional QUIC stream is exposed as a [`QuicStreamEndpoint`]
//! implementing [`hopf_core::Endpoint`].

#![warn(missing_docs)]

mod config;
mod driver;
mod error;
mod hooks;
mod runtime_ext;
mod stream;

pub use config::{
    apply_client_transport_options, apply_listen_hardening, apply_server_transport_options,
    client_config_for_certified_pem, client_config_for_certified_pem_with,
    client_config_for_pem_bytes, client_config_for_pem_bytes_with, client_config_from_pem,
    client_config_from_pem_with, server_config_from_pem, server_config_from_pem_with,
    server_config_self_signed, server_config_self_signed_with, QuicClientConfig, QuicConnectConfig,
    QuicListenConfig, QuicListenHardening, QuicListenHooksConfig, QuicServerConfig, QuicTlsOptions,
    QuicTransportOptions,
};
pub use driver::{connect_quic, connect_quic_hooks, listen_quic, listen_quic_hooks, QuicDriverHandle};
pub use error::{
    connection_close_error, stream_stopped_error, QuicConnectionCloseError, QuicStreamStoppedError,
};
pub use hooks::{ConnectionFactory, DatagramDecode, QuicConnApi, QuicConnection};
pub use runtime_ext::RuntimeQuicExt;
pub use stream::QuicStreamEndpoint;
pub use hopf_core::VERSION;

/// ALPN protocol identifier for HTTP/3.
pub const ALPN_H3: &[u8] = b"h3";
