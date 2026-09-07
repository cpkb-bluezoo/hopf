// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-tree TLS 1.3 handshake for QUIC (`quinn-proto` crypto adapter).

mod keys;
mod session;

pub use session::{
    hopf_client_config, hopf_server_config, HopfQuicTlsConfig, HopfTlsBuildParams,
};

/// Handshake metadata exported to the QUIC driver.
pub struct HopfHandshakeData {
    /// Negotiated ALPN.
    pub protocol: Option<bytes::Bytes>,
    /// SNI seen by the server.
    pub server_name: Option<String>,
}
