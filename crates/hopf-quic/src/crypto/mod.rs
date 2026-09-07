// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-tree TLS 1.3 handshake config builders for QUIC.

use std::sync::Arc;

use bytes::Bytes;
use hopf_core::crypto::kx_policy::KxPolicy;
use hopf_core::crypto::trust::TrustStore;
use hopf_core::tls::{HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials};

use crate::config::{QuicClientConfig, QuicServerConfig};

pub use crate::transport::packet::protection::{initial_secrets, KeyPair, PacketKeys};

/// Handshake metadata exported to the QUIC driver (legacy shape).
pub struct HopfHandshakeData {
    /// Negotiated ALPN.
    pub protocol: Option<Bytes>,
    /// SNI seen by the server.
    pub server_name: Option<String>,
}

/// ALPN + trust settings for building hopf QUIC TLS configs.
pub struct HopfTlsBuildParams {
    /// ALPN protocol names.
    pub alpn: Vec<Bytes>,
    /// Key-exchange preference.
    pub kx_policy: KxPolicy,
    /// Client SNI / expected server name.
    pub server_name: Option<String>,
    /// Trust store (client).
    pub trust_store: Option<TrustStore>,
    /// Server credentials (server).
    pub server: Option<ServerCredentials>,
    /// Local QUIC transport parameters wire encoding.
    pub local_transport_parameters: Option<Bytes>,
}

impl HopfTlsBuildParams {
    /// Client parameters trusting a single self-signed anchor.
    pub fn client_self_signed(
        alpn: Vec<Bytes>,
        server_name: impl Into<String>,
        anchor: Bytes,
    ) -> Self {
        let mut trust = TrustStore::new();
        trust.add_anchor(anchor);
        Self {
            alpn,
            kx_policy: KxPolicy::classical_only(),
            server_name: Some(server_name.into()),
            trust_store: Some(trust),
            server: None,
            local_transport_parameters: None,
        }
    }

    /// Server parameters with credentials.
    pub fn server(creds: ServerCredentials, alpn: Vec<Bytes>) -> Self {
        Self {
            alpn,
            kx_policy: KxPolicy::classical_only(),
            server_name: None,
            trust_store: None,
            server: Some(creds),
            local_transport_parameters: None,
        }
    }

    fn into_handshake(self, role: HandshakeRole) -> HandshakeConfig {
        HandshakeConfig {
            role,
            mode: HandshakeMode::Quic,
            alpn: self.alpn,
            server_name: self.server_name,
            server: self.server,
            kx_policy: self.kx_policy,
            local_transport_parameters: self.local_transport_parameters,
            trust_store: self.trust_store,
        }
    }
}

/// Alias kept for public API compatibility.
pub type HopfQuicTlsConfig = HandshakeConfig;

/// Build a QUIC client config using the in-tree handshake engine.
pub fn hopf_client_config(params: HopfTlsBuildParams) -> Arc<QuicClientConfig> {
    let hs = params.into_handshake(HandshakeRole::Client);
    Arc::new(QuicClientConfig::from_handshake(hs))
}

/// Build a QUIC server config using the in-tree handshake engine.
pub fn hopf_server_config(params: HopfTlsBuildParams) -> Arc<QuicServerConfig> {
    let hs = params.into_handshake(HandshakeRole::Server);
    Arc::new(QuicServerConfig::from_handshake(hs))
}
