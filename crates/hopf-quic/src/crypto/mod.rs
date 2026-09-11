// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-tree TLS 1.3 handshake config builders for QUIC.

use std::sync::Arc;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use bytes::Bytes;
use hopf_core::crypto::kx_policy::KxPolicy;
use hopf_core::crypto::trust::TrustStore;
use hopf_core::tls::{
    AntiReplay, ClientTicketStore, HandshakeConfig, HandshakeMode, HandshakeRole,
    ServerCredentials, DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
};

use crate::config::{QuicClientConfig, QuicServerConfig, QuicTlsOptions};


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
    /// Early data / ticket options.
    pub tls: QuicTlsOptions,
    /// Shared client ticket store (set for client configs).
    pub ticket_store: Option<Arc<ClientTicketStore>>,
    /// Server ticket sealing key.
    pub ticket_key: Option<[u8; 32]>,
    /// Server early-data anti-replay (shared across accepts).
    pub anti_replay: Option<Arc<AntiReplay>>,
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
            tls: QuicTlsOptions::default(),
            ticket_store: Some(ClientTicketStore::shared()),
            ticket_key: None,
            anti_replay: None,
        }
    }

    /// Server parameters with credentials.
    pub fn server(creds: ServerCredentials, alpn: Vec<Bytes>) -> Self {
        let mut ticket_key = [0u8; 32];
        let _ = SystemRandom::new().fill(&mut ticket_key);
        Self {
            alpn,
            kx_policy: KxPolicy::classical_only(),
            server_name: None,
            trust_store: None,
            server: Some(creds),
            local_transport_parameters: None,
            tls: QuicTlsOptions::default(),
            ticket_store: None,
            ticket_key: Some(ticket_key),
            anti_replay: None,
        }
    }

    /// Apply [`QuicTlsOptions`].
    pub fn with_tls(mut self, tls: QuicTlsOptions) -> Self {
        self.tls = tls;
        if self.tls.enable_early_data && self.server.is_some() && self.anti_replay.is_none() {
            self.anti_replay = Some(AntiReplay::shared_default());
        }
        self
    }

    fn into_handshake(self, role: HandshakeRole) -> HandshakeConfig {
        let anti_replay = if role == HandshakeRole::Server && self.tls.enable_early_data {
            self.anti_replay
                .or_else(|| Some(AntiReplay::shared_default()))
        } else {
            self.anti_replay
        };
        HandshakeConfig {
            role,
            mode: HandshakeMode::Quic,
            alpn: self.alpn,
            server_name: self.server_name,
            server: self.server,
            kx_policy: self.kx_policy,
            local_transport_parameters: self.local_transport_parameters,
            trust_store: self.trust_store,
            verify_override: None,
            enable_early_data: self.tls.enable_early_data,
            max_early_data_size: self.tls.max_early_data_size,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: self.ticket_key.map(hopf_core::TicketKeys::single),
            ticket_store: self.ticket_store,
            anti_replay,
            ..Default::default()
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
