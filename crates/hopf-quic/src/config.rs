// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC TLS / listen / dial configuration.

use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hopf_core::crypto::kx_policy::KxPolicy;
use hopf_core::crypto::trust::TrustStore;
use hopf_core::tls::{HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials};
use hopf_core::HandlerFactory;

use crate::crypto::{hopf_client_config, hopf_server_config, HopfTlsBuildParams};
use crate::hooks::ConnectionFactory;
use crate::transport::endpoint::{ClientConfig as TransportClientConfig, ServerConfig as TransportServerConfig};

/// Quinn-compatible server config wrapping in-tree handshake settings.
#[derive(Clone)]
pub struct QuicServerConfig {
    pub(crate) inner: TransportServerConfig,
    /// Stored hardening knobs (applied by driver / ignored for echo).
    pub(crate) max_incoming: Option<usize>,
    pub(crate) migration: Option<bool>,
    /// Placeholder validation token settings (echo milestone).
    pub validation_token: ValidationTokenConfig,
}

impl QuicServerConfig {
    /// Build from a handshake config.
    pub fn from_handshake(handshake: HandshakeConfig) -> Self {
        Self {
            inner: TransportServerConfig::new(handshake),
            max_incoming: None,
            migration: None,
            validation_token: ValidationTokenConfig,
        }
    }

    /// Into transport server config.
    pub(crate) fn into_transport(self) -> TransportServerConfig {
        self.inner
    }

    /// Clone transport config.
    pub(crate) fn transport(&self) -> TransportServerConfig {
        self.inner.clone()
    }

    /// Cap concurrent unfinished handshakes (compat no-op storage).
    pub fn max_incoming(&mut self, n: usize) {
        self.max_incoming = Some(n);
    }

    /// Incoming buffer size (no-op for echo).
    pub fn incoming_buffer_size(&mut self, _n: u64) {}

    /// Total incoming buffer size (no-op for echo).
    pub fn incoming_buffer_size_total(&mut self, _n: u64) {}

    /// Retry token lifetime (no-op for echo).
    pub fn retry_token_lifetime(&mut self, _d: Duration) {}

    /// Migration flag.
    pub fn migration(&mut self, m: bool) {
        self.migration = Some(m);
    }

    /// Validation token config (no-op for echo).
    pub fn validation_token_config(&mut self, tokens: ValidationTokenConfig) {
        self.validation_token = tokens;
    }

    /// Apply transport options (no-op for echo).
    pub fn transport_config(&mut self, _t: Arc<()>) {}
}

impl Default for QuicServerConfig {
    fn default() -> Self {
        Self::from_handshake(HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Quic,
            alpn: vec![],
            server_name: None,
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
        })
    }
}

/// Placeholder validation token settings.
#[derive(Clone, Debug, Default)]
pub struct ValidationTokenConfig;

impl ValidationTokenConfig {
    /// Lifetime (no-op).
    pub fn lifetime(&mut self, _d: Duration) {}
    /// Tokens sent (no-op).
    pub fn sent(&mut self, _n: u32) {}
}

/// Quinn-compatible client config wrapping in-tree handshake settings.
#[derive(Clone)]
pub struct QuicClientConfig {
    pub(crate) inner: TransportClientConfig,
}

impl QuicClientConfig {
    /// Build from a handshake config.
    pub fn from_handshake(handshake: HandshakeConfig) -> Self {
        Self {
            inner: TransportClientConfig::new(handshake),
        }
    }

    /// Into transport client config.
    pub(crate) fn into_transport(self) -> TransportClientConfig {
        self.inner
    }

    /// Clone transport config.
    pub(crate) fn transport(&self) -> TransportClientConfig {
        self.inner.clone()
    }

    /// Apply transport options (no-op storage for echo — defaults used).
    pub fn transport_config(&mut self, _t: Arc<()>) {}
}

/// Listen (UDP bind) configuration — one [`hopf_core::ProtocolHandler`] per bi-stream.
pub struct QuicListenConfig {
    /// Bind address (use port `0` for ephemeral).
    pub addr: SocketAddr,
    /// Server configuration (TLS + transport).
    pub server: Arc<QuicServerConfig>,
    /// Factory for handlers — one per accepted bidirectional stream.
    pub factory: HandlerFactory,
    /// Address-validation and Incoming DoS hardening.
    pub hardening: QuicListenHardening,
}

impl QuicListenConfig {
    /// Create a listen config with [`QuicListenHardening::high_security`].
    pub fn new(addr: SocketAddr, server: Arc<QuicServerConfig>, factory: HandlerFactory) -> Self {
        Self {
            addr,
            server,
            factory,
            hardening: QuicListenHardening::high_security(),
        }
    }

    /// Override listen hardening.
    pub fn with_hardening(mut self, hardening: QuicListenHardening) -> Self {
        self.hardening = hardening;
        self
    }
}

/// Listen with connection-level hooks (HTTP/3 control + request streams).
pub struct QuicListenHooksConfig {
    /// Bind address.
    pub addr: SocketAddr,
    /// Server configuration.
    pub server: Arc<QuicServerConfig>,
    /// One [`crate::QuicConnection`] per accepted QUIC connection.
    pub connection_factory: ConnectionFactory,
    /// Address-validation and Incoming DoS hardening.
    pub hardening: QuicListenHardening,
}

impl QuicListenHooksConfig {
    /// Create a hooks-based listen config.
    pub fn new(
        addr: SocketAddr,
        server: Arc<QuicServerConfig>,
        connection_factory: ConnectionFactory,
    ) -> Self {
        Self {
            addr,
            server,
            connection_factory,
            hardening: QuicListenHardening::high_security(),
        }
    }

    /// Override listen hardening.
    pub fn with_hardening(mut self, hardening: QuicListenHardening) -> Self {
        self.hardening = hardening;
        self
    }
}

/// QUIC listener DoS / address-validation hardening (RFC 9000 §8).
#[derive(Debug, Clone)]
pub struct QuicListenHardening {
    /// Require Retry / NEW_TOKEN before handshake.
    pub require_address_validation: bool,
    /// Cap concurrent unfinished handshakes.
    pub max_incoming: Option<usize>,
    /// Per-Incoming receive buffer cap.
    pub incoming_buffer_size: Option<u64>,
    /// Total Incoming receive buffer cap.
    pub incoming_buffer_size_total: Option<u64>,
    /// Retry-token lifetime.
    pub retry_token_lifetime: Option<Duration>,
    /// Whether clients may migrate.
    pub migration: Option<bool>,
    /// NEW_TOKEN lifetime.
    pub validation_token_lifetime: Option<Duration>,
    /// NEW_TOKEN frames issued when a path is validated.
    pub validation_tokens_sent: Option<u32>,
}

impl QuicListenHardening {
    /// Opinionated defaults for public / high-security listeners.
    pub fn high_security() -> Self {
        Self {
            require_address_validation: true,
            max_incoming: Some(1_024),
            incoming_buffer_size: Some(1 << 20),
            incoming_buffer_size_total: Some(32 << 20),
            retry_token_lifetime: Some(Duration::from_secs(10)),
            migration: Some(false),
            validation_token_lifetime: Some(Duration::from_secs(24 * 60 * 60)),
            validation_tokens_sent: Some(2),
        }
    }

    /// Leave defaults alone and accept without Retry.
    pub fn permissive() -> Self {
        Self {
            require_address_validation: false,
            max_incoming: None,
            incoming_buffer_size: None,
            incoming_buffer_size_total: None,
            retry_token_lifetime: None,
            migration: None,
            validation_token_lifetime: None,
            validation_tokens_sent: None,
        }
    }

    /// Require Retry / NEW_TOKEN validation (fluent).
    pub fn require_address_validation(mut self, value: bool) -> Self {
        self.require_address_validation = value;
        self
    }

    /// Cap concurrent unfinished handshakes.
    pub fn max_incoming(mut self, value: usize) -> Self {
        self.max_incoming = Some(value);
        self
    }

    /// Per-Incoming receive buffer size in bytes.
    pub fn incoming_buffer_size(mut self, value: u64) -> Self {
        self.incoming_buffer_size = Some(value);
        self
    }

    /// Total Incoming receive buffer size in bytes.
    pub fn incoming_buffer_size_total(mut self, value: u64) -> Self {
        self.incoming_buffer_size_total = Some(value);
        self
    }

    /// Retry token lifetime.
    pub fn retry_token_lifetime(mut self, value: Duration) -> Self {
        self.retry_token_lifetime = Some(value);
        self
    }

    /// Allow or deny connection migration.
    pub fn migration(mut self, value: bool) -> Self {
        self.migration = Some(value);
        self
    }

    /// NEW_TOKEN lifetime.
    pub fn validation_token_lifetime(mut self, value: Duration) -> Self {
        self.validation_token_lifetime = Some(value);
        self
    }

    /// Number of NEW_TOKEN frames to send on path validation.
    pub fn validation_tokens_sent(mut self, value: u32) -> Self {
        self.validation_tokens_sent = Some(value);
        self
    }
}

impl Default for QuicListenHardening {
    fn default() -> Self {
        Self::high_security()
    }
}

/// Apply [`QuicListenHardening`] fields onto `server`.
pub fn apply_listen_hardening(
    server: &mut Arc<QuicServerConfig>,
    hardening: &QuicListenHardening,
) {
    let cfg = Arc::make_mut(server);
    if let Some(n) = hardening.max_incoming {
        cfg.max_incoming(n);
    }
    if let Some(n) = hardening.incoming_buffer_size {
        cfg.incoming_buffer_size(n);
    }
    if let Some(n) = hardening.incoming_buffer_size_total {
        cfg.incoming_buffer_size_total(n);
    }
    if let Some(d) = hardening.retry_token_lifetime {
        cfg.retry_token_lifetime(d);
    }
    if let Some(m) = hardening.migration {
        cfg.migration(m);
    }
}

/// Dial (UDP connect-path) configuration.
pub struct QuicConnectConfig {
    /// Peer address.
    pub addr: SocketAddr,
    /// Client configuration.
    pub client: Arc<QuicClientConfig>,
    /// Server name for TLS (SNI / cert verification).
    pub server_name: String,
    /// Factory for the first bidirectional stream's handler.
    pub factory: HandlerFactory,
}

impl QuicConnectConfig {
    /// Create a dial config.
    pub fn new(
        addr: SocketAddr,
        client: Arc<QuicClientConfig>,
        server_name: impl Into<String>,
        factory: HandlerFactory,
    ) -> Self {
        Self {
            addr,
            client,
            server_name: server_name.into(),
            factory,
        }
    }
}

/// TLS options (early data — not supported on in-tree path yet).
#[derive(Debug, Clone, Copy)]
pub struct QuicTlsOptions {
    /// Offer / accept TLS 1.3 early data (0-RTT).
    pub enable_early_data: bool,
    /// Server max early data size.
    pub max_early_data_size: u32,
}

impl Default for QuicTlsOptions {
    fn default() -> Self {
        Self {
            enable_early_data: false,
            max_early_data_size: 0,
        }
    }
}

impl QuicTlsOptions {
    /// Secure defaults: early data off.
    pub fn new() -> Self {
        Self::default()
    }

    /// Opt in to 0-RTT / early data.
    pub fn with_early_data(mut self) -> Self {
        self.enable_early_data = true;
        self.max_early_data_size = u32::MAX;
        self
    }

    /// Opt in to early data with an explicit server byte cap.
    pub fn with_early_data_size(mut self, max_early_data_size: u32) -> Self {
        self.enable_early_data = true;
        self.max_early_data_size = max_early_data_size;
        self
    }
}

fn hopf_server_credentials(names: &[&str]) -> io::Result<(ServerCredentials, Vec<u8>)> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let params = rcgen::CertificateParams::new(
        names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    )
    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let creds = ServerCredentials {
        cert_chain: vec![Bytes::copy_from_slice(cert.der())],
        signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
    };
    Ok((creds, cert.pem().into_bytes()))
}

fn pem_to_der_certs(pem: &[u8]) -> io::Result<Vec<Bytes>> {
    let mut reader = BufReader::new(pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, "no certificates in PEM"));
    }
    Ok(certs
        .into_iter()
        .map(|c| Bytes::copy_from_slice(c.as_ref()))
        .collect())
}

fn load_pem_certs(path: &Path) -> io::Result<Vec<Bytes>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("no certificates in {}", path.display()),
        ));
    }
    Ok(certs
        .into_iter()
        .map(|c| Bytes::copy_from_slice(c.as_ref()))
        .collect())
}

fn load_private_key_pkcs8(path: &Path) -> io::Result<Bytes> {
    let mut reader = BufReader::new(File::open(path)?);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("no private key in {}", path.display()),
            )
        })?;
    Ok(Bytes::copy_from_slice(key.secret_der()))
}

/// Build a QUIC server config from PEM cert/key.
pub fn server_config_from_pem(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicServerConfig>> {
    server_config_from_pem_with(cert_path, key_path, alpn, QuicTlsOptions::default())
}

/// [`server_config_from_pem`] with explicit TLS options.
pub fn server_config_from_pem_with(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<Arc<QuicServerConfig>> {
    let certs = load_pem_certs(cert_path)?;
    let key = load_private_key_pkcs8(key_path)?;
    let creds = ServerCredentials {
        cert_chain: certs,
        signing_key_pkcs8: key,
    };
    let params = HopfTlsBuildParams::server(
        creds,
        alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    );
    Ok(hopf_server_config(params))
}

/// Client config trusting CA PEM.
pub fn client_config_from_pem(
    ca_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_from_pem_with(ca_path, alpn, QuicTlsOptions::default())
}

/// [`client_config_from_pem`] with explicit TLS options.
pub fn client_config_from_pem_with(
    ca_path: &Path,
    alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let certs = load_pem_certs(ca_path)?;
    let mut trust = TrustStore::new();
    for c in certs {
        trust.add_anchor(c);
    }
    let params = HopfTlsBuildParams {
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        kx_policy: KxPolicy::classical_only(),
        server_name: None,
        trust_store: Some(trust),
        server: None,
        local_transport_parameters: None,
    };
    Ok(hopf_client_config(params))
}

/// Client config trusting public WebPKI — **not yet supported** on in-tree path.
pub fn client_config_public_trust(alpn: &[&[u8]]) -> io::Result<Arc<QuicClientConfig>> {
    client_config_public_trust_with(alpn, QuicTlsOptions::default())
}

/// [`client_config_public_trust`] with options.
pub fn client_config_public_trust_with(
    _alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    Err(io::Error::new(
        ErrorKind::Unsupported,
        "public WebPKI trust not yet wired on in-tree QUIC transport",
    ))
}

/// In-memory self-signed server config (Ed25519 via hopf TLS).
pub fn server_config_self_signed(
    names: &[&str],
    alpn: &[&[u8]],
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    server_config_self_signed_hopf(names, alpn)
}

/// [`server_config_self_signed`] with TLS options.
pub fn server_config_self_signed_with(
    names: &[&str],
    alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    server_config_self_signed_hopf(names, alpn)
}

/// In-tree TLS handshake server config.
pub fn server_config_self_signed_hopf(
    names: &[&str],
    alpn: &[&[u8]],
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    server_config_self_signed_with_hopf(names, alpn, QuicTlsOptions::default())
}

/// [`server_config_self_signed_hopf`] with TLS options.
pub fn server_config_self_signed_with_hopf(
    names: &[&str],
    alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    let (creds, pem) = hopf_server_credentials(names)?;
    let params = HopfTlsBuildParams::server(
        creds,
        alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    );
    Ok((hopf_server_config(params), pem))
}

/// Client config trusting a leaf PEM file.
pub fn client_config_for_certified_pem(
    leaf_pem: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_from_pem(leaf_pem, alpn)
}

/// [`client_config_for_certified_pem`] with TLS options.
pub fn client_config_for_certified_pem_with(
    leaf_pem: &Path,
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_from_pem_with(leaf_pem, alpn, tls)
}

/// Client config trusting in-memory PEM.
pub fn client_config_for_pem_bytes(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_for_pem_bytes_hopf(leaf_pem, alpn)
}

/// [`client_config_for_pem_bytes`] with TLS options.
pub fn client_config_for_pem_bytes_with(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_for_pem_bytes_hopf(leaf_pem, alpn)
}

/// Client config trusting in-memory PEM via in-tree handshake.
pub fn client_config_for_pem_bytes_hopf(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_for_pem_bytes_with_hopf(leaf_pem, alpn, QuicTlsOptions::default())
}

/// [`client_config_for_pem_bytes_hopf`] with TLS options.
pub fn client_config_for_pem_bytes_with_hopf(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
    _tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let certs = pem_to_der_certs(leaf_pem)?;
    let params = HopfTlsBuildParams::client_self_signed(
        alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        "localhost",
        certs[0].clone(),
    );
    Ok(hopf_client_config(params))
}

/// Transport options (stored but defaults used by in-tree connection for echo).
#[derive(Debug, Clone, Default)]
pub struct QuicTransportOptions {
    max_idle_timeout: Option<Duration>,
    keep_alive_interval: Option<Duration>,
    stream_receive_window: Option<u32>,
    receive_window: Option<u32>,
    send_window: Option<u64>,
    max_concurrent_bidi_streams: Option<u32>,
    max_concurrent_uni_streams: Option<u32>,
    datagram_receive_buffer_size: Option<Option<usize>>,
    datagram_send_buffer_size: Option<usize>,
}

impl QuicTransportOptions {
    /// Start from defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Max idle timeout.
    pub fn max_idle_timeout(mut self, value: Duration) -> Self {
        self.max_idle_timeout = Some(value);
        self
    }

    /// Keep-alive interval.
    pub fn keep_alive_interval(mut self, value: Duration) -> Self {
        self.keep_alive_interval = Some(value);
        self
    }

    /// Stream receive window.
    pub fn stream_receive_window(mut self, value: u32) -> Self {
        self.stream_receive_window = Some(value);
        self
    }

    /// Connection receive window.
    pub fn receive_window(mut self, value: u32) -> Self {
        self.receive_window = Some(value);
        self
    }

    /// Send window.
    pub fn send_window(mut self, value: u64) -> Self {
        self.send_window = Some(value);
        self
    }

    /// Max concurrent bi streams.
    pub fn max_concurrent_bidi_streams(mut self, value: u32) -> Self {
        self.max_concurrent_bidi_streams = Some(value);
        self
    }

    /// Max concurrent uni streams.
    pub fn max_concurrent_uni_streams(mut self, value: u32) -> Self {
        self.max_concurrent_uni_streams = Some(value);
        self
    }

    /// Datagram receive buffer.
    pub fn datagram_receive_buffer_size(mut self, value: Option<usize>) -> Self {
        self.datagram_receive_buffer_size = Some(value);
        self
    }

    /// Datagram send buffer.
    pub fn datagram_send_buffer_size(mut self, value: usize) -> Self {
        self.datagram_send_buffer_size = Some(value);
        self
    }
}

/// Apply transport options to server (no-op for echo milestone defaults).
pub fn apply_server_transport_options(
    _server: &mut Arc<QuicServerConfig>,
    _options: &QuicTransportOptions,
) -> io::Result<()> {
    Ok(())
}

/// Apply transport options to client (no-op for echo milestone defaults).
pub fn apply_client_transport_options(
    _client: &mut Arc<QuicClientConfig>,
    _options: &QuicTransportOptions,
) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ALPN_H3;

    #[test]
    fn alpn_h3_is_h3() {
        assert_eq!(ALPN_H3, b"h3");
    }

    #[test]
    fn early_data_off_by_default() {
        let opts = QuicTlsOptions::default();
        assert!(!opts.enable_early_data);
    }

    #[test]
    fn high_security_requires_retry() {
        let h = QuicListenHardening::high_security();
        assert!(h.require_address_validation);
    }

    #[test]
    fn self_signed_server_and_matching_client_hopf() {
        let (server, pem) = server_config_self_signed_hopf(&["localhost"], &[ALPN_H3]).unwrap();
        let _ = server;
        let client = client_config_for_pem_bytes_hopf(&pem, &[ALPN_H3]).unwrap();
        let _ = client;
    }

    #[test]
    fn apply_listen_hardening_mutates_server_config() {
        let (mut server, _) = server_config_self_signed(&["localhost"], &[ALPN_H3]).unwrap();
        apply_listen_hardening(&mut server, &QuicListenHardening::high_security());
        assert_eq!(server.max_incoming, Some(1_024));
    }
}
