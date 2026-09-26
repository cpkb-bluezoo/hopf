// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC TLS / listen / dial configuration.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hopf_core::crypto::kx_policy::KxPolicy;
use hopf_core::crypto::trust::TrustStore;
use hopf_core::pem::{parse_certs, parse_pkcs8_keys};
use hopf_core::tls::{HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials};
use hopf_core::HandlerFactory;

use crate::crypto::{hopf_client_config, hopf_server_config, HopfTlsBuildParams};
use crate::hooks::ConnectionFactory;
use crate::transport::endpoint::{ClientConfig as TransportClientConfig, ServerConfig as TransportServerConfig};
use crate::transport::quic_lb::{ConnectionIdGenerator, QuicLbConfig};
pub use crate::transport::version::QuicVersion;

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

    /// Retry token lifetime.
    pub fn retry_token_lifetime(&mut self, d: Duration) {
        self.inner.retry_token_lifetime = d;
    }

    /// Issue QUIC-LB connection IDs (draft-ietf-quic-load-balancers-21) that
    /// a connection-ID-aware load balancer can route on, so a datagram keeps
    /// reaching this backend after the client's address changes.
    ///
    /// Every backend behind the balancer needs the same config ID, key and
    /// nonce length but its own server ID; the balancer holds the same
    /// [`QuicLbConfig`] to decode. Without this call, connection IDs are 8
    /// random octets. Clones of this config share one nonce sequence.
    pub fn quic_lb(&mut self, config: &QuicLbConfig) {
        self.inner.cid_generator = Some(config.generator());
    }

    /// Issue connection IDs from a custom [`ConnectionIdGenerator`] instead
    /// of 8 random octets. Every ID must have the generator's fixed length.
    pub fn connection_id_generator(&mut self, generator: Arc<dyn ConnectionIdGenerator>) {
        self.inner.cid_generator = Some(generator);
    }

    /// QUIC versions this listener accepts (default: every version this
    /// stack speaks). Also what it offers in a Version Negotiation packet. An
    /// empty list is ignored.
    pub fn versions(&mut self, versions: &[QuicVersion]) {
        if !versions.is_empty() {
            self.inner.versions = versions.to_vec();
        }
    }

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
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: hopf_core::tls::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
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

    /// Clone transport config.
    pub(crate) fn transport(&self) -> TransportClientConfig {
        self.inner.clone()
    }

    /// QUIC versions to speak, most preferred first (default: version 1
    /// only). The first is used for the first flight; if the server answers
    /// with a Version Negotiation packet the client restarts in the first of
    /// these the server offers (RFC 9000 section 6.2). An empty list is
    /// ignored.
    pub fn versions(&mut self, versions: &[QuicVersion]) {
        if !versions.is_empty() {
            self.inner.versions = versions.to_vec();
        }
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

/// TLS options (early data / 0-RTT, key-exchange groups).
#[derive(Debug, Clone)]
pub struct QuicTlsOptions {
    /// Offer / accept TLS 1.3 early data (0-RTT).
    pub enable_early_data: bool,
    /// Server max early data size.
    pub max_early_data_size: u32,
    /// Key-exchange group preference (RFC 8446 `supported_groups` /
    /// `key_share`). Defaults to [`KxPolicy::classical_only`]; see
    /// [`QuicTlsOptions::with_kx_policy`].
    pub kx_policy: KxPolicy,
}

impl Default for QuicTlsOptions {
    fn default() -> Self {
        Self {
            enable_early_data: false,
            max_early_data_size: 0,
            kx_policy: KxPolicy::classical_only(),
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

    /// Select the key-exchange group preference.
    ///
    /// The default is [`KxPolicy::classical_only`] (X25519), which every
    /// QUIC peer supports and which keeps the ClientHello small. A hybrid
    /// policy such as [`KxPolicy::pqc_first`] offers the RFC 10024 hybrid
    /// ML-KEM groups (`X25519MLKEM768` first) with X25519 as a fallback,
    /// protecting recorded traffic against a future quantum adversary. The
    /// trade-off is a ClientHello carrying a ~1.2 KiB ML-KEM key share,
    /// which no longer fits a single 1200-byte Initial datagram, so the
    /// handshake needs a second client Initial packet (one extra datagram,
    /// no extra round trip). Both peers must opt in for a hybrid group to
    /// be negotiated; otherwise the handshake falls back to X25519.
    pub fn with_kx_policy(mut self, kx_policy: KxPolicy) -> Self {
        self.kx_policy = kx_policy;
        self
    }

    /// Shorthand for [`QuicTlsOptions::with_kx_policy`] with
    /// [`KxPolicy::pqc_first`].
    pub fn with_pqc(self) -> Self {
        self.with_kx_policy(KxPolicy::pqc_first())
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
    let certs = parse_certs(pem);
    if certs.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, "no certificates in PEM"));
    }
    Ok(certs.into_iter().map(Bytes::from).collect())
}

fn load_pem_certs(path: &Path) -> io::Result<Vec<Bytes>> {
    let pem = std::fs::read(path)?;
    let certs = parse_certs(&pem);
    if certs.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("no certificates in {}", path.display()),
        ));
    }
    Ok(certs.into_iter().map(Bytes::from).collect())
}

fn load_private_key_pkcs8(path: &Path) -> io::Result<Bytes> {
    let pem = std::fs::read(path)?;
    let mut keys = parse_pkcs8_keys(&pem);
    let Some(key) = keys.pop() else {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{}: no PKCS#8 private key found (only `BEGIN PRIVATE KEY` PEM blocks are \
                 supported — re-encode PKCS#1/SEC1 keys with `openssl pkcs8 -topk8 -nocrypt`)",
                path.display()
            ),
        ));
    };
    Ok(Bytes::from(key))
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
    tls: QuicTlsOptions,
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
    )
    .with_tls(tls);
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
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let certs = load_pem_certs(ca_path)?;
    let mut trust = TrustStore::new();
    for c in certs {
        trust.add_anchor(c);
    }
    let params = HopfTlsBuildParams {
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        kx_policy: tls.kx_policy.clone(),
        server_name: None,
        trust_store: Some(trust),
        server: None,
        local_transport_parameters: None,
        tls,
        ticket_store: Some(hopf_core::tls::ClientTicketStore::shared()),
        ticket_key: None,
        anti_replay: None,
    };
    Ok(hopf_client_config(params))
}

/// Client config trusting the public WebPKI (native OS roots, falling back
/// to a vendored copy of Mozilla's CA list — see
/// [`hopf_core::crypto::trust::public_trust_store`]).
pub fn client_config_public_trust(alpn: &[&[u8]]) -> io::Result<Arc<QuicClientConfig>> {
    client_config_public_trust_with(alpn, QuicTlsOptions::default())
}

/// [`client_config_public_trust`] with options.
pub fn client_config_public_trust_with(
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let params = HopfTlsBuildParams {
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        kx_policy: tls.kx_policy.clone(),
        server_name: None,
        trust_store: Some(hopf_core::crypto::trust::public_trust_store()),
        server: None,
        local_transport_parameters: None,
        tls,
        ticket_store: Some(hopf_core::tls::ClientTicketStore::shared()),
        ticket_key: None,
        anti_replay: None,
    };
    Ok(hopf_client_config(params))
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
    tls: QuicTlsOptions,
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    server_config_self_signed_with_hopf(names, alpn, tls)
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
    tls: QuicTlsOptions,
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    let (creds, pem) = hopf_server_credentials(names)?;
    let params = HopfTlsBuildParams::server(
        creds,
        alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    )
    .with_tls(tls);
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
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_for_pem_bytes_with_hopf(leaf_pem, alpn, tls)
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
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let certs = pem_to_der_certs(leaf_pem)?;
    let mut trust = TrustStore::new();
    trust.add_anchor(certs[0].clone());
    // Leave `server_name` unset so dial-time SNI from `connect_quic*` wins
    // (HttpClient / connect_auto pass the origin host; baking "localhost"
    // here breaks certs minted for other names).
    let params = HopfTlsBuildParams {
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        kx_policy: tls.kx_policy.clone(),
        server_name: None,
        trust_store: Some(trust),
        server: None,
        local_transport_parameters: None,
        tls,
        ticket_store: Some(hopf_core::tls::ClientTicketStore::shared()),
        ticket_key: None,
        anti_replay: None,
    };
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

/// Issue QUIC-LB connection IDs from this server (see
/// [`QuicServerConfig::quic_lb`]); for configs held as
/// `Arc<QuicServerConfig>`, as the builders return them.
pub fn apply_server_quic_lb(server: &mut Arc<QuicServerConfig>, config: &QuicLbConfig) {
    Arc::make_mut(server).quic_lb(config);
}

/// Apply transport options to server.
pub fn apply_server_transport_options(
    server: &mut Arc<QuicServerConfig>,
    options: &QuicTransportOptions,
) -> io::Result<()> {
    let cfg = Arc::make_mut(server);
    if let Some(v) = options.datagram_receive_buffer_size {
        cfg.inner.max_datagram_frame_size = v.map(|n| n as u64);
    }
    if let Some(d) = options.max_idle_timeout {
        cfg.inner.max_idle_timeout = Some(d);
    }
    if let Some(n) = options.max_concurrent_bidi_streams {
        cfg.inner.initial_max_streams_bidi = Some(u64::from(n));
    }
    if let Some(n) = options.max_concurrent_uni_streams {
        cfg.inner.initial_max_streams_uni = Some(u64::from(n));
    }
    if let Some(d) = options.keep_alive_interval {
        cfg.inner.keep_alive_interval = Some(d);
    }
    Ok(())
}

/// Apply transport options to client.
pub fn apply_client_transport_options(
    client: &mut Arc<QuicClientConfig>,
    options: &QuicTransportOptions,
) -> io::Result<()> {
    let cfg = Arc::make_mut(client);
    if let Some(v) = options.datagram_receive_buffer_size {
        cfg.inner.max_datagram_frame_size = v.map(|n| n as u64);
    }
    if let Some(d) = options.max_idle_timeout {
        cfg.inner.max_idle_timeout = Some(d);
    }
    if let Some(n) = options.max_concurrent_bidi_streams {
        cfg.inner.initial_max_streams_bidi = Some(u64::from(n));
    }
    if let Some(n) = options.max_concurrent_uni_streams {
        cfg.inner.initial_max_streams_uni = Some(u64::from(n));
    }
    if let Some(d) = options.keep_alive_interval {
        cfg.inner.keep_alive_interval = Some(d);
    }
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
