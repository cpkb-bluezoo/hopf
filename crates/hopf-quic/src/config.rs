// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC TLS / listen / dial configuration (shared rustls identity with TCP via PEM).

use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig};
use hopf_core::HandlerFactory;
use quinn_proto::{TransportConfig, VarInt};

use crate::hooks::ConnectionFactory;

/// Quinn server crypto + transport config.
pub type QuicServerConfig = quinn_proto::ServerConfig;
/// Quinn client crypto + transport config.
pub type QuicClientConfig = quinn_proto::ClientConfig;

/// Listen (UDP bind) configuration — one [`hopf_core::ProtocolHandler`] per bi-stream.
pub struct QuicListenConfig {
    /// Bind address (use port `0` for ephemeral).
    pub addr: SocketAddr,
    /// Quinn server configuration (TLS + transport).
    pub server: Arc<QuicServerConfig>,
    /// Factory for handlers — one per accepted bidirectional stream.
    pub factory: HandlerFactory,
}

impl QuicListenConfig {
    /// Create a listen config.
    pub fn new(addr: SocketAddr, server: Arc<QuicServerConfig>, factory: HandlerFactory) -> Self {
        Self {
            addr,
            server,
            factory,
        }
    }
}

/// Listen with connection-level hooks (HTTP/3 control + request streams).
pub struct QuicListenHooksConfig {
    /// Bind address.
    pub addr: SocketAddr,
    /// Quinn server configuration.
    pub server: Arc<QuicServerConfig>,
    /// One [`crate::QuicConnection`] per accepted QUIC connection.
    pub connection_factory: ConnectionFactory,
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
        }
    }
}

/// Dial (UDP connect-path) configuration.
pub struct QuicConnectConfig {
    /// Peer address (Stage 0: already resolved).
    pub addr: SocketAddr,
    /// Quinn client configuration.
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

fn tls13_server(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[&[u8]],
    tls: &QuicTlsOptions,
) -> io::Result<RustlsServerConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cfg = RustlsServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    // 0 = reject early data (secure default). Non-zero advertises 0-RTT
    // acceptance — replayable; only enable via [`QuicTlsOptions::with_early_data`].
    cfg.max_early_data_size = if tls.enable_early_data {
        tls.max_early_data_size
    } else {
        0
    };
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(cfg)
}

fn tls13_client(
    roots: RootCertStore,
    alpn: &[&[u8]],
    tls: &QuicTlsOptions,
) -> io::Result<RustlsClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cfg = RustlsClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // Off by default: 0-RTT application data is replayable (RFC 9001 §5.6).
    cfg.enable_early_data = tls.enable_early_data;
    Ok(cfg)
}

/// TLS options for hopf-quic PEM builders (separate from
/// [`QuicTransportOptions`], which covers RFC 9000 transport parameters).
#[derive(Debug, Clone, Copy)]
pub struct QuicTlsOptions {
    /// Offer / accept TLS 1.3 early data (0-RTT). **Default: `false`** —
    /// early data is replayable; enable only for idempotent workloads that
    /// accept that risk (see SECURITY.md).
    pub enable_early_data: bool,
    /// Server `max_early_data_size` when early data is enabled (ignored when
    /// disabled). Default when enabling via [`Self::with_early_data`]:
    /// `u32::MAX`.
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

    /// Opt in to 0-RTT / early data (server advertises `u32::MAX` bytes;
    /// client sets `enable_early_data`).
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

/// Build a QUIC [`QuicServerConfig`] from PEM cert/key with the given ALPN list.
///
/// Early data (0-RTT) is **disabled**. Use
/// [`server_config_from_pem_with`] with [`QuicTlsOptions::with_early_data`]
/// to opt in.
pub fn server_config_from_pem(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicServerConfig>> {
    server_config_from_pem_with(cert_path, key_path, alpn, QuicTlsOptions::default())
}

/// [`server_config_from_pem`] with explicit [`QuicTlsOptions`] (e.g. early data).
pub fn server_config_from_pem_with(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let rustls_cfg = tls13_server(certs, key, alpn, &tls)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicServerConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(Arc::new(QuicServerConfig::with_crypto(Arc::new(quic_crypto))))
}

/// Build a QUIC [`QuicClientConfig`] that trusts `ca_path` PEM with the given ALPN.
///
/// Early data is **disabled**. Use [`client_config_from_pem_with`] to opt in.
pub fn client_config_from_pem(
    ca_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_from_pem_with(ca_path, alpn, QuicTlsOptions::default())
}

/// [`client_config_from_pem`] with explicit [`QuicTlsOptions`].
pub fn client_config_from_pem_with(
    ca_path: &Path,
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let certs = load_certs(ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let rustls_cfg = tls13_client(roots, alpn, &tls)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicClientConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(Arc::new(QuicClientConfig::new(Arc::new(quic_crypto))))
}

/// Build an in-memory self-signed server config (tests / demos).
///
/// Returns `(server_config, leaf_cert_pem)`. Early data is disabled; see
/// [`server_config_self_signed_with`].
pub fn server_config_self_signed(
    names: &[&str],
    alpn: &[&[u8]],
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    server_config_self_signed_with(names, alpn, QuicTlsOptions::default())
}

/// [`server_config_self_signed`] with explicit [`QuicTlsOptions`].
pub fn server_config_self_signed_with(
    names: &[&str],
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(
        names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    )
    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let pem = cert.cert.pem();
    let rustls_cfg = tls13_server(vec![cert_der], key_der, alpn, &tls)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicServerConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok((
        Arc::new(QuicServerConfig::with_crypto(Arc::new(quic_crypto))),
        pem.into_bytes(),
    ))
}

/// Client config that trusts a single leaf PEM file (self-signed smoke tests).
pub fn client_config_for_certified_pem(
    leaf_pem: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_from_pem(leaf_pem, alpn)
}

/// [`client_config_for_certified_pem`] with explicit [`QuicTlsOptions`].
pub fn client_config_for_certified_pem_with(
    leaf_pem: &Path,
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_from_pem_with(leaf_pem, alpn, tls)
}

/// Client config that trusts an in-memory PEM cert.
pub fn client_config_for_pem_bytes(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    client_config_for_pem_bytes_with(leaf_pem, alpn, QuicTlsOptions::default())
}

/// [`client_config_for_pem_bytes`] with explicit [`QuicTlsOptions`].
pub fn client_config_for_pem_bytes_with(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
    tls: QuicTlsOptions,
) -> io::Result<Arc<QuicClientConfig>> {
    let mut reader = BufReader::new(leaf_pem);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let rustls_cfg = tls13_client(roots, alpn, &tls)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicClientConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(Arc::new(QuicClientConfig::new(Arc::new(quic_crypto))))
}

/// Commonly-tuned QUIC transport parameters (RFC 9000 §18.2), applied on
/// top of a config already built by one of this module's PEM-based
/// constructors via [`apply_server_transport_options`] /
/// [`apply_client_transport_options`] — hopf-quic's own builders otherwise
/// leave everything at quinn-proto's compiled-in defaults (e.g. a 30s idle
/// timeout and no keepalive). Any field left `None` keeps quinn-proto's
/// default for it.
#[derive(Debug, Clone, Default)]
pub struct QuicTransportOptions {
    max_idle_timeout: Option<Duration>,
    keep_alive_interval: Option<Duration>,
    stream_receive_window: Option<u32>,
    receive_window: Option<u32>,
    send_window: Option<u64>,
    max_concurrent_bidi_streams: Option<u32>,
    max_concurrent_uni_streams: Option<u32>,
    /// `None` = leave quinn default (datagrams enabled with a receive buffer).
    /// `Some(None)` = disable inbound DATAGRAM (RFC 9221).
    /// `Some(Some(n))` = set receive buffer to `n` bytes.
    datagram_receive_buffer_size: Option<Option<usize>>,
    datagram_send_buffer_size: Option<usize>,
}

impl QuicTransportOptions {
    /// Start from quinn-proto's defaults; only fields set via the builder
    /// methods below are overridden.
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum duration of inactivity to accept before timing out the
    /// connection (quinn-proto default: 30s).
    pub fn max_idle_timeout(mut self, value: Duration) -> Self {
        self.max_idle_timeout = Some(value);
        self
    }

    /// Interval at which to send QUIC keep-alive probes when the connection
    /// is otherwise idle (RFC 9000 §10.1.2).
    ///
    /// Quinn default is disabled (`None`). Must be shorter than both peers'
    /// idle timeouts to be effective; only one side needs it enabled.
    pub fn keep_alive_interval(mut self, value: Duration) -> Self {
        self.keep_alive_interval = Some(value);
        self
    }

    /// Maximum bytes the peer may send on any one stream before becoming
    /// blocked, awaiting a window update.
    pub fn stream_receive_window(mut self, value: u32) -> Self {
        self.stream_receive_window = Some(value);
        self
    }

    /// Maximum bytes the peer may send across all streams of the
    /// connection before becoming blocked.
    pub fn receive_window(mut self, value: u32) -> Self {
        self.receive_window = Some(value);
        self
    }

    /// Maximum bytes to transmit to the peer without acknowledgment.
    pub fn send_window(mut self, value: u64) -> Self {
        self.send_window = Some(value);
        self
    }

    /// Maximum number of incoming bidirectional streams the peer may have
    /// open concurrently.
    pub fn max_concurrent_bidi_streams(mut self, value: u32) -> Self {
        self.max_concurrent_bidi_streams = Some(value);
        self
    }

    /// Maximum number of incoming unidirectional streams the peer may have
    /// open concurrently.
    pub fn max_concurrent_uni_streams(mut self, value: u32) -> Self {
        self.max_concurrent_uni_streams = Some(value);
        self
    }

    /// Maximum inbound QUIC DATAGRAM payload bytes to buffer (RFC 9221), or
    /// `None` to refuse DATAGRAM frames (clears `max_datagram_frame_size`).
    /// Quinn's default enables a receive buffer; call this only to override.
    pub fn datagram_receive_buffer_size(mut self, value: Option<usize>) -> Self {
        self.datagram_receive_buffer_size = Some(value);
        self
    }

    /// Maximum outbound QUIC DATAGRAM bytes to buffer before older datagrams
    /// are dropped (RFC 9221).
    pub fn datagram_send_buffer_size(mut self, value: usize) -> Self {
        self.datagram_send_buffer_size = Some(value);
        self
    }

    fn build(&self) -> io::Result<TransportConfig> {
        let mut transport = TransportConfig::default();
        if let Some(value) = self.max_idle_timeout {
            let idle = value
                .try_into()
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("max_idle_timeout: {e}")))?;
            transport.max_idle_timeout(Some(idle));
        }
        if let Some(value) = self.keep_alive_interval {
            transport.keep_alive_interval(Some(value));
        }
        if let Some(value) = self.stream_receive_window {
            transport.stream_receive_window(VarInt::from_u32(value));
        }
        if let Some(value) = self.receive_window {
            transport.receive_window(VarInt::from_u32(value));
        }
        if let Some(value) = self.send_window {
            transport.send_window(value);
        }
        if let Some(value) = self.max_concurrent_bidi_streams {
            transport.max_concurrent_bidi_streams(VarInt::from_u32(value));
        }
        if let Some(value) = self.max_concurrent_uni_streams {
            transport.max_concurrent_uni_streams(VarInt::from_u32(value));
        }
        if let Some(value) = self.datagram_receive_buffer_size {
            transport.datagram_receive_buffer_size(value);
        }
        if let Some(value) = self.datagram_send_buffer_size {
            transport.datagram_send_buffer_size(value);
        }
        Ok(transport)
    }
}

/// Apply `options` to `server`'s transport config (RFC 9000 §18.2),
/// on top of a config already built by [`server_config_from_pem`] or
/// [`server_config_self_signed`].
pub fn apply_server_transport_options(
    server: &mut Arc<QuicServerConfig>,
    options: &QuicTransportOptions,
) -> io::Result<()> {
    let transport = options.build()?;
    Arc::make_mut(server).transport_config(Arc::new(transport));
    Ok(())
}

/// Apply `options` to `client`'s transport config (RFC 9000 §18.2), on top
/// of a config already built by [`client_config_from_pem`],
/// [`client_config_for_pem_bytes`], or [`client_config_for_certified_pem`].
pub fn apply_client_transport_options(
    client: &mut Arc<QuicClientConfig>,
    options: &QuicTransportOptions,
) -> io::Result<()> {
    let transport = options.build()?;
    Arc::make_mut(client).transport_config(Arc::new(transport));
    Ok(())
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("no certificates in {}", path.display()),
        ));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("no private key in {}", path.display()),
            )
        })
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
    fn self_signed_server_and_matching_client() {
        let (server, pem) = server_config_self_signed(&["localhost"], &[ALPN_H3]).unwrap();
        let _ = server;
        let client = client_config_for_pem_bytes(&pem, &[ALPN_H3]).unwrap();
        let _ = client;
    }

    #[test]
    fn listen_config_new_stores_addr() {
        let (server, _) = server_config_self_signed(&["localhost"], &[b"hq-interop"]).unwrap();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let cfg = QuicListenConfig::new(
            addr,
            server,
            std::sync::Arc::new(|| {
                Box::new(hopf_core::NopHandler) as Box<dyn hopf_core::ProtocolHandler>
            }),
        );
        assert_eq!(cfg.addr, addr);
    }

    #[test]
    fn early_data_off_by_default() {
        let opts = QuicTlsOptions::default();
        assert!(!opts.enable_early_data);
        assert_eq!(opts.max_early_data_size, 0);
        let on = QuicTlsOptions::new().with_early_data();
        assert!(on.enable_early_data);
        assert_eq!(on.max_early_data_size, u32::MAX);
    }

    #[test]
    fn tls13_helpers_honor_early_data_flag() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_bytes = cert.key_pair.serialize_der();

        let off = tls13_server(
            vec![cert_der.clone()],
            PrivateKeyDer::Pkcs8(key_bytes.clone().into()),
            &[ALPN_H3],
            &QuicTlsOptions::default(),
        )
        .unwrap();
        assert_eq!(off.max_early_data_size, 0);

        let on = tls13_server(
            vec![cert_der],
            PrivateKeyDer::Pkcs8(key_bytes.into()),
            &[ALPN_H3],
            &QuicTlsOptions::new().with_early_data(),
        )
        .unwrap();
        assert_eq!(on.max_early_data_size, u32::MAX);

        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client_off =
            tls13_client(roots.clone(), &[ALPN_H3], &QuicTlsOptions::default()).unwrap();
        assert!(!client_off.enable_early_data);
        let client_on =
            tls13_client(roots, &[ALPN_H3], &QuicTlsOptions::new().with_early_data()).unwrap();
        assert!(client_on.enable_early_data);
    }
}
