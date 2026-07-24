// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC TLS / listen / dial configuration (shared rustls identity with TCP via PEM).

use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore, ServerConfig as RustlsServerConfig};
use hopf_core::HandlerFactory;

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
) -> io::Result<RustlsServerConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cfg = RustlsServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    cfg.max_early_data_size = u32::MAX;
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(cfg)
}

fn tls13_client(roots: RootCertStore, alpn: &[&[u8]]) -> io::Result<RustlsClientConfig> {
    let provider = rustls::crypto::ring::default_provider();
    let mut cfg = RustlsClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg.enable_early_data = true;
    Ok(cfg)
}

/// Build a QUIC [`QuicServerConfig`] from PEM cert/key with the given ALPN list.
pub fn server_config_from_pem(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let rustls_cfg = tls13_server(certs, key, alpn)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicServerConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(Arc::new(QuicServerConfig::with_crypto(Arc::new(quic_crypto))))
}

/// Build a QUIC [`QuicClientConfig`] that trusts `ca_path` PEM with the given ALPN.
pub fn client_config_from_pem(
    ca_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<QuicClientConfig>> {
    let certs = load_certs(ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let rustls_cfg = tls13_client(roots, alpn)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicClientConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(Arc::new(QuicClientConfig::new(Arc::new(quic_crypto))))
}

/// Build an in-memory self-signed server config (tests / demos).
///
/// Returns `(server_config, leaf_cert_pem)`.
pub fn server_config_self_signed(
    names: &[&str],
    alpn: &[&[u8]],
) -> io::Result<(Arc<QuicServerConfig>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(
        names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    )
    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let pem = cert.cert.pem();
    let rustls_cfg = tls13_server(vec![cert_der], key_der, alpn)?;
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

/// Client config that trusts an in-memory PEM cert.
pub fn client_config_for_pem_bytes(
    leaf_pem: &[u8],
    alpn: &[&[u8]],
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
    let rustls_cfg = tls13_client(roots, alpn)?;
    let quic_crypto: quinn_proto::crypto::rustls::QuicClientConfig = Arc::new(rustls_cfg)
        .try_into()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(Arc::new(QuicClientConfig::new(Arc::new(quic_crypto))))
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
}
