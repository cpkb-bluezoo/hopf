// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! PEM-loaded TLS 1.3 acceptors/connectors on the in-tree [`TlsRecordEngine`]
//! (TCP TLS / STARTTLS) — the Phase 4 replacement for `hopf-tls`'s rustls-backed
//! equivalents. Only PKCS#8 private keys are supported (`BEGIN PRIVATE KEY`);
//! re-encode legacy PKCS#1/SEC1 PEM with e.g. `openssl pkcs8 -topk8 -nocrypt`.

use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

use crate::crypto::kx_policy::KxPolicy;
use crate::crypto::trust::TrustStore;

use super::engine::{HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials, VerifyOverride};
use super::handshake::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS;
use super::record::TlsRecordEngine;

/// Factory for server-side TLS engines (shared across accepts).
pub trait TlsAcceptor: Send + Sync {
    /// Create a new server-role engine for one TCP connection.
    fn accept(&self) -> TlsRecordEngine;
}

/// Shared acceptor handle stored on listeners / connections.
pub type SharedTlsAcceptor = Arc<dyn TlsAcceptor>;

/// Factory for client-side TLS engines (shared across dials).
pub trait TlsConnector: Send + Sync {
    /// Create a new client-role engine for `server_name` (SNI / cert identity).
    fn connect(&self, server_name: &str) -> io::Result<TlsRecordEngine>;
}

/// Shared connector handle stored on dial configs / connections.
pub type SharedTlsConnector = Arc<dyn TlsConnector>;

fn base_config(role: HandshakeRole, alpn: &[&[u8]]) -> HandshakeConfig {
    HandshakeConfig {
        role,
        mode: HandshakeMode::TcpRecordLayer,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        server_name: None,
        server: None,
        kx_policy: KxPolicy::default(),
        local_transport_parameters: None,
        trust_store: None,
        verify_override: None,
        enable_early_data: false,
        max_early_data_size: 0,
        max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
        ticket_key: None,
        ticket_store: None,
        anti_replay: None,
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Bytes>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("no certificates in {}", path.display()),
        ));
    }
    Ok(certs.into_iter().map(|c| Bytes::copy_from_slice(c.as_ref())).collect())
}

fn load_pkcs8_key(path: &Path) -> io::Result<Bytes> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let Some(key) = keys.pop() else {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "{}: no PKCS#8 private key found (only `BEGIN PRIVATE KEY` PEM blocks are \
                 supported today — re-encode PKCS#1/SEC1 keys with `openssl pkcs8 -topk8 -nocrypt`)",
                path.display()
            ),
        ));
    };
    Ok(Bytes::copy_from_slice(key.secret_pkcs8_der()))
}

/// Load a PEM certificate chain and PKCS#8 private key into [`ServerCredentials`].
pub fn server_credentials_from_pem(cert_path: &Path, key_path: &Path) -> io::Result<ServerCredentials> {
    Ok(ServerCredentials {
        cert_chain: load_certs(cert_path)?,
        signing_key_pkcs8: load_pkcs8_key(key_path)?,
    })
}

struct PemAcceptor {
    creds: ServerCredentials,
    alpn: Vec<Bytes>,
}

impl TlsAcceptor for PemAcceptor {
    fn accept(&self) -> TlsRecordEngine {
        let mut config = base_config(HandshakeRole::Server, &[]);
        config.alpn = self.alpn.clone();
        config.server = Some(self.creds.clone());
        TlsRecordEngine::new(config)
    }
}

/// Build a [`SharedTlsAcceptor`] from PEM cert-chain and PKCS#8 key files.
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn acceptor_from_pem(cert_path: &Path, key_path: &Path, alpn: &[&[u8]]) -> io::Result<SharedTlsAcceptor> {
    let creds = server_credentials_from_pem(cert_path, key_path)?;
    Ok(Arc::new(PemAcceptor {
        creds,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    }))
}

struct TrustedConnector {
    trust_store: Option<TrustStore>,
    verify_override: Option<VerifyOverride>,
    alpn: Vec<Bytes>,
}

impl TlsConnector for TrustedConnector {
    fn connect(&self, server_name: &str) -> io::Result<TlsRecordEngine> {
        let mut config = base_config(HandshakeRole::Client, &[]);
        config.alpn = self.alpn.clone();
        config.server_name = Some(server_name.to_string());
        config.trust_store = self.trust_store.clone();
        config.verify_override = self.verify_override.clone();
        Ok(TlsRecordEngine::new(config))
    }
}

/// Build a [`SharedTlsConnector`] whose server-chain verification is entirely
/// custom — e.g. DANE TLSA matching, or any trust model that isn't a fixed
/// root set. See [`VerifyOverride`].
pub fn connector_with_verify_override(
    verify: Arc<dyn Fn(&[Bytes], Option<&str>) -> bool + Send + Sync>,
    alpn: &[&[u8]],
) -> SharedTlsConnector {
    Arc::new(TrustedConnector {
        trust_store: None,
        verify_override: Some(VerifyOverride(verify)),
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    })
}

/// Build a [`SharedTlsConnector`] that trusts the given PEM CA / leaf cert file.
/// `alpn` entries are protocol names such as `b"http/1.1"`.
pub fn connector_from_pem(ca_path: &Path, alpn: &[&[u8]]) -> io::Result<SharedTlsConnector> {
    let mut trust = TrustStore::new();
    for cert in load_certs(ca_path)? {
        trust.add_anchor(cert);
    }
    Ok(Arc::new(TrustedConnector {
        trust_store: Some(trust),
        verify_override: None,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    }))
}

/// Accepts any certificate, performing no validation at all — for opportunistic
/// TLS, where the point is encrypting the connection, not authenticating the
/// peer (e.g. RFC 3207/7672 opportunistic MTA-to-MTA STARTTLS, where requiring a
/// trusted certificate would break delivery to most real-world mail servers).
/// Never use this where the peer's identity actually matters — DANE
/// (`hopf_dns::dane::DaneServerCertVerifier`) or [`connector_from_pem`] is what
/// authenticates the peer when that's actually possible/required.
pub fn insecure_connector(alpn: &[&[u8]]) -> SharedTlsConnector {
    Arc::new(TrustedConnector {
        trust_store: None,
        verify_override: None,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_pem(key_pair: &rcgen::KeyPair) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::Builder::new().prefix("hopf-core-tls-pem-").tempdir().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(key_pair).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (dir, cert_path, key_path)
    }

    #[test]
    fn acceptor_from_pem_loads_ed25519_key() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let (_dir, cert_path, key_path) = write_temp_pem(&key_pair);
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[b"h2"]).unwrap();
        let _engine = acceptor.accept();
    }

    #[test]
    fn acceptor_from_pem_loads_ecdsa_p256_key() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let (_dir, cert_path, key_path) = write_temp_pem(&key_pair);
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();
        let _engine = acceptor.accept();
    }

    #[test]
    fn connector_from_pem_trusts_the_given_ca() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let (_dir, cert_path, _key_path) = write_temp_pem(&key_pair);
        let connector = connector_from_pem(&cert_path, &[b"h2"]).unwrap();
        let _engine = connector.connect("localhost").unwrap();
    }

    #[test]
    fn insecure_connector_builds_without_a_trust_store() {
        let connector = insecure_connector(&[]);
        let _engine = connector.connect("anything.example").unwrap();
    }

    #[test]
    fn verify_override_connector_builds_a_client_role_engine() {
        // Full accept/reject behavior is exercised in tls::engine's own
        // loopback tests (verify_override drives HandshakeEngine::on_certificate
        // directly); this just proves the connector wiring compiles and runs.
        let connector = super::connector_with_verify_override(Arc::new(|_chain, _name| true), &[]);
        let _engine = connector.connect("dane.example").unwrap();
    }
}
