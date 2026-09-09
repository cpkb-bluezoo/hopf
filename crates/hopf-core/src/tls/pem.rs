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
use crate::crypto::trust::{public_trust_store, TrustStore};

use super::engine::{
    ClientAuthPolicy, HandshakeConfig, HandshakeMode, HandshakeRole, ServerCredentials, VerifyOverride,
};
use super::handshake::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS;
use super::record::TlsRecordEngine;
use super::tls12;
use super::TlsVariant;

/// Factory for server-side TLS engines (shared across accepts).
pub trait TlsAcceptor: Send + Sync {
    /// Create a new server-role engine for one TCP connection.
    fn accept(&self) -> TlsVariant;
}

/// Shared acceptor handle stored on listeners / connections.
pub type SharedTlsAcceptor = Arc<dyn TlsAcceptor>;

/// Factory for client-side TLS engines (shared across dials).
pub trait TlsConnector: Send + Sync {
    /// Create a new client-role engine for `server_name` (SNI / cert identity).
    fn connect(&self, server_name: &str) -> io::Result<TlsVariant>;
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
        ..Default::default()
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
    client_auth: ClientAuthPolicy,
    client_trust_store: Option<TrustStore>,
}

impl TlsAcceptor for PemAcceptor {
    fn accept(&self) -> TlsVariant {
        let mut config = base_config(HandshakeRole::Server, &[]);
        config.alpn = self.alpn.clone();
        config.server = Some(self.creds.clone());
        config.client_auth = self.client_auth;
        config.client_trust_store = self.client_trust_store.clone();
        TlsVariant::V13(TlsRecordEngine::new(config))
    }
}

/// Build a [`SharedTlsAcceptor`] from PEM cert-chain and PKCS#8 key files.
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn acceptor_from_pem(cert_path: &Path, key_path: &Path, alpn: &[&[u8]]) -> io::Result<SharedTlsAcceptor> {
    let creds = server_credentials_from_pem(cert_path, key_path)?;
    Ok(Arc::new(PemAcceptor {
        creds,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        client_auth: ClientAuthPolicy::None,
        client_trust_store: None,
    }))
}

/// Build a mutual-TLS [`SharedTlsAcceptor`]: like [`acceptor_from_pem`], but
/// also requests a client certificate (`policy`) and verifies it against the
/// CA(s) in `client_ca_path`.
pub fn acceptor_from_pem_with_client_auth(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
    policy: ClientAuthPolicy,
    client_ca_path: &Path,
) -> io::Result<SharedTlsAcceptor> {
    let creds = server_credentials_from_pem(cert_path, key_path)?;
    let mut trust = TrustStore::new();
    for cert in load_certs(client_ca_path)? {
        trust.add_anchor(cert);
    }
    Ok(Arc::new(PemAcceptor {
        creds,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        client_auth: policy,
        client_trust_store: Some(trust),
    }))
}

struct TrustedConnector {
    trust_store: Option<TrustStore>,
    verify_override: Option<VerifyOverride>,
    alpn: Vec<Bytes>,
    client_credentials: Option<ServerCredentials>,
}

impl TlsConnector for TrustedConnector {
    fn connect(&self, server_name: &str) -> io::Result<TlsVariant> {
        let mut config = base_config(HandshakeRole::Client, &[]);
        config.alpn = self.alpn.clone();
        config.server_name = Some(server_name.to_string());
        config.trust_store = self.trust_store.clone();
        config.verify_override = self.verify_override.clone();
        config.client_credentials = self.client_credentials.clone();
        Ok(TlsVariant::V13(TlsRecordEngine::new(config)))
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
        client_credentials: None,
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
        client_credentials: None,
    }))
}

/// Build a mutual-TLS [`SharedTlsConnector`]: like [`connector_from_pem`], but
/// also presents `client_cert_path`/`client_key_path` when the server sends
/// `CertificateRequest`.
pub fn connector_from_pem_with_client_cert(
    ca_path: &Path,
    client_cert_path: &Path,
    client_key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<SharedTlsConnector> {
    let mut trust = TrustStore::new();
    for cert in load_certs(ca_path)? {
        trust.add_anchor(cert);
    }
    let client_creds = server_credentials_from_pem(client_cert_path, client_key_path)?;
    Ok(Arc::new(TrustedConnector {
        trust_store: Some(trust),
        verify_override: None,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        client_credentials: Some(client_creds),
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
        client_credentials: None,
    })
}

/// Build a [`SharedTlsConnector`] that trusts the public WebPKI — the
/// standard "does this chain to a trusted public root and match the
/// hostname" validation any ordinary HTTPS client performs, with no
/// caller-supplied root. See [`public_trust_store`] for the native/vendored
/// fallback behavior.
///
/// This is what authenticates a certificate advertised by an endpoint
/// discovered rather than explicitly configured (e.g. an RFC 9462 DDR
/// candidate) — [`connector_from_pem`] and [`insecure_connector`] both need
/// the caller to already know who they're trusting; this doesn't.
pub fn public_trust_connector(alpn: &[&[u8]]) -> SharedTlsConnector {
    Arc::new(TrustedConnector {
        trust_store: Some(public_trust_store()),
        verify_override: None,
        alpn: alpn.iter().map(|p| Bytes::copy_from_slice(p)).collect(),
        client_credentials: None,
    })
}

// ---------------------------------------------------------------------------
// TLS 1.2 — explicit legacy interop only (RFC 5246, ECDHE + GCM). Callers
// dial these deliberately for a known-legacy target; there's no opportunistic
// version fallback from the TLS 1.3 path above (see crypto-migration-plan.md
// Phase 5's "explicit connector, not negotiated fallback" scope note).
// ---------------------------------------------------------------------------

struct PemAcceptorTls12 {
    creds: ServerCredentials,
    client_auth: ClientAuthPolicy,
    client_trust_store: Option<TrustStore>,
}

impl TlsAcceptor for PemAcceptorTls12 {
    fn accept(&self) -> TlsVariant {
        let config = tls12::engine::Config {
            role: tls12::engine::Role::Server,
            server_name: None,
            server: Some(self.creds.clone()),
            trust_store: None,
            // As with TLS 1.3's `base_config` above: session-ticket support
            // needs a `Tls12Config` built directly by the caller, not this
            // simple PEM-loaded helper.
            ticket_key: None,
            client_ticket_store: None,
            client_auth: self.client_auth,
            client_trust_store: self.client_trust_store.clone(),
            ..Default::default()
        };
        TlsVariant::V12(tls12::record::Tls12RecordEngine::new(config))
    }
}

/// Build a TLS 1.2 [`SharedTlsAcceptor`] from PEM cert-chain and PKCS#8 key
/// files — RSA or ECDSA P-256/P-384 only (see `tls12::engine`'s module doc).
pub fn acceptor_from_pem_tls12(cert_path: &Path, key_path: &Path) -> io::Result<SharedTlsAcceptor> {
    let creds = server_credentials_from_pem(cert_path, key_path)?;
    Ok(Arc::new(PemAcceptorTls12 { creds, client_auth: ClientAuthPolicy::None, client_trust_store: None }))
}

/// Build a mutual-TLS TLS 1.2 [`SharedTlsAcceptor`]: like
/// [`acceptor_from_pem_tls12`], but also requests a client certificate
/// (`policy`) and verifies it against the CA(s) in `client_ca_path`.
pub fn acceptor_from_pem_tls12_with_client_auth(
    cert_path: &Path,
    key_path: &Path,
    policy: ClientAuthPolicy,
    client_ca_path: &Path,
) -> io::Result<SharedTlsAcceptor> {
    let creds = server_credentials_from_pem(cert_path, key_path)?;
    let mut trust = TrustStore::new();
    for cert in load_certs(client_ca_path)? {
        trust.add_anchor(cert);
    }
    Ok(Arc::new(PemAcceptorTls12 { creds, client_auth: policy, client_trust_store: Some(trust) }))
}

struct TrustedConnectorTls12 {
    trust_store: Option<TrustStore>,
    client_credentials: Option<ServerCredentials>,
}

impl TlsConnector for TrustedConnectorTls12 {
    fn connect(&self, server_name: &str) -> io::Result<TlsVariant> {
        let config = tls12::engine::Config {
            role: tls12::engine::Role::Client,
            server_name: Some(server_name.to_string()),
            server: None,
            trust_store: self.trust_store.clone(),
            ticket_key: None,
            client_ticket_store: None,
            client_credentials: self.client_credentials.clone(),
            ..Default::default()
        };
        Ok(TlsVariant::V12(tls12::record::Tls12RecordEngine::new(config)))
    }
}

/// Build a TLS 1.2 [`SharedTlsConnector`] that trusts the given PEM CA / leaf
/// cert file.
pub fn connector_from_pem_tls12(ca_path: &Path) -> io::Result<SharedTlsConnector> {
    let mut trust = TrustStore::new();
    for cert in load_certs(ca_path)? {
        trust.add_anchor(cert);
    }
    Ok(Arc::new(TrustedConnectorTls12 { trust_store: Some(trust), client_credentials: None }))
}

/// Build a mutual-TLS TLS 1.2 [`SharedTlsConnector`]: like
/// [`connector_from_pem_tls12`], but also presents
/// `client_cert_path`/`client_key_path` when the server sends `CertificateRequest`.
pub fn connector_from_pem_tls12_with_client_cert(
    ca_path: &Path,
    client_cert_path: &Path,
    client_key_path: &Path,
) -> io::Result<SharedTlsConnector> {
    let mut trust = TrustStore::new();
    for cert in load_certs(ca_path)? {
        trust.add_anchor(cert);
    }
    let client_creds = server_credentials_from_pem(client_cert_path, client_key_path)?;
    Ok(Arc::new(TrustedConnectorTls12 { trust_store: Some(trust), client_credentials: Some(client_creds) }))
}

/// TLS 1.2 analogue of [`insecure_connector`] — accepts any certificate, for
/// opportunistic legacy STARTTLS where encryption without authentication is
/// still strictly better than plaintext.
pub fn insecure_connector_tls12() -> SharedTlsConnector {
    Arc::new(TrustedConnectorTls12 { trust_store: None, client_credentials: None })
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
