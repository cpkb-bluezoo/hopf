// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! rustls TLS for Hopf endpoints (TLS-from-accept and STARTTLS).
//!
//! Handlers still see only plaintext via [`hopf_core::Endpoint`]. Ciphertext
//! stays under the connection's TLS session.

#![warn(missing_docs)]

use std::fs::File;
use std::io::{self, BufReader, ErrorKind};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ResolvesServerCert, ResolvesServerCertUsingSni, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use hopf_core::{
    SecurityInfo, SharedTlsAcceptor, SharedTlsConnector, TlsAcceptor, TlsConnector, TlsProgress,
    TlsSession,
};

/// Load a PEM certificate chain and private key into a rustls [`ServerConfig`].
///
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn server_config_from_pem(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Build a [`SharedTlsAcceptor`] from an existing [`ServerConfig`].
pub fn acceptor(config: Arc<ServerConfig>) -> SharedTlsAcceptor {
    Arc::new(RustlsAcceptor { config })
}

/// Convenience: PEM paths → shared acceptor.
pub fn acceptor_from_pem(
    cert_path: &Path,
    key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<SharedTlsAcceptor> {
    Ok(acceptor(server_config_from_pem(cert_path, key_path, alpn)?))
}

/// Build a [`ServerConfig`] that selects the certificate per connection via
/// a custom [`ResolvesServerCert`] — e.g. virtual-hosting multiple
/// certificates behind one listener, keyed by the client's SNI hostname.
///
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn server_config_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// Convenience: an existing resolver → shared acceptor.
pub fn acceptor_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn: &[&[u8]],
) -> SharedTlsAcceptor {
    acceptor(server_config_with_resolver(resolver, alpn))
}

/// Build a [`ServerConfig`] that dispatches on SNI hostname to one of
/// several `(hostname, cert_path, key_path)` PEM triples. A client that
/// sends no SNI, or a hostname with no matching entry, fails the handshake
/// (rustls's default behavior for [`ResolvesServerCertUsingSni`]) — include
/// an entry for every hostname you intend to serve.
///
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn server_config_with_sni_certs(
    certs: &[(&str, &Path, &Path)],
    alpn: &[&[u8]],
) -> io::Result<Arc<ServerConfig>> {
    let builder = ServerConfig::builder().with_no_client_auth();
    let provider = Arc::clone(builder.crypto_provider());
    let mut resolver = ResolvesServerCertUsingSni::new();
    for (name, cert_path, key_path) in certs {
        let chain = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        let certified = CertifiedKey::from_der(chain, key, &provider)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        resolver
            .add(name, certified)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let mut config = builder.with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Convenience: SNI PEM triples → shared acceptor.
pub fn acceptor_with_sni_certs(
    certs: &[(&str, &Path, &Path)],
    alpn: &[&[u8]],
) -> io::Result<SharedTlsAcceptor> {
    Ok(acceptor(server_config_with_sni_certs(certs, alpn)?))
}

/// Build a [`ServerConfig`] that requires or optionally accepts a client
/// certificate for mutual TLS, verified against `client_roots`.
///
/// When `required` is `false`, clients that present no certificate are
/// still accepted (opportunistic mTLS) — check
/// [`SecurityInfo::peer_certificate_fingerprint`] to see whether one was
/// actually presented on a given connection.
///
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn server_config_with_client_auth(
    cert_path: &Path,
    key_path: &Path,
    client_roots_path: &Path,
    required: bool,
    alpn: &[&[u8]],
) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(client_roots_path)? {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if !required {
        verifier_builder = verifier_builder.allow_unauthenticated();
    }
    let verifier = verifier_builder
        .build()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Convenience: PEM paths → shared acceptor requiring/accepting client certs.
pub fn acceptor_with_client_auth(
    cert_path: &Path,
    key_path: &Path,
    client_roots_path: &Path,
    required: bool,
    alpn: &[&[u8]],
) -> io::Result<SharedTlsAcceptor> {
    Ok(acceptor(server_config_with_client_auth(
        cert_path,
        key_path,
        client_roots_path,
        required,
        alpn,
    )?))
}

/// Build a [`ClientConfig`] that trusts the given PEM CA / leaf cert file.
///
/// `alpn` entries are protocol names such as `b"http/1.1"`.
pub fn client_config_from_pem(ca_path: &Path, alpn: &[&[u8]]) -> io::Result<Arc<ClientConfig>> {
    let certs = load_certs(ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Build a [`SharedTlsConnector`] from an existing [`ClientConfig`].
pub fn connector(config: Arc<ClientConfig>) -> SharedTlsConnector {
    Arc::new(RustlsConnector { config })
}

/// Convenience: PEM trust roots → shared connector.
pub fn connector_from_pem(ca_path: &Path, alpn: &[&[u8]]) -> io::Result<SharedTlsConnector> {
    Ok(connector(client_config_from_pem(ca_path, alpn)?))
}

/// Build a [`ClientConfig`] that trusts `ca_path` and presents a client
/// identity certificate for mutual TLS.
///
/// `alpn` entries are protocol names such as `b"http/1.1"`.
pub fn client_config_with_identity(
    ca_path: &Path,
    identity_cert_path: &Path,
    identity_key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<Arc<ClientConfig>> {
    let ca_certs = load_certs(ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in ca_certs {
        roots
            .add(cert)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    }
    let identity_certs = load_certs(identity_cert_path)?;
    let identity_key = load_private_key(identity_key_path)?;
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(identity_certs, identity_key)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Convenience: CA + identity PEM paths → shared connector presenting a
/// client certificate.
pub fn connector_with_identity(
    ca_path: &Path,
    identity_cert_path: &Path,
    identity_key_path: &Path,
    alpn: &[&[u8]],
) -> io::Result<SharedTlsConnector> {
    Ok(connector(client_config_with_identity(
        ca_path,
        identity_cert_path,
        identity_key_path,
        alpn,
    )?))
}

/// Dangerous: trust a specific leaf certificate (self-signed smoke tests).
pub fn connector_for_certified_pem(
    leaf_pem: &Path,
    alpn: &[&[u8]],
) -> io::Result<SharedTlsConnector> {
    connector_from_pem(leaf_pem, alpn)
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

struct RustlsAcceptor {
    config: Arc<ServerConfig>,
}

impl TlsAcceptor for RustlsAcceptor {
    fn accept(&self) -> Box<dyn TlsSession> {
        let conn = ServerConnection::new(Arc::clone(&self.config))
            .expect("ServerConnection::new with valid ServerConfig");
        Box::new(RustlsServerSession {
            conn,
            was_handshaking: true,
        })
    }
}

struct RustlsServerSession {
    conn: ServerConnection,
    was_handshaking: bool,
}

impl TlsSession for RustlsServerSession {
    fn read_tls(&mut self, input: &mut &[u8]) -> io::Result<usize> {
        match self.conn.read_tls(input) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn process_new_packets(&mut self) -> io::Result<TlsProgress> {
        self.conn
            .process_new_packets()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let handshaking = self.conn.is_handshaking();
        let just = self.was_handshaking && !handshaking;
        self.was_handshaking = handshaking;
        Ok(TlsProgress {
            handshake_just_completed: just,
        })
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        let mut reader = self.conn.reader();
        match reader.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        let mut writer = self.conn.writer();
        writer.write(buf)
    }

    fn write_tls(&mut self, output: &mut Vec<u8>) -> io::Result<usize> {
        match self.conn.write_tls(output) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn security_info(&self) -> SecurityInfo {
        let alpn = self
            .conn
            .alpn_protocol()
            .filter(|p| !p.is_empty())
            .map(|p| p.to_vec());
        let protocol = self.conn.protocol_version().map(|v| format!("{v:?}"));
        let cipher_suite = self
            .conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()));
        let sni = self.conn.server_name().map(|s| s.to_string());
        let peer_certificate_fingerprint = self
            .conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|leaf| sha256_hex(leaf));
        SecurityInfo::secure(alpn, protocol, cipher_suite)
            .with_sni(sni)
            .with_peer_certificate_fingerprint(peer_certificate_fingerprint)
    }

    fn send_close_notify(&mut self) {
        self.conn.send_close_notify();
    }
}

/// Lowercase hex SHA-256 digest of `der`, used as the SASL EXTERNAL
/// `cert_key` for a peer's client certificate.
fn sha256_hex(der: &CertificateDer<'_>) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

struct RustlsConnector {
    config: Arc<ClientConfig>,
}

impl TlsConnector for RustlsConnector {
    fn connect(&self, server_name: &str) -> io::Result<Box<dyn TlsSession>> {
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let conn = ClientConnection::new(Arc::clone(&self.config), name)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        Ok(Box::new(RustlsClientSession {
            conn,
            was_handshaking: true,
        }))
    }
}

struct RustlsClientSession {
    conn: ClientConnection,
    was_handshaking: bool,
}

impl TlsSession for RustlsClientSession {
    fn read_tls(&mut self, input: &mut &[u8]) -> io::Result<usize> {
        match self.conn.read_tls(input) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn process_new_packets(&mut self) -> io::Result<TlsProgress> {
        self.conn
            .process_new_packets()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let handshaking = self.conn.is_handshaking();
        let just = self.was_handshaking && !handshaking;
        self.was_handshaking = handshaking;
        Ok(TlsProgress {
            handshake_just_completed: just,
        })
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        let mut reader = self.conn.reader();
        match reader.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::io::Write;
        let mut writer = self.conn.writer();
        writer.write(buf)
    }

    fn write_tls(&mut self, output: &mut Vec<u8>) -> io::Result<usize> {
        match self.conn.write_tls(output) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }

    fn wants_write(&self) -> bool {
        self.conn.wants_write()
    }

    fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    fn security_info(&self) -> SecurityInfo {
        let alpn = self
            .conn
            .alpn_protocol()
            .filter(|p| !p.is_empty())
            .map(|p| p.to_vec());
        let protocol = self.conn.protocol_version().map(|v| format!("{v:?}"));
        let cipher_suite = self
            .conn
            .negotiated_cipher_suite()
            .map(|cs| format!("{:?}", cs.suite()));
        SecurityInfo::secure(alpn, protocol, cipher_suite)
    }

    fn send_close_notify(&mut self) {
        self.conn.send_close_notify();
    }
}

#[cfg(test)]
mod unit {
    use super::*;
    use rcgen::generate_simple_self_signed;

    fn write_temp_pem() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "hopf-tls-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path)
    }

    #[test]
    fn server_config_from_pem_sets_alpn() {
        let (cert_path, key_path) = write_temp_pem();
        let cfg = server_config_from_pem(&cert_path, &key_path, &[b"h2", b"http/1.1"]).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn client_config_from_pem_sets_alpn() {
        let (cert_path, _) = write_temp_pem();
        let cfg = client_config_from_pem(&cert_path, &[b"http/1.1"]).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn acceptor_and_connector_from_pem() {
        let (cert_path, key_path) = write_temp_pem();
        let _ = acceptor_from_pem(&cert_path, &key_path, &[b"h2"]).unwrap();
        let _ = connector_from_pem(&cert_path, &[b"h2"]).unwrap();
    }
}

#[cfg(all(test, feature = "integration"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
    use hopf_core::{
        Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig,
    };

    fn write_temp_pem() -> (std::path::PathBuf, std::path::PathBuf, CertifiedKey) {
        let dir = std::env::temp_dir().join(format!(
            "hopf-tls-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path, cert)
    }

    struct TlsEcho {
        alpn_seen: Arc<Mutex<Option<Vec<u8>>>>,
        ready: Arc<Mutex<bool>>,
    }

    impl ProtocolHandler for TlsEcho {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
            // Defer traffic until security_established (Gumdrop HTTP/SMTPS pattern).
        }

        fn security_established(
            &mut self,
            _endpoint: &mut dyn Endpoint,
            info: &SecurityInfo,
        ) {
            *self.alpn_seen.lock().unwrap() = info.alpn().map(|a| a.to_vec());
            *self.ready.lock().unwrap() = true;
        }

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            if !*self.ready.lock().unwrap() {
                return;
            }
            endpoint.send(data);
            *data = &[];
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    fn rustls_client(cert: &CertifiedKey, alpn: &[&[u8]]) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        cfg
    }

    #[test]
    fn tls_echo_exposes_alpn() {
        let (cert_path, key_path, certified) = write_temp_pem();
        let acceptor =
            acceptor_from_pem(&cert_path, &key_path, &[b"h2", b"http/1.1"]).unwrap();

        let alpn_seen = Arc::new(Mutex::new(None));
        let ready = Arc::new(Mutex::new(false));
        let alpn_f = Arc::clone(&alpn_seen);
        let ready_f = Arc::clone(&ready);

        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(TlsEcho {
                        alpn_seen: Arc::clone(&alpn_f),
                        ready: Arc::clone(&ready_f),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let client_cfg = Arc::new(rustls_client(&certified, &[b"h2", b"http/1.1"]));
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(client_cfg, server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);

        tls.write_all(b"hello-tls").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-tls");

        for _ in 0..50 {
            if alpn_seen.lock().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let alpn = alpn_seen.lock().unwrap().clone().expect("ALPN set");
        assert_eq!(alpn, b"h2");

        rt.shutdown();
    }

    struct StartTlsProbe {
        upgraded: Arc<Mutex<bool>>,
    }

    impl ProtocolHandler for StartTlsProbe {
        fn connected(&mut self, endpoint: &mut dyn Endpoint) {
            endpoint.send(b"PLAIN\n");
        }

        fn security_established(
            &mut self,
            endpoint: &mut dyn Endpoint,
            _info: &SecurityInfo,
        ) {
            *self.upgraded.lock().unwrap() = true;
            endpoint.send(b"SECURE\n");
        }

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                let line = &data[..=pos];
                if line.starts_with(b"STARTTLS") {
                    *data = &data[pos + 1..];
                    endpoint.start_tls().expect("start_tls");
                    return;
                }
            }
            *data = &[];
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    #[test]
    fn start_tls_upgrades_connection() {
        let (cert_path, key_path, certified) = write_temp_pem();
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();
        let upgraded = Arc::new(Mutex::new(false));
        let upgraded_f = Arc::clone(&upgraded);

        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(StartTlsProbe {
                        upgraded: Arc::clone(&upgraded_f),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_starttls_acceptor(acceptor),
            )
            .unwrap();

        let mut sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();

        let mut buf = [0u8; 64];
        let n = sock.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"PLAIN\n");

        sock.write_all(b"STARTTLS\n").unwrap();

        let client_cfg = Arc::new(rustls_client(&certified, &[]));
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(client_cfg, server_name).unwrap();
        let mut tls = StreamOwned::new(conn, sock);

        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"SECURE\n");
        assert!(*upgraded.lock().unwrap());

        rt.shutdown();
    }

    fn write_temp_pem_named(label: &str, hostname: &str) -> (std::path::PathBuf, std::path::PathBuf, CertifiedKey) {
        let dir = std::env::temp_dir().join(format!(
            "hopf-tls-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = generate_simple_self_signed(vec![hostname.to_string()]).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path, cert)
    }

    /// Collects every [`SecurityInfo`] seen, in handshake-completion order.
    /// hopf-core only delivers plaintext to `receive()` after
    /// `security_established` has already fired for that handshake, so
    /// there's no need to gate echoing on a "ready" flag.
    struct SecurityCollector {
        infos: Arc<Mutex<Vec<SecurityInfo>>>,
    }

    impl ProtocolHandler for SecurityCollector {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn security_established(&mut self, _endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
            self.infos.lock().unwrap().push(info.clone());
        }

        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            endpoint.send(data);
            *data = &[];
        }

        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    fn echo_roundtrip(tls: &mut StreamOwned<ClientConnection, StdTcpStream>, msg: &[u8]) {
        tls.write_all(msg).unwrap();
        tls.flush().unwrap();
        let mut buf = vec![0u8; msg.len()];
        tls.read_exact(&mut buf).unwrap();
        assert_eq!(buf, msg);
    }

    fn wait_for(infos: &Arc<Mutex<Vec<SecurityInfo>>>, count: usize) {
        for _ in 0..50 {
            if infos.lock().unwrap().len() >= count {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {count} security_established call(s)");
    }

    #[test]
    fn sni_resolver_dispatches_cert_by_hostname() {
        let (alpha_cert, alpha_key, alpha_certified) = write_temp_pem_named("alpha", "alpha.test");
        let (beta_cert, beta_key, beta_certified) = write_temp_pem_named("beta", "beta.test");
        let acceptor = acceptor_with_sni_certs(
            &[
                ("alpha.test", &alpha_cert, &alpha_key),
                ("beta.test", &beta_cert, &beta_key),
            ],
            &[],
        )
        .unwrap();

        let infos = Arc::new(Mutex::new(Vec::new()));
        let infos_f = Arc::clone(&infos);
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(SecurityCollector {
                        infos: Arc::clone(&infos_f),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        // A client that trusts only alpha's cert, requesting SNI "alpha.test",
        // must get alpha's cert back — and the server must observe that SNI.
        {
            let mut roots = RootCertStore::empty();
            roots.add(alpha_certified.cert.der().clone()).unwrap();
            let cfg = Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            let server_name = rustls::pki_types::ServerName::try_from("alpha.test").unwrap();
            let conn = ClientConnection::new(cfg, server_name).unwrap();
            let sock = StdTcpStream::connect(addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tls = StreamOwned::new(conn, sock);
            echo_roundtrip(&mut tls, b"alpha");
        }
        wait_for(&infos, 1);
        assert_eq!(infos.lock().unwrap()[0].sni(), Some("alpha.test"));

        // Same for beta — different hostname, different cert, different SNI.
        {
            let mut roots = RootCertStore::empty();
            roots.add(beta_certified.cert.der().clone()).unwrap();
            let cfg = Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            let server_name = rustls::pki_types::ServerName::try_from("beta.test").unwrap();
            let conn = ClientConnection::new(cfg, server_name).unwrap();
            let sock = StdTcpStream::connect(addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tls = StreamOwned::new(conn, sock);
            echo_roundtrip(&mut tls, b"beta");
        }
        wait_for(&infos, 2);
        assert_eq!(infos.lock().unwrap()[1].sni(), Some("beta.test"));

        // A client trusting only alpha's cert but requesting "beta.test" must
        // fail — proof the resolver actually dispatches per hostname rather
        // than always serving the same certificate.
        {
            let mut roots = RootCertStore::empty();
            roots.add(alpha_certified.cert.der().clone()).unwrap();
            let cfg = Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            let server_name = rustls::pki_types::ServerName::try_from("beta.test").unwrap();
            let conn = ClientConnection::new(cfg, server_name).unwrap();
            let sock = StdTcpStream::connect(addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tls = StreamOwned::new(conn, sock);
            let result = tls
                .write_all(b"x")
                .and_then(|_| tls.flush())
                .and_then(|_| tls.read(&mut [0u8; 8]));
            assert!(result.is_err(), "expected cert/hostname mismatch to fail");
        }
        assert_eq!(infos.lock().unwrap().len(), 2, "mismatched handshake must not complete");

        rt.shutdown();
    }

    #[test]
    fn required_client_auth_rejects_client_without_cert() {
        let (server_cert, server_key, server_certified) = write_temp_pem_named("mtls-req-srv", "localhost");
        let (client_cert, _client_key, _client_certified) =
            write_temp_pem_named("mtls-req-cli", "client1");
        let acceptor =
            acceptor_with_client_auth(&server_cert, &server_key, &client_cert, true, &[]).unwrap();

        let infos: Arc<Mutex<Vec<SecurityInfo>>> = Arc::new(Mutex::new(Vec::new()));
        let infos_f = Arc::clone(&infos);
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(SecurityCollector {
                        infos: Arc::clone(&infos_f),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(server_certified.cert.der().clone()).unwrap();
        let cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(cfg, server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        let result = tls
            .write_all(b"probe")
            .and_then(|_| tls.flush())
            .and_then(|_| tls.read(&mut [0u8; 8]));
        assert!(result.is_err(), "server must reject a client with no certificate");
        assert!(infos.lock().unwrap().is_empty(), "handshake must not have completed");

        rt.shutdown();
    }

    #[test]
    fn required_client_auth_accepts_valid_cert_and_reports_fingerprint() {
        let (server_cert, server_key, server_certified) = write_temp_pem_named("mtls-ok-srv", "localhost");
        let (client_cert, client_key, client_certified) =
            write_temp_pem_named("mtls-ok-cli", "client1");
        let acceptor =
            acceptor_with_client_auth(&server_cert, &server_key, &client_cert, true, &[]).unwrap();

        let infos = Arc::new(Mutex::new(Vec::new()));
        let infos_f = Arc::clone(&infos);
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(SecurityCollector {
                        infos: Arc::clone(&infos_f),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(server_certified.cert.der().clone()).unwrap();
        let identity_certs = load_certs(&client_cert).unwrap();
        let identity_key = load_private_key(&client_key).unwrap();
        let cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(identity_certs, identity_key)
                .unwrap(),
        );
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(cfg, server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        echo_roundtrip(&mut tls, b"hi");

        wait_for(&infos, 1);
        let fingerprint = infos.lock().unwrap()[0]
            .peer_certificate_fingerprint()
            .expect("fingerprint set")
            .to_string();
        let expected = sha256_hex(&client_certified.cert.der().clone());
        assert_eq!(fingerprint, expected);

        rt.shutdown();
    }

    #[test]
    fn optional_client_auth_accepts_client_without_cert() {
        let (server_cert, server_key, server_certified) = write_temp_pem_named("mtls-opt-srv", "localhost");
        let (client_cert, _client_key, _client_certified) =
            write_temp_pem_named("mtls-opt-cli", "client1");
        let acceptor =
            acceptor_with_client_auth(&server_cert, &server_key, &client_cert, false, &[]).unwrap();

        let infos = Arc::new(Mutex::new(Vec::new()));
        let infos_f = Arc::clone(&infos);
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(SecurityCollector {
                        infos: Arc::clone(&infos_f),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(server_certified.cert.der().clone()).unwrap();
        let cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(cfg, server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        echo_roundtrip(&mut tls, b"hi");

        wait_for(&infos, 1);
        assert_eq!(infos.lock().unwrap()[0].peer_certificate_fingerprint(), None);

        rt.shutdown();
    }
}
