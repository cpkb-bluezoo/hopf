// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Thin `hopf-core::tls` re-export shim for TCP TLS / STARTTLS.
//!
//! Through crypto-migration Phase 3b this crate ran TLS itself, on top of
//! `rustls`. Phase 4 moved that job into `hopf-core::tls` (the in-tree
//! `TlsRecordEngine`, RFC 8446 TLS 1.3) — `TcpConnection` no longer knows
//! anything about `rustls`. This crate now just re-exports the
//! `hopf-core::tls` PEM/acceptor/connector helpers under their old names, so
//! existing callers don't need to change, and is kept only for that API
//! compatibility until crypto-migration-plan.md Phase 8 removes it outright
//! (folding the remaining call sites onto `hopf_core::tls::*` directly).
//!
//! Two things the old `rustls`-backed API supported have no equivalent here
//! yet: SNI-dispatched multi-certificate acceptors and mutual-TLS client
//! certificates (`TlsRecordEngine` doesn't request/verify a client cert at
//! all today) — deferred to a later phase, matching the migration plan.

#![warn(missing_docs)]

use std::io;
use std::path::Path;

pub use hopf_core::{SharedTlsAcceptor, SharedTlsConnector};

/// Build a [`SharedTlsAcceptor`] from a PEM cert-chain and PKCS#8 private key.
/// `alpn` entries are protocol names such as `b"h2"` and `b"http/1.1"`.
pub fn acceptor_from_pem(cert_path: &Path, key_path: &Path, alpn: &[&[u8]]) -> io::Result<SharedTlsAcceptor> {
    hopf_core::acceptor_from_pem(cert_path, key_path, alpn)
}

/// Build a [`SharedTlsConnector`] that trusts the given PEM CA / leaf cert file.
/// `alpn` entries are protocol names such as `b"http/1.1"`.
pub fn connector_from_pem(ca_path: &Path, alpn: &[&[u8]]) -> io::Result<SharedTlsConnector> {
    hopf_core::connector_from_pem(ca_path, alpn)
}

/// Accepts any certificate, performing no validation at all — for
/// opportunistic TLS, where the point is encrypting the connection, not
/// authenticating the peer. Opportunistic MTA-to-MTA STARTTLS (RFC
/// 3207/7672) is the motivating case: requiring a valid, trusted
/// certificate would break delivery to most real-world mail servers, whose
/// certificates are routinely self-signed, expired, or issued for the
/// wrong name — none of which should turn off encryption entirely.
///
/// Never use this where the peer's identity actually matters.
/// [`insecure_connector`] is specifically for the "no better option, but
/// encryption is still better than plaintext" case — DANE
/// (`hopf_dns::dane`, via `hopf_core::connector_with_verify_override`) or
/// [`connector_from_pem`] is what authenticates the peer when that's
/// actually possible/required.
pub fn insecure_connector(alpn: &[&[u8]]) -> SharedTlsConnector {
    hopf_core::insecure_connector(alpn)
}

/// Build a [`SharedTlsConnector`] that trusts the public WebPKI (native OS
/// roots, falling back to a vendored copy of Mozilla's CA list). See
/// [`hopf_core::public_trust_connector`].
pub fn public_trust_connector(alpn: &[&[u8]]) -> io::Result<SharedTlsConnector> {
    Ok(hopf_core::public_trust_connector(alpn))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Returns the TempDir guard too — the caller must keep it alive for as
    // long as it uses the paths, since dropping it deletes the directory.
    // A per-call unique directory (rather than a pid/timestamp-derived name)
    // is what actually matters here: parallel test threads each get their
    // own directory, so one test's cert/key pair can never be interleaved
    // with another's.
    fn write_temp_pem(
        key_pair: &rcgen::KeyPair,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::Builder::new().prefix("hopf-tls-unit-").tempdir().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(key_pair).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (dir, cert_path, key_path)
    }

    #[test]
    fn acceptor_and_connector_from_pem() {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let (_dir, cert_path, key_path) = write_temp_pem(&key_pair);
        let _ = acceptor_from_pem(&cert_path, &key_path, &[b"h2"]).unwrap();
        let _ = connector_from_pem(&cert_path, &[b"h2"]).unwrap();
    }

    #[test]
    fn public_trust_connector_builds() {
        public_trust_connector(&[]).unwrap();
    }
}

#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hopf_core::{
        Endpoint, ProtocolHandler, Runtime, RuntimeConfig, SecurityInfo, TcpConnectorConfig,
        TcpListenerConfig,
    };
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    fn write_temp_pem(
        label: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf, CertifiedKey) {
        let dir = tempfile::Builder::new().prefix(&format!("hopf-tls-{label}-")).tempdir().unwrap();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        (dir, cert_path, key_path, cert)
    }

    fn rustls_client(cert: &CertifiedKey, alpn: &[&[u8]]) -> ClientConfig {
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut cfg = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        cfg
    }

    struct TlsEcho {
        alpn_seen: Arc<Mutex<Option<Vec<u8>>>>,
        ready: Arc<Mutex<bool>>,
    }

    impl ProtocolHandler for TlsEcho {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

        fn security_established(&mut self, _endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
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

    /// Interop proof, not just self-consistency: a real independent TLS 1.3
    /// implementation (rustls, as the client) completing a handshake against
    /// `hopf-core::tls::TlsRecordEngine` (as the server, via this crate's
    /// `acceptor_from_pem`) is the thing hopf-tls's own loopback tests
    /// (Hopf talking to Hopf) can't prove — that the wire format this crate
    /// now serves is actually RFC 8446-compliant, not just internally
    /// consistent between two instances of the same new code.
    #[test]
    fn rustls_client_completes_handshake_against_hopf_engine_server() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("interop");
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[b"h2", b"http/1.1"]).unwrap();

        let alpn_seen = Arc::new(Mutex::new(None));
        let ready = Arc::new(Mutex::new(false));
        let alpn_f = Arc::clone(&alpn_seen);
        let ready_f = Arc::clone(&ready);

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(TlsEcho { alpn_seen: Arc::clone(&alpn_f), ready: Arc::clone(&ready_f) })
                        as Box<dyn ProtocolHandler>
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

        fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
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
    fn start_tls_upgrades_connection_against_a_rustls_client() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("starttls");
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();
        let upgraded = Arc::new(Mutex::new(false));
        let upgraded_f = Arc::clone(&upgraded);

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(StartTlsProbe { upgraded: Arc::clone(&upgraded_f) }) as Box<dyn ProtocolHandler>
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

    struct EstablishedProbe {
        established: Arc<Mutex<bool>>,
    }
    impl ProtocolHandler for EstablishedProbe {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
            *self.established.lock().unwrap() = true;
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    struct NoopServer;
    impl ProtocolHandler for NoopServer {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
    }

    /// Regression test for issue #353's opportunistic-TLS foundation:
    /// [`insecure_connector`] must complete a real handshake against a
    /// certificate that matches neither the claimed server name nor any
    /// trusted root — proving it genuinely performs no validation, which is
    /// the whole point of an "encrypt without authenticating" connector.
    #[test]
    fn insecure_connector_completes_handshake_despite_hostname_and_trust_mismatch() {
        let (_dir, cert_path, key_path, _certified) = write_temp_pem("insecure"); // cert is for "localhost"
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                    Box::new(NoopServer) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let established = Arc::new(Mutex::new(false));
        let established2 = Arc::clone(&established);
        let connector = insecure_connector(&[]);
        rt.connect(
            TcpConnectorConfig::new(addr, move || {
                Box::new(EstablishedProbe { established: Arc::clone(&established2) }) as Box<dyn ProtocolHandler>
            })
            .with_tls(connector, "totally-different-name.example"),
        )
        .unwrap();

        for _ in 0..100 {
            if *established.lock().unwrap() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            *established.lock().unwrap(),
            "handshake should succeed despite the hostname/trust mismatch"
        );

        rt.shutdown();
    }

    /// Regression test for issue #375: unlike every other client path in
    /// this crate, which either pins an explicit caller-supplied root or
    /// skips validation outright, `public_trust_connector` must complete a
    /// real handshake against a certificate chaining to an actual public
    /// certificate authority — proving the connector's root store is
    /// genuinely populated (native store, vendored fallback, or both), not
    /// just non-empty in isolation. Talks to a well-known, stable public
    /// HTTPS endpoint; needs real internet access, which is exactly why
    /// this lives behind this module's `integration` feature gate rather
    /// than running in CI.
    #[test]
    fn public_trust_connector_validates_a_real_public_certificate() {
        use std::net::ToSocketAddrs;

        let host = "cloudflare.com";
        let addr = (host, 443)
            .to_socket_addrs()
            .expect("resolve cloudflare.com")
            .next()
            .expect("at least one address for cloudflare.com");

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();

        let established = Arc::new(Mutex::new(false));
        let established2 = Arc::clone(&established);
        let connector = public_trust_connector(&[]).unwrap();
        rt.connect(
            TcpConnectorConfig::new(addr, move || {
                Box::new(EstablishedProbe { established: Arc::clone(&established2) }) as Box<dyn ProtocolHandler>
            })
            .with_tls(connector, host),
        )
        .unwrap();

        for _ in 0..250 {
            if *established.lock().unwrap() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            *established.lock().unwrap(),
            "handshake against a real public certificate should validate and succeed"
        );

        rt.shutdown();
    }

    /// Companion to the real-endpoint test above, runnable with no network
    /// access at all: `public_trust_connector` must reject a self-signed
    /// certificate exactly like any other public-WebPKI client would —
    /// proving the validation is real rather than the positive test above
    /// merely reaching a server that happens to have a certificate for
    /// unrelated reasons.
    #[test]
    fn public_trust_connector_rejects_a_self_signed_server() {
        let (_dir, cert_path, key_path, _certified) = write_temp_pem("public-trust-reject");
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                    Box::new(NoopServer) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let established = Arc::new(Mutex::new(false));
        let established2 = Arc::clone(&established);
        let connector = public_trust_connector(&[]).unwrap();
        rt.connect(
            TcpConnectorConfig::new(addr, move || {
                Box::new(EstablishedProbe { established: Arc::clone(&established2) }) as Box<dyn ProtocolHandler>
            })
            .with_tls(connector, "localhost"),
        )
        .unwrap();

        std::thread::sleep(Duration::from_millis(500));
        assert!(
            !*established.lock().unwrap(),
            "a self-signed certificate must not validate against the public WebPKI trust store"
        );

        rt.shutdown();
    }

    /// Phase 5 (TLS 1.2) real interop — a `rustls` client *forced* to
    /// TLS 1.2 only (`with_protocol_versions(&[&rustls::version::TLS12])`,
    /// not just "supports 1.2 as a fallback") against
    /// `hopf_core::acceptor_from_pem_tls12`. Same rationale as the TLS 1.3
    /// interop tests above: this is the one thing Hopf-to-Hopf loopback
    /// tests structurally cannot prove — that the wire format this engine
    /// speaks is actually RFC 5246/5288-compliant, not just internally
    /// consistent between two instances of the same new code.
    #[test]
    fn rustls_tls12_client_completes_handshake_against_hopf_tls12_server() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("tls12-interop");
        let acceptor = hopf_core::acceptor_from_pem_tls12(&cert_path, &key_path).unwrap();

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                    Box::new(TlsEcho { alpn_seen: Arc::new(Mutex::new(None)), ready: Arc::new(Mutex::new(false)) })
                        as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 is a valid restricted version list")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);

        tls.write_all(b"hello-tls12").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-tls12");
        assert_eq!(tls.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));

        rt.shutdown();
    }

    /// As the test above, with the roles reversed: `hopf_core`'s own TLS 1.2
    /// *client* (`connector_from_pem_tls12`) against a `rustls` server
    /// forced to TLS 1.2 only.
    #[test]
    fn hopf_tls12_client_completes_handshake_against_rustls_tls12_server() {
        let (_dir, cert_path, _key_path, certified) = write_temp_pem("tls12-interop-rev");

        let certs = vec![certified.cert.der().clone()];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            certified.key_pair.serialize_der().into(),
        );
        let server_cfg = rustls::ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 is a valid restricted version list")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(server_cfg)).unwrap();
            let mut tls = StreamOwned::new(conn, sock);
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).unwrap();
            tls.write_all(&buf[..n]).unwrap();
            tls.flush().unwrap();
        });

        let connector = hopf_core::connector_from_pem_tls12(&cert_path).unwrap();
        let echoed = Arc::new(Mutex::new(Vec::new()));
        let echoed2 = Arc::clone(&echoed);

        struct EchoProbe {
            echoed: Arc<Mutex<Vec<u8>>>,
        }
        impl ProtocolHandler for EchoProbe {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
                endpoint.send(b"hopf-tls12-client");
            }
            fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
                self.echoed.lock().unwrap().extend_from_slice(data);
                *data = &[];
            }
            fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
        }

        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        rt.connect(
            TcpConnectorConfig::new(addr, move || {
                Box::new(EchoProbe { echoed: Arc::clone(&echoed2) }) as Box<dyn ProtocolHandler>
            })
            .with_tls(connector, "localhost"),
        )
        .unwrap();

        for _ in 0..150 {
            if echoed.lock().unwrap().as_slice() == b"hopf-tls12-client" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(echoed.lock().unwrap().as_slice(), b"hopf-tls12-client");

        rt.shutdown();
        server_thread.join().unwrap();
    }
}
