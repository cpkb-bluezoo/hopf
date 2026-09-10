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
//! The two things the old `rustls`-backed API supported that this crate's
//! own re-exports once lacked — SNI-dispatched multi-certificate acceptors
//! and mutual-TLS client certificates — both now have equivalents in
//! `hopf-core::tls`: [`hopf_core::acceptor_from_pem_with_sni`] and
//! [`hopf_core::acceptor_from_pem_with_client_auth`]/
//! [`hopf_core::ClientAuthPolicy`], respectively (this shim doesn't
//! re-export the SNI one under an old name since the pre-migration API
//! never had one to match).

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

    /// Real interop proof for session resumption (crypto-migration-plan.md
    /// Phase 5's ticket work): a `rustls` client reusing the same
    /// `ClientConfig` (and thus its own in-memory ticket cache) across two
    /// TLS-1.2-only connections to a Hopf server configured with an RFC 5077
    /// ticket key. The engine-level tests already prove the abbreviated
    /// flight is well-formed against itself; this proves an independent
    /// implementation actually recognizes and accepts it as a resumption —
    /// `rustls` reports this directly via `handshake_kind()`.
    ///
    /// `acceptor_from_pem_tls12` doesn't take a ticket key (it deliberately
    /// mirrors the TLS 1.3 `base_config` helper, which also leaves
    /// resumption disabled — see crypto-migration-plan.md), so this builds
    /// the acceptor directly from `hopf_core::Tls12Config` instead.
    #[test]
    fn rustls_tls12_client_resumes_second_connection_against_hopf_tls12_ticket_server() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("tls12-resume");
        let creds = hopf_core::server_credentials_from_pem(&cert_path, &key_path).unwrap();
        let ticket_key = [0x42u8; 32];

        struct Tls12TicketAcceptor {
            config: hopf_core::Tls12Config,
        }
        impl hopf_core::TlsAcceptor for Tls12TicketAcceptor {
            fn accept(&self) -> hopf_core::TlsVariant {
                hopf_core::TlsVariant::V12(hopf_core::tls::Tls12RecordEngine::new(self.config.clone()))
            }
        }
        let acceptor: hopf_core::SharedTlsAcceptor = Arc::new(Tls12TicketAcceptor {
            config: hopf_core::Tls12Config {
                role: hopf_core::Tls12Role::Server,
                server_name: None,
                server: Some(creds),
                trust_store: None,
                ticket_key: Some(hopf_core::TicketKeys::single(ticket_key)),
                client_ticket_store: None,
                ..Default::default()
            },
        });

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
        let client_cfg = Arc::new(
            ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
                .with_protocol_versions(&[&rustls::version::TLS12])
                .expect("TLS 1.2 is a valid restricted version list")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let round_trip = |payload: &[u8]| -> rustls::HandshakeKind {
            let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let conn = ClientConnection::new(Arc::clone(&client_cfg), server_name).unwrap();
            let sock = StdTcpStream::connect(addr).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut tls = StreamOwned::new(conn, sock);
            tls.write_all(payload).unwrap();
            tls.flush().unwrap();
            let mut buf = [0u8; 32];
            let n = tls.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], payload);
            tls.conn.handshake_kind().expect("handshake completed")
        };

        assert_eq!(round_trip(b"first"), rustls::HandshakeKind::Full, "first connection has no ticket to offer yet");
        assert_eq!(
            round_trip(b"second"),
            rustls::HandshakeKind::Resumed,
            "second connection should resume via the ticket issued on the first"
        );

        rt.shutdown();
    }

    // -------------------------------------------------------------------
    // mTLS (client certificate authentication) — real interop, both TLS
    // versions and both directions, matching the rigor of the server-cert
    // interop tests above: proves `CertificateRequest`/`Certificate`/
    // `CertificateVerify` actually round-trip against an independent
    // implementation, not just between two instances of this crate's own
    // (identically-coded) engine.
    // -------------------------------------------------------------------

    /// TLS 1.3: a `rustls` client presents its own certificate to a Hopf
    /// server configured with [`hopf_core::ClientAuthPolicy::Require`].
    #[test]
    fn rustls_client_presents_certificate_to_hopf_tls13_server_requiring_one() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("mtls13-server");
        let (_client_dir, client_cert_path, _client_key_path, client_certified) =
            write_temp_pem("mtls13-client");

        let acceptor = hopf_core::acceptor_from_pem_with_client_auth(
            &cert_path,
            &key_path,
            &[],
            hopf_core::ClientAuthPolicy::Require,
            &client_cert_path,
        )
        .unwrap();

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
        let client_key = rustls::pki_types::PrivateKeyDer::Pkcs8(client_certified.key_pair.serialize_der().into());
        let client_cfg = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_certified.cert.der().clone()], client_key)
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);

        tls.write_all(b"hello-mtls13").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-mtls13");

        rt.shutdown();
    }

    /// TLS 1.3: a Hopf server configured with
    /// [`hopf_core::ClientAuthPolicy::Require`] must refuse to complete when
    /// a `rustls` client offers no certificate at all — proving the policy
    /// is actually enforced against a real peer's (spec-compliant) empty
    /// `Certificate` response, not just accepted permissively.
    #[test]
    fn hopf_tls13_server_rejects_rustls_client_presenting_no_certificate_when_required() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("mtls13-reject-server");
        let (_client_ca_dir, client_ca_cert_path, _client_ca_key_path, _client_ca) =
            write_temp_pem("mtls13-reject-clientca");

        let acceptor = hopf_core::acceptor_from_pem_with_client_auth(
            &cert_path,
            &key_path,
            &[],
            hopf_core::ClientAuthPolicy::Require,
            &client_ca_cert_path,
        )
        .unwrap();

        let ready = Arc::new(Mutex::new(false));
        let ready_f = Arc::clone(&ready);
        let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(TlsEcho { alpn_seen: Arc::new(Mutex::new(None)), ready: Arc::clone(&ready_f) })
                        as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();

        let mut roots = RootCertStore::empty();
        roots.add(certified.cert.der().clone()).unwrap();
        let client_cfg = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);
        // rustls with no client cert configured sends a spec-compliant empty
        // Certificate in response to CertificateRequest — this may or may
        // not itself error; what matters is the server never establishes.
        let _ = tls.write_all(b"probe").and_then(|_| tls.flush());
        let mut buf = [0u8; 32];
        let _ = tls.read(&mut buf);

        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !*ready.lock().unwrap(),
            "server must not reach security_established when it required a client cert and got none"
        );

        rt.shutdown();
    }

    /// TLS 1.3, reversed: a Hopf client (`connector_from_pem_with_client_cert`)
    /// presents its own certificate to a real `rustls` server that requires
    /// one (`WebPkiClientVerifier`). Uses a raw-socket `rustls` server, same
    /// pattern as [`hopf_tls12_client_completes_handshake_against_rustls_tls12_server`].
    #[test]
    fn hopf_tls13_client_presents_certificate_to_rustls_server_requiring_one() {
        let (_dir, cert_path, _key_path, certified) = write_temp_pem("mtls13-rev-server");
        let (_client_dir, client_cert_path, client_key_path, client_certified) =
            write_temp_pem("mtls13-rev-client");

        let server_certs = vec![certified.cert.der().clone()];
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_certified.cert.der().clone()).unwrap();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let server_cfg = rustls::ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
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

        let connector = hopf_core::connector_from_pem_with_client_cert(
            &cert_path,
            &client_cert_path,
            &client_key_path,
            &[],
        )
        .unwrap();

        let echoed = Arc::new(Mutex::new(Vec::new()));
        let echoed2 = Arc::clone(&echoed);
        struct EchoProbe {
            echoed: Arc<Mutex<Vec<u8>>>,
        }
        impl ProtocolHandler for EchoProbe {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
                endpoint.send(b"hopf-tls13-mtls-client");
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
            if echoed.lock().unwrap().as_slice() == b"hopf-tls13-mtls-client" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(echoed.lock().unwrap().as_slice(), b"hopf-tls13-mtls-client");

        rt.shutdown();
        server_thread.join().unwrap();
    }

    /// TLS 1.2: a `rustls` client (forced to TLS 1.2) presents its own
    /// certificate to a Hopf TLS 1.2 server configured with
    /// [`hopf_core::ClientAuthPolicy::Require`].
    #[test]
    fn rustls_tls12_client_presents_certificate_to_hopf_tls12_server_requiring_one() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("mtls12-server");
        let (_client_dir, client_cert_path, _client_key_path, client_certified) =
            write_temp_pem("mtls12-client");

        let acceptor = hopf_core::acceptor_from_pem_tls12_with_client_auth(
            &cert_path,
            &key_path,
            hopf_core::ClientAuthPolicy::Require,
            &client_cert_path,
        )
        .unwrap();

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
        let client_key = rustls::pki_types::PrivateKeyDer::Pkcs8(client_certified.key_pair.serialize_der().into());
        let client_cfg = ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 is a valid restricted version list")
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_certified.cert.der().clone()], client_key)
            .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);

        tls.write_all(b"hello-mtls12").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-mtls12");
        assert_eq!(tls.conn.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_2));

        rt.shutdown();
    }

    /// TLS 1.2, reversed: a Hopf client
    /// (`connector_from_pem_tls12_with_client_cert`) presents its own
    /// certificate to a real `rustls` server (forced to TLS 1.2) that
    /// requires one.
    #[test]
    fn hopf_tls12_client_presents_certificate_to_rustls_tls12_server_requiring_one() {
        let (_dir, cert_path, _key_path, certified) = write_temp_pem("mtls12-rev-server");
        let (_client_dir, client_cert_path, client_key_path, client_certified) =
            write_temp_pem("mtls12-rev-client");

        let server_certs = vec![certified.cert.der().clone()];
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_certified.cert.der().clone()).unwrap();
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();
        let server_cfg = rustls::ServerConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 is a valid restricted version list")
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_certs, server_key)
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

        let connector = hopf_core::connector_from_pem_tls12_with_client_cert(
            &cert_path,
            &client_cert_path,
            &client_key_path,
        )
        .unwrap();

        let echoed = Arc::new(Mutex::new(Vec::new()));
        let echoed2 = Arc::clone(&echoed);
        struct EchoProbe {
            echoed: Arc<Mutex<Vec<u8>>>,
        }
        impl ProtocolHandler for EchoProbe {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
                endpoint.send(b"hopf-tls12-mtls-client");
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
            if echoed.lock().unwrap().as_slice() == b"hopf-tls12-mtls-client" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(echoed.lock().unwrap().as_slice(), b"hopf-tls12-mtls-client");

        rt.shutdown();
        server_thread.join().unwrap();
    }

    // -------------------------------------------------------------------
    // ChaCha20-Poly1305 cipher suite — real interop, both TLS versions,
    // both directions. A `rustls` `CryptoProvider` restricted to *only* the
    // ChaCha suite forces genuine negotiation (a normal Hopf peer always
    // offers/prefers AES-128-GCM first, so a Hopf-vs-Hopf loopback can't
    // reach this deterministically — see the engine-level
    // `server_selects_chacha20_poly1305_when_its_the_only_offered_suite`
    // test in `hopf-core` for that half of the proof).
    // -------------------------------------------------------------------

    fn chacha_only_tls13_provider() -> rustls::crypto::CryptoProvider {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
            .iter()
            .filter(|cs| cs.suite() == rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            .copied()
            .collect();
        provider
    }

    fn chacha_only_tls12_provider() -> rustls::crypto::CryptoProvider {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.cipher_suites = rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES
            .iter()
            .filter(|cs| {
                matches!(
                    cs.suite(),
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                        | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                )
            })
            .copied()
            .collect();
        provider
    }

    /// TLS 1.3: a `rustls` client restricted to `TLS_CHACHA20_POLY1305_SHA256`
    /// completes a handshake against an unrestricted Hopf server — the
    /// server's own suite selection must pick ChaCha since it's the only
    /// suite the client offers.
    #[test]
    fn rustls_client_negotiates_chacha20_poly1305_against_hopf_tls13_server() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("chacha13-server");
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

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
        let client_cfg = ClientConfig::builder_with_provider(chacha_only_tls13_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let conn = ClientConnection::new(Arc::new(client_cfg), server_name).unwrap();
        let sock = StdTcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        sock.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut tls = StreamOwned::new(conn, sock);

        tls.write_all(b"hello-chacha13").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-chacha13");
        assert_eq!(
            tls.conn.negotiated_cipher_suite().map(|cs| cs.suite()),
            Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        );

        rt.shutdown();
    }

    /// TLS 1.3, reversed: a Hopf client completes a handshake against a real
    /// `rustls` server restricted to `TLS_CHACHA20_POLY1305_SHA256` — proving
    /// the client accepts and correctly installs keys for a server-selected
    /// ChaCha suite, not just that the server-side selection logic works.
    #[test]
    fn hopf_tls13_client_negotiates_chacha20_poly1305_against_rustls_server() {
        let (_dir, cert_path, _key_path, certified) = write_temp_pem("chacha13-rev-server");

        let server_certs = vec![certified.cert.der().clone()];
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder_with_provider(chacha_only_tls13_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)
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
            assert_eq!(
                tls.conn.negotiated_cipher_suite().map(|cs| cs.suite()),
                Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            );
        });

        let connector = connector_from_pem(&cert_path, &[]).unwrap();

        let echoed = Arc::new(Mutex::new(Vec::new()));
        let echoed2 = Arc::clone(&echoed);
        struct EchoProbe {
            echoed: Arc<Mutex<Vec<u8>>>,
        }
        impl ProtocolHandler for EchoProbe {
            fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
            fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
                endpoint.send(b"hopf-tls13-chacha-client");
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
            if echoed.lock().unwrap().as_slice() == b"hopf-tls13-chacha-client" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(echoed.lock().unwrap().as_slice(), b"hopf-tls13-chacha-client");

        rt.shutdown();
        server_thread.join().unwrap();
    }

    /// TLS 1.2: a `rustls` client (forced to TLS 1.2) restricted to the
    /// ChaCha suites completes a handshake against an unrestricted Hopf
    /// TLS 1.2 server.
    #[test]
    fn rustls_tls12_client_negotiates_chacha20_poly1305_against_hopf_tls12_server() {
        let (_dir, cert_path, key_path, certified) = write_temp_pem("chacha12-server");
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
        let client_cfg = ClientConfig::builder_with_provider(chacha_only_tls12_provider().into())
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

        tls.write_all(b"hello-chacha12").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-chacha12");
        assert_eq!(
            tls.conn.negotiated_cipher_suite().map(|cs| cs.suite()),
            Some(rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
        );

        rt.shutdown();
    }

    /// TLS 1.2, reversed: a Hopf client completes a handshake against a real
    /// `rustls` server (forced to TLS 1.2) restricted to the ChaCha suites.
    #[test]
    fn hopf_tls12_client_negotiates_chacha20_poly1305_against_rustls_server() {
        let (_dir, cert_path, _key_path, certified) = write_temp_pem("chacha12-rev-server");

        let server_certs = vec![certified.cert.der().clone()];
        let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let server_cfg = rustls::ServerConfig::builder_with_provider(chacha_only_tls12_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 is a valid restricted version list")
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)
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
            assert_eq!(
                tls.conn.negotiated_cipher_suite().map(|cs| cs.suite()),
                Some(rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
            );
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
                endpoint.send(b"hopf-tls12-chacha-client");
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
            if echoed.lock().unwrap().as_slice() == b"hopf-tls12-chacha-client" {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(echoed.lock().unwrap().as_slice(), b"hopf-tls12-chacha-client");

        rt.shutdown();
        server_thread.join().unwrap();
    }
}
