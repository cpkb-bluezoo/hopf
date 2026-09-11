// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Real DTLS 1.2 interop against OpenSSL (`openssl s_client`/`s_server
//! -dtls1_2`) — `--features integration`, not run in CI (matches this
//! crate's existing `integration` feature convention). Unlike this
//! workspace's existing `rustls` interop (linked in-process as a Rust
//! dependency, see `hopf-tls`'s `integration_tests`), OpenSSL's DTLS
//! tools are external binaries reachable only over a real socket — no
//! DTLS-1.3-capable peer existed anywhere reachable when Phase 6's DTLS
//! 1.3 milestone shipped (see its own module doc), but DTLS 1.2 doesn't
//! have that problem, so this drives a real subprocess over a real
//! loopback `UdpSocket`. This is test-only plumbing, not the deferred
//! production UDP driver/listener wiring (DoDTLS/CoAPS).
//!
//! The primary proof is simply [`Dtls12RecordEngine::is_complete`] turning
//! true against a genuinely independent peer: that requires real ECDHE key
//! agreement, real certificate-signature verification, and a real Finished
//! MAC check against a transcript OpenSSL computed independently — the
//! same bar every prior phase's `rustls` interop held itself to. An
//! application-data round trip (OpenSSL's side writing to its own stdin)
//! is checked too, best-effort, in the direction that's reliably
//! scriptable against an external process's pipes.

use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::engine::{Dtls12Config, Dtls12RecordEngine};
use crate::dtls::DtlsRecordSink;
use crate::security::SecurityInfo;
use crate::tls::tls12::engine::Role;
use crate::tls::{ServerCredentials, Tls12Config, TlsProtocolError, VerifyRequest};

const OVERALL_DEADLINE: Duration = Duration::from_secs(10);
const RECV_POLL: Duration = Duration::from_millis(100);

struct TestCert {
    cert_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    credentials: ServerCredentials,
    _dir: tempfile::TempDir,
}

fn generate_test_cert() -> TestCert {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    let credentials = ServerCredentials {
        cert_chain: vec![Bytes::copy_from_slice(cert.der())],
        signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
    };
    TestCert { cert_path, key_path, credentials, _dir: dir }
}

#[derive(Default)]
struct DriverSink {
    outbound: Vec<Vec<u8>>,
    complete: bool,
    app_data: Vec<Vec<u8>>,
    errors: Vec<String>,
    armed_at: Option<Instant>,
    info: Option<SecurityInfo>,
}

impl DtlsRecordSink for DriverSink {
    fn datagram_ready(&mut self, data: &[u8]) {
        self.outbound.push(data.to_vec());
    }
    fn application_data(&mut self, plaintext: &[u8]) {
        self.app_data.push(plaintext.to_vec());
    }
    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.complete = true;
        self.info = Some(info);
    }
    fn verification_requested(&mut self, _req: VerifyRequest) {}
    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.errors.push(err.message);
    }
    fn peer_closed(&mut self) {}
    fn arm_retransmit_timer(&mut self, after: Option<Duration>) {
        self.armed_at = after.map(|d| Instant::now() + d);
    }
}

/// Pump `engine` over `socket` — sending queued outbound datagrams to
/// `peer` (learning it from the first inbound datagram when `None`),
/// feeding inbound ones in, and firing the retransmit timer when armed —
/// until `until` returns `true` or `deadline` passes.
fn pump(
    engine: &mut Dtls12RecordEngine,
    socket: &UdpSocket,
    mut peer: Option<SocketAddr>,
    deadline: Instant,
    mut until: impl FnMut(&DriverSink) -> bool,
) -> (DriverSink, SocketAddr) {
    let mut sink = DriverSink::default();
    socket.set_read_timeout(Some(RECV_POLL)).unwrap();

    loop {
        for datagram in std::mem::take(&mut sink.outbound) {
            let target = peer.expect("peer address known before sending");
            socket.send_to(&datagram, target).unwrap();
        }
        assert!(sink.errors.is_empty(), "protocol error: {:?}", sink.errors);
        if until(&sink) {
            return (sink, peer.expect("peer known by the time `until` is satisfied"));
        }
        assert!(Instant::now() < deadline, "deadline exceeded waiting for: errors={:?} app_data={:?}", sink.errors, sink.app_data);

        if let Some(armed) = sink.armed_at {
            if Instant::now() >= armed {
                engine.feed_timer(&mut sink);
                continue;
            }
        }

        let mut buf = [0u8; 4096];
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                peer.get_or_insert(from);
                engine.feed_datagram(&buf[..n], &mut sink);
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => panic!("recv_from failed: {e}"),
        }
    }
}

struct OpensslChild(Child);

impl Drop for OpensslChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn hopf_server_completes_handshake_against_openssl_client() {
    let cert = generate_test_cert();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();

    let mut child = OpensslChild(
        Command::new("openssl")
            .args([
                "s_client",
                "-dtls1_2",
                "-connect",
                &format!("127.0.0.1:{port}"),
                "-CAfile",
                cert.cert_path.to_str().unwrap(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("openssl binary not found on PATH"),
    );

    let server_cfg = Dtls12Config {
        base: Tls12Config {
            role: Role::Server,
            server: Some(cert.credentials.clone()),
            ..Default::default()
        },
        require_cookie: false,
        cookie_secret: [0x11u8; 32],
    };
    let mut engine = Dtls12RecordEngine::new(server_cfg);
    let deadline = Instant::now() + OVERALL_DEADLINE;
    let (sink, peer) = pump(&mut engine, &socket, None, deadline, |s| s.complete);
    assert_eq!(sink.info.as_ref().and_then(|i| i.protocol()), Some("DTLSv1.2"), "{:?}", sink.info);

    // Best-effort: OpenSSL's stdin -> our application_data. Not a hard
    // requirement for interop proof (handshake completion above already
    // is) — external-process pipe timing is inherently less reliable than
    // this crate's own loopback tests.
    if let Some(stdin) = child.0.stdin.as_mut() {
        if stdin.write_all(b"hello from openssl\n").is_ok() {
            let _ = stdin.flush();
            let app_deadline = Instant::now() + Duration::from_secs(3);
            let (sink2, _) = pump(&mut engine, &socket, Some(peer), app_deadline, |s| !s.app_data.is_empty());
            if let Some(got) = sink2.app_data.first() {
                assert_eq!(got, b"hello from openssl\n");
            }
        }
    }
}

#[test]
fn hopf_client_completes_handshake_against_openssl_server() {
    let cert = generate_test_cert();
    let listen_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = listen_socket.local_addr().unwrap().port();
    drop(listen_socket); // free the port for openssl to bind; small TOCTOU race, acceptable for a test

    let mut child = OpensslChild(
        Command::new("openssl")
            .args([
                "s_server",
                "-dtls1_2",
                "-accept",
                &port.to_string(),
                "-cert",
                cert.cert_path.to_str().unwrap(),
                "-key",
                cert.key_path.to_str().unwrap(),
                "-naccept",
                "1",
            ])
            // `openssl s_server` exits almost immediately once its stdin
            // hits EOF, even with no client connected yet (confirmed by
            // direct reproduction) — `Stdio::null()` here made it exit
            // before this test's client had a chance to connect. A piped
            // stdin that's never closed keeps it running for the test's
            // duration instead.
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("openssl binary not found on PATH"),
    );
    std::thread::sleep(Duration::from_millis(300)); // let s_server finish binding
    match child.0.try_wait() {
        Ok(Some(status)) => {
            use std::io::Read;
            let mut stderr = String::new();
            if let Some(mut e) = child.0.stderr.take() {
                let _ = e.read_to_string(&mut stderr);
            }
            panic!("openssl s_server exited early with {status}: {stderr}");
        }
        Ok(None) => {}
        Err(e) => panic!("try_wait failed: {e}"),
    }

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let peer_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut trust = crate::crypto::trust::TrustStore::new();
    trust.add_anchor(cert.credentials.cert_chain[0].clone());
    let client_cfg = Dtls12Config {
        base: Tls12Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            trust_store: Some(trust),
            ..Default::default()
        },
        require_cookie: false,
        cookie_secret: [0u8; 32],
    };
    let mut engine = Dtls12RecordEngine::new(client_cfg);
    let mut start_sink = DriverSink::default();
    engine.start(&mut start_sink);
    for datagram in std::mem::take(&mut start_sink.outbound) {
        socket.send_to(&datagram, peer_addr).unwrap();
    }

    let deadline = Instant::now() + OVERALL_DEADLINE;
    let (sink, _peer) = pump(&mut engine, &socket, Some(peer_addr), deadline, |s| s.complete);
    assert_eq!(sink.info.as_ref().and_then(|i| i.protocol()), Some("DTLSv1.2"), "{:?}", sink.info);
}
