// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The connection context a `DnsQueryHandler` is given (issue #524): the local
//! address the query arrived on and, over DoT and DoQ, the TLS session with the
//! client's certificate chain, which a handler can keep and read again after
//! `handle_query` has returned. Loopback only, no external network.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::Bytes;
use hopf_dns::server::{
    listen_dns_tcp, listen_dns_udp, DnsQueryCallback, DnsQueryHandler, DnsService, DnsServiceHandle,
    DnsTransport, DnsUdpListenConfig, QueryContext,
};
use hopf_dns::wire::{DnsMessage, DnsQuestion, DnsType};

/// What a handler saw of one query's connection.
#[derive(Debug, Clone, PartialEq)]
struct Seen {
    peer: SocketAddr,
    local: Option<SocketAddr>,
    transport: DnsTransport,
    secure: bool,
    sni: Option<String>,
    chain: Option<Vec<Bytes>>,
}

/// Records the context of every query. It keeps a clone of the context and
/// reads it from another thread after `handle_query` has returned, which is
/// how a handler waiting on a store or an upstream uses it.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<Seen>>>);

impl DnsQueryHandler for Recorder {
    fn handle_query(&self, query: &DnsMessage, ctx: &QueryContext, callback: DnsQueryCallback) {
        let (ctx, seen, response) = (ctx.clone(), Arc::clone(&self.0), query.response_template(0));
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            seen.lock().unwrap().push(Seen {
                peer: ctx.peer(),
                local: ctx.local(),
                transport: ctx.transport(),
                secure: ctx.security().is_some(),
                sni: ctx.sni().map(str::to_owned),
                chain: ctx.peer_certificate_chain().map(<[_]>::to_vec),
            });
            callback.respond(response);
        });
    }
}

impl Recorder {
    fn only(&self) -> Seen {
        let seen = self.0.lock().unwrap();
        assert_eq!(seen.len(), 1, "exactly one query was handled: {seen:?}");
        seen[0].clone()
    }
}

fn query_bytes(id: u16) -> Vec<u8> {
    DnsMessage::query(id, DnsQuestion::in_class("ctx.test", DnsType::A), false)
        .serialize()
        .unwrap()
}

#[test]
fn udp_reports_the_bound_address_and_no_security() {
    let recorder = Recorder::default();
    let handle = DnsServiceHandle::new(DnsService::with_handler(recorder.clone()));
    let rt = hopf_core::Runtime::start(Default::default()).unwrap();
    let (local, _) = listen_dns_udp(
        rt.pick_worker(),
        DnsUdpListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            service: handle,
        },
    )
    .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.send_to(&query_bytes(1), local).unwrap();
    let mut buf = [0u8; 512];
    client.recv_from(&mut buf).expect("the late answer still arrives");

    let seen = recorder.only();
    assert_eq!(seen.transport, DnsTransport::Udp);
    assert_eq!(seen.local, Some(local));
    assert_eq!(seen.peer, client.local_addr().unwrap());
    assert!(!seen.secure);
    assert_eq!(seen.sni, None);
    assert_eq!(seen.chain, None);
    rt.shutdown();
}

#[test]
fn cleartext_tcp_reports_the_listener_address_and_no_security() {
    let recorder = Recorder::default();
    let handle = DnsServiceHandle::new(DnsService::with_handler(recorder.clone()));
    let rt = hopf_core::Runtime::start(Default::default()).unwrap();
    let local = listen_dns_tcp(&rt, "127.0.0.1:0".parse().unwrap(), handle).unwrap();

    let mut stream = TcpStream::connect(local).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let q = query_bytes(2);
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    stream.write_all(&framed).unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).expect("the late answer still arrives");

    let seen = recorder.only();
    assert_eq!(seen.transport, DnsTransport::Tcp);
    assert_eq!(seen.local, Some(local));
    assert_eq!(seen.peer, stream.local_addr().unwrap());
    assert!(!seen.secure);
    assert_eq!(seen.chain, None);
    rt.shutdown();
}

/// A self-signed identity: certificate (PEM and DER) and PKCS#8 key (PEM).
#[cfg(any(feature = "dot", feature = "doq"))]
struct Identity {
    cert_pem: String,
    key_pem: String,
    der: Bytes,
}

#[cfg(any(feature = "dot", feature = "doq"))]
fn identity(name: &str) -> Identity {
    let cert = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    Identity {
        cert_pem: cert.cert.pem(),
        key_pem: cert.key_pair.serialize_pem(),
        der: Bytes::copy_from_slice(cert.cert.der()),
    }
}

#[cfg(feature = "dot")]
fn write_pem(label: &str, pem: &str) -> std::path::PathBuf {
    // Tests run in parallel: a process-wide counter, not the clock (which
    // can read the same microsecond twice), keeps their directories apart.
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "hopf-dns-ctx-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{label}.pem"));
    std::fs::write(&path, pem).unwrap();
    path
}

/// Ask `name` of `resolver` and wait for the answer.
#[cfg(any(feature = "dot", feature = "doq"))]
fn ask(resolver: &hopf_dns::DnsResolver, name: &'static str) -> std::io::Result<DnsMessage> {
    let got = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&got);
    resolver.query_a(name, Box::new(move |r| *sink.lock().unwrap() = Some(r)));
    for _ in 0..250 {
        if let Some(result) = got.lock().unwrap().take() {
            return result;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("no answer for {name}");
}

/// Over DoT with mutual TLS the handler sees the client's certificate chain,
/// the SNI it asked for and the listener's address, and can still read them
/// from a callback completed after `handle_query` returned.
#[cfg(all(feature = "dot", feature = "server"))]
#[test]
fn dot_with_mtls_gives_the_handler_the_client_chain_sni_and_local_address() {
    use hopf_core::ClientAuthPolicy;
    use hopf_dns::server::listen_dns_dot;

    let server = identity("localhost");
    let client = identity("client.example");
    let server_cert = write_pem("server-cert", &server.cert_pem);
    let server_key = write_pem("server-key", &server.key_pem);
    let client_cert = write_pem("client-cert", &client.cert_pem);
    let client_key = write_pem("client-key", &client.key_pem);

    let acceptor = hopf_core::acceptor_from_pem_with_client_auth(
        &server_cert,
        &server_key,
        &[b"dot"],
        ClientAuthPolicy::Require,
        &client_cert,
    )
    .unwrap();
    let connector =
        hopf_core::connector_from_pem_with_client_cert(&server_cert, &client_cert, &client_key, &[b"dot"]).unwrap();

    let recorder = Recorder::default();
    let handle = DnsServiceHandle::new(DnsService::with_handler(recorder.clone()));
    let rt = hopf_core::Runtime::start(hopf_core::RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let addr = listen_dns_dot(&rt, "127.0.0.1:0".parse().unwrap(), acceptor, handle).unwrap();

    let resolver = hopf_dns::DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server_dot(addr, "localhost", connector);
    resolver.open().unwrap();
    ask(&resolver, "dot-ctx.test").expect("the query is answered over DoT");

    let seen = recorder.only();
    assert_eq!(seen.transport, DnsTransport::Dot);
    assert_eq!(seen.local, Some(addr));
    assert!(seen.secure);
    assert_eq!(seen.sni.as_deref(), Some("localhost"));
    assert_eq!(
        seen.chain.as_deref(),
        Some(&[client.der.clone()][..]),
        "the handler sees exactly the client's certificate"
    );
    rt.shutdown();
}

/// Where a certificate is only requested, a client may present none: the
/// session is still secure, and the handler sees that no identity was proven
/// rather than an empty chain.
#[cfg(all(feature = "dot", feature = "server"))]
#[test]
fn dot_without_a_client_certificate_reports_no_chain_when_it_is_only_requested() {
    use hopf_core::ClientAuthPolicy;
    use hopf_dns::server::listen_dns_dot;

    let server = identity("localhost");
    let client = identity("client.example");
    let server_cert = write_pem("server-cert", &server.cert_pem);
    let server_key = write_pem("server-key", &server.key_pem);
    let client_cert = write_pem("client-cert", &client.cert_pem);

    let acceptor = hopf_core::acceptor_from_pem_with_client_auth(
        &server_cert,
        &server_key,
        &[b"dot"],
        ClientAuthPolicy::Request,
        &client_cert,
    )
    .unwrap();
    // A plain connector: no client credentials to present.
    let connector = hopf_core::connector_from_pem(&server_cert, &[b"dot"]).unwrap();

    let recorder = Recorder::default();
    let handle = DnsServiceHandle::new(DnsService::with_handler(recorder.clone()));
    let rt = hopf_core::Runtime::start(hopf_core::RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let addr = listen_dns_dot(&rt, "127.0.0.1:0".parse().unwrap(), acceptor, handle).unwrap();
    let resolver = hopf_dns::DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server_dot(addr, "localhost", connector);
    resolver.open().unwrap();
    ask(&resolver, "dot-anon.test").expect("a requested (not required) certificate may be absent");

    let seen = recorder.only();
    assert!(seen.secure, "the session is still encrypted");
    assert_eq!(seen.chain, None, "no certificate was presented");
    rt.shutdown();
}

/// Over DoQ with mutual TLS the handler gets the same identity from the QUIC
/// handshake.
#[cfg(all(feature = "doq", feature = "server"))]
#[test]
fn doq_with_mtls_gives_the_handler_the_client_chain_sni_and_local_address() {
    use hopf_core::crypto::TrustStore;
    use hopf_core::{ClientAuthPolicy, HandshakeConfig, HandshakeMode, HandshakeRole};
    use hopf_dns::server::listen_dns_doq;
    use hopf_quic::{QuicClientConfig, QuicServerConfig};

    let server = identity("localhost");
    let client = identity("client.example");
    let server_creds =
        hopf_core::server_credentials_from_pem_bytes(server.cert_pem.as_bytes(), server.key_pem.as_bytes()).unwrap();
    let client_creds =
        hopf_core::server_credentials_from_pem_bytes(client.cert_pem.as_bytes(), client.key_pem.as_bytes()).unwrap();

    let mut client_ca = TrustStore::new();
    client_ca.add_anchor(client.der.clone());
    let server_config = Arc::new(QuicServerConfig::from_handshake(HandshakeConfig {
        role: HandshakeRole::Server,
        mode: HandshakeMode::Quic,
        alpn: vec![Bytes::from_static(b"doq")],
        server: Some(server_creds),
        client_auth: ClientAuthPolicy::Require,
        client_trust_store: Some(client_ca),
        ..Default::default()
    }));

    let mut server_ca = TrustStore::new();
    server_ca.add_anchor(server.der.clone());
    let client_config = Arc::new(QuicClientConfig::from_handshake(HandshakeConfig {
        role: HandshakeRole::Client,
        mode: HandshakeMode::Quic,
        alpn: vec![Bytes::from_static(b"doq")],
        trust_store: Some(server_ca),
        client_credentials: Some(client_creds),
        ..Default::default()
    }));

    let recorder = Recorder::default();
    let handle = DnsServiceHandle::new(DnsService::with_handler(recorder.clone()));
    let driver = listen_dns_doq("127.0.0.1:0".parse().unwrap(), server_config, handle).unwrap();
    let addr = driver.local_addr;

    let rt = hopf_core::Runtime::start(Default::default()).unwrap();
    let resolver = hopf_dns::DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server_doq(addr, "localhost", client_config);
    resolver.open().unwrap();
    ask(&resolver, "doq-ctx.test").expect("the query is answered over DoQ");

    let seen = recorder.only();
    assert_eq!(seen.transport, DnsTransport::Doq);
    assert_eq!(seen.local, Some(addr));
    assert!(seen.secure);
    assert_eq!(seen.sni.as_deref(), Some("localhost"));
    assert_eq!(
        seen.chain.as_deref(),
        Some(&[client.der.clone()][..]),
        "the handler sees exactly the client's certificate"
    );
    rt.shutdown();
    driver.shutdown();
}
