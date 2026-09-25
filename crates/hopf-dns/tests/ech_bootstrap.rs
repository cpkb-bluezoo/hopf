// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ECH bootstrap from DNS HTTPS records: a local stub DNS server publishes an
//! `ech` SvcParam, `resolve_ech` fetches it through a real `DnsResolver`, and
//! a TLS 1.3 handshake through `connector_with_ech_cache` uses it. No external
//! network.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use hopf_core::crypto::hpke::Kem;
use hopf_core::security::SecurityInfo;
use hopf_core::tls::ech::{EchConfig, EchServerConfig, EchServerKey, HpkeCipherSuite};
use hopf_core::tls::{
    acceptor_from_pem, acceptor_with_ech, insecure_connector, TlsProtocolError, TlsRecordSink, VerifyRequest,
    VerifyResult,
};
use hopf_core::Runtime;
use hopf_dns::ech::{connector_with_ech_cache, resolve_ech, EchConfigCache, EchDiscovery};
use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA, SVCB_PARAM_ECH};
use hopf_dns::DnsResolver;

const PUBLIC: &str = "public.example";
const WITH_ECH: &str = "inner.example";
const WITHOUT_ECH: &str = "plain.example";

#[derive(Default)]
struct Sink {
    out: Vec<u8>,
    info: Option<SecurityInfo>,
    error: Option<TlsProtocolError>,
    pending_verify: Option<u64>,
}

impl TlsRecordSink for Sink {
    fn ciphertext_ready(&mut self, data: &[u8]) {
        self.out.extend_from_slice(data);
    }
    fn application_data(&mut self, _plaintext: &[u8]) {}
    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.info = Some(info);
    }
    fn verification_requested(&mut self, req: VerifyRequest) {
        self.pending_verify = Some(req.id);
    }
    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.error = Some(err);
    }
    fn peer_closed(&mut self) {}
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Stub DNS: an HTTPS record with `ech` for `WITH_ECH`, NODATA for anything
/// else. Counts HTTPS queries it answers.
fn spawn_stub(list: Vec<u8>, https_queries: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    thread::spawn(move || loop {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = sock.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            continue;
        };
        let Some(question) = q.questions.first() else {
            continue;
        };
        // Skip the resolver's own DDR probe (SVCB); only HTTPS is ours.
        if question.qtype != Some(DnsType::Https) {
            continue;
        }
        https_queries.fetch_add(1, Ordering::SeqCst);
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if question.name.eq_ignore_ascii_case(WITH_ECH) {
            resp.answers.push(
                DnsResourceRecord::https(&question.name, 300, 1, ".", &[(SVCB_PARAM_ECH, list.clone())]).unwrap(),
            );
        }
        let _ = sock.send_to(&resp.serialize().unwrap(), peer);
    });
    addr
}

fn discover(resolver: &DnsResolver, cache: &Arc<EchConfigCache>, host: &str) -> Option<EchDiscovery> {
    let (tx, rx) = mpsc::channel();
    resolve_ech(resolver, cache, host, 443, Box::new(move |d| tx.send(d).unwrap()));
    rx.recv_timeout(Duration::from_secs(5)).expect("lookup completes")
}

/// Handshake a client and server engine to completion in memory. Returns what
/// the client put on the wire and what the server learned.
fn handshake(
    connector: &hopf_core::tls::SharedTlsConnector,
    acceptor: &hopf_core::tls::SharedTlsAcceptor,
    host: &str,
) -> (Vec<u8>, Sink, Sink) {
    let mut client = connector.connect(host).unwrap();
    let mut server = acceptor.accept();
    let (mut cs, mut ss) = (Sink::default(), Sink::default());
    let mut sent = Vec::new();
    client.start(&mut cs);
    server.start(&mut ss);
    for _ in 0..6 {
        let c2s = std::mem::take(&mut cs.out);
        sent.extend_from_slice(&c2s);
        server.feed_ciphertext(&mut &c2s[..], &mut ss);
        let s2c = std::mem::take(&mut ss.out);
        client.feed_ciphertext(&mut &s2c[..], &mut cs);
        // `insecure_connector` accepts any certificate, but the engine still
        // waits for the caller to say so.
        if let Some(id) = cs.pending_verify.take() {
            client.feed_verification_result(VerifyResult { id, ok: true }, &mut cs);
        }
    }
    assert!(client.is_complete() && server.is_complete(), "client {:?} server {:?}", cs.error, ss.error);
    (sent, cs, ss)
}

#[test]
fn ech_config_from_dns_is_used_and_absent_records_fall_back_to_plain() {
    // Server: one ECH key; the DNS record advertises its config.
    let (config, key) = EchConfig::generate(
        9,
        Kem::DhkemX25519HkdfSha256,
        vec![HpkeCipherSuite { kdf_id: 1, aead_id: 1 }],
        32,
        PUBLIC,
    )
    .unwrap();
    let list = EchConfig::encode_list(std::slice::from_ref(&config)).unwrap();
    let server_ech = Arc::new(EchServerConfig::new(vec![EchServerKey::new(config, key).unwrap()]));

    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = rcgen::CertificateParams::new(vec![WITH_ECH.into(), WITHOUT_ECH.into(), PUBLIC.into()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    let dir = std::env::temp_dir().join(format!("hopf-ech-bootstrap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, kp.serialize_pem()).unwrap();
    let acceptor = acceptor_with_ech(acceptor_from_pem(&cert_path, &key_path, &[b"h2"]).unwrap(), server_ech);
    let _ = std::fs::remove_dir_all(&dir);

    // DNS: real resolver against the local stub.
    let queries = Arc::new(AtomicUsize::new(0));
    let stub = spawn_stub(list, Arc::clone(&queries));
    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(stub);
    resolver.open().unwrap();

    let cache = EchConfigCache::new();
    let found = discover(&resolver, &cache, WITH_ECH).expect("HTTPS record carries an ECH config");
    assert_eq!(found.config.configs[0].public_name, PUBLIC);
    assert!(discover(&resolver, &cache, WITHOUT_ECH).is_none(), "no record: no config");
    assert_eq!(queries.load(Ordering::SeqCst), 2);

    let connector = connector_with_ech_cache(insecure_connector(&[b"h2"]), Arc::clone(&cache));

    // With a config: the real name is encrypted, the server still learns it.
    let (wire, client, server) = handshake(&connector, &acceptor, WITH_ECH);
    assert!(contains(&wire, PUBLIC), "the outer hello names the public name");
    assert!(!contains(&wire, WITH_ECH), "the real SNI must not be on the wire");
    assert_eq!(server.info.as_ref().unwrap().sni(), Some(WITH_ECH));
    assert!(client.info.is_some());

    // Without a record: an ordinary handshake, exactly as before.
    let (wire, _, server) = handshake(&connector, &acceptor, WITHOUT_ECH);
    assert!(contains(&wire, WITHOUT_ECH), "no ECH record: plain SNI");
    assert_eq!(server.info.as_ref().unwrap().sni(), Some(WITHOUT_ECH));

    // Connecting never queries DNS: the counter did not move.
    assert_eq!(queries.load(Ordering::SeqCst), 2, "connect must read the cache, not the network");

    // A pinned config overrides DNS and needs no query at all.
    let pinned_cache = EchConfigCache::new();
    pinned_cache.set_static(WITHOUT_ECH, found.config.clone());
    assert!(discover(&resolver, &pinned_cache, WITHOUT_ECH).is_some());
    assert_eq!(queries.load(Ordering::SeqCst), 2);
    let connector = connector_with_ech_cache(insecure_connector(&[b"h2"]), pinned_cache);
    let (wire, _, server) = handshake(&connector, &acceptor, WITHOUT_ECH);
    assert!(!contains(&wire, WITHOUT_ECH));
    assert_eq!(server.info.as_ref().unwrap().sni(), Some(WITHOUT_ECH));

    rt.shutdown();
}
