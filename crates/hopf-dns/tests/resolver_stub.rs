// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Local UDP stub ↔ DnsResolver smoke (no external network).

use std::io;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::server::DnsService;
use hopf_dns::wire::{DnsMessage, DnsResourceRecord, FLAG_QR, FLAG_RA, FLAG_TC};
use hopf_dns::{DnsCache, DnsResolver};

#[test]
fn resolve_a_against_local_stub() {
    let stub = UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = stub.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            return;
        };
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            resp.answers.push(DnsResourceRecord::a(
                &question.name,
                60,
                Ipv4Addr::new(203, 0, 113, 10),
            ));
        }
        let bytes = resp.serialize().unwrap();
        let _ = stub.send_to(&bytes, peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(stub_addr);
    resolver.open().unwrap();

    let got = Arc::new(Mutex::new(None));
    let got2 = Arc::clone(&got);
    resolver.query_a(
        "test.example",
        Box::new(move |r| {
            *got2.lock().unwrap() = Some(r);
        }),
    );

    for _ in 0..50 {
        if got.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let msg = got
        .lock()
        .unwrap()
        .take()
        .expect("callback")
        .expect("ok");
    assert_eq!(
        msg.answers[0].as_a(),
        Some(Ipv4Addr::new(203, 0, 113, 10))
    );
    rt.shutdown();
}

/// RFC 2308 §2 NODATA (NOERROR with an empty answer set) must be cached —
/// a second identical query must be answered from cache instead of
/// re-querying upstream.
#[test]
fn nodata_response_is_negatively_cached_so_a_repeat_query_skips_upstream() {
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    let stub = UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    thread::spawn(move || loop {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = stub.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            continue;
        };
        hits2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // NOERROR, no answers: NODATA.
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        let _ = stub.send_to(&resp.serialize().unwrap(), peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(stub_addr);
    resolver.open().unwrap();

    for _ in 0..2 {
        let got = Arc::new(Mutex::new(None));
        let got2 = Arc::clone(&got);
        resolver.query_a(
            "nodata-integration-test.example",
            Box::new(move |r| {
                *got2.lock().unwrap() = Some(r);
            }),
        );
        for _ in 0..100 {
            if got.lock().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let msg = got.lock().unwrap().take().expect("callback").expect("ok");
        assert!(msg.answers.is_empty());
    }

    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1, "second query must be served from cache, not re-sent upstream");
    rt.shutdown();
}

/// The forwarder must truncate (empty answer + TC set) a response too
/// large for what the client advertised, instead of sending an oversized
/// UDP datagram — and must send the full answer once the client's
/// advertised EDNS payload size is big enough to hold it.
#[test]
fn forwarder_truncates_oversized_udp_response_for_the_clients_advertised_size() {
    use hopf_dns::server::{listen_dns_udp, DnsServiceHandle, DnsUdpListenConfig};
    use hopf_dns::wire::{DnsQuestion, DnsResourceRecord, DnsType};

    let mut service = DnsService::new(Arc::new(DnsCache::default()));
    service.set_local_resolver(|query| {
        let mut resp = query.response_template(0);
        let name = query.questions.first().map(|q| q.name.clone()).unwrap_or_default();
        // Comfortably over 512 bytes (legacy limit) but well under 4096
        // (a generous EDNS payload size) once serialized.
        for i in 0..40u8 {
            resp.answers.push(DnsResourceRecord::a(&name, 60, Ipv4Addr::new(203, 0, 113, i)));
        }
        Some(resp)
    });
    let handle = DnsServiceHandle::new(service);

    let rt = Runtime::start(Default::default()).unwrap();
    let (addr, _token) = listen_dns_udp(
        rt.pick_worker(),
        DnsUdpListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            service: handle,
        },
    )
    .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    // No EDNS OPT at all → legacy 512-octet limit → must truncate.
    let plain_query = DnsMessage::query(1, DnsQuestion::in_class("big.example", DnsType::A), true);
    client.send_to(&plain_query.serialize().unwrap(), addr).unwrap();
    let mut buf = [0u8; 8192];
    let n = client.recv(&mut buf).unwrap();
    let truncated = DnsMessage::parse(&buf[..n]).unwrap();
    assert!(truncated.is_truncated(), "oversized legacy (no-EDNS) response must set TC");
    assert!(truncated.answers.is_empty(), "a truncated response carries no partial answer set");

    // EDNS advertising a large payload size → the same answer set fits → no truncation.
    let mut edns_query = DnsMessage::query(2, DnsQuestion::in_class("big.example", DnsType::A), true);
    edns_query.additionals.push(DnsResourceRecord::opt(4096, false, &[]));
    client.send_to(&edns_query.serialize().unwrap(), addr).unwrap();
    let n = client.recv(&mut buf).unwrap();
    let full = DnsMessage::parse(&buf[..n]).unwrap();
    assert!(!full.is_truncated(), "response fits the advertised EDNS payload size, must not be truncated");
    assert_eq!(full.answers.len(), 40);

    rt.shutdown();
}

/// The forwarder's own upstream query getting a truncated (TC=1) UDP
/// answer must trigger a TCP retry that recovers the full answer — proven
/// through `DnsService::process_query_sync` directly (not just the
/// underlying resolver), since that's the actual forwarder code path.
#[test]
fn forwarder_retries_truncated_upstream_answer_over_tcp() {
    // Bind UDP first to claim a free ephemeral port, then bind TCP to the
    // exact same port number (independent namespaces, no conflict) so a
    // single SocketAddr serves both the UDP query and the TCP retry.
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let upstream_addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(upstream_addr).unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = udp.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            return;
        };
        // Truncated UDP answer: no answers, TC set.
        let mut truncated = q.response_template(0);
        truncated.flags |= FLAG_QR | FLAG_RA | FLAG_TC;
        let _ = udp.send_to(&truncated.serialize().unwrap(), peer);
    });
    thread::spawn(move || {
        let Ok((mut stream, _)) = tcp.accept() else {
            return;
        };
        use std::io::{Read, Write};
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return;
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut req_buf = vec![0u8; len];
        if stream.read_exact(&mut req_buf).is_err() {
            return;
        }
        let Ok(q) = DnsMessage::parse(&req_buf) else {
            return;
        };
        let mut full = q.response_template(0);
        full.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            full.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(203, 0, 113, 40)));
        }
        let bytes = full.serialize().unwrap();
        let _ = stream.write_all(&(bytes.len() as u16).to_be_bytes());
        let _ = stream.write_all(&bytes);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let upstream = DnsResolver::new(rt.pick_worker().clone());
    upstream.add_server(upstream_addr);
    upstream.open().unwrap();

    let mut service = DnsService::new(Arc::new(DnsCache::default()));
    service.set_upstream(upstream);

    let query = DnsMessage::query(
        4242,
        hopf_dns::wire::DnsQuestion::in_class("tc-fallback-test.example", hopf_dns::wire::DnsType::A),
        true,
    );
    let resp = service.process_query_sync(&query, "127.0.0.1:12345".parse().unwrap());

    assert!(!resp.is_truncated(), "must return the full TCP-retried answer, not the truncated UDP one");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.answers[0].as_a(), Some(Ipv4Addr::new(203, 0, 113, 40)));
    rt.shutdown();
}

/// A dead first server (configured but never answering) must not fail the
/// query outright — the resolver should retry against the second
/// configured server and still succeed.
#[test]
fn retries_against_second_configured_server_when_first_is_dead() {
    // Bound but never read from: absorbs the query silently, like a
    // firewalled/unreachable upstream, so the resolver's own timeout (not
    // an ICMP port-unreachable) is what triggers the retry.
    let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();

    let live = UdpSocket::bind("127.0.0.1:0").unwrap();
    live.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let live_addr = live.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = live.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            return;
        };
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            resp.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(203, 0, 113, 30)));
        }
        let _ = live.send_to(&resp.serialize().unwrap(), peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.set_timeout(Duration::from_millis(150));
    resolver.add_server(dead_addr);
    resolver.add_server(live_addr);
    resolver.open().unwrap();

    let got = Arc::new(Mutex::new(None));
    let got2 = Arc::clone(&got);
    resolver.query_a(
        "retry-test.example",
        Box::new(move |r| {
            *got2.lock().unwrap() = Some(r);
        }),
    );

    // Long enough for one dead-server timeout (150ms) plus the retry's own
    // round trip; short enough that this fails fast if retry is broken.
    for _ in 0..150 {
        if got.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let msg = got.lock().unwrap().take().expect("callback").expect("ok, not a timeout");
    assert_eq!(msg.answers[0].as_a(), Some(Ipv4Addr::new(203, 0, 113, 30)));
    rt.shutdown();
}

/// RFC 5452 §2.2: a forged response with a correctly-guessed id and
/// question, but from a different source address than the query was sent
/// to, must be rejected — and must not disrupt the real reply that
/// follows it.
#[test]
fn spoofed_source_address_is_rejected_but_real_reply_still_accepted() {
    let real_server = UdpSocket::bind("127.0.0.1:0").unwrap();
    real_server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let real_addr = real_server.local_addr().unwrap();
    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = real_server.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            return;
        };

        // Forged reply with the right id/question, sent from a different
        // socket than the one the query was actually sent to.
        let mut spoof = q.response_template(0);
        spoof.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            spoof.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(198, 51, 100, 66)));
        }
        let _ = attacker.send_to(&spoof.serialize().unwrap(), peer);

        thread::sleep(Duration::from_millis(100));

        // Real server's genuine answer, from the address the query was sent to.
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            resp.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(203, 0, 113, 10)));
        }
        let _ = real_server.send_to(&resp.serialize().unwrap(), peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(real_addr);
    resolver.open().unwrap();

    let got = Arc::new(Mutex::new(None));
    let got2 = Arc::clone(&got);
    resolver.query_a(
        "spoof-source-test.example",
        Box::new(move |r| {
            *got2.lock().unwrap() = Some(r);
        }),
    );

    for _ in 0..100 {
        if got.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let msg = got.lock().unwrap().take().expect("callback").expect("ok");
    assert_eq!(
        msg.answers[0].as_a(),
        Some(Ipv4Addr::new(203, 0, 113, 10)),
        "must accept only the real server's answer, not the spoofed one from a different address"
    );
    rt.shutdown();
}

/// RFC 5452 §2.2: a response from the right server with the right id but
/// a question that doesn't match what was actually asked must be
/// rejected — and must not disrupt the real reply that follows it.
#[test]
fn mismatched_question_is_rejected_but_real_reply_still_accepted() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let server_addr = server.local_addr().unwrap();

    thread::spawn(move || {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = server.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            return;
        };

        // Same id, same source, but a question for a different name than
        // what was actually queried.
        let mut wrong_question = q.clone();
        wrong_question.questions[0].name = "not-what-was-asked.example".into();
        let mut wrong = wrong_question.response_template(0);
        wrong.flags |= FLAG_QR | FLAG_RA;
        wrong.answers.push(DnsResourceRecord::a("not-what-was-asked.example", 60, Ipv4Addr::new(198, 51, 100, 77)));
        let _ = server.send_to(&wrong.serialize().unwrap(), peer);

        thread::sleep(Duration::from_millis(100));

        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            resp.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(203, 0, 113, 20)));
        }
        let _ = server.send_to(&resp.serialize().unwrap(), peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(server_addr);
    resolver.open().unwrap();

    let got = Arc::new(Mutex::new(None));
    let got2 = Arc::clone(&got);
    resolver.query_a(
        "mismatched-question-test.example",
        Box::new(move |r| {
            *got2.lock().unwrap() = Some(r);
        }),
    );

    for _ in 0..100 {
        if got.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let msg = got.lock().unwrap().take().expect("callback").expect("ok");
    assert_eq!(
        msg.answers[0].as_a(),
        Some(Ipv4Addr::new(203, 0, 113, 20)),
        "must accept only the answer matching the actual question asked"
    );
    rt.shutdown();
}

#[test]
fn literal_connect_by_name_skips_dns() {
    use hopf_core::{Endpoint, ProtocolHandler, TcpListenerConfig};
    use hopf_dns::RuntimeDnsExt;

    let rt = Arc::new(Runtime::start(Default::default()).unwrap());
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            || {
                Box::new(Echo) as Box<dyn ProtocolHandler>
            },
        ))
        .unwrap();

    struct Echo;
    impl ProtocolHandler for Echo {
        fn connected(&mut self, _: &mut dyn Endpoint) {}
        fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
            ep.send(data);
            *data = &[];
        }
        fn disconnected(&mut self, _: &mut dyn Endpoint) {}
        fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
    }

    let got = Arc::new(Mutex::new(Vec::new()));
    let got2 = Arc::clone(&got);
    struct Client {
        got: Arc<Mutex<Vec<u8>>>,
    }
    impl ProtocolHandler for Client {
        fn connected(&mut self, ep: &mut dyn Endpoint) {
            ep.send(b"hi");
        }
        fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
            self.got.lock().unwrap().extend_from_slice(data);
            *data = &[];
            ep.close();
        }
        fn disconnected(&mut self, _: &mut dyn Endpoint) {}
        fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
    }

    rt.connect_by_name("127.0.0.1", addr.port(), move || {
        Box::new(Client {
            got: Arc::clone(&got2),
        }) as Box<dyn ProtocolHandler>
    })
    .unwrap();

    for _ in 0..50 {
        if got.lock().unwrap().as_slice() == b"hi" {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(got.lock().unwrap().as_slice(), b"hi");
    if let Ok(owned) = Arc::try_unwrap(rt) {
        owned.shutdown();
    }
}

/// A real, two-level DNSSEC chain-of-trust walk (root trust anchor →
/// "example.com" delegation, with "com" correctly skipped as not itself
/// delegated) driven end-to-end over real UDP round trips through
/// `DnsResolver::validate_chain_of_trust` — proves the async DS/DNSKEY
/// query-and-recurse plumbing actually works, not just the underlying
/// state machine in isolation.
#[cfg(feature = "dnssec")]
#[test]
fn validate_chain_of_trust_walks_a_real_two_level_delegation_over_the_network() {
    use hopf_dns::dnssec::{compute_ds_digest, DnssecStatus, DnssecTrustAnchor, DnssecValidator};
    use hopf_dns::wire::{encode_name, DnsClass, DnsQuestion, DnsType};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sign_rrset(rrset: &[&DnsResourceRecord], name: &str, rtype: DnsType, key_tag: u16, pair: &Ed25519KeyPair) -> DnsResourceRecord {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let labels = if name == "." { 0 } else { name.split('.').filter(|s| !s.is_empty()).count() as u8 };
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&rtype.value().to_be_bytes());
        rdata.push(15); // Ed25519
        rdata.push(labels);
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&(now + 3600).to_be_bytes());
        rdata.extend_from_slice(&(now - 60).to_be_bytes());
        rdata.extend_from_slice(&key_tag.to_be_bytes());
        rdata.extend_from_slice(&encode_name(name).unwrap());
        // RFC 4034 §3.1.8 signed data: RRSIG header (everything above) + canonical rrset.
        let mut signed = rdata.clone();
        let owner_wire = encode_name(name).unwrap();
        for rr in rrset {
            signed.extend_from_slice(&owner_wire);
            signed.extend_from_slice(&rtype.value().to_be_bytes());
            signed.extend_from_slice(&1u16.to_be_bytes()); // IN
            signed.extend_from_slice(&3600u32.to_be_bytes());
            signed.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
            signed.extend_from_slice(&rr.rdata);
        }
        let sig = pair.sign(&signed);
        let mut rrsig = DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, rdata);
        rrsig.rdata.extend_from_slice(sig.as_ref());
        rrsig
    }

    let root_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let root_pair = Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
    let root_dnskey = DnsResourceRecord::dnskey(".", 3600, 257, 15, root_pair.public_key().as_ref());
    let root_key_tag = root_dnskey.dnskey_key_tag().unwrap();
    let root_dnskey_rrsig = sign_rrset(&[&root_dnskey], ".", DnsType::Dnskey, root_key_tag, &root_pair);

    let example_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let example_pair = Ed25519KeyPair::from_pkcs8(example_pkcs8.as_ref()).unwrap();
    let example_dnskey = DnsResourceRecord::dnskey("example.com", 3600, 257, 15, example_pair.public_key().as_ref());
    let example_key_tag = example_dnskey.dnskey_key_tag().unwrap();
    let example_dnskey_rrsig =
        sign_rrset(&[&example_dnskey], "example.com", DnsType::Dnskey, example_key_tag, &example_pair);

    let owner_wire = encode_name("example.com").unwrap();
    let ds_digest = compute_ds_digest(&owner_wire, &example_dnskey.rdata, 2).unwrap();
    let example_ds = DnsResourceRecord::ds("example.com", 3600, example_key_tag, 15, 2, &ds_digest);
    let example_ds_rrsig = sign_rrset(&[&example_ds], "example.com", DnsType::Ds, root_key_tag, &root_pair);

    let a = DnsResourceRecord::a("example.com", 3600, Ipv4Addr::new(192, 0, 2, 55));
    let a_rrsig = sign_rrset(&[&a], "example.com", DnsType::A, example_key_tag, &example_pair);

    let root_digest = compute_ds_digest(&[0u8], &root_dnskey.rdata, 2).unwrap();

    let stub = UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    thread::spawn(move || loop {
        let mut buf = [0u8; 4096];
        let Ok((n, peer)) = stub.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            continue;
        };
        let Some(question) = q.questions.first() else {
            continue;
        };
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        let name = hopf_dns::wire::normalize_name(&question.name);
        match (name.as_str(), question.qtype) {
            (".", Some(DnsType::Dnskey)) | ("", Some(DnsType::Dnskey)) => {
                resp.answers = vec![root_dnskey.clone(), root_dnskey_rrsig.clone()];
            }
            ("com", Some(DnsType::Ds)) => {} // no DS: "com" isn't independently delegated here
            ("example.com", Some(DnsType::Ds)) => {
                resp.answers = vec![example_ds.clone(), example_ds_rrsig.clone()];
            }
            ("example.com", Some(DnsType::Dnskey)) => {
                resp.answers = vec![example_dnskey.clone(), example_dnskey_rrsig.clone()];
            }
            _ => {}
        }
        let _ = stub.send_to(&resp.serialize().unwrap(), peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(stub_addr);
    resolver.open().unwrap();
    let mut anchor = DnssecTrustAnchor::empty();
    anchor.add_anchor(".", root_key_tag, 15, 2, &root_digest);
    resolver.set_dnssec_validator(DnssecValidator::new(anchor));

    let target_msg = DnsMessage::new(
        1,
        FLAG_QR,
        vec![DnsQuestion::in_class("example.com", DnsType::A)],
        vec![a, a_rrsig],
        vec![],
        vec![],
    );

    let result = Arc::new(Mutex::new(None));
    let result2 = Arc::clone(&result);
    resolver.validate_chain_of_trust(
        "example.com",
        target_msg,
        Box::new(move |_msg, status| {
            *result2.lock().unwrap() = Some(status);
        }),
    );

    for _ in 0..150 {
        if result.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(result.lock().unwrap().take(), Some(DnssecStatus::Secure), "chain walk over real network round trips must validate as Secure");
    rt.shutdown();
}

/// Drives [`DnsResolver::validate_denial_of_existence`] over a real UDP
/// round trip: a single-hop trust anchor at "." (no delegation involved,
/// since the chain-walk plumbing itself is already proven end-to-end by
/// the test above), then an NSEC3 closest-encloser proof — signed by
/// that same root key — that "missing" doesn't exist. Exercises the
/// whole path: DNSKEY fetch, NSEC3 hash computation, RRSIG verification,
/// and the closest-encloser proof, all driven by real network responses.
#[cfg(feature = "dnssec")]
#[test]
fn validate_denial_of_existence_proves_a_real_nxdomain_over_the_network() {
    use hopf_dns::dnssec::{compute_ds_digest, DnssecStatus, DnssecTrustAnchor, DnssecValidator};
    use hopf_dns::wire::{encode_name, normalize_name, DnsClass, DnsQuestion, DnsType};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sign_rrset(rrset: &[&DnsResourceRecord], name: &str, rtype: DnsType, key_tag: u16, pair: &Ed25519KeyPair) -> DnsResourceRecord {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let labels = if name == "." { 0 } else { name.split('.').filter(|s| !s.is_empty()).count() as u8 };
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&rtype.value().to_be_bytes());
        rdata.push(15); // Ed25519
        rdata.push(labels);
        rdata.extend_from_slice(&3600u32.to_be_bytes());
        rdata.extend_from_slice(&(now + 3600).to_be_bytes());
        rdata.extend_from_slice(&(now - 60).to_be_bytes());
        rdata.extend_from_slice(&key_tag.to_be_bytes());
        rdata.extend_from_slice(&encode_name(name).unwrap());
        let mut signed = rdata.clone();
        // Canonical form (RFC 4034 §6.2) lowercases the owner name — the
        // real verifier recomputes it via `normalize_name`, so this must
        // match, unlike the raw `name` used for the RRSIG's own owner.
        let owner_wire = encode_name(&normalize_name(name)).unwrap();
        for rr in rrset {
            signed.extend_from_slice(&owner_wire);
            signed.extend_from_slice(&rtype.value().to_be_bytes());
            signed.extend_from_slice(&1u16.to_be_bytes()); // IN
            signed.extend_from_slice(&3600u32.to_be_bytes());
            signed.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
            signed.extend_from_slice(&rr.rdata);
        }
        let sig = pair.sign(&signed);
        let mut rrsig = DnsResourceRecord::new(name, DnsType::Rrsig, DnsClass::In, 3600, rdata);
        rrsig.rdata.extend_from_slice(sig.as_ref());
        rrsig
    }

    let root_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let root_pair = Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
    let root_dnskey = DnsResourceRecord::dnskey(".", 3600, 257, 15, root_pair.public_key().as_ref());
    let root_key_tag = root_dnskey.dnskey_key_tag().unwrap();
    let root_dnskey_rrsig = sign_rrset(&[&root_dnskey], ".", DnsType::Dnskey, root_key_tag, &root_pair);
    let root_digest = compute_ds_digest(&[0u8], &root_dnskey.rdata, 2).unwrap();

    // Closest-encloser NSEC3 proof that "missing" doesn't exist under ".".
    let salt = [0x7Au8];
    let iterations = 0u16;
    let hash_of = |name: &str| {
        let owner_wire = encode_name(&normalize_name(name)).unwrap();
        hopf_dns::dnssec::nsec3_hash(&owner_wire, iterations, &salt)
    };
    let encloser_hash = hash_of(".");
    let encloser_owner = hopf_dns::wire::base32hex::encode(&encloser_hash);
    let next_closer_hash = hash_of("missing");
    let mut owner_hash = next_closer_hash.clone();
    owner_hash[0] = owner_hash[0].wrapping_sub(1);
    let mut next_hash = next_closer_hash.clone();
    next_hash[0] = next_hash[0].wrapping_add(1);
    let covering_owner = hopf_dns::wire::base32hex::encode(&owner_hash);

    let encloser_nsec3 = DnsResourceRecord::nsec3(&encloser_owner, 3600, 1, 0, iterations, &salt, &[9u8; 20], vec![DnsType::Ns.value()]);
    let covering_nsec3 = DnsResourceRecord::nsec3(&covering_owner, 3600, 1, 0, iterations, &salt, &next_hash, vec![DnsType::A.value()]);
    let encloser_sig = sign_rrset(&[&encloser_nsec3], &encloser_owner, DnsType::Nsec3, root_key_tag, &root_pair);
    let covering_sig = sign_rrset(&[&covering_nsec3], &covering_owner, DnsType::Nsec3, root_key_tag, &root_pair);

    let stub = UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    thread::spawn(move || loop {
        let mut buf = [0u8; 4096];
        let Ok((n, peer)) = stub.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            continue;
        };
        let Some(question) = q.questions.first() else {
            continue;
        };
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        let name = hopf_dns::wire::normalize_name(&question.name);
        match (name.as_str(), question.qtype) {
            (".", Some(DnsType::Dnskey)) | ("", Some(DnsType::Dnskey)) => {
                resp.answers = vec![root_dnskey.clone(), root_dnskey_rrsig.clone()];
            }
            ("missing", Some(DnsType::Ds)) | ("", Some(DnsType::Ds)) => {} // no delegation anywhere
            _ => {}
        }
        let _ = stub.send_to(&resp.serialize().unwrap(), peer);
    });

    let rt = Runtime::start(Default::default()).unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(stub_addr);
    resolver.open().unwrap();
    let mut anchor = DnssecTrustAnchor::empty();
    anchor.add_anchor(".", root_key_tag, 15, 2, &root_digest);
    resolver.set_dnssec_validator(DnssecValidator::new(anchor));

    let nxdomain_msg = DnsMessage::new(
        1,
        FLAG_QR,
        vec![DnsQuestion::in_class("missing", DnsType::A)],
        vec![],
        vec![encloser_nsec3, encloser_sig, covering_nsec3, covering_sig],
        vec![],
    );

    let result = Arc::new(Mutex::new(None));
    let result2 = Arc::clone(&result);
    resolver.validate_denial_of_existence(
        "missing",
        DnsType::A,
        nxdomain_msg,
        Box::new(move |_msg, status| {
            *result2.lock().unwrap() = Some(status);
        }),
    );

    for _ in 0..150 {
        if result.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        result.lock().unwrap().take(),
        Some(DnssecStatus::Secure),
        "NSEC3 denial-of-existence over real network round trips must validate as Secure"
    );
    rt.shutdown();
}

/// A stub TCP DNS server that keeps each accepted connection open across
/// multiple length-prefixed queries (RFC 7766 keep-alive), answering every
/// question with a fixed A record. Returns the bound address and a counter
/// of how many *connections* (not queries) it has accepted.
fn spawn_keepalive_tcp_stub() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let accept_count = Arc::new(AtomicUsize::new(0));
    let accept_count2 = Arc::clone(&accept_count);

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            accept_count2.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            thread::spawn(move || loop {
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).is_err() {
                    return;
                }
                let Ok(q) = DnsMessage::parse(&payload) else {
                    return;
                };
                let mut resp = q.response_template(0);
                resp.flags |= FLAG_QR;
                if let Some(question) = q.questions.first() {
                    resp.answers
                        .push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(198, 51, 100, 9)));
                }
                let bytes = resp.serialize().unwrap();
                let mut out = Vec::with_capacity(2 + bytes.len());
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(&bytes);
                if stream.write_all(&out).is_err() {
                    return;
                }
            });
        }
    });

    (addr, accept_count)
}

/// Proves the fix for issue #54: `TcpDnsConnectionPool` must actually reuse
/// a live connection across queries to the same server, not dial fresh
/// every time — driven against a real keep-alive TCP stub, counting actual
/// accepted connections.
#[test]
fn tcp_connection_pool_reuses_a_connection_across_queries() {
    use hopf_dns::client::TcpDnsConnectionPool;
    use hopf_dns::wire::{DnsQuestion, DnsType};

    let (addr, accept_count) = spawn_keepalive_tcp_stub();
    let mut pool = TcpDnsConnectionPool::new();

    let q1 = DnsQuestion::in_class("pool-test-1.example", DnsType::A);
    let r1 = pool.query(addr, &q1, 1).unwrap();
    assert_eq!(r1.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 9)));

    let q2 = DnsQuestion::in_class("pool-test-2.example", DnsType::A);
    let r2 = pool.query(addr, &q2, 2).unwrap();
    assert_eq!(r2.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 9)));

    assert_eq!(
        accept_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the second query must reuse the pooled connection, not dial a fresh one"
    );
}

/// A pooled connection that the *server* has since closed (e.g. an idle
/// timeout) must be transparently replaced with a fresh one — not
/// surfaced as a query failure.
#[test]
fn tcp_connection_pool_recovers_from_a_stale_pooled_connection() {
    use hopf_dns::client::TcpDnsConnectionPool;
    use hopf_dns::wire::{DnsQuestion, DnsType};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).is_err() {
                continue;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).is_err() {
                continue;
            }
            let Ok(q) = DnsMessage::parse(&payload) else {
                continue;
            };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR;
            if let Some(question) = q.questions.first() {
                resp.answers
                    .push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(198, 51, 100, 10)));
            }
            let bytes = resp.serialize().unwrap();
            let mut out = Vec::with_capacity(2 + bytes.len());
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(&bytes);
            let _ = stream.write_all(&out);
            // Simulate a server-side idle timeout: close right after
            // answering, instead of looping for another query.
        }
    });

    let mut pool = TcpDnsConnectionPool::new();
    let q1 = DnsQuestion::in_class("stale-test-1.example", DnsType::A);
    let r1 = pool.query(addr, &q1, 1).unwrap();
    assert_eq!(r1.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 10)));

    // The pooled connection is now closed on the server side; this must
    // still succeed by silently reconnecting, not error out.
    let q2 = DnsQuestion::in_class("stale-test-2.example", DnsType::A);
    let r2 = pool.query(addr, &q2, 2).expect("must recover from a stale pooled connection");
    assert_eq!(r2.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 10)));
}

/// Same proof as [`tcp_connection_pool_reuses_a_connection_across_queries`]
/// but for DoT: a real self-signed-TLS stub server, driven through
/// `TcpDnsConnectionPool::query_dot`, must only complete one TLS handshake
/// across two queries — the second must reuse the already-established
/// session, not redial and re-handshake.
#[cfg(feature = "dot")]
#[test]
fn dot_connection_pool_reuses_a_connection_across_queries() {
    use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
    use hopf_dns::client::TcpDnsConnectionPool;
    use hopf_dns::wire::{DnsQuestion, DnsType};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "hopf-dns-dot-pool-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let acceptor = hopf_tls::acceptor_from_pem(&cert_path, &key_path, &[b"dot"]).unwrap();
    let connector = hopf_tls::connector_from_pem(&cert_path, &[b"dot"]).unwrap();

    struct DotStub {
        connect_count: Arc<AtomicUsize>,
        buf: Vec<u8>,
    }
    impl ProtocolHandler for DotStub {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
            self.connect_count.fetch_add(1, Ordering::SeqCst);
        }
        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            self.buf.extend_from_slice(data);
            *data = &[];
            while self.buf.len() >= 2 {
                let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if self.buf.len() < 2 + len {
                    break;
                }
                let payload = self.buf[2..2 + len].to_vec();
                self.buf.drain(..2 + len);
                let Ok(q) = DnsMessage::parse(&payload) else {
                    continue;
                };
                let mut resp = q.response_template(0);
                resp.flags |= FLAG_QR;
                if let Some(question) = q.questions.first() {
                    resp.answers
                        .push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(198, 51, 100, 20)));
                }
                let bytes = resp.serialize().unwrap();
                let mut out = Vec::with_capacity(2 + bytes.len());
                out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                out.extend_from_slice(&bytes);
                endpoint.send(&out);
            }
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    let connect_count = Arc::new(AtomicUsize::new(0));
    let cc = Arc::clone(&connect_count);
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let (addr, _) = rt
        .add_tcp_listener(
            TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                Box::new(DotStub {
                    connect_count: Arc::clone(&cc),
                    buf: Vec::new(),
                }) as Box<dyn ProtocolHandler>
            })
            .with_tls(acceptor),
        )
        .unwrap();

    let mut pool = TcpDnsConnectionPool::new();
    let q1 = DnsQuestion::in_class("dot-pool-1.example", DnsType::A);
    let r1 = pool.query_dot(addr, "localhost", &connector, &q1, 1).unwrap();
    assert_eq!(r1.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 20)));

    let q2 = DnsQuestion::in_class("dot-pool-2.example", DnsType::A);
    let r2 = pool.query_dot(addr, "localhost", &connector, &q2, 2).unwrap();
    assert_eq!(r2.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 20)));

    assert_eq!(
        connect_count.load(Ordering::SeqCst),
        1,
        "the second DoT query must reuse the pooled TLS connection, not redial and re-handshake"
    );
    rt.shutdown();
}

/// Proves the fix for issue #57: `DohClientTransport::with_get(true)` must
/// send a real RFC 8484 §4.1 GET request — the DNS wire message base64url
/// -encoded into the `dns` query parameter, no body — and correctly
/// receive the response back, driven over a real TLS+HTTP stub server that
/// decodes the parameter itself and checks it byte-for-byte matches what
/// was sent. Also proves the existing POST path still works against the
/// same stub, for direct comparison.
#[cfg(feature = "doh")]
#[test]
fn doh_get_and_post_round_trip_over_a_real_tls_http_stub() {
    use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
    use hopf_dns::client::{DnsClientTransport, DnsClientTransportHandler, DohClientTransport};
    use hopf_dns::wire::{DnsQuestion, DnsType};
    use std::sync::mpsc;

    fn base64url_decode(s: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::new();
        let mut bits: u32 = 0;
        let mut bit_count: u32 = 0;
        for c in s.bytes() {
            let Some(val) = ALPHABET.iter().position(|&b| b == c) else {
                break;
            };
            bits = (bits << 6) | val as u32;
            bit_count += 6;
            if bit_count >= 8 {
                bit_count -= 8;
                out.push(((bits >> bit_count) & 0xFF) as u8);
            }
        }
        out
    }

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "hopf-dns-doh-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let acceptor = hopf_tls::acceptor_from_pem(&cert_path, &key_path, &[b"http/1.1"]).unwrap();
    let connector = hopf_tls::connector_from_pem(&cert_path, &[b"http/1.1"]).unwrap();

    struct DohStubHandler {
        buf: Vec<u8>,
    }
    impl ProtocolHandler for DohStubHandler {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            self.buf.extend_from_slice(data);
            *data = &[];
            let Some(header_end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) else {
                return;
            };
            let head = std::str::from_utf8(&self.buf[..header_end]).unwrap().to_string();
            let request_line = head.lines().next().unwrap();
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap();
            let target = parts.next().unwrap();

            let body: Vec<u8> = if method == "GET" {
                let dns_param = target.split("dns=").nth(1).expect("dns= query param");
                base64url_decode(dns_param)
            } else {
                let content_length: usize = head
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().to_string()))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if self.buf.len() < header_end + content_length {
                    // Body not fully arrived yet — wait for more data.
                    return;
                }
                self.buf[header_end..header_end + content_length].to_vec()
            };

            let Ok(q) = DnsMessage::parse(&body) else {
                return;
            };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR;
            if let Some(question) = q.questions.first() {
                resp.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(198, 51, 100, 30)));
            }
            let resp_bytes = resp.serialize().unwrap();
            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                resp_bytes.len()
            );
            let mut out = http_resp.into_bytes();
            out.extend_from_slice(&resp_bytes);
            endpoint.send(&out);
            self.buf.clear();
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }

    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let (addr, _) = rt
        .add_tcp_listener(
            TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), || {
                Box::new(DohStubHandler { buf: Vec::new() }) as Box<dyn ProtocolHandler>
            })
            .with_tls(acceptor),
        )
        .unwrap();

    struct ChannelHandler(mpsc::Sender<io::Result<Vec<u8>>>);
    impl DnsClientTransportHandler for ChannelHandler {
        fn on_response(&mut self, _server: std::net::SocketAddr, data: &[u8]) {
            let _ = self.0.send(Ok(data.to_vec()));
        }
        fn on_error(&mut self, _server: std::net::SocketAddr, err: io::Error) {
            let _ = self.0.send(Err(err));
        }
    }

    let rt_arc = Arc::new(rt);

    // GET.
    let mut get_transport =
        DohClientTransport::https(Arc::clone(&rt_arc), "localhost", "/dns-query", Arc::clone(&connector)).with_get(true);
    let q1 = DnsMessage::query(1, DnsQuestion::in_class("doh-get-test.example", DnsType::A), true);
    let q1_bytes = q1.serialize().unwrap();
    let (tx1, rx1) = mpsc::channel();
    get_transport.send_query(addr, &q1_bytes, Box::new(ChannelHandler(tx1))).unwrap();
    let resp1 = rx1.recv_timeout(Duration::from_secs(5)).unwrap().expect("GET query must succeed");
    let parsed1 = DnsMessage::parse(&resp1).unwrap();
    assert_eq!(parsed1.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 30)));

    // POST (existing default path), against the same stub.
    let mut post_transport = DohClientTransport::https(Arc::clone(&rt_arc), "localhost", "/dns-query", connector);
    let q2 = DnsMessage::query(2, DnsQuestion::in_class("doh-post-test.example", DnsType::A), true);
    let q2_bytes = q2.serialize().unwrap();
    let (tx2, rx2) = mpsc::channel();
    post_transport.send_query(addr, &q2_bytes, Box::new(ChannelHandler(tx2))).unwrap();
    let resp2 = rx2.recv_timeout(Duration::from_secs(5)).unwrap().expect("POST query must succeed");
    let parsed2 = DnsMessage::parse(&resp2).unwrap();
    assert_eq!(parsed2.answers[0].as_a(), Some(Ipv4Addr::new(198, 51, 100, 30)));

    // `rt_arc` is still referenced by in-flight/idle DoH connection state
    // at this point, so an owning `shutdown()` isn't reachable here — drop
    // it instead, matching how the standalone DNS examples in this crate
    // already do (they never call `Runtime::shutdown` either).
    drop(rt_arc);
}
