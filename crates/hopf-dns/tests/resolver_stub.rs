// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Local UDP stub ↔ DnsResolver smoke (no external network).

use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::wire::{DnsMessage, DnsResourceRecord, FLAG_QR, FLAG_RA};
use hopf_dns::DnsResolver;

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
