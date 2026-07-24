// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in integration tests: real loopback TCP/TLS/DNS and filesystem I/O.
//!
//! These are deliberately excluded from CI. Run them manually with:
//! `cargo test -p hopf-smtp --features integration`.

#![cfg(feature = "integration")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_tls::acceptor_from_pem;

use crate::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, SmtpClientBuilder, SmtpConfig, SmtpService,
};

fn start_accept_all(capture: Arc<Mutex<Vec<u8>>>) -> (Arc<Runtime>, SocketAddr) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "test.example.com");
    let handler = AcceptAllSmtpHandler::new("test.example.com").with_capture(capture);
    let factory = Arc::new(AcceptAllSmtpHandlerFactory::new(handler));
    let service = SmtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

#[test]
fn client_send_captured() {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let (_rt, bound) = start_accept_all(Arc::clone(&capture));

    let mut c = SmtpClientBuilder::new()
        .timeout(Duration::from_secs(3))
        .connect(bound)
        .unwrap();
    assert_eq!(c.welcome().code, 220);
    c.ehlo("client.example").unwrap();
    c.mail("from@example.com").unwrap();
    c.rcpt("to@example.com").unwrap();
    let body = b"Subject: hi\r\n\r\nhello smtp\r\n";
    c.data(body).unwrap();
    c.quit().unwrap();

    // Allow handler to finish.
    std::thread::sleep(Duration::from_millis(50));
    let got = capture.lock().unwrap().clone();
    assert!(
        got.windows(b"hello smtp".len()).any(|w| w == b"hello smtp"),
        "capture={got:?}"
    );
}

#[test]
fn client_starttls_send() {
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

    let capture = Arc::new(Mutex::new(Vec::new()));
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "test.example.com").with_tls(acceptor);
    let handler = AcceptAllSmtpHandler::new("test.example.com").with_capture(Arc::clone(&capture));
    let factory = Arc::new(AcceptAllSmtpHandlerFactory::new(handler));
    let service = SmtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client_tls = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let mut c = SmtpClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .tls(client_tls, "localhost")
        .connect(bound)
        .unwrap();
    c.ehlo("client.example").unwrap();
    assert!(c.has_capability("STARTTLS"));
    c.starttls().unwrap();
    c.ehlo("client.example").unwrap();
    c.mail("a@b.com").unwrap();
    c.rcpt("c@d.com").unwrap();
    c.data(b"Subject: tls\r\n\r\nsecret\r\n").unwrap();
    c.quit().unwrap();

    std::thread::sleep(Duration::from_millis(50));
    let got = capture.lock().unwrap().clone();
    assert!(
        got.windows(b"secret".len()).any(|w| w == b"secret"),
        "capture={got:?}"
    );
}

#[test]
fn simple_relay_mx_to_local_sink() {
    use crate::{SimpleRelayService, SmtpClientBuilder, SmtpConfig};
    use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;
    use std::net::Ipv4Addr;
    use std::thread;

    // Sink SMTP that captures the forwarded message.
    let capture = Arc::new(Mutex::new(Vec::new()));
    let (rt, sink_addr) = start_accept_all(Arc::clone(&capture));

    // DNS stub: MX for example.com → mx.example.com, A → 127.0.0.1
    let stub = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = stub.recv_from(&mut buf) else {
                break;
            };
            let Ok(q) = DnsMessage::parse(&buf[..n]) else {
                continue;
            };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR | FLAG_RA;
            if let Some(question) = q.questions.first() {
                match question.qtype {
                    DnsType::Mx => {
                        // Literal exchange skips A/AAAA and dials 127.0.0.1:outbound_port.
                        resp.answers.push(
                            DnsResourceRecord::mx(&question.name, 60, 10, "127.0.0.1").unwrap(),
                        );
                    }
                    DnsType::A => {
                        resp.answers.push(DnsResourceRecord::a(
                            &question.name,
                            60,
                            Ipv4Addr::new(127, 0, 0, 1),
                        ));
                    }
                    DnsType::Aaaa => {}
                    _ => {}
                }
            }
            let bytes = resp.serialize().unwrap();
            let _ = stub.send_to(&bytes, peer);
        }
    });

    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    dns.add_server(stub_addr);
    dns.set_timeout(Duration::from_millis(500));
    dns.open().unwrap();

    let relay_listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(relay_listen, "relay.example.com");
    let relay = SimpleRelayService::with_resolver(config, Arc::clone(&rt), dns, sink_addr.port());
    let relay_addr = relay.start(Arc::clone(&rt)).unwrap();

    let mut c = SmtpClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect(relay_addr)
        .unwrap();
    c.ehlo("client.example").unwrap();
    c.mail("alice@elsewhere.test").unwrap();
    c.rcpt("bob@example.com").unwrap();
    c.data(b"Subject: relay\r\n\r\nrelayed-body\r\n").unwrap();
    c.quit().unwrap();

    for _ in 0..100 {
        let got = capture.lock().unwrap().clone();
        if got
            .windows(b"relayed-body".len())
            .any(|w| w == b"relayed-body")
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let got = capture.lock().unwrap().clone();
    panic!("sink did not receive relayed message: {got:?}");
}

#[test]
fn local_delivery_appends_to_maildir() {
    use crate::{LocalDeliveryService, SmtpClientBuilder, SmtpConfig};
    use hopf_mailbox::MaildirFactory;
    use std::thread;

    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "mail.example.com");
    let svc = LocalDeliveryService::new(config, Arc::clone(&rt), factory, "example.com");
    let addr = svc.start(Arc::clone(&rt)).unwrap();

    let mut c = SmtpClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .connect(addr)
        .unwrap();
    c.ehlo("client.example").unwrap();
    c.mail("alice@elsewhere.test").unwrap();
    // Wrong domain → relay denied
    assert!(c.rcpt("bob@other.example").is_err());
    c.rcpt("bob@example.com").unwrap();
    c.rcpt("carol@example.com").unwrap();
    c.data(b"Subject: local\r\n\r\nlocal-body\r\n").unwrap();
    c.quit().unwrap();

    // Allow storage pool to finish APPENDs (Maildir++ end_append → cur/).
    let mut found_bob = false;
    let mut found_carol = false;
    for _ in 0..100 {
        for (user, found) in [("bob", &mut found_bob), ("carol", &mut found_carol)] {
            let cur = dir.path().join(user).join("cur");
            if !cur.is_dir() {
                continue;
            }
            for ent in std::fs::read_dir(&cur).unwrap() {
                let p = ent.unwrap().path();
                if p.is_file() {
                    let bytes = std::fs::read(&p).unwrap();
                    if bytes
                        .windows(b"local-body".len())
                        .any(|w| w == b"local-body")
                    {
                        *found = true;
                    }
                }
            }
        }
        if found_bob && found_carol {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("maildir delivery incomplete: bob={found_bob} carol={found_carol}");
}
