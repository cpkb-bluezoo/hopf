// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in integration tests: real loopback TCP/TLS and filesystem I/O.
//!
//! These are deliberately excluded from CI. Run them manually with:
//! `cargo test -p hopf-smtp --features integration`.

#![cfg(feature = "integration")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_tls::{acceptor_from_pem, connector};

use crate::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, SmtpClient, SmtpClientTimeouts, SmtpConfig,
    SmtpSend, SmtpService,
};

/// Helper: spin-wait up to `max` millis for `pred` to return true.
fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
    for _ in 0..(max_ms / 10) {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pred()
}

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

/// Send one message to a server, wait for async completion, return outcome.
fn send_one(
    rt: &Arc<Runtime>,
    addr: SocketAddr,
    timeouts: SmtpClientTimeouts,
    from: &str,
    to: &str,
    body: &[u8],
) -> bool {
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let send = SmtpSend::new("client.example")
        .mail_from(from)
        .rcpt_to(to)
        .message(body.to_vec())
        .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));
    SmtpClient::from_addr(addr)
        .timeouts(timeouts)
        .connect(rt, Arc::new(send))
        .unwrap();
    wait_for(|| done.lock().unwrap().is_some(), 3000);
    let outcome = done.lock().unwrap().unwrap_or(false);
    outcome
}

#[test]
fn client_send_captured() {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let (rt, bound) = start_accept_all(Arc::clone(&capture));

    let timeouts = SmtpClientTimeouts {
        stage: Duration::from_secs(3),
        ..Default::default()
    };
    let ok = send_one(
        &rt,
        bound,
        timeouts,
        "from@example.com",
        "to@example.com",
        b"Subject: hi\r\n\r\nhello smtp\r\n",
    );
    assert!(ok, "delivery should succeed");

    // Allow handler to finish writing capture.
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
    let client_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tls_connector = connector(client_config);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let send = SmtpSend::new("client.example")
        .mail_from("a@b.com")
        .rcpt_to("c@d.com")
        .message(b"Subject: tls\r\n\r\nsecret\r\n".to_vec())
        .require_starttls(true)
        .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

    SmtpClient::from_addr(bound)
        .starttls(tls_connector, "localhost")
        .timeouts(SmtpClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        })
        .connect(&rt, Arc::new(send))
        .unwrap();

    assert!(
        wait_for(|| done.lock().unwrap().is_some(), 5000),
        "tls delivery timed out"
    );
    assert_eq!(*done.lock().unwrap(), Some(true), "tls delivery failed");

    std::thread::sleep(Duration::from_millis(50));
    let got = capture.lock().unwrap().clone();
    assert!(
        got.windows(b"secret".len()).any(|w| w == b"secret"),
        "capture={got:?}"
    );
}

#[test]
fn simple_relay_mx_to_local_sink() {
    use crate::{SimpleRelayService, SmtpConfig};
    use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;
    use std::net::Ipv4Addr;
    use std::thread;

    // Sink SMTP that captures the forwarded message.
    let capture = Arc::new(Mutex::new(Vec::new()));
    let (rt, sink_addr) = start_accept_all(Arc::clone(&capture));

    // DNS stub: MX for example.com → 127.0.0.1.
    let stub = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = stub.recv_from(&mut buf) else { break };
            let Ok(q) = DnsMessage::parse(&buf[..n]) else { continue };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR | FLAG_RA;
            if let Some(question) = q.questions.first() {
                match question.qtype {
                    Some(DnsType::Mx) => {
                        resp.answers.push(
                            DnsResourceRecord::mx(&question.name, 60, 10, "127.0.0.1").unwrap(),
                        );
                    }
                    Some(DnsType::A) => {
                        resp.answers.push(DnsResourceRecord::a(
                            &question.name,
                            60,
                            Ipv4Addr::new(127, 0, 0, 1),
                        ));
                    }
                    Some(DnsType::Aaaa) => {}
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
    let relay =
        SimpleRelayService::with_resolver(config, Arc::clone(&rt), dns, sink_addr.port());
    let relay_addr = relay.start(Arc::clone(&rt)).unwrap();

    // Submit via async client to the relay.
    let timeouts = SmtpClientTimeouts {
        stage: Duration::from_secs(5),
        ..Default::default()
    };
    let ok = send_one(
        &rt,
        relay_addr,
        timeouts,
        "alice@elsewhere.test",
        "bob@example.com",
        b"Subject: relay\r\n\r\nrelayed-body\r\n",
    );
    assert!(ok, "relay inbound submission should succeed");

    // Allow relay async outbound delivery to complete.
    assert!(
        wait_for(
            || {
                let got = capture.lock().unwrap().clone();
                got.windows(b"relayed-body".len())
                    .any(|w| w == b"relayed-body")
            },
            5000
        ),
        "sink did not receive relayed message"
    );
}

#[test]
fn local_delivery_appends_to_maildir() {
    use crate::{LocalDeliveryService, SmtpConfig};
    use hopf_mailbox::MaildirFactory;

    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "mail.example.com");
    let svc = LocalDeliveryService::new(config, Arc::clone(&rt), factory, "example.com");
    let addr = svc.start(Arc::clone(&rt)).unwrap();

    let timeouts = SmtpClientTimeouts {
        stage: Duration::from_secs(5),
        ..Default::default()
    };
    let ok = send_one(
        &rt,
        addr,
        timeouts,
        "alice@elsewhere.test",
        "bob@example.com",
        b"Subject: local\r\n\r\nlocal-body\r\n",
    );
    assert!(ok, "local delivery submission should succeed");

    // Wait for Maildir++ APPEND to complete.
    let found = wait_for(
        || {
            let cur = dir.path().join("bob").join("cur");
            if !cur.is_dir() {
                return false;
            }
            for ent in std::fs::read_dir(&cur).unwrap() {
                let p = ent.unwrap().path();
                if p.is_file() {
                    let bytes = std::fs::read(&p).unwrap();
                    if bytes.windows(b"local-body".len()).any(|w| w == b"local-body") {
                        return true;
                    }
                }
            }
            false
        },
        5000,
    );
    assert!(found, "maildir delivery incomplete");
}
