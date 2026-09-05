// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in integration tests: real loopback TCP/TLS and filesystem I/O.
//!
//! These are deliberately excluded from CI. Run them manually with:
//! `cargo test -p hopf-smtp --features integration`.

#![cfg(feature = "integration")]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmimeparser::EmailAddress;

use hopf_auth::{
    CertificateIdentity, Cb, CredentialStore, PasswordStore, ScramCredentials, SaslMechanism,
    TokenValidation,
};
use hopf_core::retry::RetryPolicy;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_tls::{acceptor_from_pem, connector};

use crate::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, AuthenticateState, ConnectedState,
    DsnRecipientParams, HelloHandler, HelloState, MailFromHandler, MailFromState,
    MessageDataHandler, MessageEndState, MessageStartState, RecipientHandler, RecipientState,
    ResetState, RetryingSend, SmtpClient, SmtpClientConnected, SmtpClientTimeouts, SmtpConfig,
    SmtpConnectionMetadata, SmtpHandlerFactory, SmtpPipeline, SmtpSend, SmtpSendOutcome,
    SmtpService, smtp_retry_policy,
};

/// Test helper: a one-shot `message_with` source yielding `bytes` once.
fn once(bytes: Vec<u8>) -> impl FnMut() -> Option<Vec<u8>> + Send {
    let mut bytes = Some(bytes);
    move || bytes.take()
}

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
    let config = SmtpConfig::new(listen, "test.example.com").auth_required(false);
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
        .message_with(once(body.to_vec()))
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

/// The server advertises CHUNKING (BDAT), and a real BDAT client sends
/// `BDAT size LAST\r\n` immediately followed by that many raw bytes in one
/// write, with no round trip in between (RFC 3030) — exactly what
/// `SmtpClient`'s own auto-pilot does whenever CHUNKING is advertised. Both
/// pieces routinely land in the same `receive()` call; previously the
/// server's line lexer kept scanning past the `BDAT` line and misparsed the
/// message body (which itself contains CRLFs) as further bogus commands,
/// rejecting every such delivery (issue #218).
#[test]
fn bdat_command_and_payload_in_one_write_is_not_misparsed() {
    let capture = Arc::new(Mutex::new(Vec::new()));
    let (rt, addr) = start_accept_all(Arc::clone(&capture));

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("\r\n"));

    write_cmd(&mut stream, b"EHLO client.example\r\n");
    let ehlo = read_until(&mut stream, &mut buf, |s| s.contains("250 "));
    assert!(ehlo.contains("CHUNKING"), "{ehlo}");

    write_cmd(&mut stream, b"MAIL FROM:<from@example.com>\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with('2') || s.starts_with('5')).starts_with("250"));

    write_cmd(&mut stream, b"RCPT TO:<to@example.com>\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with('2') || s.starts_with('5')).starts_with("250"));

    let body: &[u8] = b"Subject: hi\r\n\r\nhello smtp\r\n";
    let mut single_write = format!("BDAT {} LAST\r\n", body.len()).into_bytes();
    single_write.extend_from_slice(body);
    write_cmd(&mut stream, &single_write);

    let reply = read_until(&mut stream, &mut buf, |s| s.starts_with('2') || s.starts_with('5'));
    assert!(reply.starts_with("250"), "BDAT delivery must succeed, not be misparsed: {reply}");
    drop(rt);
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
    let config = SmtpConfig::new(listen, "test.example.com")
        .auth_required(false)
        .with_tls(acceptor);
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
        .message_with(once(b"Subject: tls\r\n\r\nsecret\r\n".to_vec()))
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

fn start_smtp_server_with_store(store: Arc<PasswordStore>) -> (Arc<Runtime>, SocketAddr) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "test.example.com").with_store(store);
    let handler = AcceptAllSmtpHandler::new("test.example.com");
    let factory = Arc::new(AcceptAllSmtpHandlerFactory::new(handler));
    let service = SmtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

/// Like [`start_smtp_server_with_store`], but with a caller-supplied
/// [`CredentialStore`] — used with [`SlowStore`] to widen the async SASL
/// step offload's window for pipelining regression tests (issue #181).
fn start_smtp_server_with_credential_store(store: Arc<dyn CredentialStore>) -> (Arc<Runtime>, SocketAddr) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "test.example.com").with_store(store);
    let handler = AcceptAllSmtpHandler::new("test.example.com");
    let factory = Arc::new(AcceptAllSmtpHandlerFactory::new(handler));
    let service = SmtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

/// A store enrolling "alice"/"secret" that can drive CRAM-MD5 and
/// DIGEST-MD5, not just SCRAM-SHA-256 — [`start_smtp_server_with_store`]'s
/// bare `PasswordStore` deliberately can't (see [`SlowStore`]'s doc
/// comment), and has no digest realm set, so it can't either.
fn cram_and_digest_capable_store() -> Arc<dyn CredentialStore> {
    Arc::new(SlowStore {
        inner: PasswordStore::new()
            .with_digest_realm("test.example.com")
            .with_user("alice", "secret"),
        delay: Duration::ZERO,
    })
}

/// Wraps a [`PasswordStore`] and sleeps inside `password_match`/
/// `plaintext_password` — deterministically widens the window a credential
/// check spends offloaded to the storage pool (issue #181), so a
/// pipelining regression test can reliably observe whether a command sent
/// right behind AUTH gets processed (or in SMTP's case, soft-rejected)
/// before or after the check resolves, rather than depending on the
/// storage thread happening to be slow by chance.
struct SlowStore {
    inner: PasswordStore,
    delay: Duration,
}

impl CredentialStore for SlowStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        // `plaintext_password` below always resolves for enrolled users, so
        // unlike `PasswordStore` this store really can drive CRAM-MD5 —
        // advertise it (issue #218).
        let mut mechs = self.inner.supported_mechanisms();
        mechs.push(SaslMechanism::CramMd5);
        mechs
    }
    fn password_match(&self, username: &str, password: &str) -> bool {
        std::thread::sleep(self.delay);
        self.inner.password_match(username, password)
    }
    fn plaintext_password(&self, username: &str) -> Option<String> {
        // `PasswordStore` deliberately discards plaintext after enrollment
        // and so can't drive CRAM-MD5, which needs a recoverable secret —
        // override it here so `SlowStore` can, since CRAM-MD5's
        // server-first, multi-round-trip shape is what the AUTH pipelining
        // test below needs to exercise the `first_step`/continuation
        // offload path. CRAM-MD5 verification goes through this method
        // (not `password_match`), so it needs the same delay.
        std::thread::sleep(self.delay);
        (username == "alice").then(|| "secret".to_string())
    }
    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String> {
        self.inner.digest_ha1(username, realm)
    }
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        self.inner.scram_credentials(username)
    }
    fn validate_bearer(&self, token: &str, cb: Cb<Option<TokenValidation>>) {
        self.inner.validate_bearer(token, cb)
    }
    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        self.inner.authenticate_certificate(cert_key)
    }
}

fn write_cmd(stream: &mut TcpStream, cmd: &[u8]) {
    stream.write_all(cmd).unwrap();
    stream.flush().unwrap();
}

/// Read until `pred` matches the accumulated text (bounded by read timeout).
fn read_until(stream: &mut TcpStream, buf: &mut [u8], pred: impl Fn(&str) -> bool) -> String {
    let mut acc = String::new();
    for _ in 0..100 {
        match stream.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(std::str::from_utf8(&buf[..n]).unwrap_or(""));
                if pred(&acc) {
                    return acc;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read error: {e}"),
        }
    }
    acc
}

/// SMTP AUTH must drive the full mechanism menu, not just PLAIN — matching
/// the pattern already established for hopf-pop3/hopf-imap (#111).
#[test]
fn smtp_auth_cram_md5_raw() {
    let (rt, addr) = start_smtp_server_with_credential_store(cram_and_digest_capable_store());

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("220 "));

    write_cmd(&mut stream, b"EHLO client.example\r\n");
    let ehlo = read_until(&mut stream, &mut buf, |s| s.contains("250 "));
    assert!(ehlo.contains("CRAM-MD5"), "expected CRAM-MD5 in {ehlo}");

    write_cmd(&mut stream, b"AUTH CRAM-MD5\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.starts_with("334 "));
    let b64 = r.trim().strip_prefix("334 ").expect("continuation prefix");
    let challenge = String::from_utf8(rmimeparser::charset::base64::decode(b64).unwrap())
        .expect("challenge is ASCII");
    let digest = hopf_auth::cram_md5::compute_response("secret", &challenge);
    let response = format!("alice {digest}");
    write_cmd(
        &mut stream,
        format!(
            "{}\r\n",
            rmimeparser::charset::base64::encode(response.as_bytes())
        )
        .as_bytes(),
    );
    let r = read_until(&mut stream, &mut buf, |s| s.starts_with("235 ") || s.starts_with("535 "));
    assert!(r.starts_with("235 "), "authenticate cram-md5: {r}");

    write_cmd(&mut stream, b"MAIL FROM:<a@b.com>\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.starts_with("250 ") || s.starts_with("5"));
    assert!(r.starts_with("250 "), "mail from after CRAM-MD5 auth: {r}");
    drop(rt);
}

/// LOGIN requires TLS — over a plain connection it must be refused up
/// front, never even reaching the username challenge.
#[test]
fn smtp_auth_login_mechanism_requires_tls() {
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let (rt, addr) = start_smtp_server_with_store(store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("220 "));
    write_cmd(&mut stream, b"EHLO client.example\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("250 "));

    write_cmd(&mut stream, b"AUTH LOGIN\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.starts_with("538 ") || s.starts_with("334 "));
    assert!(
        r.starts_with("538 "),
        "LOGIN mechanism must be refused without TLS: {r}"
    );
    drop(rt);
}

#[test]
fn smtp_auth_unsupported_mechanism_is_rejected() {
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let (rt, addr) = start_smtp_server_with_store(store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("220 "));
    write_cmd(&mut stream, b"EHLO client.example\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("250 "));

    write_cmd(&mut stream, b"AUTH GSSAPI\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.starts_with("504 "));
    assert!(r.starts_with("504 "), "GSSAPI is not implemented: {r}");
    drop(rt);
}

/// EHLO's AUTH line must list every mechanism the store can drive,
/// filtered by TLS requirement — not just a hardcoded `AUTH PLAIN`.
#[test]
fn smtp_ehlo_lists_mechanisms_filtered_by_tls() {
    let (rt, addr) = start_smtp_server_with_credential_store(cram_and_digest_capable_store());

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("220 "));
    write_cmd(&mut stream, b"EHLO client.example\r\n");
    let ehlo = read_until(&mut stream, &mut buf, |s| s.contains("250 "));

    for present in ["CRAM-MD5", "DIGEST-MD5", "SCRAM-SHA-256"] {
        assert!(ehlo.contains(present), "expected {present} in {ehlo}");
    }
    for absent in ["PLAIN", "LOGIN", "OAUTHBEARER", "EXTERNAL"] {
        assert!(
            !ehlo.contains(absent),
            "{absent} requires TLS, must not be advertised on a plain connection: {ehlo}"
        );
    }
    drop(rt);
}

/// `SmtpSend`'s auto-pilot must drive the full client-side SASL exchange
/// (#114), not just PLAIN — including absorbing SCRAM-SHA-256's trailing
/// `v=` verifier continuation rather than treating it as an abort-worthy
/// unexpected challenge.
#[test]
fn client_auth_scram_send() {
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let capture = Arc::new(Mutex::new(Vec::new()));
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "test.example.com").with_store(store);
    let handler = AcceptAllSmtpHandler::new("test.example.com").with_capture(Arc::clone(&capture));
    let factory = Arc::new(AcceptAllSmtpHandlerFactory::new(handler));
    let service = SmtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let send = SmtpSend::new("client.example")
        .mail_from("a@b.com")
        .rcpt_to("c@d.com")
        .message_with(once(b"Subject: scram\r\n\r\nauthenticated hello\r\n".to_vec()))
        .auth_plain("alice", "secret")
        .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

    SmtpClient::from_addr(bound)
        .timeouts(SmtpClientTimeouts {
            stage: Duration::from_secs(3),
            ..Default::default()
        })
        .connect(&rt, Arc::new(send))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 3000), "delivery timed out");
    assert_eq!(*done.lock().unwrap(), Some(true), "SCRAM-authenticated delivery should succeed");

    std::thread::sleep(Duration::from_millis(50));
    let got = capture.lock().unwrap().clone();
    assert!(
        got.windows(b"authenticated hello".len()).any(|w| w == b"authenticated hello"),
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
    let config = SmtpConfig::new(relay_listen, "relay.example.com").auth_required(false);
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

/// One recipient domain resolves to a real sink (delivery succeeds), the
/// other resolves to an address nothing is listening on (delivery fails).
/// Proves two things: (1) the relay waits for each domain's *real*
/// `SmtpSend` completion instead of counting a domain "delivered" the
/// instant the outbound connect call was issued, and (2) partial success
/// accepts the inbound transaction (250) so clients do not retry and
/// duplicate the already-delivered copy — failure DSNs cover the rest.
#[test]
fn simple_relay_accepts_transaction_on_partial_domain_success() {
    use crate::{SimpleRelayService, SmtpConfig};
    use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;
    use std::net::Ipv4Addr;
    use std::thread;

    let capture = Arc::new(Mutex::new(Vec::new()));
    let (rt, sink_addr) = start_accept_all(Arc::clone(&capture));

    // DNS stub: good.example -> 127.0.0.1 (the real sink) resolves
    // normally; bad.example's MX resolves but its A lookup comes back empty
    // (NODATA) — a pure DNS-level failure, deterministic and fast,
    // independent of how this sandbox's network stack happens to handle a
    // TCP connect to an address nothing is listening on.
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
                let is_bad = question.name.to_ascii_lowercase().starts_with("bad.");
                match question.qtype {
                    Some(DnsType::Mx) => {
                        resp.answers
                            .push(DnsResourceRecord::mx(&question.name, 60, 10, &question.name).unwrap());
                    }
                    Some(DnsType::A) if !is_bad => {
                        resp.answers.push(DnsResourceRecord::a(
                            &question.name,
                            60,
                            Ipv4Addr::new(127, 0, 0, 1),
                        ));
                    }
                    // bad.example's A lookup answers NOERROR/NODATA — no
                    // address, so the relay's resolve() call fails cleanly.
                    Some(DnsType::A) | Some(DnsType::Aaaa) => {}
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
    let config = SmtpConfig::new(relay_listen, "relay.example.com").auth_required(false);
    let relay = SimpleRelayService::with_resolver(config, Arc::clone(&rt), dns, sink_addr.port());
    let relay_addr = relay.start(Arc::clone(&rt)).unwrap();

    let timeouts = SmtpClientTimeouts {
        stage: Duration::from_secs(2),
        message: Duration::from_secs(3),
        ..Default::default()
    };
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let send = SmtpSend::new("client.example")
        .mail_from("alice@elsewhere.test")
        .rcpt_to("bob@good.example")
        .rcpt_to("carol@bad.example")
        .message_with(once(b"Subject: partial\r\n\r\npartial-fanout-body\r\n".to_vec()))
        .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));
    SmtpClient::from_addr(relay_addr)
        .timeouts(timeouts)
        .connect(&rt, Arc::new(send))
        .unwrap();
    assert!(
        wait_for(|| done.lock().unwrap().is_some(), 5000),
        "relay submission timed out"
    );

    // The good domain's delivery — streamed from the spool file — went through.
    assert!(
        wait_for(
            || {
                let got = capture.lock().unwrap().clone();
                got.windows(b"partial-fanout-body".len())
                    .any(|w| w == b"partial-fanout-body")
            },
            5000
        ),
        "the succeeding domain should still have received the message"
    );

    // Partial success must accept the inbound transaction so a client
    // retry does not duplicate the already-delivered copy.
    assert_eq!(
        *done.lock().unwrap(),
        Some(true),
        "any domain succeeding must accept the transaction"
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
    let config = SmtpConfig::new(listen, "mail.example.com").auth_required(false);
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

/// AUTH's SASL step runs off the reactor thread (issue #181), using
/// CRAM-MD5 — a server-first, multi-round-trip mechanism whose *first*
/// step offload is the new `first_step` code path added for this issue.
/// A command pipelined right behind the continuation response, in the same
/// write, must be soft-rejected (matching the existing `Delivering`-state
/// precedent) rather than processed against stale pre-auth state — and the
/// AUTH exchange itself must still complete correctly once the offloaded
/// step resolves. `SlowStore` widens the offload's window so this is
/// reliably observable rather than a timing coincidence.
#[test]
fn smtp_auth_pipelined_with_mail_from_is_soft_rejected_until_async_step_resolves() {
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: PasswordStore::new().with_user("alice", "secret"),
        delay: Duration::from_millis(150),
    });
    let (rt, addr) = start_smtp_server_with_credential_store(store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("220 "));

    write_cmd(&mut stream, b"EHLO client.example\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("250 "));

    write_cmd(&mut stream, b"AUTH CRAM-MD5\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.starts_with("334 "));
    let b64 = r.trim().strip_prefix("334 ").expect("continuation prefix");
    let challenge = String::from_utf8(rmimeparser::charset::base64::decode(b64).unwrap())
        .expect("challenge is ASCII");
    let digest = hopf_auth::cram_md5::compute_response("secret", &challenge);
    let response = rmimeparser::charset::base64::encode(format!("alice {digest}").as_bytes());

    // One write, both commands — proves the pipelined MAIL FROM was
    // actually sitting on the wire during the offloaded step, not just
    // sent afterward by coincidence.
    write_cmd(&mut stream, format!("{response}\r\nMAIL FROM:<a@b.com>\r\n").as_bytes());

    let r = read_until(&mut stream, &mut buf, |s| {
        s.contains("235 ") && (s.contains("451 ") || s.contains("250 "))
    });
    assert!(r.contains("235 "), "authenticate cram-md5: {r}");
    assert!(
        r.contains("451 "),
        "MAIL FROM pipelined behind the AUTH continuation must be soft-\
         rejected while the SASL step is still offloaded, not processed \
         early: {r}"
    );

    // Now that AUTH has resolved, the same command must go through cleanly.
    write_cmd(&mut stream, b"MAIL FROM:<a@b.com>\r\n");
    let r2 = read_until(&mut stream, &mut buf, |s| s.starts_with("250 ") || s.starts_with("5"));
    assert!(r2.starts_with("250 "), "mail from after CRAM-MD5 auth: {r2}");
    drop(rt);
}

// ── Regression tests for issue #344 (SMTP-aligned retry strategy) ──────────

/// Server-side handler that accepts HELO/MAIL/RCPT unconditionally, then
/// rejects at message-completion time with a scripted reply code for the
/// first `reject_first_n` connection attempts (counted via `attempts`,
/// shared across every clone the factory hands out — one per accepted
/// connection, i.e. one per [`RetryingSend`] dial), accepting from then on.
#[derive(Clone)]
struct ScriptedMessageHandler {
    hostname: String,
    attempts: Arc<AtomicUsize>,
    reject_first_n: usize,
    reject_code: u16,
}

impl SmtpClientConnected for ScriptedMessageHandler {
    fn connected(&mut self, state: &mut dyn ConnectedState, _meta: &SmtpConnectionMetadata) {
        let greeting = format!("{} ESMTP Hopf", self.hostname);
        state.accept_connection(&greeting, Box::new(self.clone()));
    }

    fn disconnected(&mut self) {}
}

impl HelloHandler for ScriptedMessageHandler {
    fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
        state.accept_hello(Box::new(self.clone()));
    }

    fn tls_established(&mut self, _info: &hopf_core::SecurityInfo) {}

    fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
        state.accept(Box::new(self.clone()));
    }

    fn quit(&mut self) {}
}

impl MailFromHandler for ScriptedMessageHandler {
    fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
        None
    }

    fn mail_from(
        &mut self,
        state: &mut dyn MailFromState,
        _sender: Option<&EmailAddress>,
        _smtputf8: bool,
        _delivery: &crate::DeliveryRequirements,
    ) {
        state.accept_sender(Box::new(self.clone()));
    }

    fn reset(&mut self, state: &mut dyn ResetState) {
        state.accept_reset(Box::new(self.clone()));
    }

    fn quit(&mut self) {}
}

impl RecipientHandler for ScriptedMessageHandler {
    fn rcpt_to(
        &mut self,
        state: &mut dyn RecipientState,
        _recipient: &EmailAddress,
        _dsn: &DsnRecipientParams,
    ) {
        state.accept_recipient(Box::new(self.clone()));
    }

    fn start_message(&mut self, state: &mut dyn MessageStartState) {
        state.accept_message(Box::new(self.clone()));
    }

    fn reset(&mut self, state: &mut dyn ResetState) {
        state.accept_reset(Box::new(self.clone()));
    }

    fn quit(&mut self) {}
}

impl MessageDataHandler for ScriptedMessageHandler {
    fn message_content(&mut self, _chunk: &[u8]) {}

    fn message_complete(&mut self, state: &mut dyn MessageEndState) {
        let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if attempt <= self.reject_first_n {
            state.reject(self.reject_code, "scripted rejection", Box::new(self.clone()));
        } else {
            state.accept_message_delivery(None, Box::new(self.clone()));
        }
    }

    fn message_aborted(&mut self) {}
}

#[derive(Clone)]
struct ScriptedMessageHandlerFactory(ScriptedMessageHandler);

impl SmtpHandlerFactory for ScriptedMessageHandlerFactory {
    fn create(&self) -> Box<dyn SmtpClientConnected> {
        Box::new(self.0.clone())
    }
}

fn start_scripted_server(reject_first_n: usize, reject_code: u16) -> (Arc<Runtime>, SocketAddr, Arc<AtomicUsize>) {
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = SmtpConfig::new(listen, "test.example.com").auth_required(false);
    let attempts = Arc::new(AtomicUsize::new(0));
    let handler = ScriptedMessageHandler {
        hostname: "test.example.com".into(),
        attempts: Arc::clone(&attempts),
        reject_first_n,
        reject_code,
    };
    let factory = Arc::new(ScriptedMessageHandlerFactory(handler));
    let service = SmtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound, attempts)
}

/// Regression test for issue #344: a server that replies with a transient
/// (4xx) rejection on the first two delivery attempts, then accepts, must
/// end up delivered by [`RetryingSend`] — proving the retry loop actually
/// redials and resends, not just that the policy's math allows it.
#[test]
fn retrying_send_delivers_after_transient_rejections_then_success() {
    let (rt, addr, attempts) = start_scripted_server(2, 452);

    let policy = RetryPolicy::exponential_backoff()
        .with_initial_delay(Duration::from_millis(20))
        .with_max_delay(Duration::from_millis(50))
        .with_max_attempts(5);

    let outcome: Arc<Mutex<Option<SmtpSendOutcome>>> = Arc::new(Mutex::new(None));
    let outcome2 = Arc::clone(&outcome);
    let client = SmtpClient::from_addr(addr).timeouts(SmtpClientTimeouts {
        stage: Duration::from_secs(3),
        ..Default::default()
    });
    let retrying = RetryingSend::new(client, Arc::clone(&rt), policy, || {
        SmtpSend::new("client.example")
            .mail_from("from@example.com")
            .rcpt_to("to@example.com")
            .message_with(once(b"Subject: hi\r\n\r\nhello\r\n".to_vec()))
    })
    .on_final(move |o| *outcome2.lock().unwrap() = Some(o));
    retrying.send();

    assert!(
        wait_for(|| outcome.lock().unwrap().is_some(), 5000),
        "retrying send never reached a final outcome"
    );
    let final_outcome = outcome.lock().unwrap().take().unwrap();
    assert!(
        matches!(final_outcome, SmtpSendOutcome::Delivered),
        "expected eventual delivery, got {final_outcome:?}"
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        3,
        "should have redialed exactly 3 times: 2 rejections + 1 success"
    );
}

/// Regression test for issue #344: a permanent (5xx) rejection must never
/// be retried — [`RetryingSend`] should report failure after exactly one
/// attempt, not redial.
#[test]
fn retrying_send_never_retries_a_permanent_rejection() {
    let (rt, addr, attempts) = start_scripted_server(usize::MAX, 550);

    let policy = RetryPolicy::exponential_backoff()
        .with_initial_delay(Duration::from_millis(20))
        .with_max_delay(Duration::from_millis(50))
        .with_max_attempts(5);

    let outcome: Arc<Mutex<Option<SmtpSendOutcome>>> = Arc::new(Mutex::new(None));
    let outcome2 = Arc::clone(&outcome);
    let client = SmtpClient::from_addr(addr).timeouts(SmtpClientTimeouts {
        stage: Duration::from_secs(3),
        ..Default::default()
    });
    let retrying = RetryingSend::new(client, Arc::clone(&rt), policy, || {
        SmtpSend::new("client.example")
            .mail_from("from@example.com")
            .rcpt_to("to@example.com")
            .message_with(once(b"Subject: hi\r\n\r\nhello\r\n".to_vec()))
    })
    .on_final(move |o| *outcome2.lock().unwrap() = Some(o));
    retrying.send();

    assert!(
        wait_for(|| outcome.lock().unwrap().is_some(), 2000),
        "retrying send never reached a final outcome"
    );
    let final_outcome = outcome.lock().unwrap().take().unwrap();
    assert!(
        matches!(final_outcome, SmtpSendOutcome::Rejected { code: 550, .. }),
        "expected an immediate permanent rejection, got {final_outcome:?}"
    );

    // Give a wrongly-scheduled retry plenty of time to (not) happen.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "a 5xx reply must never be retried"
    );
}

/// Sanity check that [`smtp_retry_policy`]'s RFC 5321-aligned defaults are
/// actually the values the issue calls for, not just "some policy that
/// compiles" — first retry no sooner than 30 minutes, growing but capped
/// well under a day between attempts.
#[test]
fn smtp_retry_policy_matches_rfc_5321_aligned_defaults() {
    let policy = smtp_retry_policy();
    // ±10% jitter is part of the defaults, so check bounds rather than an
    // exact value: RFC 5321 §4.5.4 recommends the first retry be delayed
    // at least 30 minutes.
    let first = policy.delay_for_attempt(1).as_secs();
    assert!(
        (30 * 60 * 9 / 10..=30 * 60 * 11 / 10).contains(&first),
        "expected ~30 minutes (±10% jitter), got {first}s"
    );
    assert!(
        policy.delay_for_attempt(2) > policy.delay_for_attempt(1),
        "backoff should grow between attempts, not stay fixed"
    );
    let capped = policy.delay_for_attempt(20).as_secs();
    assert!(
        capped <= 4 * 60 * 60 * 11 / 10,
        "delay must stay capped well under a day between attempts, got {capped}s"
    );
}

/// End-to-end proof that [`crate::AuthPipeline`] can be returned from
/// [`crate::MailFromHandler::pipeline`], and that its [`crate::AuthVerdictHandle`]
/// correctly drives [`crate::MessageEndState::defer`] / [`crate::DeferredDelivery`]
/// when the DMARC verdict isn't ready by the time `message_complete` runs
/// (which — since DNS answers only ever arrive on a later reactor turn — it
/// never is, so this always exercises the deferred path, not just the
/// already-resolved one).
mod dmarc_pipeline {
    use super::*;
    use crate::auth::dmarc::AuthVerdict;
    use crate::auth::AuthVerdictHandle;
    use crate::{
        AuthPipeline, AuthenticateState, ConnectedState, DeliveryRequirements, DsnRecipientParams,
        HelloHandler, HelloState, MailFromHandler, MailFromState, MessageDataHandler,
        MessageEndState, MessageStartState, RecipientHandler, RecipientState, ResetState,
        SmtpClientConnected, SmtpConnectionMetadata, SmtpHandlerFactory, SmtpPipeline,
    };
    use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;
    use rmimeparser::EmailAddress;
    use std::net::IpAddr;
    use std::thread;

    #[derive(Clone)]
    struct DmarcTestHandler {
        hostname: String,
        dns: Arc<DnsResolver>,
        peer_ip: Option<IpAddr>,
        verdict: Option<AuthVerdictHandle>,
    }

    struct DmarcTestHandlerFactory {
        hostname: String,
        dns: Arc<DnsResolver>,
    }

    impl SmtpHandlerFactory for DmarcTestHandlerFactory {
        fn create(&self) -> Box<dyn SmtpClientConnected> {
            Box::new(DmarcTestHandler {
                hostname: self.hostname.clone(),
                dns: Arc::clone(&self.dns),
                peer_ip: None,
                verdict: None,
            })
        }
    }

    impl SmtpClientConnected for DmarcTestHandler {
        fn connected(&mut self, state: &mut dyn ConnectedState, meta: &SmtpConnectionMetadata) {
            self.peer_ip = Some(meta.peer.ip());
            let greeting = format!("{} ESMTP", self.hostname);
            state.accept_connection(&greeting, Box::new(self.clone()));
        }
        fn disconnected(&mut self) {}
    }

    impl HelloHandler for DmarcTestHandler {
        fn hello(&mut self, state: &mut dyn HelloState, _extended: bool, _hostname: &str) {
            state.accept_hello(Box::new(self.clone()));
        }
        fn tls_established(&mut self, _info: &hopf_core::SecurityInfo) {}
        fn authenticated(&mut self, state: &mut dyn AuthenticateState, _user: &str) {
            state.accept(Box::new(self.clone()));
        }
        fn quit(&mut self) {}
    }

    impl MailFromHandler for DmarcTestHandler {
        fn pipeline(&mut self) -> Option<Box<dyn SmtpPipeline>> {
            let dns_resolver = Arc::clone(&self.dns);
            let dns: Arc<dyn crate::auth::DnsLookup> = dns_resolver;
            let p =
                AuthPipeline::builder(dns, self.peer_ip.unwrap(), self.hostname.clone()).build();
            self.verdict = Some(p.verdict());
            Some(Box::new(p))
        }

        fn mail_from(
            &mut self,
            state: &mut dyn MailFromState,
            _sender: Option<&EmailAddress>,
            _smtputf8: bool,
            _delivery: &DeliveryRequirements,
        ) {
            state.accept_sender(Box::new(self.clone()));
        }
        fn reset(&mut self, state: &mut dyn ResetState) {
            state.accept_reset(Box::new(self.clone()));
        }
        fn quit(&mut self) {}
    }

    impl RecipientHandler for DmarcTestHandler {
        fn rcpt_to(
            &mut self,
            state: &mut dyn RecipientState,
            _recipient: &EmailAddress,
            _dsn: &DsnRecipientParams,
        ) {
            state.accept_recipient(Box::new(self.clone()));
        }
        fn start_message(&mut self, state: &mut dyn MessageStartState) {
            state.accept_message(Box::new(self.clone()));
        }
        fn reset(&mut self, state: &mut dyn ResetState) {
            state.accept_reset(Box::new(self.clone()));
        }
        fn quit(&mut self) {}
    }

    impl MessageDataHandler for DmarcTestHandler {
        // AuthPipeline is registered as the transaction pipeline, so all
        // content goes there, not here (see control.rs `feed_data`).
        fn message_content(&mut self, _chunk: &[u8]) {}

        fn message_complete(&mut self, state: &mut dyn MessageEndState) {
            let verdict = self.verdict.take().expect("pipeline() always sets verdict");
            match verdict.poll() {
                Some(AuthVerdict::Reject) => {
                    state.reject_message_policy(
                        "5.7.1 Rejected by DMARC policy",
                        Box::new(self.clone()),
                    );
                }
                Some(_) => {
                    state.accept_message_delivery(None, Box::new(self.clone()));
                }
                None => {
                    let deferred = state.defer(Box::new(self.clone()));
                    verdict.on_ready(move |v| match v {
                        AuthVerdict::Reject => {
                            deferred.reject(550, "5.7.1 Rejected by DMARC policy")
                        }
                        _ => deferred.accept(None),
                    });
                }
            }
        }

        fn message_aborted(&mut self) {}
    }

    /// DNS stub: TXT records only, driven by a closure so each test can
    /// supply its own zone data.
    fn start_dns_stub(records: Vec<(&'static str, &'static str)>) -> SocketAddr {
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
                    if question.qtype == Some(DnsType::Txt) {
                        for (name, value) in &records {
                            if question.name.eq_ignore_ascii_case(name) {
                                resp.answers.push(
                                    DnsResourceRecord::txt(question.name.clone(), 60, value)
                                        .unwrap(),
                                );
                            }
                        }
                    }
                }
                let bytes = resp.serialize().unwrap();
                let _ = stub.send_to(&bytes, peer);
            }
        });
        stub_addr
    }

    fn start_dmarc_server(
        dns_records: Vec<(&'static str, &'static str)>,
    ) -> (Arc<Runtime>, SocketAddr) {
        let stub_addr = start_dns_stub(dns_records);
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
        dns.add_server(stub_addr);
        dns.set_timeout(Duration::from_millis(500));
        dns.open().unwrap();

        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let config = SmtpConfig::new(listen, "test.example.com").auth_required(false);
        let factory = Arc::new(DmarcTestHandlerFactory {
            hostname: "test.example.com".to_string(),
            dns,
        });
        let service = SmtpService::with_handler_factory(config, factory);
        let bound = service.start(Arc::clone(&rt)).unwrap();
        (rt, bound)
    }

    #[test]
    fn aligned_spf_pass_is_accepted() {
        let (rt, addr) = start_dmarc_server(vec![
            ("example.com", "v=spf1 ip4:127.0.0.1/8 -all"),
            ("_dmarc.example.com", "v=DMARC1; p=reject"),
        ]);
        let timeouts = SmtpClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        };
        let ok = send_one(
            &rt,
            addr,
            timeouts,
            "sender@example.com",
            "bob@elsewhere.test",
            b"From: alice@example.com\r\nSubject: hi\r\n\r\naligned message\r\n",
        );
        assert!(
            ok,
            "SPF-aligned mail should be accepted via the deferred DMARC path"
        );
    }

    #[test]
    fn unaligned_spf_fail_is_rejected_by_dmarc_policy() {
        let (rt, addr) = start_dmarc_server(vec![
            // "attacker.example" publishes no usable SPF authorization for us.
            ("attacker.example", "v=spf1 -all"),
            ("_dmarc.example.com", "v=DMARC1; p=reject"),
        ]);
        let timeouts = SmtpClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        };
        let ok = send_one(
            &rt,
            addr,
            timeouts,
            "sender@attacker.example",
            "bob@elsewhere.test",
            b"From: victim@example.com\r\nSubject: spoofed\r\n\r\nforged message\r\n",
        );
        assert!(!ok, "DMARC p=reject should reject unaligned, unsigned mail");
    }
}
