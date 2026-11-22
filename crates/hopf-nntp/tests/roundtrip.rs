// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The hopf NNTP client against the hopf NNTP server, over real connections:
//! plain, with STARTTLS, and with implicit TLS.
//!
//! Run with `cargo test -p hopf-nntp --features integration --test roundtrip`.

use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_auth::{CredentialStore, PasswordStore};
use hopf_core::{acceptor_from_pem, connector_from_pem, Runtime, RuntimeConfig, SharedTlsAcceptor, SharedTlsConnector};
use hopf_mailbox::{AppendGuard, MailboxFactory, MaildirFactory};
use hopf_nntp::{NntpClient, NntpClientHandler, NntpConfig, NntpGreeting, NntpService, NntpSession, OverviewEntry};

#[derive(Default)]
struct Outcome {
    greeting: Option<NntpGreeting>,
    error: Option<String>,
    disconnected: bool,
    group: Option<Result<(u64, u64, u64), String>>,
    overview: Vec<OverviewEntry>,
    article: Vec<u8>,
    posted: Option<Result<(), String>>,
    readback: Vec<u8>,
    body_done: Option<String>,
}

type Shared = Arc<Mutex<Outcome>>;

struct Run(Shared);

impl NntpClientHandler for Run {
    fn on_connected(&mut self, session: &NntpSession, greeting: &NntpGreeting) {
        self.0.lock().unwrap().greeting = Some(greeting.clone());
        let o = Arc::clone(&self.0);
        session.group("misc.test", move |r| {
            o.lock().unwrap().group = Some(r.map(|g| (g.count, g.first, g.last)).map_err(|e| e.to_string()));
        });
        let o = Arc::clone(&self.0);
        session.over(1, 1, move |e| o.lock().unwrap().overview.push(e), |_| {});
        let o = Arc::clone(&self.0);
        session.article(1, move |l| o.lock().unwrap().article.extend_from_slice(l), |_| {});
        let o = Arc::clone(&self.0);
        session.post(
            b"From: p@x.org\r\nNewsgroups: misc.test\r\nSubject: from the client\r\nMessage-ID: <client@x.org>\r\n\r\n.starts with a dot\r\nsecond\r\n",
            move |r| o.lock().unwrap().posted = Some(r.map_err(|e| e.to_string())),
        );
        let o = Arc::clone(&self.0);
        let (o2, o3) = (Arc::clone(&self.0), Arc::clone(&self.0));
        let _ = o;
        session.body(2, move |l| o2.lock().unwrap().readback.extend_from_slice(l), move |r| {
            o3.lock().unwrap().body_done = Some(format!("{r:?}"));
        });
        session.quit();
    }

    fn on_error(&mut self, error: &io::Error) {
        self.0.lock().unwrap().error = Some(error.to_string());
    }

    fn on_disconnected(&mut self) {
        self.0.lock().unwrap().disconnected = true;
    }
}

fn tls_pair() -> (SharedTlsAcceptor, SharedTlsConnector, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&key).unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (acceptor_from_pem(&cert_path, &key_path, &[]).unwrap(), connector_from_pem(&cert_path, &[]).unwrap(), dir)
}

fn spool(root: &std::path::Path) -> Arc<MaildirFactory> {
    let factory = Arc::new(MaildirFactory::new(root));
    let mut store = factory.create_store();
    store.open("news").unwrap();
    store.create_mailbox("misc/test").unwrap();
    let mut mb = store.open_mailbox("misc/test", false).unwrap();
    let mut guard = AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
    guard
        .append_content(b"From: a@x.org\r\nSubject: first\r\nMessage-ID: <first@x.org>\r\nReferences: <root@x.org>\r\n\r\n.dotted\r\nbody\r\n")
        .unwrap();
    guard.commit().unwrap();
    mb.close(false).unwrap();
    store.close().unwrap();
    factory
}

fn wait_for(mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

fn check(out: &Shared, secure: bool) {
    assert!(wait_for(|| out.lock().unwrap().disconnected), "the session never ended: {:?}", out.lock().unwrap().error);
    let o = out.lock().unwrap();
    assert_eq!(o.error, None);
    let g = o.greeting.as_ref().expect("connected");
    assert_eq!((g.secure, g.authenticated), (secure, true));
    assert_eq!(o.group, Some(Ok((1, 1, 1))));
    assert_eq!(o.overview.len(), 1);
    assert_eq!((o.overview[0].subject.as_str(), o.overview[0].references.as_str()), ("first", "<root@x.org>"));
    assert_eq!(
        String::from_utf8_lossy(&o.article),
        "From: a@x.org\r\nSubject: first\r\nMessage-ID: <first@x.org>\r\nReferences: <root@x.org>\r\n\r\n.dotted\r\nbody\r\n"
    );
    assert_eq!(o.posted, Some(Ok(())));
    assert_eq!(o.body_done.as_deref(), Some("Ok(())"), "BODY 2");
    assert_eq!(String::from_utf8_lossy(&o.readback), ".starts with a dot\r\nsecond\r\n", "what was posted reads back");
}

fn store() -> Arc<dyn CredentialStore> {
    Arc::new(PasswordStore::new().with_user("alice", "secret"))
}

fn serve(config: NntpConfig, root: &std::path::Path) -> (Arc<Runtime>, NntpService, std::net::SocketAddr) {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let svc = NntpService::new(config, Arc::clone(&rt), spool(root));
    let addr = svc.start().unwrap();
    (rt, svc, addr)
}

fn base() -> NntpConfig {
    NntpConfig::new("127.0.0.1:0".parse().unwrap(), "news.example").with_credentials(store())
}

#[test]
fn the_client_reads_and_posts_over_a_plain_connection() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(base().allow_cleartext_auth(), dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr).credentials("alice", "secret").connect_with(&rt, Box::new(Run(Arc::clone(&out)))).unwrap();
    check(&out, false);
}

#[test]
fn the_client_will_not_send_a_password_in_the_clear_to_a_server_that_wants_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(base().require_authentication(), dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr).credentials("alice", "secret").connect_with(&rt, Box::new(Run(Arc::clone(&out)))).unwrap();
    // The server offers only SCRAM until TLS: authentication still works.
    check(&out, false);
}

#[test]
fn starttls_then_authenticate_then_read_and_post() {
    let dir = tempfile::tempdir().unwrap();
    let (acceptor, connector, _certs) = tls_pair();
    let (rt, _svc, addr) = serve(base().with_tls(acceptor).require_authentication(), dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .starttls(connector, "localhost")
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(Run(Arc::clone(&out))))
        .unwrap();
    check(&out, true);
}

#[test]
fn implicit_tls_then_authenticate_then_read_and_post() {
    let dir = tempfile::tempdir().unwrap();
    let (acceptor, connector, _certs) = tls_pair();
    let (rt, _svc, addr) = serve(base().with_tls(acceptor).implicit_tls().require_authentication(), dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .implicit_tls(connector, "localhost")
        .credentials("alice", "secret")
        .connect_with(&rt, Box::new(Run(Arc::clone(&out))))
        .unwrap();
    check(&out, true);
}

// ---- choosing the mechanism ----

use hopf_auth::SaslMechanism;

fn base_with_tokens() -> NntpConfig {
    let store: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new().with_user("alice", "secret").with_token("tok123", "alice"));
    NntpConfig::new("127.0.0.1:0".parse().unwrap(), "news.example").with_credentials(store).allow_cleartext_auth()
}

#[test]
fn every_password_mechanism_authenticates_when_asked_for() {
    for mechanism in [SaslMechanism::Plain, SaslMechanism::Login, SaslMechanism::ScramSha256] {
        let dir = tempfile::tempdir().unwrap();
        let (rt, svc, addr) = serve(base_with_tokens(), dir.path());
        let out: Shared = Arc::default();
        NntpClient::from_addr(addr)
            .credentials("alice", "secret")
            .sasl_mechanisms(&[mechanism])
            .connect_with(&rt, Box::new(Run(Arc::clone(&out))))
            .unwrap();
        check(&out, false);
        assert_eq!(svc.metrics().auth_ok.load(std::sync::atomic::Ordering::Relaxed), 1, "{mechanism}");
    }
}

#[test]
fn bearer_tokens_authenticate_with_oauthbearer_and_xoauth2() {
    for mechanisms in [None, Some(&[SaslMechanism::XOauth2][..])] {
        let dir = tempfile::tempdir().unwrap();
        let (rt, _svc, addr) = serve(base_with_tokens(), dir.path());
        let out: Shared = Arc::default();
        let mut client = NntpClient::from_addr(addr).bearer_token("alice", "tok123");
        if let Some(m) = mechanisms {
            client = client.sasl_mechanisms(m);
        }
        client.connect_with(&rt, Box::new(Run(Arc::clone(&out)))).unwrap();
        check(&out, false);
    }
}

#[test]
fn a_bad_token_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(base_with_tokens(), dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr).bearer_token("alice", "wrong").connect_with(&rt, Box::new(Run(Arc::clone(&out)))).unwrap();
    assert!(wait_for(|| out.lock().unwrap().error.is_some()));
    assert!(out.lock().unwrap().error.as_deref().unwrap().contains("481"), "{:?}", out.lock().unwrap().error);
}

#[test]
fn a_mechanism_the_server_does_not_offer_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(base_with_tokens(), dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .credentials("alice", "secret")
        .sasl_mechanisms(&[SaslMechanism::External])
        .connect_with(&rt, Box::new(Run(Arc::clone(&out))))
        .unwrap();
    assert!(wait_for(|| out.lock().unwrap().error.is_some()));
    let error = out.lock().unwrap().error.clone().unwrap();
    assert!(error.contains("EXTERNAL") && error.contains("none of the SASL mechanisms"), "{error}");
}

#[test]
fn external_authenticates_with_the_client_certificate() {
    use hopf_core::tls::ClientAuthPolicy;
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, content: String| {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    };
    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let server_cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&server_key).unwrap();
    let client_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let client_cert = rcgen::CertificateParams::new(vec!["alice".into()]).unwrap().self_signed(&client_key).unwrap();
    let (sc, sk) = (write("server.pem", server_cert.pem()), write("server.key", server_key.serialize_pem()));
    let (cc, ck) = (write("client.pem", client_cert.pem()), write("client.key", client_key.serialize_pem()));
    let acceptor = hopf_core::acceptor_from_pem_with_client_auth(&sc, &sk, &[], ClientAuthPolicy::Request, &cc).unwrap();
    let connector = hopf_core::connector_from_pem_with_client_cert(&sc, &cc, &ck, &[]).unwrap();
    let fingerprint = hopf_core::crypto::sha256_fingerprint_hex(client_cert.der());
    let store: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new().with_user("alice", "secret").with_certificate(fingerprint, "alice"));
    let config = NntpConfig::new("127.0.0.1:0".parse().unwrap(), "news.example").with_credentials(store).with_tls(acceptor);
    let spool_dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(config, spool_dir.path());
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr)
        .starttls(connector, "localhost")
        .sasl_external("")
        .connect_with(&rt, Box::new(Run(Arc::clone(&out))))
        .unwrap();
    check(&out, true);
}

// ---- attachments ----

/// Posts text and attachments, then reads the article back with the files
/// told apart from the text.
struct PostFiles {
    files: Vec<hopf_nntp::NntpAttachment>,
    result: Shared,
    seen: Arc<Mutex<Seen>>,
}

#[derive(Default)]
struct Seen {
    text: Vec<u8>,
    files: Vec<(Vec<u8>, u32, u64, u64, bool)>,
}

struct Reader(Arc<Mutex<Seen>>);

/// Keeps a count and a checksum of each file, not the file.
impl hopf_nntp::NntpArticleHandler for Reader {
    fn text(&mut self, data: &[u8]) {
        self.0.lock().unwrap().text.extend_from_slice(data);
    }
    fn attachment_begin(&mut self, mode: u32, name: &[u8]) {
        self.0.lock().unwrap().files.push((name.to_vec(), mode, 0, 0, false));
    }
    fn attachment_data(&mut self, data: &[u8]) {
        let mut seen = self.0.lock().unwrap();
        let file = seen.files.last_mut().unwrap();
        file.2 += data.len() as u64;
        file.3 = data.iter().fold(file.3, |sum, &b| sum.wrapping_mul(31).wrapping_add(u64::from(b)));
    }
    fn attachment_end(&mut self, complete: bool) {
        self.0.lock().unwrap().files.last_mut().unwrap().4 = complete;
    }
}

impl NntpClientHandler for PostFiles {
    fn on_connected(&mut self, session: &NntpSession, _greeting: &NntpGreeting) {
        let files = std::mem::take(&mut self.files);
        let o = Arc::clone(&self.result);
        session.post_with_attachments(
            b"From: p@x.org\r\nNewsgroups: misc.test\r\nSubject: with files\r\nMessage-ID: <files@x.org>\r\n\r\nSee the files.\r\n",
            files,
            move |r| o.lock().unwrap().posted = Some(r.map_err(|e| e.to_string())),
        );
        let o = Arc::clone(&self.result);
        session.group("misc.test", move |r| {
            o.lock().unwrap().group = Some(r.map(|g| (g.count, g.first, g.last)).map_err(|e| e.to_string()));
        });
        let o = Arc::clone(&self.result);
        session.article_with_attachments(2, Reader(Arc::clone(&self.seen)), move |r| {
            o.lock().unwrap().body_done = Some(format!("{r:?}"));
        });
        session.quit();
    }

    fn on_error(&mut self, error: &io::Error) {
        self.result.lock().unwrap().error = Some(error.to_string());
    }

    fn on_disconnected(&mut self) {
        self.result.lock().unwrap().disconnected = true;
    }
}

fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |sum, &b| sum.wrapping_mul(31).wrapping_add(u64::from(b)))
}

#[test]
fn files_posted_as_attachments_come_back_the_same_from_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(base_with_tokens(), dir.path());
    let on_disk: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(7) % 256) as u8).collect();
    let path = dir.path().join("data.bin");
    std::fs::write(&path, &on_disk).unwrap();
    let in_memory: Vec<u8> = b"\x00\x01.leading dot\r\n.\r\n\xff".to_vec();
    let result: Shared = Arc::default();
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let handler = PostFiles {
        files: vec![
            hopf_nntp::NntpAttachment::from_path(&path),
            hopf_nntp::NntpAttachment::from_bytes("small.txt", in_memory.clone()),
            hopf_nntp::NntpAttachment::from_bytes("empty.dat", Vec::new()),
        ],
        result: Arc::clone(&result),
        seen: Arc::clone(&seen),
    };
    NntpClient::from_addr(addr).credentials("alice", "secret").connect_with(&rt, Box::new(handler)).unwrap();
    assert!(wait_for(|| result.lock().unwrap().disconnected), "{:?}", result.lock().unwrap().error);
    let r = result.lock().unwrap();
    assert_eq!(r.error, None);
    assert_eq!(r.posted, Some(Ok(())));
    assert_eq!(r.group, Some(Ok((2, 1, 2))));
    assert_eq!(r.body_done.as_deref(), Some("Ok(())"));
    let seen = seen.lock().unwrap();
    assert!(String::from_utf8_lossy(&seen.text).ends_with("See the files.\r\n"), "{:?}", String::from_utf8_lossy(&seen.text));
    assert_eq!(seen.files.len(), 3);
    assert_eq!((seen.files[0].0.as_slice(), seen.files[0].2, seen.files[0].3, seen.files[0].4), (&b"data.bin"[..], on_disk.len() as u64, checksum(&on_disk), true));
    assert_eq!((seen.files[1].0.as_slice(), seen.files[1].2, seen.files[1].3), (&b"small.txt"[..], in_memory.len() as u64, checksum(&in_memory)));
    assert_eq!((seen.files[2].0.as_slice(), seen.files[2].2, seen.files[2].4), (&b"empty.dat"[..], 0, true));
}

#[test]
fn an_attachment_that_cannot_be_read_fails_the_post_and_files_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, _svc, addr) = serve(base_with_tokens(), dir.path());
    let result: Shared = Arc::default();
    let handler = PostFiles {
        files: vec![hopf_nntp::NntpAttachment::from_path(dir.path().join("missing.bin"))],
        result: Arc::clone(&result),
        seen: Arc::default(),
    };
    NntpClient::from_addr(addr).credentials("alice", "secret").connect_with(&rt, Box::new(handler)).unwrap();
    assert!(wait_for(|| result.lock().unwrap().disconnected));
    assert!(matches!(result.lock().unwrap().posted, Some(Err(_))), "{:?}", result.lock().unwrap().posted);
    // Nothing was filed: a new connection sees the one article there was.
    let out: Shared = Arc::default();
    NntpClient::from_addr(addr).credentials("alice", "secret").connect_with(&rt, Box::new(Run(Arc::clone(&out)))).unwrap();
    check(&out, false);
}
