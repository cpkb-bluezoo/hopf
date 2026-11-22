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
