// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in POP3 integration smoke (not run in CI `--lib`).

use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_auth::{
    CertificateIdentity, Cb, CredentialStore, PasswordStore, ScramCredentials, SaslMechanism,
    TokenValidation,
};
use hopf_core::{Runtime, RuntimeConfig};
use hopf_mailbox::{MailboxFactory, MaildirFactory};

use crate::client::MessageReceiveCallback;
use crate::{Pop3Client, Pop3ClientTimeouts, Pop3Config, Pop3Fetch, Pop3Service};

/// Test-only whole-message append, via the real streaming push triad
/// ([`hopf_mailbox::AppendGuard`]) — never bypasses it.
fn append_whole(mb: &mut dyn hopf_mailbox::Mailbox, data: &[u8]) {
    let mut guard = hopf_mailbox::AppendGuard::start(mb, &BTreeSet::new(), None).unwrap();
    guard.append_content(data).unwrap();
    guard.commit().unwrap();
}

/// Test-only [`MessageReceiveCallback`] that collects each message's whole
/// content into `received` for assertions — the real streaming callback
/// path is still exercised end-to-end; this just happens to buffer the
/// result for comparison, per this crate's testing convention.
struct CollectMessages(Arc<Mutex<Vec<Vec<u8>>>>, Vec<u8>);

impl MessageReceiveCallback for CollectMessages {
    fn start_message(&mut self, _id: u32, _uid: Option<&str>) {
        self.1.clear();
    }
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.1.extend_from_slice(chunk);
        true
    }
    fn end_message(&mut self) {
        self.0.lock().unwrap().push(std::mem::take(&mut self.1));
    }
}

#[test]
fn pop3_user_pass_stat_retr_dele_quit() {
    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: hi\r\n\r\nhello\r\n");
        mb.close(false).unwrap();
        store.close().unwrap();
    }

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 4096];

    let greet = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK"));
    assert!(greet.starts_with("+OK"), "{greet}");

    write_cmd(&mut stream, b"USER alice\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with("+OK")).starts_with("+OK"));

    write_cmd(&mut stream, b"PASS secret\r\n");
    let opened = read_until(&mut stream, &mut buf, |s| s.contains("Mailbox opened"));
    assert!(opened.contains("Mailbox opened"), "{opened}");

    write_cmd(&mut stream, b"STAT\r\n");
    let resp = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK"));
    assert!(resp.starts_with("+OK 1 "), "{resp}");

    write_cmd(&mut stream, b"RETR 1\r\n");
    let body = read_until(&mut stream, &mut buf, |s| s.contains("\r\n.\r\n"));
    assert!(body.contains("hello"), "{body}");

    write_cmd(&mut stream, b"DELE 1\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with("+OK")).starts_with("+OK"));

    write_cmd(&mut stream, b"QUIT\r\n");
    let bye = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK") || s.starts_with("-ERR"));
    assert!(bye.starts_with("+OK"), "{bye}");
    drop(rt);
}

fn write_cmd(stream: &mut TcpStream, cmd: &[u8]) {
    stream.write_all(cmd).unwrap();
    stream.flush().unwrap();
}

fn read_until(stream: &mut TcpStream, buf: &mut [u8], pred: impl Fn(&str) -> bool) -> String {
    let mut acc = String::new();
    for _ in 0..50 {
        match stream.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.push_str(std::str::from_utf8(&buf[..n]).unwrap_or(""));
                if pred(&acc) {
                    return acc;
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => panic!("read failed: {e}"),
        }
    }
    acc
}

/// Spin-wait up to `max_ms` milliseconds for `pred` to return `true`.
#[cfg(test)]
fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
    for _ in 0..(max_ms / 10) {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pred()
}

/// Start a Pop3Service with one message in alice's INBOX and return (rt, addr).
#[cfg(test)]
fn start_pop3_server_with_message(
    dir: &tempfile::TempDir,
) -> (Arc<Runtime>, std::net::SocketAddr) {
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: client test\r\n\r\nhello pop3 client\r\n");
        mb.close(false).unwrap();
        store.close().unwrap();
    }
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let pass = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", pass, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();
    (rt, addr)
}

/// Like [`start_pop3_server_with_message`], but with a caller-supplied
/// [`CredentialStore`] — used with [`SlowStore`] to widen the async
/// credential-check offload's window for pipelining regression tests
/// (issue #181).
fn start_pop3_server_with_store(
    dir: &tempfile::TempDir,
    store: Arc<dyn CredentialStore>,
) -> (Arc<Runtime>, std::net::SocketAddr) {
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut s = factory.create_store();
        s.open("alice").unwrap();
        let mut mb = s.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: client test\r\n\r\nhello pop3 client\r\n");
        mb.close(false).unwrap();
        s.close().unwrap();
    }
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();
    (rt, addr)
}

/// Wraps a [`PasswordStore`] and sleeps inside `password_match`/
/// `plaintext_password` — deterministically widens the window a credential
/// check spends offloaded to the storage pool (issue #181), so a
/// pipelining regression test can reliably observe whether a command sent
/// right behind PASS/AUTH gets processed before or after the check
/// resolves, rather than depending on the storage thread happening to be
/// slow by chance.
struct SlowStore {
    inner: PasswordStore,
    delay: Duration,
}

impl CredentialStore for SlowStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        self.inner.supported_mechanisms()
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

// ── Client integration tests ──────────────────────────────────────────────────

#[test]
fn client_fetch_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_pop3_server_with_message(&dir);

    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        // `PasswordStore` never retains a recoverable plaintext password
        // (see its doc comment), so it can't verify APOP; `prefer_apop`
        // defaults to true and the server always advertises a timestamp
        // (issue #218), so without this the auto-pilot tries APOP first
        // and fails before ever attempting USER/PASS.
        .prefer_apop(false)
        .on_message(Box::new(CollectMessages(received2, Vec::new())))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts { stage: Duration::from_secs(5), ..Default::default() })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));

    let ok = done.lock().unwrap().unwrap_or(false);
    assert!(ok, "pop3 fetch should succeed");

    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "should receive exactly one message");
    assert!(
        msgs[0].windows(b"hello pop3 client".len()).any(|w| w == b"hello pop3 client"),
        "message body should contain expected content: {:?}",
        String::from_utf8_lossy(&msgs[0])
    );
}

#[test]
fn client_fetch_delete_after_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_pop3_server_with_message(&dir);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        // See the comment on the same call in `client_fetch_round_trip`.
        .prefer_apop(false)
        .delete_after_fetch(true)
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts { stage: Duration::from_secs(5), ..Default::default() })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(done.lock().unwrap().unwrap_or(false), "fetch+delete should succeed");
}

#[test]
fn client_greeting_timeout() {
    use std::net::TcpListener;

    // Bind a listener but never accept — greeting times out.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new().on_complete(Box::new(move |ok| {
        *done2.lock().unwrap() = Some(ok);
    }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts {
            stage: Duration::from_millis(300),
            connect: Duration::from_millis(300),
            ..Default::default()
        })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 3000));
    let ok = done.lock().unwrap().unwrap_or(true);
    assert!(!ok, "should fail on greeting timeout");
    drop(listener);
}

#[test]
fn client_empty_maildrop() {
    // Server with no messages — STAT returns 0, should complete successfully.
    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("bob").unwrap();
        store.close().unwrap();
    }
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let pass = Arc::new(PasswordStore::new().with_user("bob", "pw"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", pass, factory);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = Pop3Fetch::new()
        .credentials("bob", "pw")
        // See the comment on the same call in `client_fetch_round_trip`.
        .prefer_apop(false)
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .timeouts(Pop3ClientTimeouts { stage: Duration::from_secs(5), ..Default::default() })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 3000));
    assert!(done.lock().unwrap().unwrap_or(false), "empty maildrop should complete ok");
}

/// Hostname dial via `localhost` (hosts-file path) must not block the caller.
#[test]
fn client_localhost_hostname_dial() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_pop3_server_with_message(&dir);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        .prefer_apop(false)
        .on_message(Box::new(CollectMessages(received2, Vec::new())))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    let start = std::time::Instant::now();
    Pop3Client::new("localhost", addr.port())
        .timeouts(Pop3ClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        })
        .connect(&rt, Arc::new(fetch))
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "hostname connect must return immediately"
    );

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(done.lock().unwrap().unwrap_or(false), "localhost dial should succeed");
    assert_eq!(received.lock().unwrap().len(), 1);
}

/// Explicit STLS upgrade against a TLS-capable Pop3Service.
#[test]
fn client_stls_fetch() {
    use hopf_tls::{acceptor_from_pem, connector};

    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        append_whole(mb.as_mut(), b"From: a@b\r\nSubject: stls\r\n\r\nstls-body\r\n");
        mb.close(false).unwrap();
        store.close().unwrap();
    }

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let pass = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = Pop3Config::new("127.0.0.1:0".parse().unwrap(), "localhost", pass, factory)
        .with_tls(acceptor);
    let svc = Pop3Service::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let tls_connector = connector(client_cfg);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);

    let fetch = Pop3Fetch::new()
        .credentials("alice", "secret")
        .prefer_apop(false)
        .require_stls(true)
        .on_message(Box::new(CollectMessages(received2, Vec::new())))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    Pop3Client::from_addr(addr)
        .stls(tls_connector, "localhost")
        .timeouts(Pop3ClientTimeouts {
            stage: Duration::from_secs(5),
            ..Default::default()
        })
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 8000));
    assert!(done.lock().unwrap().unwrap_or(false), "STLS fetch should succeed");
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(
        msgs[0]
            .windows(b"stls-body".len())
            .any(|w| w == b"stls-body"),
        "body={:?}",
        String::from_utf8_lossy(&msgs[0])
    );
}

/// PASS's credential check runs off the reactor thread (issue #181); a
/// STAT pipelined right behind it in the same TCP write must not be
/// processed until the check resolves and the session actually becomes
/// TRANSACTION — otherwise it would race ahead and see stale
/// (AUTHORIZATION-state) state. `SlowStore` widens the offload's window so
/// this is reliably observable rather than a timing coincidence.
#[test]
fn server_pass_pipelined_with_stat_waits_for_async_credential_check() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: PasswordStore::new().with_user("alice", "secret"),
        delay: Duration::from_millis(150),
    });
    let (rt, addr) = start_pop3_server_with_store(&dir, store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let greet = read_until(&mut stream, &mut buf, |s| s.starts_with("+OK"));
    assert!(greet.starts_with("+OK"), "{greet}");

    write_cmd(&mut stream, b"USER alice\r\n");
    assert!(read_until(&mut stream, &mut buf, |s| s.starts_with("+OK")).starts_with("+OK"));

    // One write, both commands — proves this isn't just "two separate
    // reads happened to land in order." Both replies are awaited from a
    // single accumulating read (not two separate `read_until` calls): the
    // two replies can legitimately land in the same TCP segment once the
    // credential check and mailbox open both resolve quickly, and a second
    // fresh `read_until` call has no way to see bytes a prior call already
    // drained out of the socket.
    write_cmd(&mut stream, b"PASS secret\r\nSTAT\r\n");
    let r = read_until(&mut stream, &mut buf, |s| {
        s.contains("Mailbox opened") && s.contains("+OK 1 ")
    });
    assert!(r.contains("Mailbox opened"), "pass: {r}");
    assert!(
        r.contains("+OK 1 "),
        "pipelined STAT must be processed only after PASS's async \
         credential check completes, against authenticated state: {r}"
    );
    drop(rt);
}

/// Same race, but for the SASL path (issue #181), using CRAM-MD5 — a
/// server-first, multi-round-trip mechanism whose *first* step offload is
/// the new `first_step` code path added for this issue. Challenge
/// round-trip, then the client's response and a pipelined STAT sent in the
/// same write right behind it.
#[test]
fn server_auth_pipelined_with_stat_waits_for_async_step() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: PasswordStore::new().with_user("alice", "secret"),
        delay: Duration::from_millis(150),
    });
    let (rt, addr) = start_pop3_server_with_store(&dir, store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 4096];
    read_until(&mut stream, &mut buf, |s| s.starts_with("+OK"));

    write_cmd(&mut stream, b"AUTH CRAM-MD5\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("+ ") && s.ends_with("\r\n"));
    let b64 = r.trim().strip_prefix("+ ").expect("continuation prefix");
    let challenge = String::from_utf8(rmimeparser::charset::base64::decode(b64).unwrap())
        .expect("challenge is ASCII");
    let digest = hopf_auth::cram_md5::compute_response("secret", &challenge);
    let response = rmimeparser::charset::base64::encode(format!("alice {digest}").as_bytes());
    write_cmd(&mut stream, format!("{response}\r\nSTAT\r\n").as_bytes());

    let r = read_until(&mut stream, &mut buf, |s| {
        s.contains("Mailbox opened") && s.contains("+OK 1 ")
    });
    assert!(r.contains("Mailbox opened"), "auth: {r}");
    assert!(
        r.contains("+OK 1 "),
        "pipelined STAT must be processed only after the offloaded SASL \
         step completes, against authenticated state: {r}"
    );
    drop(rt);
}
