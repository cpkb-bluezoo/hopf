// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in IMAP integration tests (not run in CI `--lib`).
//!
//! Run with `cargo test -p hopf-imap --features integration`. Tests use
//! loopback TCP sockets, temporary Maildir stores, and self-signed TLS
//! certificates; no sleeps are used for synchronization — everything is
//! time-bounded polling (`wait_for`) or blocking reads with timeouts.

use std::collections::BTreeSet;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_auth::{
    CertificateIdentity, Cb, CredentialStore, PasswordStore, ScramCredentials, SaslMechanism,
    TokenValidation,
};
use hopf_core::{Endpoint, Runtime, RuntimeConfig};
use hopf_mailbox::{MailboxFactory, MaildirFactory};

use crate::client::pipeline_status_and_list;
use crate::client::MessageReceiveCallback;
use crate::{
    ImapAppendUid, ImapCapabilities, ImapClient, ImapClientAppend, ImapClientAuthExchange,
    ImapClientAuthenticated, ImapClientDriver, ImapClientHandlerFactory, ImapClientNotAuthenticated,
    ImapClientSelected, ImapClientTimeouts, ImapConfig, ImapFetch, ImapIdle, ImapListEntry,
    ImapMailboxInfo, ImapService, ImapStatus, ImapStatusData, MailboxEventListener,
};

const MESSAGE: &[u8] = b"From: a@b\r\nSubject: hi\r\n\r\nhello imap\r\n";

/// Test-only [`MessageReceiveCallback`] that collects each message's
/// `(seq, uid, whole content)` into `received` for assertions — the real
/// streaming callback path is still exercised end-to-end; this just
/// happens to buffer the result for comparison.
struct CollectMessages {
    received: Arc<Mutex<Vec<(u32, Option<u32>, Vec<u8>)>>>,
    seq: u32,
    body: Vec<u8>,
}

impl MessageReceiveCallback for CollectMessages {
    fn start_message(&mut self, seq: u32) {
        self.seq = seq;
        self.body.clear();
    }
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.body.extend_from_slice(chunk);
        true
    }
    fn end_message(&mut self, uid: Option<u32>) {
        self.received
            .lock()
            .unwrap()
            .push((self.seq, uid, std::mem::take(&mut self.body)));
    }
}

/// Like [`CollectMessages`], but keeping only the bodies.
struct CollectBodies(Arc<Mutex<Vec<Vec<u8>>>>, Vec<u8>);

impl MessageReceiveCallback for CollectBodies {
    fn start_message(&mut self, _seq: u32) {
        self.1.clear();
    }
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.1.extend_from_slice(chunk);
        true
    }
    fn end_message(&mut self, _uid: Option<u32>) {
        self.0.lock().unwrap().push(std::mem::take(&mut self.1));
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Spin-wait up to `max_ms` milliseconds for `pred` to return `true`.
fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
    for _ in 0..(max_ms / 10) {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    pred()
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
            Err(e) => panic!("read failed: {e}"),
        }
    }
    acc
}

/// Populate alice's INBOX with one message under `dir`.
fn seed_mailbox(dir: &tempfile::TempDir) -> Arc<MaildirFactory> {
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        let mut guard = hopf_mailbox::AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
        guard.append_content(MESSAGE).unwrap();
        guard.commit().unwrap();
        mb.close(false).unwrap();
        store.close().unwrap();
    }
    factory
}

/// Populate alice's INBOX with three messages exercising SORT (base-subject
/// folding with a sequence tie-break) and THREAD REFERENCES (a real reply
/// chain alongside an unrelated root) together: message 1 is the original,
/// message 2 is a reply to it sent an hour later, message 3 is unrelated
/// and sent an hour before message 1.
fn seed_sort_thread_mailbox(dir: &tempfile::TempDir) -> Arc<MaildirFactory> {
    let factory = Arc::new(MaildirFactory::new(dir.path()));
    {
        let mut store = factory.create_store();
        store.open("alice").unwrap();
        let mut mb = store.open_mailbox("INBOX", false).unwrap();
        let msgs: [&[u8]; 3] = [
            b"From: a@b\r\nSubject: Question\r\nMessage-Id: <1@x>\r\nDate: Thu, 01 Jan 2026 10:00:00 +0000\r\n\r\nfirst\r\n",
            b"From: c@d\r\nSubject: Re: Question\r\nMessage-Id: <2@x>\r\nIn-Reply-To: <1@x>\r\nReferences: <1@x>\r\nDate: Thu, 01 Jan 2026 11:00:00 +0000\r\n\r\nreply\r\n",
            b"From: e@f\r\nSubject: Other\r\nMessage-Id: <3@x>\r\nDate: Thu, 01 Jan 2026 09:00:00 +0000\r\n\r\nunrelated\r\n",
        ];
        for m in msgs {
            let mut guard =
                hopf_mailbox::AppendGuard::start(mb.as_mut(), &BTreeSet::new(), None).unwrap();
            guard.append_content(m).unwrap();
            guard.commit().unwrap();
        }
        mb.close(false).unwrap();
        store.close().unwrap();
    }
    factory
}

/// Start an ImapService against [`seed_sort_thread_mailbox`]'s fixture.
fn start_imap_server_with_sort_thread_fixture(
    dir: &tempfile::TempDir,
) -> (Arc<Runtime>, SocketAddr) {
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let factory = seed_sort_thread_mailbox(dir);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let config = ImapConfig::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory);
    let svc = ImapService::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();
    (rt, addr)
}

/// Start an ImapService with one message in alice's INBOX; returns (rt, addr).
fn start_imap_server(dir: &tempfile::TempDir) -> (Arc<Runtime>, SocketAddr) {
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    start_imap_server_with_store(dir, store)
}

/// Like [`start_imap_server`], but with a caller-supplied [`CredentialStore`]
/// — used with [`SlowStore`] to widen the async credential-check offload's
/// window for pipelining regression tests (issue #181).
fn start_imap_server_with_store(
    dir: &tempfile::TempDir,
    store: Arc<dyn CredentialStore>,
) -> (Arc<Runtime>, SocketAddr) {
    let factory = seed_mailbox(dir);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let config = ImapConfig::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory);
    let svc = ImapService::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();
    (rt, addr)
}

/// A store enrolling "alice"/"secret" that can drive CRAM-MD5 and
/// DIGEST-MD5, not just SCRAM-SHA-256 — [`start_imap_server`]'s bare
/// `PasswordStore` deliberately can't (see [`SlowStore`]'s doc comment),
/// and has no digest realm set, so it can't either.
fn cram_and_digest_capable_store() -> Arc<dyn CredentialStore> {
    Arc::new(SlowStore {
        inner: PasswordStore::new()
            .with_digest_realm("localhost")
            .with_user("alice", "secret"),
        delay: Duration::ZERO,
    })
}

/// Wraps a [`PasswordStore`] and sleeps for `delay` inside `password_match`
/// — deterministically widens the window a credential check spends offloaded
/// to the storage pool (issue #181), so a pipelining regression test can
/// reliably observe whether a command sent right behind LOGIN/AUTHENTICATE
/// gets processed before or after the check resolves, rather than depending
/// on the storage thread happening to be slow by chance.
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
        // (see its doc comment) and so can't drive CRAM-MD5, which needs a
        // recoverable secret — override it here so `SlowStore` can, since
        // CRAM-MD5's server-first, multi-round-trip shape is exactly what
        // the pipelining regression test below needs to exercise the
        // `first_step`/continuation offload path. CRAM-MD5 verification
        // goes through this method (not `password_match`), so it needs the
        // same artificial delay to make the offload's window observable.
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

/// Self-signed cert for `localhost`: returns (acceptor, client connector).
fn tls_pair(
    dir: &tempfile::TempDir,
) -> (
    hopf_core::tls::SharedTlsAcceptor,
    hopf_core::SharedTlsConnector,
) {
    use hopf_core::{acceptor_from_pem, connector_from_pem};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();
    let connector = connector_from_pem(&cert_path, &[]).unwrap();
    (acceptor, connector)
}

fn fetch_timeouts() -> ImapClientTimeouts {
    ImapClientTimeouts {
        stage: Duration::from_secs(5),
        ..Default::default()
    }
}

// ── raw server coverage ───────────────────────────────────────────────────────

/// LOGIN → SELECT → FETCH → APPEND → NOOP (EXISTS update) → LOGOUT over raw TCP.
#[test]
fn server_login_select_fetch_append_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    let greet = read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    assert!(greet.contains("* OK"), "greeting: {greet}");

    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 OK"), "login: {r}");
    // The capability string embedded in the LOGIN `OK` response (RFC 9051
    // §6.2.3) must reflect the *post*-auth capability set: IDLE is
    // authenticated-only, so its presence here proves the response wasn't
    // built from session state captured before authentication completed.
    assert!(
        r.contains("[CAPABILITY") && r.contains("IDLE"),
        "LOGIN's embedded CAPABILITY must already be the authenticated set: {r}"
    );

    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "select: {r}");
    assert!(r.contains("1 EXISTS"), "select exists: {r}");

    write_cmd(&mut stream, b"a3 FETCH 1 (RFC822)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "fetch: {r}");
    assert!(r.contains("hello imap"), "fetch body: {r}");

    let payload = b"From: c@d\r\nSubject: two\r\n\r\nsecond message\r\n";
    write_cmd(
        &mut stream,
        format!("a4 APPEND INBOX {{{}}}\r\n", payload.len()).as_bytes(),
    );
    let r = read_until(&mut stream, &mut buf, |s| s.contains("+ "));
    assert!(r.contains("+ "), "append continuation: {r}");
    write_cmd(&mut stream, payload);
    write_cmd(&mut stream, b"\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(r.contains("a4 OK"), "append: {r}");
    assert!(r.contains("APPENDUID"), "appenduid: {r}");

    // NOOP reports the new EXISTS since this session appended.
    write_cmd(&mut stream, b"a5 NOOP\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    assert!(r.contains("a5 OK"), "noop: {r}");
    assert!(r.contains("2 EXISTS"), "noop exists: {r}");

    write_cmd(&mut stream, b"a6 LOGOUT\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a6 "));
    assert!(r.contains("* BYE") && r.contains("a6 OK"), "logout: {r}");
    drop(rt);
}

/// ENVELOPE, BODYSTRUCTURE, and a `BODY[section]<start.count>` partial
/// fetch over a real server connection and real maildir-backed mailbox —
/// the three sub-fixes for issue #6.
#[test]
fn server_fetch_envelope_bodystructure_partial_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a1 OK"));
    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a2 OK"));

    // MESSAGE = "From: a@b\r\nSubject: hi\r\n\r\nhello imap\r\n" — no Date,
    // single From address, plain-text body.
    write_cmd(&mut stream, b"a3 FETCH 1 (ENVELOPE)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "envelope fetch: {r}");
    assert!(r.contains("ENVELOPE ("), "envelope present: {r}");
    assert!(r.contains("\"hi\""), "subject: {r}");
    assert!(r.contains("NIL NIL \"a\" \"b\""), "from address: {r}");

    write_cmd(&mut stream, b"a4 FETCH 1 (BODYSTRUCTURE)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(r.contains("a4 OK"), "bodystructure fetch: {r}");
    assert!(
        r.contains("BODYSTRUCTURE (\"TEXT\" \"PLAIN\""),
        "bodystructure: {r}"
    );
    assert!(r.contains("\"7BIT\""), "encoding: {r}");

    // Partial fetch: `<0.5>` of BODY[TEXT] returns exactly "hello" (the
    // first 5 bytes of the body), with a matching {5} literal length —
    // and, combined with FLAGS in the same command, proves the lexer no
    // longer mis-tokenizes the trailing `<0.5>` as a bogus following item.
    write_cmd(&mut stream, b"a5 FETCH 1 (BODY[TEXT]<0.5> FLAGS)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    assert!(r.contains("a5 OK"), "partial fetch: {r}");
    assert!(
        r.contains("BODY[TEXT]<0> {5}\r\nhello"),
        "partial body: {r}"
    );
    assert!(r.contains("FLAGS ("), "flags still parsed: {r}");

    write_cmd(&mut stream, b"a6 LOGOUT\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a6 "));
    drop(rt);
}

/// Pipelined STATUS+LIST in one TCP segment: the server queues the second
/// command while the first is offloaded to storage and answers both in order.
#[test]
fn server_pipelined_status_list_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a1 OK"));

    // Both tagged commands in a single write — outstanding simultaneously.
    write_cmd(
        &mut stream,
        b"a2 STATUS INBOX (MESSAGES UIDNEXT)\r\na3 LIST \"\" *\r\n",
    );
    let r = read_until(&mut stream, &mut buf, |s| {
        s.contains("a2 OK") && s.contains("a3 OK")
    });
    assert!(r.contains("* STATUS INBOX"), "status line: {r}");
    assert!(r.contains("MESSAGES 1"), "status messages: {r}");
    assert!(r.contains("* LIST"), "list line: {r}");
    assert!(r.contains("INBOX"), "list inbox: {r}");
    // Hopf serializes: a2 completes before a3.
    let a2 = r.find("a2 OK").unwrap();
    let a3 = r.find("a3 OK").unwrap();
    assert!(a2 < a3, "tagged order: {r}");

    write_cmd(&mut stream, b"a4 LOGOUT\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    drop(rt);
}

/// IDLE continuation then DONE completes with the tagged OK on the real server.
#[test]
fn server_idle_done_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a1 OK"));
    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a2 OK"));

    write_cmd(&mut stream, b"a3 IDLE\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("+ "));
    assert!(r.contains("+ "), "idle continuation: {r}");

    write_cmd(&mut stream, b"DONE\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "idle done: {r}");

    write_cmd(&mut stream, b"a4 LOGOUT\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    drop(rt);
}

// ── async client coverage ─────────────────────────────────────────────────────

/// ImapFetch auto-pilot against the real server delivers the full message body.
#[test]
fn client_fetch_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let received: Arc<Mutex<Vec<(u32, Option<u32>, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let fetch = ImapFetch::new()
        .credentials("alice", "secret")
        .on_message(Box::new(CollectMessages {
            received: received2,
            seq: 0,
            body: Vec::new(),
        }))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    ImapClient::from_addr(addr)
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(
        done.lock().unwrap().unwrap_or(false),
        "fetch should succeed"
    );

    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1, "one message expected: {msgs:?}");
    let (seq, _uid, body) = &msgs[0];
    assert_eq!(*seq, 1);
    assert!(
        body.windows(b"hello imap".len())
            .any(|w| w == b"hello imap"),
        "body: {:?}",
        String::from_utf8_lossy(body)
    );
}

/// Hostname dial via `localhost` (hosts-file path) must not block the caller.
#[test]
fn client_localhost_hostname_dial() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    let count2 = Arc::clone(&count);

    struct CountMessages(Arc<Mutex<usize>>);
    impl MessageReceiveCallback for CountMessages {
        fn message_content(&mut self, _chunk: &[u8]) -> bool {
            true
        }
        fn end_message(&mut self, _uid: Option<u32>) {
            *self.0.lock().unwrap() += 1;
        }
    }
    let fetch = ImapFetch::new()
        .credentials("alice", "secret")
        .on_message(Box::new(CountMessages(count2)))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    let start = std::time::Instant::now();
    ImapClient::new("localhost", addr.port())
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(fetch))
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "hostname connect must return immediately"
    );

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(
        done.lock().unwrap().unwrap_or(false),
        "localhost dial should succeed"
    );
    assert_eq!(*count.lock().unwrap(), 1);
}

/// Explicit STARTTLS upgrade against a TLS-capable ImapService.
#[test]
fn client_starttls_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let factory = seed_mailbox(&dir);
    let (acceptor, tls_connector) = tls_pair(&dir);

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = ImapConfig::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory)
        .with_tls(acceptor);
    let svc = ImapService::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);

    let fetch = ImapFetch::new()
        .credentials("alice", "secret")
        .require_starttls(true)
        .on_message(Box::new(CollectBodies(received2, Vec::new())))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    ImapClient::from_addr(addr)
        .starttls(tls_connector, "localhost")
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 8000));
    assert!(
        done.lock().unwrap().unwrap_or(false),
        "STARTTLS fetch should succeed"
    );
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0]
        .windows(b"hello imap".len())
        .any(|w| w == b"hello imap"));
}

/// Implicit TLS (IMAPS): TLS from the first byte on both sides.
#[test]
fn client_implicit_tls_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let factory = seed_mailbox(&dir);
    let (acceptor, tls_connector) = tls_pair(&dir);

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = ImapConfig::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory)
        .with_tls(acceptor)
        .implicit_tls();
    let svc = ImapService::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();

    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);
    let received: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);

    let fetch = ImapFetch::new()
        .credentials("alice", "secret")
        .on_message(Box::new(CollectBodies(received2, Vec::new())))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    ImapClient::from_addr(addr)
        .implicit_tls(tls_connector, "localhost")
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(fetch))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 8000));
    assert!(
        done.lock().unwrap().unwrap_or(false),
        "IMAPS fetch should succeed"
    );
    let msgs = received.lock().unwrap();
    assert_eq!(msgs.len(), 1);
    assert!(msgs[0]
        .windows(b"hello imap".len())
        .any(|w| w == b"hello imap"));
}

// ── pipelined STATUS+LIST driver ──────────────────────────────────────────────

#[derive(Default)]
struct PipelineState {
    status: Option<ImapStatusData>,
    list_names: Vec<String>,
    status_done: bool,
    list_done: bool,
    done: Option<bool>,
}

struct PipelineDriver {
    state: Arc<Mutex<PipelineState>>,
}

struct PipelineFactory(Arc<Mutex<PipelineState>>);

impl ImapClientHandlerFactory for PipelineFactory {
    fn create(&self) -> Box<dyn ImapClientDriver> {
        Box::new(PipelineDriver {
            state: Arc::clone(&self.0),
        })
    }
}

impl ImapClientDriver for PipelineDriver {
    fn on_greeting(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _text: &str,
        _preauth: bool,
        _caps: &ImapCapabilities,
    ) {
        auth.capability();
    }

    fn on_capability(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _caps: &ImapCapabilities,
    ) {
        auth.login("alice", "secret");
    }

    fn on_tls_established(
        &mut self,
        _post: &mut dyn crate::ImapClientPostStarttls,
        _ep: &mut dyn Endpoint,
    ) {
    }

    fn on_tls_unavailable(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
    }

    fn on_authenticated(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _caps: &ImapCapabilities,
    ) {
        // Both commands go out before either tagged reply arrives.
        pipeline_status_and_list(session, "INBOX", "MESSAGES UIDNEXT", "", "*");
    }

    fn on_auth_failed(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.state.lock().unwrap().done = Some(false);
        ep.close();
    }

    fn on_auth_continue(
        &mut self,
        _exchange: &mut dyn ImapClientAuthExchange,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
    }

    fn on_selected(
        &mut self,
        _selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        _info: &ImapMailboxInfo,
        _read_only: bool,
    ) {
    }

    fn on_select_failed(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
    }

    fn on_fetch_literal(&mut self, _data: &[u8], _ep: &mut dyn Endpoint) {}

    fn on_fetch_complete(
        &mut self,
        _selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _message: &str,
    ) {
    }

    fn on_status_data(&mut self, data: &ImapStatusData) {
        self.state.lock().unwrap().status = Some(data.clone());
    }

    fn on_list_entry(&mut self, entry: &ImapListEntry) {
        self.state.lock().unwrap().list_names.push(entry.name.clone());
    }

    fn on_status_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        status: ImapStatus,
        _message: &str,
    ) {
        let mut st = self.state.lock().unwrap();
        st.status_done = status == ImapStatus::Ok;
        if st.status_done && st.list_done {
            st.done = Some(true);
            drop(st);
            session.logout();
        }
    }

    fn on_list_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        status: ImapStatus,
        _message: &str,
    ) {
        let mut st = self.state.lock().unwrap();
        st.list_done = status == ImapStatus::Ok;
        if st.status_done && st.list_done {
            st.done = Some(true);
            drop(st);
            session.logout();
        }
    }

    fn on_append_continue(
        &mut self,
        _append: &mut dyn ImapClientAppend,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
    }

    fn on_append_complete(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _appenduid: Option<&ImapAppendUid>,
        _message: &str,
    ) {
    }

    fn on_error(&mut self, _ep: &mut dyn Endpoint, _err: &io::Error) {
        let mut st = self.state.lock().unwrap();
        if st.done.is_none() {
            st.done = Some(false);
        }
    }

    fn on_timeout(&mut self, _ep: &mut dyn Endpoint) {
        let mut st = self.state.lock().unwrap();
        if st.done.is_none() {
            st.done = Some(false);
        }
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {
        let mut st = self.state.lock().unwrap();
        if st.done.is_none() {
            st.done = Some(false);
        }
    }
}

/// Pipelined STATUS+LIST against the real (serializing) Hopf server: both
/// commands outstanding, untagged lines routed to the right consumers.
#[test]
fn client_pipelined_status_list_real_server() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let state = Arc::new(Mutex::new(PipelineState::default()));
    ImapClient::from_addr(addr)
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(PipelineFactory(Arc::clone(&state))))
        .unwrap();

    assert!(wait_for(|| state.lock().unwrap().done.is_some(), 5000));
    let st = state.lock().unwrap();
    assert_eq!(st.done, Some(true), "pipeline should succeed");
    let status = st.status.as_ref().expect("status data");
    assert_eq!(status.mailbox, "INBOX");
    assert_eq!(status.messages, Some(1));
    assert!(
        st.list_names.iter().any(|n| n.contains("INBOX")),
        "list names: {:?}",
        st.list_names
    );
}

// ── scripted server (out-of-order tags, IDLE events) ──────────────────────────

/// Spawn a scripted IMAP server on a loopback port; `script` runs per-connection.
fn scripted_server(script: impl FnOnce(TcpStream) + Send + 'static) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            script(stream);
        }
    });
    addr
}

fn read_line(reader: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    let _ = reader.read_line(&mut line);
    line.trim_end().to_string()
}

fn tag_of(line: &str) -> String {
    line.split_whitespace().next().unwrap_or("").to_string()
}

/// Synthetic out-of-order tagged replies: LIST (issued second) completes
/// before STATUS (issued first). The client must route by tag, not order.
#[test]
fn client_pipelined_out_of_order_scripted() {
    let addr = scripted_server(|stream| {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        writer.write_all(b"* OK scripted ready\r\n").unwrap();

        // CAPABILITY
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(
                format!("* CAPABILITY IMAP4rev2\r\n{t} OK CAPABILITY completed\r\n").as_bytes(),
            )
            .unwrap();

        // LOGIN
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(format!("{t} OK LOGIN completed\r\n").as_bytes())
            .unwrap();

        // STATUS then LIST arrive pipelined; collect both before replying.
        let status_line = read_line(&mut reader);
        let list_line = read_line(&mut reader);
        assert!(status_line.to_ascii_uppercase().contains("STATUS"));
        assert!(list_line.to_ascii_uppercase().contains("LIST"));
        let status_tag = tag_of(&status_line);
        let list_tag = tag_of(&list_line);

        // Reply out of order: LIST completes first.
        writer
            .write_all(
                format!(
                    "* LIST () \"/\" INBOX\r\n{list_tag} OK LIST completed\r\n\
                     * STATUS INBOX (MESSAGES 7 UIDNEXT 9)\r\n{status_tag} OK STATUS completed\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

        // LOGOUT
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(format!("* BYE scripted\r\n{t} OK LOGOUT completed\r\n").as_bytes())
            .unwrap();
    });

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let state = Arc::new(Mutex::new(PipelineState::default()));
    ImapClient::from_addr(addr)
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(PipelineFactory(Arc::clone(&state))))
        .unwrap();

    assert!(wait_for(|| state.lock().unwrap().done.is_some(), 5000));
    let st = state.lock().unwrap();
    assert_eq!(st.done, Some(true), "out-of-order pipeline should succeed");
    let status = st.status.as_ref().expect("status data");
    assert_eq!(status.messages, Some(7));
    assert_eq!(status.uid_next, Some(9));
    assert!(st.list_names.iter().any(|n| n.contains("INBOX")));
    drop(rt);
}

struct RecordingListener {
    exists: Arc<Mutex<Vec<u32>>>,
}

impl MailboxEventListener for RecordingListener {
    fn on_exists(&mut self, count: u32) {
        self.exists.lock().unwrap().push(count);
    }
    fn on_recent(&mut self, _count: u32) {}
    fn on_expunge(&mut self, _seq: u32) {}
    fn on_flags(&mut self, _seq: u32, _flags: &[String]) {}
}

/// IDLE: unsolicited `* n EXISTS` reaches the listener and `done_on_event`
/// sends DONE; the tagged OK completes the pipeline.
#[test]
fn client_idle_exists_done_scripted() {
    let addr = scripted_server(|stream| {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        writer.write_all(b"* OK scripted ready\r\n").unwrap();

        // CAPABILITY (advertise IDLE so the pipeline proceeds).
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(
                format!("* CAPABILITY IMAP4rev2 IDLE\r\n{t} OK CAPABILITY completed\r\n")
                    .as_bytes(),
            )
            .unwrap();

        // LOGIN
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(format!("{t} OK LOGIN completed\r\n").as_bytes())
            .unwrap();

        // SELECT
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(
                format!(
                    "* 1 EXISTS\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n\
                     {t} OK [READ-WRITE] SELECT completed\r\n"
                )
                .as_bytes(),
            )
            .unwrap();

        // IDLE → continuation, then push an EXISTS event.
        let l = read_line(&mut reader);
        let idle_tag = tag_of(&l);
        writer.write_all(b"+ idling\r\n").unwrap();
        writer.write_all(b"* 2 EXISTS\r\n").unwrap();

        // DONE
        let l = read_line(&mut reader);
        assert!(l.eq_ignore_ascii_case("DONE"), "expected DONE, got {l}");
        writer
            .write_all(format!("{idle_tag} OK IDLE completed\r\n").as_bytes())
            .unwrap();

        // LOGOUT
        let l = read_line(&mut reader);
        let t = tag_of(&l);
        writer
            .write_all(format!("* BYE scripted\r\n{t} OK LOGOUT completed\r\n").as_bytes())
            .unwrap();
    });

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let exists: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let idle = ImapIdle::new()
        .credentials("alice", "secret")
        .prefer_auth_plain(false)
        .done_on_event(true)
        .mailbox_events(Box::new(RecordingListener {
            exists: Arc::clone(&exists),
        }))
        .on_complete(Box::new(move |ok| {
            *done2.lock().unwrap() = Some(ok);
        }));

    ImapClient::from_addr(addr)
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(idle))
        .unwrap();

    assert!(wait_for(|| done.lock().unwrap().is_some(), 5000));
    assert!(
        done.lock().unwrap().unwrap_or(false),
        "IDLE pipeline should succeed"
    );
    let seen = exists.lock().unwrap();
    assert!(seen.contains(&2), "EXISTS events: {seen:?}");
    drop(rt);
}

// ── AUTHENTICATE: SASL mechanisms beyond PLAIN (issue #128) ────────────────────

/// CRAM-MD5 doesn't require TLS, so this exercises the full non-PLAIN
/// dispatch — mechanism lookup, server-first challenge, `create_server`,
/// and completion — over a plain connection.
#[test]
fn server_authenticate_cram_md5_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server_with_store(&dir, cram_and_digest_capable_store());

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    write_cmd(&mut stream, b"a1 AUTHENTICATE CRAM-MD5\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("+ ") && s.ends_with("\r\n"));
    assert!(r.contains("+ "), "cram-md5 challenge: {r}");
    let b64 = r.trim().strip_prefix("+ ").expect("continuation prefix");
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
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 OK"), "authenticate cram-md5: {r}");

    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "select after CRAM-MD5 auth: {r}");
    drop(rt);
}

/// LOGIN (the SASL mechanism, not the LOGIN command) requires TLS, matching
/// Gumdrop — over a plain connection it must be refused up front, never
/// even reaching the username challenge.
#[test]
fn server_authenticate_login_mechanism_requires_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    write_cmd(&mut stream, b"a1 AUTHENTICATE LOGIN\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(
        r.contains("a1 NO"),
        "LOGIN mechanism must be refused without TLS: {r}"
    );
    assert!(
        !r.contains("+ "),
        "must not even prompt for a username before the TLS check: {r}"
    );
    drop(rt);
}

#[test]
fn server_authenticate_unsupported_mechanism_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    write_cmd(&mut stream, b"a1 AUTHENTICATE GSSAPI\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 NO"), "GSSAPI is not implemented: {r}");
    drop(rt);
}

/// The greeting's inline CAPABILITY must list every mechanism the store can
/// drive, filtered by TLS requirement — not just a hardcoded `AUTH=PLAIN`.
#[test]
fn server_capability_lists_mechanisms_filtered_by_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server_with_store(&dir, cram_and_digest_capable_store());

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];
    let greet = read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    for present in ["AUTH=CRAM-MD5", "AUTH=DIGEST-MD5", "AUTH=SCRAM-SHA-256"] {
        assert!(greet.contains(present), "expected {present} in {greet}");
    }
    for absent in ["AUTH=PLAIN", "AUTH=LOGIN", "AUTH=OAUTHBEARER", "AUTH=EXTERNAL"] {
        assert!(
            !greet.contains(absent),
            "{absent} requires TLS, must not be advertised on a plain connection: {greet}"
        );
    }
    drop(rt);
}

/// LOGIN's credential check runs off the reactor thread (issue #181); a
/// SELECT pipelined right behind it in the same TCP write must not be
/// processed until the check resolves and the session actually becomes
/// Authenticated — otherwise it would race ahead and see stale
/// (not-authenticated) state. `SlowStore` widens the offload's window so
/// this is reliably observable rather than a timing coincidence.
#[test]
fn server_login_pipelined_with_select_waits_for_async_credential_check() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: PasswordStore::new().with_user("alice", "secret"),
        delay: Duration::from_millis(150),
    });
    let (rt, addr) = start_imap_server_with_store(&dir, store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    // One write, both commands — proves this isn't just "two separate
    // reads happened to land in order." Both replies are awaited from a
    // single accumulating read (not two separate `read_until` calls): the
    // two replies can legitimately land in the same TCP segment once the
    // credential check and mailbox open both resolve quickly, and a second
    // fresh `read_until` call has no way to see bytes a prior call already
    // drained out of the socket.
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\na2 SELECT INBOX\r\n");
    let r = read_until(&mut stream, &mut buf, |s| {
        s.contains("a1 OK") && s.contains("a2 ")
    });
    assert!(r.contains("a1 OK"), "login: {r}");
    assert!(
        r.contains("a2 OK") && r.contains("1 EXISTS"),
        "pipelined SELECT must be processed only after LOGIN's async \
         credential check completes, against authenticated state: {r}"
    );
    drop(rt);
}

/// Same race, but for the SASL path (issue #181), using CRAM-MD5 — a
/// server-first, multi-round-trip mechanism (no TLS required) whose
/// *first* step offload is the new `first_step` code path added for this
/// issue. Challenge round-trip, then the client's response and a pipelined
/// SELECT sent in the same write right behind it.
#[test]
fn server_authenticate_pipelined_with_select_waits_for_async_step() {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: PasswordStore::new().with_user("alice", "secret"),
        delay: Duration::from_millis(150),
    });
    let (rt, addr) = start_imap_server_with_store(&dir, store);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];
    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    write_cmd(&mut stream, b"a1 AUTHENTICATE CRAM-MD5\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("+ ") && s.ends_with("\r\n"));
    let b64 = r.trim().strip_prefix("+ ").expect("continuation prefix");
    let challenge = String::from_utf8(rmimeparser::charset::base64::decode(b64).unwrap())
        .expect("challenge is ASCII");
    let digest = hopf_auth::cram_md5::compute_response("secret", &challenge);
    let response = rmimeparser::charset::base64::encode(format!("alice {digest}").as_bytes());
    write_cmd(
        &mut stream,
        format!("{response}\r\na2 SELECT INBOX\r\n").as_bytes(),
    );

    let r = read_until(&mut stream, &mut buf, |s| {
        s.contains("a1 OK") && s.contains("a2 ")
    });
    assert!(r.contains("a1 OK"), "authenticate: {r}");
    assert!(
        r.contains("a2 OK") && r.contains("1 EXISTS"),
        "pipelined SELECT must be processed only after the offloaded SASL \
         step completes, against authenticated state: {r}"
    );
    drop(rt);
}

// ── COMPRESS=DEFLATE (RFC 4978) ───────────────────────────────────────────────

#[derive(Default)]
struct CompressState {
    compress_ok: Option<bool>,
    selected: Option<bool>,
    done: Option<bool>,
}

struct CompressDriver {
    state: Arc<Mutex<CompressState>>,
}

struct CompressFactory(Arc<Mutex<CompressState>>);

impl ImapClientHandlerFactory for CompressFactory {
    fn create(&self) -> Box<dyn ImapClientDriver> {
        Box::new(CompressDriver {
            state: Arc::clone(&self.0),
        })
    }
}

impl ImapClientDriver for CompressDriver {
    fn on_greeting(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _text: &str,
        _preauth: bool,
        _caps: &ImapCapabilities,
    ) {
        auth.capability();
    }

    fn on_capability(
        &mut self,
        auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        caps: &ImapCapabilities,
    ) {
        // RFC 4978 §3 / issue #408: COMPRESS=DEFLATE is authenticated-only,
        // so it must not appear on the pre-auth CAPABILITY response.
        assert!(!caps.compress_deflate, "COMPRESS=DEFLATE must not be advertised pre-auth");
        auth.login("alice", "secret");
    }

    fn on_tls_established(
        &mut self,
        _post: &mut dyn crate::ImapClientPostStarttls,
        _ep: &mut dyn Endpoint,
    ) {
    }

    fn on_tls_unavailable(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
    }

    fn on_authenticated(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        caps: &ImapCapabilities,
    ) {
        assert!(caps.compress_deflate, "post-auth capability must include COMPRESS=DEFLATE");
        session.compress_deflate();
    }

    fn on_auth_failed(
        &mut self,
        _auth: &mut dyn ImapClientNotAuthenticated,
        ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        self.state.lock().unwrap().done = Some(false);
        ep.close();
    }

    fn on_auth_continue(
        &mut self,
        _exchange: &mut dyn ImapClientAuthExchange,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
    }

    fn on_compress_complete(
        &mut self,
        session: &mut dyn ImapClientAuthenticated,
        ep: &mut dyn Endpoint,
        status: ImapStatus,
        _message: &str,
    ) {
        let ok = status == ImapStatus::Ok;
        self.state.lock().unwrap().compress_ok = Some(ok);
        if ok {
            // Every byte from here on, in both directions, is DEFLATE
            // -compressed — SELECT's multi-line untagged response
            // (FLAGS/EXISTS/RECENT/OK[...]) must still parse correctly.
            session.select("INBOX");
        } else {
            self.state.lock().unwrap().done = Some(false);
            ep.close();
        }
    }

    fn on_selected(
        &mut self,
        selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        _info: &ImapMailboxInfo,
        _read_only: bool,
    ) {
        self.state.lock().unwrap().selected = Some(true);
        selected.logout();
    }

    fn on_select_failed(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _message: &str,
    ) {
        let mut st = self.state.lock().unwrap();
        st.selected = Some(false);
        st.done = Some(false);
    }

    fn on_fetch_literal(&mut self, _data: &[u8], _ep: &mut dyn Endpoint) {}

    fn on_fetch_complete(
        &mut self,
        _selected: &mut dyn ImapClientSelected,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _message: &str,
    ) {
    }

    fn on_append_continue(
        &mut self,
        _append: &mut dyn ImapClientAppend,
        _ep: &mut dyn Endpoint,
        _text: &str,
    ) {
    }

    fn on_append_complete(
        &mut self,
        _session: &mut dyn ImapClientAuthenticated,
        _ep: &mut dyn Endpoint,
        _status: ImapStatus,
        _appenduid: Option<&ImapAppendUid>,
        _message: &str,
    ) {
    }

    fn on_error(&mut self, _ep: &mut dyn Endpoint, _err: &io::Error) {
        let mut st = self.state.lock().unwrap();
        if st.done.is_none() {
            st.done = Some(false);
        }
    }

    fn on_timeout(&mut self, _ep: &mut dyn Endpoint) {
        let mut st = self.state.lock().unwrap();
        if st.done.is_none() {
            st.done = Some(false);
        }
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {
        let mut st = self.state.lock().unwrap();
        if st.done.is_none() {
            st.done = Some(st.selected == Some(true));
        }
    }
}

/// Full client+server round trip through `COMPRESS DEFLATE`: LOGIN, then
/// negotiate compression, then SELECT (whose multi-line untagged response
/// must still parse correctly) over the now-compressed connection, then
/// LOGOUT — exercising both hopf-imap's server-side and client-side RFC
/// 4978 support against each other.
#[test]
fn client_compress_deflate_round_trip_real_server() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let state = Arc::new(Mutex::new(CompressState::default()));
    ImapClient::from_addr(addr)
        .timeouts(fetch_timeouts())
        .connect(&rt, Arc::new(CompressFactory(Arc::clone(&state))))
        .unwrap();

    assert!(wait_for(|| state.lock().unwrap().done.is_some(), 5000));
    let st = state.lock().unwrap();
    assert_eq!(st.compress_ok, Some(true), "COMPRESS DEFLATE must succeed");
    assert_eq!(st.selected, Some(true), "SELECT over the compressed connection must succeed");
    assert_eq!(st.done, Some(true));
}

/// Wire-level proof independent of hopf-imap's own `ImapCompressLayer`: a
/// hand-rolled raw-DEFLATE (RFC 1951, no zlib wrapper) encoder/decoder,
/// exactly matching what any RFC 4978-conformant peer would use, both
/// reads the server's compressed reply and writes a compressed command —
/// standing in for interop with a second implementation.
#[test]
fn server_compress_deflate_wire_bytes_round_trip_raw() {
    use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};

    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 OK"), "login: {r}");

    write_cmd(&mut stream, b"a2 COMPRESS DEFLATE\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "compress negotiation: {r}");

    // From here on the wire is raw DEFLATE (RFC 4978 §3), flushed with
    // Z_SYNC_FLUSH per write so a peer can decode it immediately — a fresh,
    // independent `Compress`/`Decompress` pair, not hopf-imap's own
    // `ImapCompressLayer`.
    let mut compressor = Compress::new(Compression::default(), false);
    let mut wire_cmd = vec![0u8; 256];
    compressor
        .compress(b"a3 NOOP\r\n", &mut wire_cmd, FlushCompress::Sync)
        .unwrap();
    wire_cmd.truncate(compressor.total_out() as usize);
    stream.write_all(&wire_cmd).unwrap();

    let mut decompressor = Decompress::new(false);
    let mut plaintext = Vec::new();
    let mut scratch = vec![0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !String::from_utf8_lossy(&plaintext).contains("a3 OK") {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a3 OK: {:?}",
            String::from_utf8_lossy(&plaintext)
        );
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            continue;
        }
        let out0 = decompressor.total_out();
        decompressor
            .decompress(&buf[..n], &mut scratch, FlushDecompress::None)
            .unwrap();
        let produced = (decompressor.total_out() - out0) as usize;
        plaintext.extend_from_slice(&scratch[..produced]);
    }
    let text = String::from_utf8_lossy(&plaintext);
    assert!(text.contains("a3 OK"), "NOOP over compressed wire: {text}");

    drop(rt);
}

// ── UTF8=ACCEPT (RFC 6855) ────────────────────────────────────────────────────

/// `ENABLE UTF8=ACCEPT` followed by CREATE/LIST/SELECT of a non-ASCII
/// mailbox name, sent and echoed back as raw UTF-8 (no modified UTF-7).
#[test]
fn server_utf8_accept_enable_and_internationalized_mailbox_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 OK"), "login: {r}");
    assert!(
        r.contains("UTF8=ACCEPT"),
        "post-auth CAPABILITY must include UTF8=ACCEPT: {r}"
    );

    write_cmd(&mut stream, b"a2 ENABLE UTF8=ACCEPT\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "enable: {r}");
    assert!(
        r.contains("ENABLED") && r.contains("UTF8=ACCEPT"),
        "server must confirm UTF8=ACCEPT was enabled: {r}"
    );

    // "Buzon Francais" with accented characters, sent as raw UTF-8 in a
    // quoted string — RFC 6855 §4 replaces the modified-UTF-7 requirement
    // with plain UTF-8 once UTF8=ACCEPT is enabled.
    let name = "Bu\u{00ee}te \u{00e9}t\u{00e9}"; // "Boîte été"
    let create_cmd = format!("a3 CREATE \"{name}\"\r\n");
    write_cmd(&mut stream, create_cmd.as_bytes());
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "create: {r}");

    write_cmd(&mut stream, b"a4 LIST \"\" \"*\"\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(r.contains("a4 OK"), "list: {r}");
    assert!(
        r.contains(name),
        "LIST must echo the mailbox name as raw UTF-8, not modified UTF-7: {r}"
    );

    let select_cmd = format!("a5 SELECT \"{name}\"\r\n");
    write_cmd(&mut stream, select_cmd.as_bytes());
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    assert!(r.contains("a5 OK"), "select the internationalized mailbox: {r}");

    drop(rt);
}

/// COMPRESS DEFLATE's rejection paths must not disturb the (still
/// uncompressed) connection: wrong mechanism name, then a real negotiation,
/// then a second attempt correctly refused as already active.
#[test]
fn server_compress_deflate_rejection_paths_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));

    // Pre-auth: COMPRESS is authenticated-only.
    write_cmd(&mut stream, b"a1 COMPRESS DEFLATE\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(
        r.contains("a1 NO") || r.contains("a1 BAD"),
        "COMPRESS before LOGIN must be refused: {r}"
    );

    write_cmd(&mut stream, b"a2 LOGIN alice secret\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "login: {r}");

    // Unsupported mechanism name.
    write_cmd(&mut stream, b"a3 COMPRESS GZIP\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 BAD"), "unsupported mechanism must be BAD: {r}");

    // Real negotiation succeeds.
    write_cmd(&mut stream, b"a4 COMPRESS DEFLATE\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(r.contains("a4 OK"), "compress: {r}");

    // A second attempt, now compressed on the wire — encode with a fresh,
    // independent raw-DEFLATE compressor and confirm the server answers NO
    // without corrupting the (still-compressed) connection state.
    use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
    let mut c = Compress::new(Compression::default(), false);
    let mut wire = vec![0u8; 256];
    c.compress(b"a5 COMPRESS DEFLATE\r\n", &mut wire, FlushCompress::Sync)
        .unwrap();
    wire.truncate(c.total_out() as usize);
    stream.write_all(&wire).unwrap();

    let mut d = Decompress::new(false);
    let mut plaintext = Vec::new();
    let mut scratch = vec![0u8; 4096];
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !String::from_utf8_lossy(&plaintext).contains("a5 ") {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a5 reply: {:?}",
            String::from_utf8_lossy(&plaintext)
        );
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            continue;
        }
        let out0 = d.total_out();
        d.decompress(&buf[..n], &mut scratch, FlushDecompress::None).unwrap();
        let produced = (d.total_out() - out0) as usize;
        plaintext.extend_from_slice(&scratch[..produced]);
    }
    let text = String::from_utf8_lossy(&plaintext);
    assert!(
        text.contains("a5 NO"),
        "a second COMPRESS while already active must be refused: {text}"
    );

    drop(rt);
}

/// SORT (RFC 5256 §3) and THREAD REFERENCES (RFC 5256 §2.2) over a real
/// server and Maildir-backed mailbox, plus STATUS=SIZE (RFC 8438) —
/// capability advertisement and one success path per command family.
#[test]
fn server_sort_thread_and_status_size_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server_with_sort_thread_fixture(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 OK"), "login: {r}");
    assert!(
        r.contains(" SORT")
            && r.contains("THREAD=REFERENCES")
            && r.contains("THREAD=ORDEREDSUBJECT")
            && r.contains("STATUS=SIZE"),
        "post-auth CAPABILITY must advertise SORT, THREAD=*, and STATUS=SIZE: {r}"
    );

    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK") && r.contains("3 EXISTS"), "select: {r}");

    // Base subject folds "Re: Question" and "Question" together, so the
    // sort tie between messages 1 and 2 must fall back to sequence order,
    // after "Other" sorts first.
    write_cmd(&mut stream, b"a3 SORT (SUBJECT) UTF-8 ALL\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "sort: {r}");
    assert!(
        r.contains("* SORT 3 1 2"),
        "expected \"Other\" then the \"Question\"/\"Re: Question\" tie in sequence order: {r}"
    );

    // Message 2 is a reply to message 1 (References); message 3 is
    // unrelated and sent earlier, so it threads as an independent root
    // ahead of the reply chain.
    write_cmd(&mut stream, b"a4 THREAD REFERENCES UTF-8 ALL\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(r.contains("a4 OK"), "thread: {r}");
    assert!(
        r.contains("* THREAD (3)(1 2)"),
        "expected message 3 as an earlier standalone root, then 1's reply chain to 2: {r}"
    );

    write_cmd(&mut stream, b"a5 STATUS INBOX (SIZE)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    assert!(
        r.contains("a5 OK") && r.contains("SIZE"),
        "status size: {r}"
    );

    drop(rt);
}

/// A STATUS command issued while a mailbox is selected must not lose the
/// session's "selected" handler — found while adding STATUS (MAILBOXID)
/// coverage for issue #409: `StatusState::proceed`/`no` only ever hand
/// back a `Box<dyn AuthenticatedHandler>` (STATUS is valid from either
/// Authenticated or Selected state), so a naive restore after the async
/// completion silently dropped `self.selected` forever, breaking every
/// following SELECTED-state command (FETCH, STORE, SEARCH, …) until the
/// client re-SELECTed — with no error response at all, just a hang.
#[test]
fn server_status_while_selected_does_not_lose_the_selected_session_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a1 OK"));
    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "select: {r}");

    write_cmd(&mut stream, b"a3 STATUS INBOX (MESSAGES)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "status: {r}");

    // Before the fix, this FETCH got no response at all: `self.selected`
    // had been silently cleared by the STATUS above.
    write_cmd(&mut stream, b"a4 FETCH 1 (FLAGS)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(
        r.contains("a4 OK"),
        "FETCH after STATUS-while-selected must still work: {r}"
    );

    write_cmd(&mut stream, b"a5 LOGOUT\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    drop(rt);
}

/// OBJECTID (RFC 8474): CAPABILITY, `MAILBOXID` on SELECT/STATUS, and
/// `EMAILID`/SEARCH EMAILID — over a real loopback server and real
/// Maildir-backed mailbox.
#[test]
fn server_objectid_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a1 "));
    assert!(r.contains("a1 OK"), "login: {r}");
    assert!(
        r.contains("OBJECTID") && r.contains("METADATA") && r.contains("NOTIFY"),
        "post-auth CAPABILITY must advertise OBJECTID, METADATA, and NOTIFY: {r}"
    );

    write_cmd(&mut stream, b"a2 SELECT INBOX\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK") && r.contains("1 EXISTS"), "select: {r}");
    assert!(
        r.contains("OK [MAILBOXID ("),
        "SELECT must report MAILBOXID: {r}"
    );
    let mailboxid = extract_paren_value(&r, "MAILBOXID (");

    write_cmd(&mut stream, b"a3 STATUS INBOX (MAILBOXID)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "status mailboxid: {r}");
    assert!(
        r.contains(&format!("MAILBOXID ({mailboxid})")),
        "STATUS MAILBOXID must match SELECT's: {r}"
    );

    write_cmd(&mut stream, b"a4 FETCH 1 (EMAILID THREADID)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a4 "));
    assert!(r.contains("a4 OK"), "fetch emailid: {r}");
    assert!(r.contains("THREADID NIL"), "threadid unsupported: {r}");
    assert!(r.contains("EMAILID ("), "fetch emailid: {r}");
    let emailid = extract_paren_value(&r, "EMAILID (");
    assert!(
        emailid.starts_with(&format!("E{mailboxid}.")),
        "EMAILID must be derived from this mailbox's MAILBOXID: {emailid}"
    );

    write_cmd(
        &mut stream,
        format!("a5 SEARCH EMAILID \"{emailid}\"\r\n").as_bytes(),
    );
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    assert!(
        r.contains("a5 OK") && r.contains("* SEARCH 1"),
        "search by emailid must find message 1: {r}"
    );

    write_cmd(&mut stream, b"a6 LOGOUT\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a6 "));
    drop(rt);
}

/// Extract the value inside `"{prefix}<value>)"` from `s` — a small test
/// helper for pulling a MAILBOXID/EMAILID out of a raw server response
/// line without a full IMAP response parser.
fn extract_paren_value(s: &str, prefix: &str) -> String {
    let start = s.find(prefix).unwrap_or_else(|| panic!("{prefix} not found in: {s}")) + prefix.len();
    let end = s[start..].find(')').unwrap_or_else(|| panic!("unclosed {prefix} in: {s}"));
    s[start..start + end].to_string()
}

/// METADATA (RFC 5464): SETMETADATA / GETMETADATA on a real mailbox, with
/// DEPTH and server-vs-mailbox scoping, over a real loopback server.
#[test]
fn server_metadata_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = vec![0u8; 8192];

    read_until(&mut stream, &mut buf, |s| s.contains("* OK"));
    write_cmd(&mut stream, b"a1 LOGIN alice secret\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a1 OK"));

    write_cmd(
        &mut stream,
        b"a2 SETMETADATA INBOX (/private/comment \"hello\")\r\n",
    );
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK"), "setmetadata: {r}");

    write_cmd(&mut stream, b"a3 GETMETADATA INBOX (/private/comment)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "getmetadata: {r}");
    assert!(
        r.contains("* METADATA INBOX (/private/comment \"hello\")"),
        "getmetadata response: {r}"
    );

    // Server-level ("" mailbox) annotations are a separate namespace from
    // the same entry set on a real mailbox.
    write_cmd(
        &mut stream,
        b"a4 SETMETADATA \"\" (/private/comment \"server-wide\")\r\n",
    );
    read_until(&mut stream, &mut buf, |s| s.contains("a4 OK"));
    write_cmd(&mut stream, b"a5 GETMETADATA \"\" (/private/comment)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a5 "));
    assert!(
        r.contains("\"server-wide\""),
        "server metadata must be independent of INBOX's: {r}"
    );
    write_cmd(&mut stream, b"a6 GETMETADATA INBOX (/private/comment)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a6 "));
    assert!(
        r.contains("\"hello\"") && !r.contains("server-wide"),
        "mailbox metadata must be unaffected by the server-level SETMETADATA: {r}"
    );

    // NIL deletes the entry.
    write_cmd(
        &mut stream,
        b"a7 SETMETADATA INBOX (/private/comment NIL)\r\n",
    );
    read_until(&mut stream, &mut buf, |s| s.contains("a7 OK"));
    write_cmd(&mut stream, b"a8 GETMETADATA INBOX (/private/comment)\r\n");
    let r = read_until(&mut stream, &mut buf, |s| s.contains("a8 "));
    assert!(
        r.contains("* METADATA INBOX ()"),
        "deleted entry must not appear: {r}"
    );

    write_cmd(&mut stream, b"a9 LOGOUT\r\n");
    read_until(&mut stream, &mut buf, |s| s.contains("a9 "));
    drop(rt);
}

/// NOTIFY (RFC 5465, SELECTED subset): after `NOTIFY SET (SELECTED
/// MessageNew)`, an APPEND from a *second* connection is pushed to the
/// first as an unsolicited `EXISTS` without that connection ever issuing
/// IDLE or another command — the whole point of NOTIFY over plain IDLE.
#[test]
fn server_notify_selected_message_new_raw() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, addr) = start_imap_server(&dir);

    let mut watcher = TcpStream::connect(addr).unwrap();
    watcher
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut wbuf = vec![0u8; 8192];
    read_until(&mut watcher, &mut wbuf, |s| s.contains("* OK"));
    write_cmd(&mut watcher, b"a1 LOGIN alice secret\r\n");
    read_until(&mut watcher, &mut wbuf, |s| s.contains("a1 OK"));
    write_cmd(&mut watcher, b"a2 SELECT INBOX\r\n");
    let r = read_until(&mut watcher, &mut wbuf, |s| s.contains("a2 "));
    assert!(r.contains("a2 OK") && r.contains("1 EXISTS"), "select: {r}");

    write_cmd(
        &mut watcher,
        b"a3 NOTIFY SET (SELECTED MessageNew MessageExpunge FlagChange)\r\n",
    );
    let r = read_until(&mut watcher, &mut wbuf, |s| s.contains("a3 "));
    assert!(r.contains("a3 OK"), "notify set: {r}");

    let mut appender = TcpStream::connect(addr).unwrap();
    appender
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut abuf = vec![0u8; 8192];
    read_until(&mut appender, &mut abuf, |s| s.contains("* OK"));
    write_cmd(&mut appender, b"b1 LOGIN alice secret\r\n");
    read_until(&mut appender, &mut abuf, |s| s.contains("b1 OK"));
    let payload = b"From: c@d\r\nSubject: pushed\r\n\r\nnotify me\r\n";
    write_cmd(
        &mut appender,
        format!("b2 APPEND INBOX {{{}}}\r\n", payload.len()).as_bytes(),
    );
    read_until(&mut appender, &mut abuf, |s| s.contains("+ "));
    write_cmd(&mut appender, payload);
    write_cmd(&mut appender, b"\r\n");
    let r = read_until(&mut appender, &mut abuf, |s| s.contains("b2 "));
    assert!(r.contains("b2 OK"), "append: {r}");

    // The watcher never sends another command — this must arrive from the
    // NOTIFY poll timer, not a NOOP/IDLE-triggered diff.
    let r = read_until(&mut watcher, &mut wbuf, |s| s.contains("2 EXISTS"));
    assert!(
        r.contains("2 EXISTS"),
        "NOTIFY must push the new message without any command on this connection: {r}"
    );

    drop(rt);
}
