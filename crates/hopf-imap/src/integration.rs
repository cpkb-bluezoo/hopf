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

use hopf_auth::PasswordStore;
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

/// Start an ImapService with one message in alice's INBOX; returns (rt, addr).
fn start_imap_server(dir: &tempfile::TempDir) -> (Arc<Runtime>, SocketAddr) {
    let factory = seed_mailbox(dir);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let store = Arc::new(PasswordStore::new().with_user("alice", "secret"));
    let config = ImapConfig::new("127.0.0.1:0".parse().unwrap(), "localhost", store, factory);
    let svc = ImapService::new(config, Arc::clone(&rt));
    let addr = svc.start().unwrap();
    (rt, addr)
}

/// Self-signed cert for `localhost`: returns (acceptor, client connector).
fn tls_pair(
    dir: &tempfile::TempDir,
) -> (
    hopf_core::tls::SharedTlsAcceptor,
    hopf_core::SharedTlsConnector,
) {
    use hopf_tls::{acceptor_from_pem, connector};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[]).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    (acceptor, connector(client_cfg))
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
    let (rt, addr) = start_imap_server(&dir);

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
    let (rt, addr) = start_imap_server(&dir);

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
