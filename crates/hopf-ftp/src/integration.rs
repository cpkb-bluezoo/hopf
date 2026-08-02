// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Optional PASV / client smoke tests (feature `integration`).
//!
//! These tests start an in-process FTP server and exercise it via the async
//! [`FtpClient`] + [`FtpGet`] / [`FtpPut`] pipelines.

#![cfg(feature = "integration")]

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_auth::PasswordTrustPolicy;
use hopf_core::{Runtime, RuntimeConfig};
use hopf_core::QuotaManager as _;

use crate::{
    BasicFtpFileSystem, DirectoryChange, FtpAbortHandle, FtpAuthResult, FtpClient,
    FtpClientTimeouts, FtpConnectionHandler, FtpConnectionHandlerFactory, FtpConnectionMetadata,
    FtpError, FtpFileInfo, FtpFileOpResult, FtpFileSystem, FtpGet, FtpOperation, FtpPipeline,
    FtpPut, FtpSessionWrite, FtpStorHandle, FtpConfig, FtpService, MessageReceiveCallback,
    StorReady, TransferObserver, UniqueName,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Test-only [`MessageReceiveCallback`] that assembles a whole-buffer result
/// purely so the test can assert on it — the transfer itself is still
/// driven entirely through the real streaming callback, chunk by chunk.
struct CollectReceiver {
    buf: Vec<u8>,
    out: Arc<Mutex<Option<io::Result<Vec<u8>>>>>,
}

impl CollectReceiver {
    fn new(out: Arc<Mutex<Option<io::Result<Vec<u8>>>>>) -> Self {
        Self { buf: Vec::new(), out }
    }
}

impl MessageReceiveCallback for CollectReceiver {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.buf.extend_from_slice(chunk);
        true
    }

    fn end_message(&mut self, result: io::Result<()>) {
        let buf = std::mem::take(&mut self.buf);
        *self.out.lock().unwrap() = Some(result.map(|_| buf));
    }
}

/// Test-only `ready` callback that pushes a whole in-memory buffer through
/// a [`FtpStorHandle`] once armed.
fn stor_ready_with(data: Vec<u8>) -> StorReady {
    Box::new(move |handle: FtpStorHandle| {
        handle.feed(&data);
        handle.finish();
    })
}

fn start_server(root: &std::path::Path) -> (Arc<Runtime>, SocketAddr) {
    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, root, policy.shared());
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

/// Self-signed cert for `localhost`: returns (acceptor, client connector).
fn tls_pair(
    dir: &tempfile::TempDir,
) -> (hopf_core::tls::SharedTlsAcceptor, hopf_core::SharedTlsConnector) {
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

/// Start a server requiring explicit `AUTH TLS` + `PROT P` for data
/// connections (rejects plaintext data channels).
fn start_server_explicit_ftps(
    root: &std::path::Path,
    acceptor: hopf_core::tls::SharedTlsAcceptor,
) -> (Arc<Runtime>, SocketAddr) {
    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, root, policy.shared())
        .with_tls(acceptor)
        .require_data_tls();
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

/// Run an [`FtpGet`] pipeline and block until the result arrives.
fn run_get(
    rt: &Arc<Runtime>,
    addr: SocketAddr,
    remote: &str,
) -> std::io::Result<Vec<u8>> {
    let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let pipeline = FtpGet::new(remote, Box::new(CollectReceiver::new(Arc::clone(&result))));
    FtpClient::new(addr.ip().to_string())
        .port(addr.port())
        .credentials("u", "p")
        .prefer_epsv(false) // server uses PASV
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(rt, Box::new(pipeline))?;
    wait_result(result)
}

/// Run an [`FtpPut`] pipeline and block until the result arrives.
fn run_put(
    rt: &Arc<Runtime>,
    addr: SocketAddr,
    remote: &str,
    data: Vec<u8>,
) -> std::io::Result<()> {
    let result: Arc<Mutex<Option<std::io::Result<()>>>> = Arc::new(Mutex::new(None));
    let result2 = Arc::clone(&result);
    let pipeline = FtpPut::new(remote, Box::new(io::Cursor::new(data)), move |r| {
        *result2.lock().unwrap() = Some(r);
    });
    FtpClient::new(addr.ip().to_string())
        .port(addr.port())
        .credentials("u", "p")
        .prefer_epsv(false)
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(rt, Box::new(pipeline))?;
    wait_result(result)
}

fn wait_result<T>(cell: Arc<Mutex<Option<std::io::Result<T>>>>) -> std::io::Result<T> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(r) = cell.lock().unwrap().take() {
            return r;
        }
        if Instant::now() > deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "FTP integration test timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Explicit FTPS: `AUTH TLS` on the control channel, `PBSZ 0`/`PROT P`
/// negotiated, then a real RETR — the server rejects plaintext data
/// connections (`require_data_tls`), so this fails unless the client's
/// PROT P negotiation *and* TLS-wrapped data connection both actually work.
#[test]
fn async_client_auth_tls_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secret.txt"), b"over-tls").unwrap();
    let (acceptor, connector) = tls_pair(&dir);
    let (rt, bound) = start_server_explicit_ftps(dir.path(), acceptor);

    let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let pipeline = FtpGet::new("secret.txt", Box::new(CollectReceiver::new(Arc::clone(&result))));
    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .prefer_epsv(false)
        .auth_tls(connector, "localhost")
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();

    let body = wait_result(result).unwrap();
    assert_eq!(body, b"over-tls");

    drop(rt);
}

/// Implicit FTPS: TLS from the first byte (no `AUTH TLS` negotiation) —
/// still negotiates `PBSZ 0`/`PROT P` before the transfer.
#[test]
fn async_client_implicit_tls_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secret.txt"), b"implicit-tls-data").unwrap();
    let (acceptor, connector) = tls_pair(&dir);

    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, dir.path(), policy.shared())
        .with_tls(acceptor)
        .implicit_ftps()
        .require_data_tls();
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();

    let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let pipeline = FtpGet::new("secret.txt", Box::new(CollectReceiver::new(Arc::clone(&result))));
    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .prefer_epsv(false)
        .implicit_tls(connector, "localhost")
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();

    let body = wait_result(result).unwrap();
    assert_eq!(body, b"implicit-tls-data");

    drop(rt);
}

/// Reads one (single-line) reply from `ctrl`.
fn read_reply(ctrl: &mut std::net::TcpStream) -> String {
    use std::io::Read;
    let mut buf = [0u8; 4096];
    let n = ctrl.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Sends one command over `ctrl` and returns the (single-line) reply text.
fn raw_cmd(ctrl: &mut std::net::TcpStream, cmd: &str) -> String {
    use std::io::Write;
    ctrl.write_all(cmd.as_bytes()).unwrap();
    read_reply(ctrl)
}

/// Connects and logs in over a raw control socket (bypassing `FtpSessionWrite`)
/// — needed for the two tests below that assert server-side PROT-P /
/// require-TLS behaviour with hand-rolled PORT sequences.
fn raw_login(bound: SocketAddr) -> std::net::TcpStream {
    use std::io::Read;
    let mut ctrl = std::net::TcpStream::connect(bound).unwrap();
    ctrl.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4096];
    let _ = ctrl.read(&mut buf).unwrap(); // 220 welcome
    let r = raw_cmd(&mut ctrl, "USER u\r\n");
    assert!(r.starts_with("331") || r.starts_with("230"), "USER: {r}");
    if r.starts_with("331") {
        let r = raw_cmd(&mut ctrl, "PASS p\r\n");
        assert!(r.starts_with("230"), "PASS: {r}");
    }
    ctrl
}

/// Issue #3 (2b): `require_tls_for_data` must actually reject a data
/// transfer attempted without `PROT P`, not silently force TLS on the PASV
/// listener while leaving a plaintext-only client to just hang/fail
/// unexpectedly. Exercised with PASV directly over a raw control socket —
/// a client that never negotiated `PROT P` should be turned away at the
/// PASV command itself, with a clear reply, before any listener opens.
#[test]
fn require_tls_for_data_rejects_pasv_without_prot_p() {
    let dir = tempfile::tempdir().unwrap();
    let (acceptor, _connector) = tls_pair(&dir);
    let (rt, bound) = start_server_explicit_ftps(dir.path(), acceptor);

    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "TYPE I\r\n");
    assert!(r.starts_with("200"), "TYPE I: {r}");

    // No AUTH TLS, no PBSZ/PROT P — require_tls_for_data must reject this.
    let r = raw_cmd(&mut ctrl, "PASV\r\n");
    assert!(r.starts_with("522"), "PASV without PROT P should be rejected, got: {r}");

    drop(rt);
}

/// Issue #3 (2a): `PROT P` must protect active-mode (PORT) data
/// connections too, not just PASV — previously hardcoded to cleartext
/// regardless of `PROT P` (`prepare_data`'s `DataMode::Active` arm). Drives
/// PORT/PROT P by hand over a raw control socket (independent of the async
/// client's own active-mode path) and proves the resulting connection is
/// really TLS-secured by checking `security_established` actually fires on
/// our own accepting listener — not just that decodable bytes arrived,
/// which wouldn't distinguish "really encrypted" from "happened to already
/// be cleartext".
#[test]
fn active_mode_prot_p_actually_encrypts_the_data_connection() {
    use hopf_core::{Endpoint, ProtocolHandler, TcpListenerConfig};
    use std::sync::atomic::{AtomicBool, Ordering};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("secret.txt"), b"active-mode-secret").unwrap();

    // One cert/key pair for the server's own control+PASV acceptor
    // (unused by this test beyond satisfying `cmd_prot`'s availability
    // check), a second, independent pair for the direction this test
    // actually exercises: the server dialing OUT to our fake FTP client's
    // data listener, which must present as a TLS *server* to accept it.
    let control_dir = tempfile::tempdir().unwrap();
    let (control_acceptor, _unused) = tls_pair(&control_dir);
    let (client_acceptor, server_data_connector) = tls_pair(&dir);

    let mut policy = PasswordTrustPolicy::default();
    policy = policy.with_user("u", "p");
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, dir.path(), policy.shared())
        .with_tls(control_acceptor)
        .with_data_tls_connector(server_data_connector, "localhost");
    let service = FtpService::new(config);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();

    struct Capture {
        buf: Arc<Mutex<Vec<u8>>>,
        secured: Arc<AtomicBool>,
    }
    impl ProtocolHandler for Capture {
        fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &hopf_core::SecurityInfo) {
            self.secured.store(true, Ordering::SeqCst);
        }
        fn receive(&mut self, _endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
            self.buf.lock().unwrap().extend_from_slice(data);
            *data = &[];
        }
        fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
        fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &io::Error) {}
    }
    let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let secured = Arc::new(AtomicBool::new(false));
    let (r2, s2) = (Arc::clone(&received), Arc::clone(&secured));
    let (data_listen_addr, _) = rt
        .add_tcp_listener(
            TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                Box::new(Capture { buf: Arc::clone(&r2), secured: Arc::clone(&s2) }) as Box<dyn ProtocolHandler>
            })
            .with_tls(client_acceptor),
        )
        .unwrap();

    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "TYPE I\r\n");
    assert!(r.starts_with("200"), "TYPE I: {r}");
    let r = raw_cmd(&mut ctrl, "PBSZ 0\r\n");
    assert!(r.starts_with("200"), "PBSZ 0: {r}");
    let r = raw_cmd(&mut ctrl, "PROT P\r\n");
    assert!(r.starts_with("200"), "PROT P: {r}");

    let p1 = (data_listen_addr.port() / 256) as u16;
    let p2 = data_listen_addr.port() % 256;
    let r = raw_cmd(&mut ctrl, &format!("PORT 127,0,0,1,{p1},{p2}\r\n"));
    assert!(r.starts_with("200"), "PORT: {r}");

    let r = raw_cmd(&mut ctrl, "RETR secret.txt\r\n");
    assert!(r.starts_with("150"), "RETR not accepted: {r}");
    let r = read_reply(&mut ctrl);
    assert!(r.starts_with("226"), "transfer did not complete: {r}");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if secured.load(Ordering::SeqCst) && !received.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        secured.load(Ordering::SeqCst),
        "active-mode data connection must be TLS-secured once PROT P is in effect"
    );
    assert_eq!(&*received.lock().unwrap(), b"active-mode-secret");

    drop(rt);
}

#[test]
fn async_client_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), b"hi-async-ftp").unwrap();
    let (rt, bound) = start_server(dir.path());

    let body = run_get(&rt, bound, "hello.txt").unwrap();
    assert_eq!(body, b"hi-async-ftp");

    drop(rt);
}

#[test]
fn async_client_stor() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, bound) = start_server(dir.path());

    run_put(&rt, bound, "out.txt", b"uploaded-async".to_vec()).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("out.txt")).unwrap(),
        b"uploaded-async"
    );

    drop(rt);
}

/// Active-mode RETR via `FtpClient::active_mode` (PORT — IPv4 loopback).
#[test]
fn async_client_active_mode_retr() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("active.txt"), b"via-port").unwrap();
    let (rt, bound) = start_server(dir.path());

    let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let pipeline = FtpGet::new("active.txt", Box::new(CollectReceiver::new(Arc::clone(&result))));
    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .active_mode(true)
        .prefer_eprt(false) // exercise classic PORT
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();
    let body = wait_result(result).unwrap();
    assert_eq!(body, b"via-port");

    drop(rt);
}

/// Active-mode STOR via EPRT.
#[test]
fn async_client_active_mode_stor_eprt() {
    let dir = tempfile::tempdir().unwrap();
    let (rt, bound) = start_server(dir.path());

    let result: Arc<Mutex<Option<std::io::Result<()>>>> = Arc::new(Mutex::new(None));
    let result2 = Arc::clone(&result);
    let pipeline = FtpPut::new(
        "eprt-out.txt",
        Box::new(io::Cursor::new(b"via-eprt".to_vec())),
        move |r| {
            *result2.lock().unwrap() = Some(r);
        },
    );
    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .active_mode(true)
        .prefer_eprt(true)
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();
    wait_result(result).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("eprt-out.txt")).unwrap(),
        b"via-eprt"
    );

    drop(rt);
}

/// Custom pipeline exercising APPE / NLST / STOU in one session.
struct AppeNlstStouPipeline {
    appe_path: String,
    appe_data: Vec<u8>,
    results: Arc<Mutex<AppeNlstStouResults>>,
}

#[derive(Default)]
struct AppeNlstStouResults {
    appe: Option<std::io::Result<()>>,
    nlst: Option<std::io::Result<Vec<u8>>>,
    stou: Option<std::io::Result<String>>,
    failed: Option<FtpError>,
}

/// Streams NLST content straight into `AppeNlstStouResults::nlst`.
struct NlstReceiver {
    buf: Vec<u8>,
    results: Arc<Mutex<AppeNlstStouResults>>,
}

impl NlstReceiver {
    fn new(results: Arc<Mutex<AppeNlstStouResults>>) -> Self {
        Self { buf: Vec::new(), results }
    }
}

impl MessageReceiveCallback for NlstReceiver {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        self.buf.extend_from_slice(chunk);
        true
    }

    fn end_message(&mut self, result: io::Result<()>) {
        let buf = std::mem::take(&mut self.buf);
        self.results.lock().unwrap().nlst = Some(result.map(|_| buf));
    }
}

impl FtpPipeline for AppeNlstStouPipeline {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: FtpAbortHandle) {
        session.type_image();

        let r = Arc::clone(&self.results);
        session.appe(
            &self.appe_path,
            stor_ready_with(self.appe_data.clone()),
            Box::new(move |res| {
                r.lock().unwrap().appe = Some(res);
            }),
        );

        let r = Arc::clone(&self.results);
        session.nlst(None, Box::new(NlstReceiver::new(r)));

        let r = Arc::clone(&self.results);
        session.stou(
            stor_ready_with(b"unique-payload".to_vec()),
            Box::new(move |res| {
                r.lock().unwrap().stou = Some(res);
            }),
        );

        session.quit();
    }

    fn done(&mut self) {}

    fn failed(&mut self, err: FtpError) {
        self.results.lock().unwrap().failed = Some(err);
    }
}

#[test]
fn async_client_appe_nlst_stou() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("append-me.txt"), b"base-").unwrap();
    let (rt, bound) = start_server(dir.path());

    let results = Arc::new(Mutex::new(AppeNlstStouResults::default()));
    let pipeline = AppeNlstStouPipeline {
        appe_path: "append-me.txt".into(),
        appe_data: b"appended".to_vec(),
        results: Arc::clone(&results),
    };

    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .prefer_epsv(false)
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        {
            let g = results.lock().unwrap();
            if g.stou.is_some() || g.failed.is_some() {
                break;
            }
        }
        assert!(Instant::now() < deadline, "appe/nlst/stou test timed out");
        std::thread::sleep(Duration::from_millis(10));
    }

    let g = results.lock().unwrap();
    assert!(g.failed.is_none(), "pipeline failed: {:?}", g.failed);
    g.appe.as_ref().unwrap().as_ref().expect("APPE should succeed");
    let nlst = g.nlst.as_ref().unwrap().as_ref().expect("NLST should succeed");
    assert!(
        String::from_utf8_lossy(nlst).contains("append-me.txt"),
        "NLST output: {:?}",
        String::from_utf8_lossy(nlst)
    );
    g.stou.as_ref().unwrap().as_ref().expect("STOU should succeed");
    drop(g);

    assert_eq!(
        std::fs::read(dir.path().join("append-me.txt")).unwrap(),
        b"base-appended"
    );

    drop(rt);
}

/// Custom pipeline exercising `retr_from` (RFC 959 §4.1.3 REST + RETR).
struct RetrFromPipeline {
    path: String,
    offset: u64,
    result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>>,
}

impl FtpPipeline for RetrFromPipeline {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: FtpAbortHandle) {
        session.type_image();
        let r = Arc::clone(&self.result);
        session.retr_from(&self.path, self.offset, Box::new(CollectReceiver::new(r)));
        session.quit();
    }

    fn done(&mut self) {}

    fn failed(&mut self, err: FtpError) {
        *self.result.lock().unwrap() = Some(Err(err.into_io()));
    }
}

#[test]
fn async_client_retr_from_resumes_at_offset() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("resume.txt"), b"0123456789").unwrap();
    let (rt, bound) = start_server(dir.path());

    let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let pipeline = RetrFromPipeline {
        path: "resume.txt".into(),
        offset: 5,
        result: Arc::clone(&result),
    };

    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .prefer_epsv(false)
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();

    let body = wait_result(result).unwrap();
    assert_eq!(body, b"56789");

    drop(rt);
}

/// Custom pipeline exercising `stor_from` (RFC 959 §4.1.3 REST + STOR).
struct StorFromPipeline {
    path: String,
    offset: u64,
    data: Vec<u8>,
    result: Arc<Mutex<Option<std::io::Result<()>>>>,
}

impl FtpPipeline for StorFromPipeline {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: FtpAbortHandle) {
        session.type_image();
        let r = Arc::clone(&self.result);
        session.stor_from(
            &self.path,
            self.offset,
            stor_ready_with(self.data.clone()),
            Box::new(move |res| {
                *r.lock().unwrap() = Some(res);
            }),
        );
        session.quit();
    }

    fn done(&mut self) {}

    fn failed(&mut self, err: FtpError) {
        *self.result.lock().unwrap() = Some(Err(err.into_io()));
    }
}

/// Resumed upload writes at the REST offset instead of truncating the
/// file back to empty — the exact server-side bug found while building
/// `stor_from`: the server previously ignored the REST marker on STOR.
#[test]
fn async_client_stor_from_resumes_at_offset() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("resume.txt"), b"0123456789").unwrap();
    let (rt, bound) = start_server(dir.path());

    let result: Arc<Mutex<Option<std::io::Result<()>>>> = Arc::new(Mutex::new(None));
    let pipeline = StorFromPipeline {
        path: "resume.txt".into(),
        offset: 5,
        data: b"XYZ".to_vec(),
        result: Arc::clone(&result),
    };

    FtpClient::new(bound.ip().to_string())
        .port(bound.port())
        .credentials("u", "p")
        .prefer_epsv(false)
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(3),
            stage: Duration::from_secs(5),
            data: Duration::from_secs(10),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();

    wait_result(result).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("resume.txt")).unwrap(),
        b"01234XYZ89"
    );

    drop(rt);
}

#[test]
fn async_client_retr_then_stor() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("src.txt"), b"source-data").unwrap();
    let (rt, bound) = start_server(dir.path());

    let body = run_get(&rt, bound, "src.txt").unwrap();
    assert_eq!(body, b"source-data");

    run_put(&rt, bound, "dst.txt", body).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("dst.txt")).unwrap(),
        b"source-data"
    );

    drop(rt);
}

/// A listener that accepts but never sends the 220 greeting must trip the
/// stage timer (greeting budget), not hang forever.
#[test]
fn async_client_greeting_timeout() {
    use hopf_core::{Endpoint, ProtocolHandler, TcpListenerConfig};

    struct Silent;
    impl ProtocolHandler for Silent {
        fn connected(&mut self, _: &mut dyn Endpoint) {}
        fn receive(&mut self, _: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _: &mut dyn Endpoint) {}
        fn error(&mut self, _: &mut dyn Endpoint, _: &std::io::Error) {}
    }

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            || Box::new(Silent) as Box<dyn ProtocolHandler>,
        ))
        .unwrap();

    let result: Arc<Mutex<Option<std::io::Result<Vec<u8>>>>> = Arc::new(Mutex::new(None));
    let pipeline = FtpGet::new("x.txt", Box::new(CollectReceiver::new(Arc::clone(&result))));
    FtpClient::new(addr.ip().to_string())
        .port(addr.port())
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(1),
            connect: Duration::from_secs(2),
            stage: Duration::from_millis(300),
            data: Duration::from_secs(2),
        })
        .connect(&rt, Box::new(pipeline))
        .unwrap();

    let got = wait_result(result);
    let err = got.expect_err("greeting timeout should fail the pipeline");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "err={err}");

    drop(rt);
}

/// A dial to a blackholed address must be cut off by the core connect timeout.
#[test]
fn connect_timeout_fires_for_unreachable_peer() {
    use hopf_core::{Endpoint, ProtocolHandler, TcpConnectorConfig};

    struct Watch {
        errored: Arc<Mutex<Option<std::io::ErrorKind>>>,
    }
    impl ProtocolHandler for Watch {
        fn connected(&mut self, _: &mut dyn Endpoint) {}
        fn receive(&mut self, _: &mut dyn Endpoint, data: &mut &[u8]) {
            *data = &[];
        }
        fn disconnected(&mut self, _: &mut dyn Endpoint) {}
        fn error(&mut self, _: &mut dyn Endpoint, err: &std::io::Error) {
            *self.errored.lock().unwrap() = Some(err.kind());
        }
    }

    let rt = Runtime::start(RuntimeConfig::default()).unwrap();
    let errored: Arc<Mutex<Option<std::io::ErrorKind>>> = Arc::new(Mutex::new(None));
    let errored2 = Arc::clone(&errored);

    // TEST-NET-1 (RFC 5737) — guaranteed unroutable; SYN is blackholed.
    let addr: SocketAddr = "192.0.2.1:21".parse().unwrap();
    rt.connect(
        TcpConnectorConfig::new(addr, move || {
            Box::new(Watch {
                errored: Arc::clone(&errored2),
            }) as Box<dyn ProtocolHandler>
        })
        .connect_timeout(Some(Duration::from_millis(300))),
    )
    .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(kind) = *errored.lock().unwrap() {
            assert_eq!(kind, std::io::ErrorKind::TimedOut);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "connect timeout did not fire within 5s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    rt.shutdown();
}

// ---------------------------------------------------------------------------
// App-handler wiring: is_authorized gates, SITE dispatch, disconnected notify
// ---------------------------------------------------------------------------

/// Test handler: authenticates "u"/"p" like [`start_server`], but denies
/// exactly one [`FtpOperation`] (to prove the corresponding command is
/// actually gated by `is_authorized`), answers `SITE PING` and reports
/// anything else as not-supported, and records `disconnected`.
struct AuthzTestHandler {
    fs: BasicFtpFileSystem,
    denied: FtpOperation,
    disconnected: Arc<Mutex<bool>>,
    observer: Option<Arc<dyn TransferObserver>>,
    quota: Option<Arc<dyn hopf_core::QuotaManager>>,
}

impl FtpConnectionHandler for AuthzTestHandler {
    fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        _account: Option<&str>,
        _meta: &FtpConnectionMetadata,
    ) -> FtpAuthResult {
        match password {
            None => FtpAuthResult::NeedPassword,
            Some(p) if username == "u" && p == "p" => FtpAuthResult::Success,
            Some(_) => FtpAuthResult::Failed,
        }
    }

    fn file_system(&mut self, _meta: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem {
        &mut self.fs
    }

    fn is_authorized(&self, op: FtpOperation, _path: &str, _meta: &FtpConnectionMetadata) -> bool {
        op != self.denied
    }

    fn handle_site_command(
        &mut self,
        command: &str,
        _meta: &FtpConnectionMetadata,
    ) -> FtpFileOpResult {
        if command.eq_ignore_ascii_case("PING") {
            FtpFileOpResult::Ok
        } else {
            FtpFileOpResult::NotSupported
        }
    }

    fn disconnected(&mut self, _meta: &FtpConnectionMetadata) {
        *self.disconnected.lock().unwrap() = true;
    }

    fn transfer_observer(&self, _meta: &FtpConnectionMetadata) -> Option<Arc<dyn TransferObserver>> {
        self.observer.clone()
    }

    fn quota_manager(&self) -> Option<Arc<dyn hopf_core::QuotaManager>> {
        self.quota.clone()
    }
}

struct AuthzTestHandlerFactory {
    root: std::path::PathBuf,
    denied: FtpOperation,
    disconnected: Arc<Mutex<bool>>,
    observer: Option<Arc<dyn TransferObserver>>,
    quota: Option<Arc<dyn hopf_core::QuotaManager>>,
}

impl FtpConnectionHandlerFactory for AuthzTestHandlerFactory {
    fn create(&self) -> Box<dyn FtpConnectionHandler> {
        Box::new(AuthzTestHandler {
            fs: BasicFtpFileSystem::new(&self.root, false).unwrap(),
            denied: self.denied,
            disconnected: Arc::clone(&self.disconnected),
            observer: self.observer.clone(),
            quota: self.quota.clone(),
        })
    }
}

fn start_server_with_authz(
    root: &std::path::Path,
    denied: FtpOperation,
    disconnected: Arc<Mutex<bool>>,
) -> (Arc<Runtime>, SocketAddr) {
    start_server_with_authz_ext(root, denied, disconnected, None, None)
}

fn start_server_with_authz_ext(
    root: &std::path::Path,
    denied: FtpOperation,
    disconnected: Arc<Mutex<bool>>,
    observer: Option<Arc<dyn TransferObserver>>,
    quota: Option<Arc<dyn hopf_core::QuotaManager>>,
) -> (Arc<Runtime>, SocketAddr) {
    let policy = PasswordTrustPolicy::default(); // unused: AuthzTestHandler authenticates itself
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, root, policy.shared());
    let factory = Arc::new(AuthzTestHandlerFactory {
        root: root.to_path_buf(),
        denied,
        disconnected,
        observer,
        quota,
    });
    let service = FtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

/// Like [`AuthzTestHandler`], but denies `Rename` only when the path contains
/// `dest` — so RNFR can succeed while RNTO of `/dest.txt` is gated.
struct RntoDenyHandler {
    fs: BasicFtpFileSystem,
}

impl FtpConnectionHandler for RntoDenyHandler {
    fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        _account: Option<&str>,
        _meta: &FtpConnectionMetadata,
    ) -> FtpAuthResult {
        match password {
            None => FtpAuthResult::NeedPassword,
            Some(p) if username == "u" && p == "p" => FtpAuthResult::Success,
            Some(_) => FtpAuthResult::Failed,
        }
    }

    fn file_system(&mut self, _meta: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem {
        &mut self.fs
    }

    fn is_authorized(&self, op: FtpOperation, path: &str, _meta: &FtpConnectionMetadata) -> bool {
        !(op == FtpOperation::Rename && path.contains("dest"))
    }
}

struct RntoDenyFactory {
    root: std::path::PathBuf,
}

impl FtpConnectionHandlerFactory for RntoDenyFactory {
    fn create(&self) -> Box<dyn FtpConnectionHandler> {
        Box::new(RntoDenyHandler {
            fs: BasicFtpFileSystem::new(&self.root, false).unwrap(),
        })
    }
}

fn start_server_with_rnto_authz(root: &std::path::Path) -> (Arc<Runtime>, SocketAddr) {
    let policy = PasswordTrustPolicy::default();
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, root, policy.shared());
    let factory = Arc::new(RntoDenyFactory {
        root: root.to_path_buf(),
    });
    let service = FtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

#[test]
fn mkd_is_gated_by_is_authorized_create_dir() {
    let dir = tempfile::tempdir().unwrap();
    let (_rt, bound) =
        start_server_with_authz(dir.path(), FtpOperation::CreateDir, Arc::new(Mutex::new(false)));
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "MKD /newdir\r\n");
    assert!(r.starts_with("550"), "MKD should be denied: {r}");
    assert!(
        !dir.path().join("newdir").exists(),
        "a denied MKD must not touch the filesystem"
    );
}

#[test]
fn rmd_is_gated_by_is_authorized_delete_dir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    let (_rt, bound) =
        start_server_with_authz(dir.path(), FtpOperation::DeleteDir, Arc::new(Mutex::new(false)));
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "RMD /d\r\n");
    assert!(r.starts_with("550"), "RMD should be denied: {r}");
    assert!(
        dir.path().join("d").exists(),
        "a denied RMD must not touch the filesystem"
    );
}

#[test]
fn rnfr_is_gated_by_is_authorized_rename() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"hi").unwrap();
    let (_rt, bound) =
        start_server_with_authz(dir.path(), FtpOperation::Rename, Arc::new(Mutex::new(false)));
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "RNFR /f.txt\r\n");
    assert!(r.starts_with("550"), "RNFR should be denied: {r}");
}

#[test]
fn rnto_is_gated_by_is_authorized_rename() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f.txt"), b"hi").unwrap();
    let (_rt, bound) = start_server_with_rnto_authz(dir.path());
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "RNFR /f.txt\r\n");
    assert!(r.starts_with("350"), "RNFR should succeed: {r}");
    let r = raw_cmd(&mut ctrl, "RNTO /dest.txt\r\n");
    assert!(r.starts_with("550"), "RNTO should be denied: {r}");
    assert!(
        dir.path().join("f.txt").exists(),
        "denied RNTO must not rename"
    );
}

#[test]
fn cwd_is_gated_by_is_authorized_navigate() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("d")).unwrap();
    let (_rt, bound) =
        start_server_with_authz(dir.path(), FtpOperation::Navigate, Arc::new(Mutex::new(false)));
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "CWD /d\r\n");
    assert!(r.starts_with("550"), "CWD should be denied: {r}");
}

#[test]
fn site_command_dispatches_to_the_application_handler() {
    let dir = tempfile::tempdir().unwrap();
    // Nothing this test does is gated by is_authorized, so deny an
    // unrelated operation.
    let (_rt, bound) =
        start_server_with_authz(dir.path(), FtpOperation::Admin, Arc::new(Mutex::new(false)));
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "SITE PING\r\n");
    assert!(r.starts_with("200"), "SITE PING should succeed: {r}");
    let r = raw_cmd(&mut ctrl, "SITE BOGUS\r\n");
    assert!(
        r.starts_with("502"),
        "an unrecognised SITE subcommand should be 502: {r}"
    );
}

#[test]
fn disconnected_notifies_the_application_handler() {
    let dir = tempfile::tempdir().unwrap();
    let flag = Arc::new(Mutex::new(false));
    let (_rt, bound) =
        start_server_with_authz(dir.path(), FtpOperation::Admin, Arc::clone(&flag));
    {
        let mut ctrl = raw_login(bound);
        let r = raw_cmd(&mut ctrl, "QUIT\r\n");
        assert!(r.starts_with("221"), "QUIT: {r}");
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    while !*flag.lock().unwrap() {
        assert!(Instant::now() < deadline, "disconnected() did not fire within 2s");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Transfer progress hooks + quota enforcement
// ---------------------------------------------------------------------------

/// Records every [`TransferObserver`] call it sees, for assertions.
#[derive(Default)]
struct RecordingObserver {
    events: Mutex<Vec<String>>,
}

impl TransferObserver for RecordingObserver {
    fn transfer_progress(&self, path: &str, upload: bool, data: &[u8], total_transferred: u64) {
        self.events
            .lock()
            .unwrap()
            .push(format!("progress:{path}:{upload}:{}:{total_transferred}", data.len()));
    }

    fn transfer_completed(&self, path: &str, upload: bool, total_transferred: u64, success: bool) {
        self.events
            .lock()
            .unwrap()
            .push(format!("completed:{path}:{upload}:{total_transferred}:{success}"));
    }
}

#[test]
fn transfer_observer_sees_progress_and_completion_for_upload_and_download() {
    let dir = tempfile::tempdir().unwrap();
    let observer: Arc<RecordingObserver> = Arc::new(RecordingObserver::default());
    let (rt, bound) = start_server_with_authz_ext(
        dir.path(),
        FtpOperation::Admin,
        Arc::new(Mutex::new(false)),
        Some(observer.clone() as Arc<dyn TransferObserver>),
        None,
    );

    run_put(&rt, bound, "/up.txt", b"hello world".to_vec()).unwrap();
    let got = run_get(&rt, bound, "/up.txt").unwrap();
    assert_eq!(got, b"hello world");

    let events = observer.events.lock().unwrap();
    assert!(
        events.iter().any(|e| e.starts_with("progress:/up.txt:true:")),
        "expected upload progress events, got {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "completed:/up.txt:true:11:true"),
        "expected a successful upload completion event, got {events:?}"
    );
    assert!(
        events.iter().any(|e| e.starts_with("progress:/up.txt:false:")),
        "expected download progress events, got {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "completed:/up.txt:false:11:true"),
        "expected a successful download completion event, got {events:?}"
    );
}

#[test]
fn quota_blocks_upload_once_a_user_is_already_over_limit() {
    let dir = tempfile::tempdir().unwrap();
    let quota = Arc::new(hopf_core::MemoryQuotaManager::new());
    quota.set_user_quota("u", 10, -1);
    quota.record_bytes_added("u", 10); // already at the limit

    let (rt, bound) = start_server_with_authz_ext(
        dir.path(),
        FtpOperation::Admin,
        Arc::new(Mutex::new(false)),
        None,
        Some(quota as Arc<dyn hopf_core::QuotaManager>),
    );

    let err = run_put(&rt, bound, "/blocked.txt", b"more data".to_vec()).unwrap_err();
    let _ = err; // exact FtpError shape isn't the point — it must fail
    assert!(
        !dir.path().join("blocked.txt").exists(),
        "a quota-blocked upload must not create the file"
    );
}

#[test]
fn quota_usage_is_recorded_on_upload_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let quota = Arc::new(hopf_core::MemoryQuotaManager::new());
    quota.set_user_quota("u", 1_000_000, -1);
    let quota_dyn: Arc<dyn hopf_core::QuotaManager> = quota.clone();

    let (rt, bound) = start_server_with_authz_ext(
        dir.path(),
        FtpOperation::Admin,
        Arc::new(Mutex::new(false)),
        None,
        Some(quota_dyn),
    );

    run_put(&rt, bound, "/tracked.txt", b"0123456789".to_vec()).unwrap();
    assert_eq!(quota.get_quota("u").storage_used(), 10);

    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "DELE /tracked.txt\r\n");
    assert!(r.starts_with("250"), "DELE: {r}");

    let deadline = Instant::now() + Duration::from_secs(2);
    while quota.get_quota("u").storage_used() != 0 {
        assert!(Instant::now() < deadline, "usage was never decremented after DELE");
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// ALLO -> FtpFileSystem::allocate_space
// ---------------------------------------------------------------------------

/// Delegates everything to a [`BasicFtpFileSystem`] except `allocate_space`,
/// which rejects anything over `max` — proof the ALLO hook is real, not
/// just always-succeeding.
struct AllocRejectingFs {
    inner: BasicFtpFileSystem,
    max: u64,
}

impl FtpFileSystem for AllocRejectingFs {
    fn list_directory(&self, path: &str, meta: &FtpConnectionMetadata) -> Option<Vec<FtpFileInfo>> {
        self.inner.list_directory(path, meta)
    }
    fn change_directory(&self, path: &str, cwd: &str, meta: &FtpConnectionMetadata) -> DirectoryChange {
        self.inner.change_directory(path, cwd, meta)
    }
    fn file_info(&self, path: &str, meta: &FtpConnectionMetadata) -> Option<FtpFileInfo> {
        self.inner.file_info(path, meta)
    }
    fn mkdir(&self, path: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        self.inner.mkdir(path, meta)
    }
    fn rmdir(&self, path: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        self.inner.rmdir(path, meta)
    }
    fn delete(&self, path: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        self.inner.delete(path, meta)
    }
    fn rename(&self, from: &str, to: &str, meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        self.inner.rename(from, to, meta)
    }
    fn resolve(&self, path: &str, cwd: &str) -> String {
        self.inner.resolve(path, cwd)
    }
    fn open_read(
        &self,
        path: &str,
        restart: u64,
        meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn io::Read + Send>, FtpFileOpResult> {
        self.inner.open_read(path, restart, meta)
    }
    fn open_write(
        &self,
        path: &str,
        append: bool,
        restart: u64,
        meta: &FtpConnectionMetadata,
    ) -> Result<Box<dyn io::Write + Send>, FtpFileOpResult> {
        self.inner.open_write(path, append, restart, meta)
    }
    fn generate_unique_name(
        &self,
        base: &str,
        suggested: Option<&str>,
        meta: &FtpConnectionMetadata,
    ) -> UniqueName {
        self.inner.generate_unique_name(base, suggested, meta)
    }
    fn allocate_space(&self, _path: &str, size: u64, _meta: &FtpConnectionMetadata) -> FtpFileOpResult {
        if size > self.max {
            FtpFileOpResult::Failed
        } else {
            FtpFileOpResult::Ok
        }
    }
}

struct AllocHandler {
    fs: AllocRejectingFs,
}

impl FtpConnectionHandler for AllocHandler {
    fn authenticate(
        &mut self,
        username: &str,
        password: Option<&str>,
        _account: Option<&str>,
        _meta: &FtpConnectionMetadata,
    ) -> FtpAuthResult {
        match password {
            None => FtpAuthResult::NeedPassword,
            Some(p) if username == "u" && p == "p" => FtpAuthResult::Success,
            Some(_) => FtpAuthResult::Failed,
        }
    }

    fn file_system(&mut self, _meta: &FtpConnectionMetadata) -> &mut dyn FtpFileSystem {
        &mut self.fs
    }
}

struct AllocHandlerFactory {
    root: std::path::PathBuf,
    max: u64,
}

impl FtpConnectionHandlerFactory for AllocHandlerFactory {
    fn create(&self) -> Box<dyn FtpConnectionHandler> {
        Box::new(AllocHandler {
            fs: AllocRejectingFs {
                inner: BasicFtpFileSystem::new(&self.root, false).unwrap(),
                max: self.max,
            },
        })
    }
}

fn start_server_with_alloc_cap(root: &std::path::Path, max: u64) -> (Arc<Runtime>, SocketAddr) {
    let policy = PasswordTrustPolicy::default(); // unused: AllocHandler authenticates itself
    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let config = FtpConfig::new(listen, root, policy.shared());
    let factory = Arc::new(AllocHandlerFactory {
        root: root.to_path_buf(),
        max,
    });
    let service = FtpService::with_handler_factory(config, factory);
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let bound = service.start(Arc::clone(&rt)).unwrap();
    (rt, bound)
}

#[test]
fn allo_defaults_to_a_no_op_success() {
    // The default FtpFileSystem::allocate_space is a no-op success
    // (matches Gumdrop's own default), so a stock server accepts any ALLO.
    let dir = tempfile::tempdir().unwrap();
    let (_rt, bound) = start_server(dir.path());
    let mut ctrl = raw_login(bound);
    let r = raw_cmd(&mut ctrl, "ALLO 999999999\r\n");
    assert!(r.starts_with("202"), "ALLO: {r}");
}

#[test]
fn allo_is_dispatched_to_the_file_system_hook() {
    let dir = tempfile::tempdir().unwrap();
    let (_rt, bound) = start_server_with_alloc_cap(dir.path(), 100);
    let mut ctrl = raw_login(bound);

    let r = raw_cmd(&mut ctrl, "ALLO 50\r\n");
    assert!(r.starts_with("202"), "ALLO under cap should succeed: {r}");

    let r = raw_cmd(&mut ctrl, "ALLO 500\r\n");
    assert!(r.starts_with("552"), "ALLO over cap should be rejected: {r}");
}
