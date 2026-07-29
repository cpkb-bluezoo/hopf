// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Optional PASV / client smoke tests (feature `integration`).
//!
//! These tests start an in-process FTP server and exercise it via the async
//! [`FtpClient`] + [`FtpGet`] / [`FtpPut`] pipelines.

#![cfg(feature = "integration")]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_auth::PasswordTrustPolicy;
use hopf_core::{Runtime, RuntimeConfig};

use crate::{
    FtpAbortHandle, FtpClient, FtpClientTimeouts, FtpError, FtpGet, FtpPipeline, FtpPut,
    FtpSessionWrite, FtpConfig, FtpService,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    let result2 = Arc::clone(&result);
    let pipeline = FtpGet::new(remote, move |r| {
        *result2.lock().unwrap() = Some(r);
    });
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
    let pipeline = FtpPut::new(remote, data, move |r| {
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
    let result2 = Arc::clone(&result);
    let pipeline = FtpGet::new("secret.txt", move |r| {
        *result2.lock().unwrap() = Some(r);
    });
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
    let result2 = Arc::clone(&result);
    let pipeline = FtpGet::new("secret.txt", move |r| {
        *result2.lock().unwrap() = Some(r);
    });
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

impl FtpPipeline for AppeNlstStouPipeline {
    fn start(&mut self, session: &mut dyn FtpSessionWrite, _abort: FtpAbortHandle) {
        session.type_image();

        let r = Arc::clone(&self.results);
        session.appe(&self.appe_path, self.appe_data.clone(), Box::new(move |res| {
            r.lock().unwrap().appe = Some(res);
        }));

        let r = Arc::clone(&self.results);
        session.nlst(None, Box::new(move |res| {
            r.lock().unwrap().nlst = Some(res);
        }));

        let r = Arc::clone(&self.results);
        session.stou(b"unique-payload".to_vec(), Box::new(move |res| {
            r.lock().unwrap().stou = Some(res);
        }));

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
        session.retr_from(
            &self.path,
            self.offset,
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
    let result2 = Arc::clone(&result);
    let pipeline = FtpGet::new("x.txt", move |r| {
        *result2.lock().unwrap() = Some(r);
    });
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
