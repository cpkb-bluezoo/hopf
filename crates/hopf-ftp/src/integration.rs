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

use crate::{FtpClient, FtpClientTimeouts, FtpGet, FtpPut, FtpConfig, FtpService};

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
