// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime TCP smoke tests (enable with `--features integration`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tempfile::tempdir;
use hopf_core::{
    storage::{StorageConfig, StorageExecutor},
    ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig,
};
use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};

use crate::{DeadPropMode, WebDavConfig, WebDavFactory};

fn listen_webdav(root: std::path::PathBuf) -> (Runtime, std::net::SocketAddr) {
    listen_webdav_with(root, WebDavConfig::default().max_put_body)
}

fn listen_webdav_with(root: std::path::PathBuf, max_put_body: u64) -> (Runtime, std::net::SocketAddr) {
    let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
    let factory = Arc::new(
        WebDavFactory::new(
            WebDavConfig {
                root_path: root,
                allow_write: true,
                webdav_enabled: true,
                welcome_file: "index.html".into(),
                dead_property_storage: DeadPropMode::Sidecar,
                max_put_body,
            },
            storage,
        )
        .unwrap(),
    );
    let rt = Runtime::start(RuntimeConfig::default()).unwrap();
    let factory2 = Arc::clone(&factory);
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            move || {
                Box::new(CleartextHttpEndpoint::new(
                    Arc::clone(&factory2) as Arc<dyn ServerHandlerFactory>,
                    HttpLimits::default(),
                )) as Box<dyn ProtocolHandler>
            },
        ))
        .unwrap();
    (rt, addr)
}

fn http_exchange(addr: std::net::SocketAddr, req: &str) -> String {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    c.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = c.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn options_advertises_dav() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let resp = http_exchange(
        addr,
        "OPTIONS / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(resp.contains("200"), "{resp}");
    assert!(
        resp.to_ascii_lowercase().contains("dav:"),
        "missing DAV header: {resp}"
    );
    assert!(resp.contains("1,2") || resp.contains("1, 2"), "{resp}");
    rt.shutdown();
}

#[test]
fn put_get_roundtrip() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let put = http_exchange(
        addr,
        "PUT /hello.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    );
    assert!(
        put.contains("201") || put.contains("200") || put.contains("204"),
        "PUT failed: {put:?}"
    );
    let get = http_exchange(
        addr,
        "GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(get.contains("200"), "GET status: {get:?}");
    assert!(get.contains("hello"), "GET body: {get:?}");
    rt.shutdown();
}

/// A payload spanning many 8KB read/write chunks round-trips byte for byte
/// through the streaming PUT/GET path (no `fs::read`/`fs::write` of a whole
/// buffer anywhere in the handler).
#[test]
fn put_get_roundtrip_spans_many_chunks() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    // Deterministic, non-repeating-enough-to-hide-bugs pattern spanning
    // several 8KB chunks in both directions.
    let body: String = (0..200_000u32).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let put_req = format!(
        "PUT /big.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let put = http_exchange(addr, &put_req);
    assert!(
        put.contains("201") || put.contains("200") || put.contains("204"),
        "PUT failed: {}",
        &put[..put.len().min(200)]
    );

    let get = http_exchange(
        addr,
        "GET /big.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let header_end = get.find("\r\n\r\n").expect("response should have a header/body split");
    assert_eq!(&get[header_end + 4..], body.as_str(), "round-tripped body mismatch");

    let on_disk = std::fs::read(dir.path().join("big.txt")).unwrap();
    assert_eq!(on_disk, body.into_bytes());

    rt.shutdown();
}

/// A PUT whose body exceeds the configured cap is rejected with `413`
/// before the whole body has to arrive — proven here by using a tiny cap
/// (well under the request body) rather than the real 10 GiB default.
#[test]
fn put_over_size_cap_is_rejected() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav_with(dir.path().to_path_buf(), 16);
    thread::sleep(Duration::from_millis(50));

    let body = "this body is well over sixteen bytes long";
    let put_req = format!(
        "PUT /toobig.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let put = http_exchange(addr, &put_req);
    assert!(put.contains("413"), "expected 413, got: {put:?}");
    assert!(
        !dir.path().join("toobig.txt").exists()
            || std::fs::read(dir.path().join("toobig.txt")).unwrap().len() <= 16,
        "oversized file should not have been written whole"
    );

    rt.shutdown();
}

#[test]
fn propfind_depth_zero() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let body = "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:propname/></D:propfind>";
    let req = format!(
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http_exchange(addr, &req);
    assert!(
        resp.contains("207") || resp.contains("200"),
        "PROPFIND status: {resp:?}"
    );
    assert!(
        resp.to_ascii_lowercase().contains("multistatus"),
        "PROPFIND body: {resp:?}"
    );
    rt.shutdown();
}
