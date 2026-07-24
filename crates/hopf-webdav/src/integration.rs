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
    let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
    let factory = Arc::new(
        WebDavFactory::new(
            WebDavConfig {
                root_path: root,
                allow_write: true,
                webdav_enabled: true,
                welcome_file: "index.html".into(),
                dead_property_storage: DeadPropMode::Sidecar,
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
