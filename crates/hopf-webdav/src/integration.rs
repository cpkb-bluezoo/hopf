// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime TCP smoke tests (enable with `--features integration`).

use std::fs;
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

use crate::{WebDavConfig, WebDavFactory};

fn listen_webdav(root: std::path::PathBuf) -> (Runtime, std::net::SocketAddr) {
    listen_webdav_cfg(WebDavConfig {
        root_path: root,
        allow_write: true,
        webdav_enabled: true,
        allow_unauthenticated_access: true,
        ..Default::default()
    })
}

fn listen_webdav_with(root: std::path::PathBuf, max_put_body: u64) -> (Runtime, std::net::SocketAddr) {
    listen_webdav_cfg(WebDavConfig {
        root_path: root,
        allow_write: true,
        webdav_enabled: true,
        allow_unauthenticated_access: true,
        max_put_body,
        ..Default::default()
    })
}

fn listen_webdav_cfg(config: WebDavConfig) -> (Runtime, std::net::SocketAddr) {
    let storage = Arc::new(StorageExecutor::new(StorageConfig::default()));
    let factory = Arc::new(WebDavFactory::new(config, storage).unwrap());
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

/// Issue #186: a zero-length PUT never queues a chunk for
/// `drain_put_writes` to write, so the offloaded open's own completion
/// callback is what has to notice `end_request_body` already fired and
/// send `201` — the one path a chunk-triggered drain never exercises.
#[test]
fn put_empty_body_creates_a_zero_length_file() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let put = http_exchange(
        addr,
        "PUT /empty.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert!(
        put.contains("201") || put.contains("200") || put.contains("204"),
        "PUT failed: {put:?}"
    );
    let on_disk = std::fs::read(dir.path().join("empty.txt")).expect("file created");
    assert!(on_disk.is_empty());
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
/// (well under the request body) rather than the real default.
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

/// Depth: infinity PROPFIND stops at `max_tree_entries` with 507.
#[test]
fn propfind_depth_infinity_respects_tree_entry_cap() {
    let dir = tempdir().unwrap();
    for i in 0..5 {
        std::fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
    }
    let (rt, addr) = listen_webdav_cfg(WebDavConfig {
        root_path: dir.path().to_path_buf(),
        allow_write: true,
        webdav_enabled: true,
        allow_unauthenticated_access: true,
        max_tree_entries: 3, // root + 2 children before overflow
        ..Default::default()
    });
    thread::sleep(Duration::from_millis(50));
    let body = "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:propname/></D:propfind>";
    let req = format!(
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: infinity\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http_exchange(addr, &req);
    assert!(
        resp.contains("507"),
        "expected 507 when tree walk exceeds cap, got: {resp:?}"
    );
    rt.shutdown();
}

/// Issue #193: a multistatus response with several resources streams out
/// via chunked transfer-encoding (one `response_body_content` call per
/// `<D:response>`) instead of being buffered whole behind a
/// `Content-Length` — proven both by the framing (chunked, no
/// Content-Length) and by every resource still round-tripping correctly.
#[test]
fn propfind_streams_multiple_chunks_for_many_resources() {
    let dir = tempdir().unwrap();
    for i in 0..8 {
        std::fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
    }
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let body = "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:propname/></D:propfind>";
    let req = format!(
        "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = http_exchange(addr, &req);
    assert!(resp.contains("207"), "PROPFIND status: {resp:?}");
    assert!(
        resp.to_ascii_lowercase().contains("transfer-encoding: chunked"),
        "large multistatus responses must stream via chunked transfer-encoding, \
         not a single Content-Length body: {resp:?}"
    );
    assert!(
        !resp.to_ascii_lowercase().contains("content-length:"),
        "a chunked response must not also carry Content-Length: {resp:?}"
    );
    // root collection + 8 files = 9 <D:response> elements, each delivered
    // as its own chunk.
    assert_eq!(
        resp.matches("<D:response>").count(),
        9,
        "expected one <D:response> per resource: {resp:?}"
    );
    rt.shutdown();
}

fn lock_body_exclusive() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
     <D:lockinfo xmlns:D=\"DAV:\">\
       <D:lockscope><D:exclusive/></D:lockscope>\
       <D:locktype><D:write/></D:locktype>\
       <D:owner><D:href>hopf-test</D:href></D:owner>\
     </D:lockinfo>"
}

fn extract_lock_token(resp: &str) -> String {
    for line in resp.lines() {
        if line.to_ascii_lowercase().starts_with("lock-token:") {
            let raw = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            return raw.trim().trim_matches(|c| c == '<' || c == '>').to_string();
        }
    }
    panic!("no Lock-Token header in response: {resp}");
}

/// RFC 4918 §7.3: LOCK on an unmapped URL creates a locked empty resource
/// (201), visible to PROPFIND; UNLOCK releases the lock but leaves the
/// empty file (recommended model — not deprecated lock-null removal).
#[test]
fn lock_unmapped_url_creates_locked_empty_resource() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let body = lock_body_exclusive();
    let lock_req = format!(
        "LOCK /reserved.txt HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\
         Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let lock = http_exchange(addr, &lock_req);
    assert!(lock.contains("201"), "expected 201 Created, got: {lock}");
    assert!(
        lock.to_ascii_lowercase().contains("lock-token:"),
        "missing Lock-Token: {lock}"
    );
    let path = dir.path().join("reserved.txt");
    assert!(path.is_file(), "locked empty resource must exist on disk");
    assert_eq!(std::fs::read(&path).unwrap(), b"", "resource must be empty");

    let propfind_body =
        "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:propname/></D:propfind>";
    let propfind = http_exchange(
        addr,
        &format!(
            "PROPFIND / HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\n\
             Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{propfind_body}",
            propfind_body.len()
        ),
    );
    assert!(propfind.contains("207") || propfind.contains("200"), "{propfind}");
    assert!(
        propfind.contains("reserved.txt"),
        "empty locked resource must appear in parent PROPFIND: {propfind}"
    );

    let token = extract_lock_token(&lock);
    let unlock = http_exchange(
        addr,
        &format!(
            "UNLOCK /reserved.txt HTTP/1.1\r\nHost: localhost\r\n\
             Lock-Token: <{token}>\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(unlock.contains("204"), "UNLOCK status: {unlock}");
    assert!(
        path.is_file(),
        "§7.3: unlocked empty resource MUST remain (not lock-null removal)"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"");

    rt.shutdown();
}

/// After LOCK creates an empty resource, PUT with the lock token supplies
/// content; after UNLOCK, a fresh LOCK on the mapped URL returns 200.
#[test]
fn lock_then_put_fills_empty_resource_and_relock_is_200() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let body = lock_body_exclusive();
    let lock = http_exchange(
        addr,
        &format!(
            "LOCK /draft.txt HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\
             Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(lock.contains("201"), "{lock}");
    let token = extract_lock_token(&lock);

    let put = http_exchange(
        addr,
        &format!(
            "PUT /draft.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\
             If: (<{token}>)\r\nConnection: close\r\n\r\nhello"
        ),
    );
    assert!(
        put.contains("201") || put.contains("200") || put.contains("204"),
        "PUT with lock token failed: {put}"
    );
    assert_eq!(std::fs::read(dir.path().join("draft.txt")).unwrap(), b"hello");

    let unlock = http_exchange(
        addr,
        &format!(
            "UNLOCK /draft.txt HTTP/1.1\r\nHost: localhost\r\n\
             Lock-Token: <{token}>\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(unlock.contains("204"), "{unlock}");

    let lock2 = http_exchange(
        addr,
        &format!(
            "LOCK /draft.txt HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\
             Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(
        lock2.contains("200"),
        "LOCK on already-mapped URL must be 200, got: {lock2}"
    );

    rt.shutdown();
}

/// §7.3: locked empty resource MUST NOT become a collection — MKCOL fails.
#[test]
fn mkcol_on_locked_empty_resource_fails() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let body = lock_body_exclusive();
    let lock = http_exchange(
        addr,
        &format!(
            "LOCK /not-a-col HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\
             Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(lock.contains("201"), "{lock}");
    let token = extract_lock_token(&lock);

    let mkcol = http_exchange(
        addr,
        &format!(
            "MKCOL /not-a-col HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\
             If: (<{token}>)\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(
        mkcol.contains("405") || mkcol.contains("403") || mkcol.contains("409"),
        "MKCOL on locked empty file must fail: {mkcol}"
    );
    assert!(dir.path().join("not-a-col").is_file());

    rt.shutdown();
}

/// LOCK under a missing parent collection is a conflict, not mkdir -p.
#[test]
fn lock_unmapped_with_missing_parent_is_409() {
    let dir = tempdir().unwrap();
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let body = lock_body_exclusive();
    let lock = http_exchange(
        addr,
        &format!(
            "LOCK /missing/child.txt HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\
             Content-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    );
    assert!(lock.contains("409"), "expected 409, got: {lock}");
    assert!(!dir.path().join("missing").exists());

    rt.shutdown();
}

fn header_value(resp: &str, name: &str) -> Option<String> {
    resp.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// A file's mtime carries sub-second precision but `Last-Modified` is sent
/// truncated to whole seconds. Echoing that exact value back in
/// `If-Modified-Since` must therefore mean "not modified" (RFC 9110
/// §13.1.3), not a full re-send: comparing the untruncated mtime against
/// the truncated date made every such revalidation miss.
#[test]
fn if_modified_since_echoing_last_modified_gets_304_despite_subsecond_mtime() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("a.txt");
    fs::write(&file, b"hello").unwrap();
    // 2023-11-14T22:13:20.5Z: a half-second past a whole second.
    let mtime = std::time::UNIX_EPOCH + Duration::from_millis(1_700_000_000_500);
    fs::OpenOptions::new().write(true).open(&file).unwrap().set_modified(mtime).unwrap();

    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let first = http_exchange(
        addr,
        "GET /a.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert!(first.starts_with("HTTP/1.1 200"), "{first}");
    let lm = header_value(&first, "last-modified").expect("Last-Modified");

    let again = http_exchange(
        addr,
        &format!("GET /a.txt HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: {lm}\r\nConnection: close\r\n\r\n"),
    );
    assert!(again.starts_with("HTTP/1.1 304"), "expected 304 for {lm}, got: {again}");
    rt.shutdown();
}

/// One request, read up to the end of its own framing (head plus any
/// `Content-Length` body) rather than to connection close.
fn exchange(addr: std::net::SocketAddr, req: &str) -> String {
    let head_only = req.starts_with("HEAD ");
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..p + 4]).into_owned();
            let want = header_value(&head, "content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            if head_only || buf.len() >= p + 4 + want {
                break;
            }
        }
        let n = c.read(&mut tmp).expect("response timed out");
        assert!(n > 0, "connection closed early: {:?}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&tmp[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn req(method: &str, path: &str, fields: &[(&str, &str)], body: &str) -> String {
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    for (n, v) in fields {
        r.push_str(&format!("{n}: {v}\r\n"));
    }
    if !body.is_empty() || method == "PUT" {
        r.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    r.push_str("\r\n");
    r.push_str(body);
    r
}

fn status_of(resp: &str) -> u16 {
    resp.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// A file with a fixed mtime (2023-11-14T22:13:20Z) so date conditions are exact.
fn dated_file(dir: &std::path::Path, name: &str, content: &[u8]) {
    let f = dir.join(name);
    fs::write(&f, content).unwrap();
    let t = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fs::OpenOptions::new().write(true).open(&f).unwrap().set_modified(t).unwrap();
}

const AFTER_MTIME: &str = "Tue, 14 Nov 2023 22:13:21 GMT";
const BEFORE_MTIME: &str = "Tue, 14 Nov 2023 22:13:19 GMT";

#[test]
fn get_revalidates_with_if_none_match_and_the_304_repeats_the_validators() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"hello");
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let first = exchange(addr, &req("GET", "/a.txt", &[], ""));
    assert_eq!(status_of(&first), 200, "{first}");
    let etag = header_value(&first, "etag").expect("ETag");

    for method in ["GET", "HEAD"] {
        let r = exchange(addr, &req(method, "/a.txt", &[("If-None-Match", &etag)], ""));
        assert_eq!(status_of(&r), 304, "{method}: {r}");
        assert_eq!(header_value(&r, "etag").as_deref(), Some(etag.as_str()), "{method}: {r}");
        assert!(header_value(&r, "last-modified").is_some(), "{method}: {r}");
        assert!(!r.contains("hello"), "{method}: a 304 has no body");
    }
    let r = exchange(addr, &req("GET", "/a.txt", &[("If-None-Match", "\"other\"")], ""));
    assert_eq!(status_of(&r), 200, "{r}");
    assert!(r.contains("hello"), "{r}");
    let r = exchange(addr, &req("GET", "/a.txt", &[("If-Modified-Since", BEFORE_MTIME)], ""));
    assert_eq!(status_of(&r), 200, "{r}");
    rt.shutdown();
}

#[test]
fn get_with_a_failed_if_match_or_if_unmodified_since_is_412() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"hello");
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let r = exchange(addr, &req("GET", "/a.txt", &[("If-Unmodified-Since", BEFORE_MTIME)], ""));
    assert_eq!(status_of(&r), 412, "{r}");
    let r = exchange(addr, &req("GET", "/a.txt", &[("If-Match", "\"other\"")], ""));
    assert_eq!(status_of(&r), 412, "{r}");
    rt.shutdown();
}

/// `If-None-Match: *` makes a PUT create-only: it must fail on an existing
/// resource *without* having truncated it.
#[test]
fn put_if_none_match_star_is_create_only_and_never_clobbers() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"original");
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let r = exchange(addr, &req("PUT", "/a.txt", &[("If-None-Match", "*")], "replacement"));
    assert_eq!(status_of(&r), 412, "{r}");
    assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"original", "a refused PUT must not truncate");

    let r = exchange(addr, &req("PUT", "/new.txt", &[("If-None-Match", "*")], "fresh"));
    assert_eq!(status_of(&r), 201, "{r}");
    assert_eq!(fs::read(dir.path().join("new.txt")).unwrap(), b"fresh");
    rt.shutdown();
}

/// A date-based lost-update guard: the client last saw the resource before
/// somebody else changed it.
#[test]
fn put_if_unmodified_since_guards_against_lost_updates() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"original");
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let r = exchange(addr, &req("PUT", "/a.txt", &[("If-Unmodified-Since", BEFORE_MTIME)], "stale write"));
    assert_eq!(status_of(&r), 412, "{r}");
    assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"original");

    let r = exchange(addr, &req("PUT", "/a.txt", &[("If-Unmodified-Since", AFTER_MTIME)], "current write"));
    assert!(matches!(status_of(&r), 200 | 201 | 204), "{r}");
    assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"current write");
    rt.shutdown();
}

#[test]
fn delete_honours_preconditions() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"keep me");
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let r = exchange(addr, &req("DELETE", "/a.txt", &[("If-Unmodified-Since", BEFORE_MTIME)], ""));
    assert_eq!(status_of(&r), 412, "{r}");
    assert!(dir.path().join("a.txt").exists(), "a refused DELETE must not delete");

    let r = exchange(addr, &req("DELETE", "/a.txt", &[("If-Unmodified-Since", AFTER_MTIME)], ""));
    assert_eq!(status_of(&r), 204, "{r}");
    assert!(!dir.path().join("a.txt").exists());
    rt.shutdown();
}

/// The ETag is weak, and `If-Match` compares strongly (RFC 9110 §13.1.1), so
/// it can never match: a conditional write guarded by it fails closed
/// rather than silently succeeding.
#[test]
fn if_match_against_the_weak_etag_fails_closed() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"original");
    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));

    let etag = header_value(&exchange(addr, &req("GET", "/a.txt", &[], "")), "etag").unwrap();
    assert!(etag.starts_with("W/"), "{etag}");
    let r = exchange(addr, &req("PUT", "/a.txt", &[("If-Match", &etag)], "x"));
    assert_eq!(status_of(&r), 412, "{r}");
    assert_eq!(fs::read(dir.path().join("a.txt")).unwrap(), b"original");
    rt.shutdown();
}

#[test]
fn cache_control_is_sent_on_file_responses_only_when_configured() {
    let dir = tempdir().unwrap();
    dated_file(dir.path(), "a.txt", b"hello");

    let (rt, addr) = listen_webdav(dir.path().to_path_buf());
    thread::sleep(Duration::from_millis(50));
    let r = exchange(addr, &req("GET", "/a.txt", &[], ""));
    assert!(header_value(&r, "cache-control").is_none(), "off by default: {r}");
    rt.shutdown();

    let (rt, addr) = listen_webdav_cfg(
        WebDavConfig {
            root_path: dir.path().to_path_buf(),
            allow_unauthenticated_access: true,
            ..Default::default()
        }
        .with_cache_control(hopf_http::CacheControl::new().public().max_age(Duration::from_secs(300))),
    );
    thread::sleep(Duration::from_millis(50));
    let ok = exchange(addr, &req("GET", "/a.txt", &[], ""));
    assert_eq!(header_value(&ok, "cache-control").as_deref(), Some("public, max-age=300"), "{ok}");
    let etag = header_value(&ok, "etag").unwrap();
    let nm = exchange(addr, &req("GET", "/a.txt", &[("If-None-Match", &etag)], ""));
    assert_eq!(status_of(&nm), 304, "{nm}");
    assert_eq!(header_value(&nm, "cache-control").as_deref(), Some("public, max-age=300"), "the 304 repeats it: {nm}");
    rt.shutdown();
}
