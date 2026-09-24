// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! End-to-end content-coding tests over real loopback sockets: the real
//! [`HttpServer`] and [`HttpClient`] on HTTP/1.1 and HTTP/2, plus raw-socket
//! peers for the cases a real hopf peer would never produce (a server that
//! trickles bytes, sends an unknown coding, or sends a bomb).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};

use super::tests::{decode, encode, plain, GOLDEN_BROTLI, GOLDEN_GZIP, GOLDEN_ZLIB};
use super::*;
use crate::{
    ContentEncodingServerFactory, Headers, HttpClient, HttpClientSessionHandle,
    HttpConnectionHandler, HttpLimits, HttpResponseHandler, HttpServer, ServerContentEncodingPolicy,
};
use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};

// ---------------------------------------------------------------------------
// Application under test
// ---------------------------------------------------------------------------

fn text_body() -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..8000u32 {
        v.extend_from_slice(format!("line {i}: the quick brown fox jumps over the lazy dog\n").as_bytes());
    }
    v
}

struct App {
    path: String,
    method: String,
    req_body: Vec<u8>,
}

impl ServerHandler for App {
    fn headers(&mut self, _w: &mut dyn ServerWriter, h: &Headers) {
        self.path = h.path().unwrap_or("").to_string();
        self.method = h.method().unwrap_or("").to_string();
    }

    fn request_body_content(&mut self, _w: &mut dyn ServerWriter, data: &[u8]) {
        self.req_body.extend_from_slice(data);
    }

    fn request_complete(&mut self, w: &mut dyn ServerWriter) {
        let mut h = Headers::new();
        h.status(200);
        match (self.method.as_str(), self.path.as_str()) {
            ("POST", "/echo") => {
                let sum: u64 = self.req_body.iter().map(|&b| b as u64).sum();
                let body = format!("len={} sum={}", self.req_body.len(), sum);
                h.set("content-type", "text/plain");
                h.set("content-length", body.len().to_string());
                w.headers(h);
                w.response_body_content(body.as_bytes());
            }
            (_, "/text") => {
                h.set("content-type", "text/plain; charset=utf-8");
                h.set("etag", "\"v1\"");
                w.headers(h);
                // Streamed in uneven chunks, as an SPI producer would.
                let body = text_body();
                for chunk in body.chunks(29_000) {
                    w.response_body_content(chunk);
                }
            }
            (_, "/deferred") => {
                // The whole response is produced later, off the request
                // callback, through the cloneable response handle (the
                // storage / SPI pattern).
                h.set("content-type", "text/plain");
                let handle = w.response_handle();
                std::thread::spawn(move || {
                    handle.execute(move |w| w.headers(h));
                    for chunk in text_body().chunks(50_000) {
                        let c = chunk.to_vec();
                        handle.execute(move |w| w.response_body_content(&c));
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    handle.execute(|w| {
                        w.end_response_body();
                        w.complete();
                    });
                });
                return;
            }
            (_, "/deferred-one") => {
                h.set("content-type", "text/plain");
                let handle = w.response_handle();
                handle.execute(move |w| {
                    w.headers(h);
                    for chunk in text_body()[..60_000].chunks(7_000) {
                        w.response_body_content(chunk);
                    }
                    w.end_response_body();
                    w.complete();
                });
                return;
            }
            (_, "/small") => {
                h.set("content-type", "text/plain");
                h.set("content-length", "10");
                w.headers(h);
                w.response_body_content(b"tiny reply");
            }
            (_, "/binary") => {
                h.set("content-type", "image/png");
                w.headers(h);
                w.response_body_content(&vec![7u8; 4000]);
            }
            (_, "/empty") => {
                h.set("content-type", "text/plain");
                w.headers(h);
            }
            _ => {
                h.status(404);
                w.headers(h);
            }
        }
        w.end_response_body();
        w.complete();
    }
}

struct AppFactory;
impl ServerHandlerFactory for AppFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(App {
            path: String::new(),
            method: String::new(),
            req_body: Vec::new(),
        })
    }
}

fn start_server(rt: &Arc<Runtime>, policy: ServerContentEncodingPolicy) -> SocketAddr {
    let factory: Arc<dyn ServerHandlerFactory> =
        Arc::new(ContentEncodingServerFactory::new(Arc::new(AppFactory), policy));
    HttpServer::new()
        .bind(rt, "127.0.0.1:0".parse().unwrap(), factory)
        .unwrap()
        .0
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Outcome {
    version: Option<crate::version::HttpVersion>,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    closed: bool,
    failed: Option<std::io::Error>,
}

impl Outcome {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

struct Rec(Arc<Mutex<Outcome>>);

impl HttpResponseHandler for Rec {
    fn ok(&mut self, status: u16) {
        self.0.lock().unwrap().status = status;
    }
    fn error(&mut self, status: u16) {
        self.0.lock().unwrap().status = status;
    }
    fn header(&mut self, name: &str, value: &str) {
        self.0.lock().unwrap().headers.push((name.to_string(), value.to_string()));
    }
    fn response_body_content(&mut self, data: &[u8]) {
        self.0.lock().unwrap().body.extend_from_slice(data);
    }
    fn close(&mut self) {
        self.0.lock().unwrap().closed = true;
    }
    fn failed(&mut self, err: std::io::Error) {
        self.0.lock().unwrap().failed = Some(err);
    }
}

enum Job {
    Get(&'static str),
    Post { path: &'static str, coding: Option<ContentCoding>, body: Vec<u8> },
}

struct Conn {
    job: Option<Job>,
    out: Arc<Mutex<Outcome>>,
}

impl HttpConnectionHandler for Conn {
    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        self.out.lock().unwrap().version = Some(session.version());
        match self.job.take().unwrap() {
            Job::Get(path) => {
                session.get(path).send(Box::new(Rec(Arc::clone(&self.out)))).unwrap();
            }
            Job::Post { path, coding, body } => {
                let mut req = session.post(path);
                let wire = match coding {
                    Some(c) => {
                        req.header("Content-Encoding", c.token()).unwrap();
                        let mut e = Encoder::new(c).unwrap();
                        let mut w = Vec::new();
                        e.push(&body, &mut |b| w.extend_from_slice(b)).unwrap();
                        e.finish(&mut |b| w.extend_from_slice(b)).unwrap();
                        w
                    }
                    None => body,
                };
                req.start_request_body(Box::new(Rec(Arc::clone(&self.out)))).unwrap();
                let mut sent = 0;
                let deadline = Instant::now() + Duration::from_secs(5);
                while sent < wire.len() && Instant::now() < deadline {
                    sent += req.request_body_content(&wire[sent..]).unwrap();
                }
                assert_eq!(sent, wire.len(), "request body did not fit the send window");
                req.end_request_body().unwrap();
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Proto {
    H1,
    H2,
}

fn run(rt: &Arc<Runtime>, addr: SocketAddr, proto: Proto, policy: Option<ContentEncodingPolicy>, job: Job) -> Outcome {
    let out = Arc::new(Mutex::new(Outcome::default()));
    let mut client = HttpClient::from_addr(addr);
    if let Proto::H2 = proto {
        client = client.h2_prior_knowledge(true);
    }
    if let Some(p) = policy {
        client = client.content_encoding(p);
    }
    client
        .connect(rt, Box::new(Conn { job: Some(job), out: Arc::clone(&out) }))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let g = out.lock().unwrap();
            if g.closed || g.failed.is_some() {
                break;
            }
        }
        assert!(Instant::now() < deadline, "request timed out");
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut g = out.lock().unwrap();
    std::mem::take(&mut *g)
}

fn rt() -> Arc<Runtime> {
    Arc::new(Runtime::start(RuntimeConfig::default()).unwrap())
}

fn client_policy(codings: &[ContentCoding]) -> ContentEncodingPolicy {
    ContentEncodingPolicy::new(&HttpLimits::default()).accept(codings)
}

fn server_policy() -> ServerContentEncodingPolicy {
    ServerContentEncodingPolicy::new(&HttpLimits::default())
}

const CODED: [ContentCoding; 3] = [ContentCoding::Brotli, ContentCoding::Gzip, ContentCoding::Deflate];

/// Read one complete HTTP/1.1 response off `s`, framed by its own headers
/// (the server keeps the connection alive, so EOF cannot delimit it).
/// `head_only` for HEAD. Returns (head, body-as-received).
fn read_response(s: &mut TcpStream, head_only: bool) -> (String, Vec<u8>) {
    let mut all = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        if let Some(p) = all.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&all[..p + 4]).to_string();
            let body = &all[p + 4..];
            let chunked = head_has(&head, "transfer-encoding", "chunked");
            let len = head
                .lines()
                .find_map(|l| l.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("content-length")))
                .and_then(|(_, v)| v.trim().parse::<usize>().ok());
            let complete = head_only
                || (chunked && body.ends_with(b"0\r\n\r\n"))
                || len.is_some_and(|n| body.len() >= n)
                || (!chunked && len.is_none() && (head.contains(" 204 ") || head.contains(" 304 ")));
            if complete {
                return (head, body.to_vec());
            }
        }
        let n = s.read(&mut buf).expect("response timed out or connection error");
        assert!(n > 0, "connection closed before a complete response: {:?}", String::from_utf8_lossy(&all));
        all.extend_from_slice(&buf[..n]);
    }
}

/// Raw HTTP/1.1 GET over a plain socket; returns (head, body-as-received).
fn raw_get(addr: SocketAddr, path: &str, accept_encoding: Option<&str>) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let ae = accept_encoding
        .map(|v| format!("Accept-Encoding: {v}\r\n"))
        .unwrap_or_default();
    write!(s, "GET {path} HTTP/1.1\r\nHost: t\r\n{ae}\r\n").unwrap();
    read_response(&mut s, false)
}

fn head_has(head: &str, name: &str, value: &str) -> bool {
    head.lines().any(|l| {
        l.split_once(':')
            .is_some_and(|(n, v)| n.eq_ignore_ascii_case(name) && v.trim().eq_ignore_ascii_case(value))
    })
}

fn head_lacks(head: &str, name: &str) -> bool {
    !head
        .lines()
        .any(|l| l.split_once(':').is_some_and(|(n, _)| n.eq_ignore_ascii_case(name)))
}

/// De-chunk an HTTP/1.1 chunked body.
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n").expect("chunk size line");
        let n = usize::from_str_radix(std::str::from_utf8(&b[..eol]).unwrap().trim(), 16).unwrap();
        b = &b[eol + 2..];
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&b[..n]);
        b = &b[n + 2..];
    }
}

// ---------------------------------------------------------------------------
// Server compresses; client decodes; handler sees plain bytes
// ---------------------------------------------------------------------------

#[test]
fn client_gets_decoded_body_for_every_coding_on_h1_and_h2() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    let want = text_body();
    for proto in [Proto::H1, Proto::H2] {
        for coding in CODED {
            let o = run(&rt, addr, proto, Some(client_policy(&[coding])), Job::Get("/text"));
            assert!(o.failed.is_none(), "{proto:?} {coding}: {:?}", o.failed);
            let want_version = match proto {
                Proto::H1 => crate::version::HttpVersion::Http11,
                Proto::H2 => crate::version::HttpVersion::Http2,
            };
            assert_eq!(o.version, Some(want_version), "test must exercise the protocol it names");
            assert_eq!(o.status, 200, "{proto:?} {coding}");
            assert_eq!(o.body.len(), want.len(), "{proto:?} {coding}");
            assert!(o.body == want, "{proto:?} {coding}: body differs");
            assert!(o.header("content-encoding").is_none(), "{proto:?} {coding}: header must be stripped");
            assert!(o.header("content-length").is_none(), "{proto:?} {coding}");
            assert_eq!(o.header("vary"), Some("Accept-Encoding"), "{proto:?} {coding}");
            assert_eq!(o.header("content-type"), Some("text/plain; charset=utf-8"));
            assert_eq!(o.header("etag"), Some("W/\"v1\""), "{proto:?} {coding}: strong ETag must be weakened");
        }
    }
}

#[test]
fn deferred_response_writes_go_through_the_encoder() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    let want = text_body();
    // On the wire: advertised as gzip and genuinely gzip-framed, even though
    // the body is written from another thread via the response handle.
    let (head, body) = raw_get(addr, "/deferred", Some("gzip"));
    assert!(head_has(&head, "content-encoding", "gzip"), "{head}");
    let coded = dechunk(&body);
    assert!(coded.len() * 10 < want.len(), "deferred body was not compressed");
    assert!(decode(ContentCoding::Gzip, &coded, 4096, 1 << 30).unwrap() == want);
    // Through the decoding client, streamed across several handle calls (H1)
    // and produced in one handle call (H1 and H2).
    let o = run(&rt, addr, Proto::H1, Some(client_policy(&CODED)), Job::Get("/deferred"));
    assert!(o.failed.is_none(), "{:?}", o.failed);
    assert!(o.body == want);
    for proto in [Proto::H1, Proto::H2] {
        let o = run(&rt, addr, proto, Some(client_policy(&CODED)), Job::Get("/deferred-one"));
        assert!(o.failed.is_none(), "{proto:?}: {:?}", o.failed);
        assert!(o.body == want[..60_000], "{proto:?}");
        assert!(o.header("content-encoding").is_none(), "{proto:?}");
    }
}

#[test]
fn the_wire_really_is_compressed_and_only_when_accepted() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    let want = text_body();

    for (ae, coding) in [("br", "br"), ("gzip", "gzip"), ("deflate", "deflate"), ("gzip, br", "br")] {
        let (head, body) = raw_get(addr, "/text", Some(ae));
        assert!(head_has(&head, "content-encoding", coding), "{ae}: {head}");
        assert!(head_has(&head, "transfer-encoding", "chunked"), "{ae}: {head}");
        assert!(head_lacks(&head, "content-length"), "{ae}: {head}");
        assert!(head_has(&head, "vary", "Accept-Encoding"), "{ae}: {head}");
        let coded = dechunk(&body);
        assert!(coded.len() * 10 < want.len(), "{ae}: not compressed ({} of {})", coded.len(), want.len());
        let c = ContentCoding::from_token(coding).unwrap();
        assert!(decode(c, &coded, 4096, 1 << 30).unwrap() == want, "{ae}");
    }

    // No Accept-Encoding, or refused: plain body, but Vary still declared.
    for ae in [None, Some("identity"), Some("br;q=0, gzip;q=0")] {
        let (head, body) = raw_get(addr, "/text", ae);
        assert!(head_lacks(&head, "content-encoding"), "{ae:?}: {head}");
        assert!(head_has(&head, "vary", "Accept-Encoding"), "{ae:?}: {head}");
        assert!(dechunk(&body) == want, "{ae:?}");
    }
}

#[test]
fn ineligible_responses_are_left_alone() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    // Below the minimum length, non-compressible type, and no body at all.
    for path in ["/small", "/binary", "/empty"] {
        let (head, _) = raw_get(addr, path, Some("br, gzip"));
        assert!(head_lacks(&head, "content-encoding"), "{path}: {head}");
        assert!(head_lacks(&head, "vary"), "{path}: {head}");
    }
    let (head, body) = raw_get(addr, "/small", Some("gzip"));
    assert!(head_has(&head, "content-length", "10"), "{head}");
    assert_eq!(body, b"tiny reply");

    // HEAD is never compressed.
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(s, "HEAD /text HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip\r\n\r\n").unwrap();
    let (head, _) = read_response(&mut s, true);
    assert!(head_lacks(&head, "content-encoding"), "{head}");
}

#[test]
fn client_without_a_policy_sees_the_raw_wire_body() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    // The client sends no Accept-Encoding of its own, so the server answers
    // plain; with no policy nothing is added or altered.
    let o = run(&rt, addr, Proto::H1, None, Job::Get("/text"));
    assert!(o.body == text_body());
    assert!(o.header("content-encoding").is_none());
}

#[test]
fn small_and_empty_responses_pass_through_the_decoding_client() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    for proto in [Proto::H1, Proto::H2] {
        let o = run(&rt, addr, proto, Some(client_policy(&CODED)), Job::Get("/small"));
        assert_eq!(o.body, b"tiny reply", "{proto:?}");
        assert_eq!(o.header("content-length"), Some("10"), "uncoded: untouched, {proto:?}");
        let o = run(&rt, addr, proto, Some(client_policy(&CODED)), Job::Get("/empty"));
        assert!(o.closed && o.body.is_empty(), "{proto:?}");
    }
}

// ---------------------------------------------------------------------------
// Client request bodies decoded by the server
// ---------------------------------------------------------------------------

#[test]
fn server_decodes_content_coded_request_bodies() {
    let rt = rt();
    let addr = start_server(&rt, server_policy());
    // Kept under the client's outbound buffer so one write takes it all.
    let body = text_body()[..100_000].to_vec();
    let sum: u64 = body.iter().map(|&b| b as u64).sum();
    let want = format!("len={} sum={}", body.len(), sum);
    for proto in [Proto::H1, Proto::H2] {
        for coding in [None, Some(ContentCoding::Gzip), Some(ContentCoding::Deflate), Some(ContentCoding::Brotli)] {
            let o = run(&rt, addr, proto, None, Job::Post { path: "/echo", coding, body: body.clone() });
            assert_eq!(o.status, 200, "{proto:?} {coding:?}");
            assert_eq!(String::from_utf8_lossy(&o.body), want, "{proto:?} {coding:?}");
        }
    }
}

#[test]
fn server_rejects_bad_request_bodies_fail_closed() {
    let rt = rt();
    let addr = start_server(&rt, server_policy().max_decoded_body(100_000));
    let post = |head_extra: &str, body: &[u8]| -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "POST /echo HTTP/1.1\r\nHost: t\r\nContent-Length: {}\r\n{head_extra}\r\n",
            body.len()
        )
        .unwrap();
        s.write_all(body).unwrap();
        let (head, _) = read_response(&mut s, true);
        head
    };

    // Unknown coding: 415, handler never runs.
    let r = post("Content-Encoding: zstd\r\n", b"whatever");
    assert!(r.starts_with("HTTP/1.1 415"), "{r}");
    // Corrupt gzip: 400.
    let r = post("Content-Encoding: gzip\r\n", b"this is not gzip data");
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    // Truncated gzip: 400.
    let good = encode(ContentCoding::Gzip, b"hello world hello world", 100);
    let r = post("Content-Encoding: gzip\r\n", &good[..good.len() - 4]);
    assert!(r.starts_with("HTTP/1.1 400"), "{r}");
    // Bomb over the cap: 413.
    let bomb = encode(ContentCoding::Brotli, &vec![0u8; 4 * 1024 * 1024], 65536);
    let r = post("Content-Encoding: br\r\n", &bomb);
    assert!(r.starts_with("HTTP/1.1 413"), "{r}");
}

// ---------------------------------------------------------------------------
// Hostile / awkward servers, against the decoding client
// ---------------------------------------------------------------------------

/// One-shot raw HTTP/1.1 server: replies to the first request with `head` +
/// `body`, writing `chunk` bytes at a time.
fn raw_server(head: String, body: Vec<u8>, chunk: usize, pause: Duration) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_nodelay(true).unwrap();
        let mut buf = [0u8; 4096];
        let mut seen = Vec::new();
        while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                return;
            }
            seen.extend_from_slice(&buf[..n]);
        }
        let _ = s.write_all(head.as_bytes());
        for c in body.chunks(chunk) {
            if s.write_all(c).is_err() {
                return;
            }
            let _ = s.flush();
            if !pause.is_zero() {
                std::thread::sleep(pause);
            }
        }
    });
    addr
}

fn coded_head(coding: &str, len: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: {coding}\r\nContent-Length: {len}\r\n\r\n"
    )
}

#[test]
fn one_byte_tcp_segments_decode_to_golden_output() {
    let rt = rt();
    for (coding, golden) in [
        ("gzip", GOLDEN_GZIP),
        ("br", GOLDEN_BROTLI),
        ("deflate", GOLDEN_ZLIB),
    ] {
        let addr = raw_server(coded_head(coding, golden.len()), golden.to_vec(), 1, Duration::from_micros(300));
        let o = run(&rt, addr, Proto::H1, Some(client_policy(&CODED)), Job::Get("/"));
        assert!(o.failed.is_none(), "{coding}: {:?}", o.failed);
        assert_eq!(o.body, plain(), "{coding}");
        assert!(o.header("content-encoding").is_none(), "{coding}");
        assert!(o.header("content-length").is_none(), "{coding}");
    }
}

#[test]
fn unknown_response_coding_fails_the_request() {
    let rt = rt();
    let addr = raw_server(coded_head("zstd", 4), b"abcd".to_vec(), 4, Duration::ZERO);
    let o = run(&rt, addr, Proto::H1, Some(client_policy(&CODED)), Job::Get("/"));
    let e = o.failed.expect("unknown coding must fail closed");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    assert!(o.body.is_empty(), "no undecoded bytes may leak to the handler");
}

#[test]
fn response_bomb_over_the_limit_fails_closed() {
    let rt = rt();
    let bomb = encode(ContentCoding::Gzip, &vec![0u8; 8 * 1024 * 1024], 65536);
    let addr = raw_server(coded_head("gzip", bomb.len()), bomb, 1024, Duration::ZERO);
    let policy = client_policy(&CODED).max_decoded_body(100_000);
    let o = run(&rt, addr, Proto::H1, Some(policy), Job::Get("/"));
    let e = o.failed.expect("bomb must fail closed");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    assert!(o.body.len() <= 100_000, "delivered {} bytes past the cap", o.body.len());
}

#[test]
fn corrupt_and_truncated_response_bodies_fail() {
    let rt = rt();
    let mut bad = GOLDEN_GZIP.to_vec();
    bad[30] ^= 0x55;
    let addr = raw_server(coded_head("gzip", bad.len()), bad, 8, Duration::ZERO);
    let o = run(&rt, addr, Proto::H1, Some(client_policy(&CODED)), Job::Get("/"));
    assert!(o.failed.is_some(), "corrupt gzip must fail");

    let cut = GOLDEN_BROTLI[..GOLDEN_BROTLI.len() - 5].to_vec();
    let addr = raw_server(coded_head("br", cut.len()), cut, 8, Duration::ZERO);
    let o = run(&rt, addr, Proto::H1, Some(client_policy(&CODED)), Job::Get("/"));
    assert!(o.failed.is_some(), "truncated brotli must fail");
}

#[test]
fn stacked_response_codings_are_undone_in_reverse() {
    let rt = rt();
    let inner = encode(ContentCoding::Gzip, &plain(), 64);
    let wire = encode(ContentCoding::Brotli, &inner, 64);
    let addr = raw_server(coded_head("gzip, br", wire.len()), wire, 5, Duration::ZERO);
    let o = run(&rt, addr, Proto::H1, Some(client_policy(&CODED)), Job::Get("/"));
    assert!(o.failed.is_none(), "{:?}", o.failed);
    assert_eq!(o.body, plain());
}

/// HTTP/3: the same decorators over a real QUIC connection.
#[cfg(feature = "h3")]
#[test]
fn h3_round_trip_decodes_and_server_decodes_requests() {
    use crate::client::h3_session::connect_h3_session;
    use hopf_quic::{client_config_for_pem_bytes, server_config_self_signed, ALPN_H3};

    let (server_cfg, pem) = server_config_self_signed(&["localhost"], &[ALPN_H3]).unwrap();
    let client_cfg = client_config_for_pem_bytes(&pem, &[ALPN_H3]).unwrap();
    let factory: Arc<dyn ServerHandlerFactory> =
        Arc::new(ContentEncodingServerFactory::new(Arc::new(AppFactory), server_policy()));
    let server = crate::h3::listen_h3(
        "127.0.0.1:0".parse().unwrap(),
        server_cfg,
        factory,
        HttpLimits::default(),
    )
    .unwrap();

    let run_h3 = |policy: Option<ContentEncodingPolicy>, job: Job| -> Outcome {
        let out = Arc::new(Mutex::new(Outcome::default()));
        let conn = Conn { job: Some(job), out: Arc::clone(&out) };
        struct Shim(Conn, Option<ContentEncodingPolicy>);
        impl HttpConnectionHandler for Shim {
            fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
                if let Some(p) = self.1.take() {
                    session.content_encoding(p);
                }
                self.0.on_connected(session);
            }
        }
        connect_h3_session(
            server.local_addr,
            client_cfg.clone(),
            "localhost",
            "localhost",
            server.local_addr.port(),
            HttpLimits::default(),
            Box::new(Shim(conn, policy)),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            {
                let g = out.lock().unwrap();
                if g.closed || g.failed.is_some() {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "h3 request timed out");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut g = out.lock().unwrap();
        std::mem::take(&mut *g)
    };

    let want = text_body();
    for coding in CODED {
        let o = run_h3(Some(client_policy(&[coding])), Job::Get("/text"));
        assert!(o.failed.is_none(), "h3 {coding}: {:?}", o.failed);
        assert_eq!(o.version, Some(crate::version::HttpVersion::Http3));
        assert!(o.body == want, "h3 {coding}: body differs ({} bytes)", o.body.len());
        assert!(o.header("content-encoding").is_none(), "h3 {coding}");
    }

    let body = text_body()[..100_000].to_vec();
    let sum: u64 = body.iter().map(|&b| b as u64).sum();
    let o = run_h3(None, Job::Post { path: "/echo", coding: Some(ContentCoding::Brotli), body: body.clone() });
    assert_eq!(String::from_utf8_lossy(&o.body), format!("len={} sum={}", body.len(), sum));
    server.shutdown();
}
