// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Conditional requests end to end: the real [`HttpServer`] (which wraps
//! handlers in [`ConditionalServerFactory`] by default) against raw HTTP/1.1
//! peers and the real [`HttpClient`] over HTTP/2.

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::Runtime;

use crate::content_coding::e2e_tests::{
    client_for, dechunk, head_has, head_lacks, read_response, rt, run_with, Job, Outcome, Proto,
};
use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};
use crate::{CacheControl, Headers, HttpServer};

const LAST_MODIFIED: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
const LATER: &str = "Mon, 07 Nov 1994 08:49:37 GMT";
const EARLIER: &str = "Sat, 05 Nov 1994 08:49:37 GMT";

fn body() -> Vec<u8> {
    "a validated representation, long enough to be worth not re-sending\n"
        .repeat(60)
        .into_bytes()
}

struct App {
    method: String,
    path: String,
}

impl App {
    fn validated() -> Headers {
        let mut h = Headers::new();
        h.status(200);
        h.set("content-type", "text/plain");
        h.set("etag", "\"v1\"");
        h.set("last-modified", LAST_MODIFIED);
        CacheControl::new().public().max_age(Duration::from_secs(60)).apply(&mut h);
        h
    }
}

impl ServerHandler for App {
    fn headers(&mut self, _w: &mut dyn ServerWriter, h: &Headers) {
        self.method = h.method().unwrap_or("").to_string();
        self.path = h.path().unwrap_or("").to_string();
    }

    fn request_complete(&mut self, w: &mut dyn ServerWriter) {
        match self.path.as_str() {
            "/deferred" => {
                // The whole response comes from another thread, through the
                // response handle.
                let handle = w.response_handle();
                std::thread::spawn(move || {
                    handle.execute(|w| {
                        w.headers(App::validated());
                        w.response_body_content(&body());
                        w.end_response_body();
                        w.complete();
                    });
                });
                return;
            }
            "/res" => {
                w.headers(Self::validated());
                w.response_body_content(&body());
            }
            "/plain" => {
                let mut h = Headers::new();
                h.status(200);
                h.set("content-type", "text/plain");
                w.headers(h);
                w.response_body_content(&body());
            }
            _ => {
                let mut h = Headers::new();
                h.status(404);
                h.set("etag", "\"v1\"");
                w.headers(h);
            }
        }
        w.end_response_body();
        w.complete();
    }
}

struct Factory;
impl ServerHandlerFactory for Factory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(App { method: String::new(), path: String::new() })
    }
}

fn server(rt: &Arc<Runtime>, server: HttpServer) -> SocketAddr {
    server
        .bind(rt, "127.0.0.1:0".parse().unwrap(), Arc::new(Factory))
        .unwrap()
        .0
}

/// Raw exchange: returns (head, de-chunked body).
fn exchange(addr: SocketAddr, method: &str, path: &str, fields: &[(&str, &str)]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: t\r\n");
    for (n, v) in fields {
        req.push_str(&format!("{n}: {v}\r\n"));
    }
    if method == "POST" {
        req.push_str("Content-Length: 0\r\n");
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let (head, b) = read_response(&mut s, method == "HEAD");
    let b = if head_has(&head, "transfer-encoding", "chunked") { dechunk(&b) } else { b };
    (head, b)
}

fn status(head: &str) -> u16 {
    head.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn matching_validators_give_304_with_the_headers_a_200_would_carry() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());

    // Baseline: an unconditional GET is a normal 200.
    let (head, b) = exchange(addr, "GET", "/res", &[]);
    assert_eq!(status(&head), 200, "{head}");
    assert!(b == body());

    for (label, fields) in [
        ("If-None-Match strong", vec![("If-None-Match", "\"v1\"")]),
        ("If-None-Match weak form", vec![("If-None-Match", "W/\"v1\"")]),
        ("If-None-Match list", vec![("If-None-Match", "\"zzz\", \"v1\"")]),
        ("If-None-Match *", vec![("If-None-Match", "*")]),
        ("If-Modified-Since equal", vec![("If-Modified-Since", LAST_MODIFIED)]),
        ("If-Modified-Since later", vec![("If-Modified-Since", LATER)]),
    ] {
        let (head, b) = exchange(addr, "GET", "/res", &fields);
        assert_eq!(status(&head), 304, "{label}: {head}");
        assert!(b.is_empty(), "{label}: a 304 has no body, got {} bytes", b.len());
        assert!(head_has(&head, "etag", "\"v1\""), "{label}: {head}");
        assert!(head_has(&head, "last-modified", LAST_MODIFIED), "{label}: {head}");
        assert!(head_has(&head, "cache-control", "public, max-age=60"), "{label}: {head}");
        assert!(head_lacks(&head, "content-type"), "{label}: {head}");
        assert!(head_lacks(&head, "content-length") || head_has(&head, "content-length", "0"), "{label}: {head}");
        assert!(head_lacks(&head, "transfer-encoding"), "{label}: a 304 must not be chunked: {head}");
    }
}

#[test]
fn non_matching_validators_send_the_full_body() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    for (label, fields) in [
        ("different etag", vec![("If-None-Match", "\"v0\"")]),
        ("older If-Modified-Since", vec![("If-Modified-Since", EARLIER)]),
        ("If-Modified-Since ignored when If-None-Match present", vec![("If-None-Match", "\"v0\""), ("If-Modified-Since", LATER)]),
        ("garbage date is ignored", vec![("If-Modified-Since", "not a date")]),
        ("If-Match satisfied", vec![("If-Match", "\"v1\"")]),
        ("If-Unmodified-Since satisfied", vec![("If-Unmodified-Since", LATER)]),
    ] {
        let (head, b) = exchange(addr, "GET", "/res", &fields);
        assert_eq!(status(&head), 200, "{label}: {head}");
        assert!(b == body(), "{label}");
    }
}

#[test]
fn failed_if_match_and_if_unmodified_since_give_412() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    for (label, fields) in [
        ("If-Match mismatch", vec![("If-Match", "\"other\"")]),
        ("If-Match weak never matches", vec![("If-Match", "W/\"v1\"")]),
        ("If-Unmodified-Since before the last change", vec![("If-Unmodified-Since", EARLIER)]),
    ] {
        let (head, b) = exchange(addr, "GET", "/res", &fields);
        assert_eq!(status(&head), 412, "{label}: {head}");
        assert!(b.is_empty(), "{label}");
    }
}

#[test]
fn head_is_conditional_too() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    let (head, _) = exchange(addr, "HEAD", "/res", &[("If-None-Match", "\"v1\"")]);
    assert_eq!(status(&head), 304, "{head}");
    let (head, _) = exchange(addr, "HEAD", "/res", &[]);
    assert_eq!(status(&head), 200, "{head}");
}

#[test]
fn only_a_200_with_something_to_compare_is_touched() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    // Not a 200 (preconditions are ignored for other statuses).
    let (head, _) = exchange(addr, "GET", "/missing", &[("If-None-Match", "*")]);
    assert_eq!(status(&head), 404, "{head}");
    // A 200 with no validators: only existence conditions can apply.
    let (head, b) = exchange(addr, "GET", "/plain", &[("If-None-Match", "\"v1\""), ("If-Modified-Since", LAST_MODIFIED)]);
    assert_eq!(status(&head), 200, "{head}");
    assert!(b == body());
    // Unsafe methods are the handler's to evaluate: the decorator leaves them alone.
    let (head, _) = exchange(addr, "POST", "/res", &[("If-None-Match", "\"v1\"")]);
    assert_eq!(status(&head), 200, "{head}");
}

#[test]
fn a_response_produced_through_the_response_handle_is_still_conditional() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    let (head, b) = exchange(addr, "GET", "/deferred", &[("If-None-Match", "\"v1\"")]);
    assert_eq!(status(&head), 304, "{head}");
    assert!(b.is_empty());
    let (head, b) = exchange(addr, "GET", "/deferred", &[]);
    assert_eq!(status(&head), 200, "{head}");
    assert!(b == body());
}

#[test]
fn a_304_carries_the_vary_and_weak_etag_of_the_compressed_200() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    // The compressed 200 has a weakened validator and Vary; the client
    // revalidates with what it saw.
    let (head, _) = exchange(addr, "GET", "/res", &[("Accept-Encoding", "gzip")]);
    assert_eq!(status(&head), 200, "{head}");
    assert!(head_has(&head, "content-encoding", "gzip"), "{head}");
    assert!(head_has(&head, "etag", "W/\"v1\""), "{head}");
    assert!(head_has(&head, "vary", "Accept-Encoding"), "{head}");

    let (head, b) = exchange(addr, "GET", "/res", &[("Accept-Encoding", "gzip"), ("If-None-Match", "W/\"v1\"")]);
    assert_eq!(status(&head), 304, "{head}");
    assert!(b.is_empty());
    assert!(head_has(&head, "etag", "W/\"v1\""), "{head}");
    assert!(head_has(&head, "vary", "Accept-Encoding"), "the 304 must vary like the 200: {head}");
    assert!(head_lacks(&head, "content-encoding"), "{head}");
}

#[test]
fn disabled_server_ignores_preconditions() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new().disable_conditional_requests());
    let (head, b) = exchange(addr, "GET", "/res", &[("If-None-Match", "\"v1\"")]);
    assert_eq!(status(&head), 200, "{head}");
    assert!(b == body());
}

#[test]
fn conditional_requests_work_over_http2() {
    let rt = rt();
    let addr = server(&rt, HttpServer::new());
    let client = client_for(addr, Proto::H2, None);
    let get = |extra: Vec<(&'static str, &'static str)>| -> Outcome {
        run_with(&rt, &client, Job::GetWith("/res", extra))
    };

    let o = get(vec![]);
    assert_eq!(o.status, 200);
    assert!(o.body == body());

    let o = get(vec![("If-None-Match", "\"v1\"")]);
    assert_eq!(o.status, 304);
    assert!(o.body.is_empty());
    assert_eq!(o.header("etag"), Some("\"v1\""));
    assert_eq!(o.header("cache-control"), Some("public, max-age=60"));

    let o = get(vec![("If-Modified-Since", LAST_MODIFIED)]);
    assert_eq!(o.status, 304);

    let o = get(vec![("If-None-Match", "\"v0\"")]);
    assert_eq!(o.status, 200);
    assert!(o.body == body());

    let o = get(vec![("If-Match", "\"other\"")]);
    assert_eq!(o.status, 412);
}
