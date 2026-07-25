// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in integration tests: real loopback TCP round-trips for the async
//! HTTP client dial path ([`crate::client::connect_http`]).
//!
//! These are deliberately excluded from CI. Run them manually with:
//! `cargo test -p hopf-http --features integration`.

#![cfg(feature = "integration")]

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

use crate::client::{connect_http, HttpClientTimeouts};
use crate::{ClientHandler, ClientHandlerFactory, ClientWriter, Headers, HttpLimits};

// ---------------------------------------------------------------------------
// Minimal in-process HTTP/1.1 server
// ---------------------------------------------------------------------------

/// Replies `200 OK` with a fixed body to every request.
struct FixedHttpServer {
    buf: Vec<u8>,
}

impl ProtocolHandler for FixedHttpServer {
    fn connected(&mut self, _: &mut dyn Endpoint) {}

    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if self.buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let body = b"hello-http-client";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            ep.send(resp.as_bytes());
            ep.send(body);
            ep.close();
        }
    }

    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

fn start_server(rt: &Arc<Runtime>) -> SocketAddr {
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            || {
                Box::new(FixedHttpServer { buf: Vec::new() }) as Box<dyn ProtocolHandler>
            },
        ))
        .unwrap();
    addr
}

// ---------------------------------------------------------------------------
// GET client handler
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Outcome {
    status: u16,
    body: Vec<u8>,
    done: bool,
}

struct GetOnce {
    out: Arc<Mutex<Outcome>>,
}

impl ClientHandler for GetOnce {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set(":path", "/");
        h.set("host", "test.local");
        h.set("connection", "close");
        request.headers(h);
        request.complete_request();
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        self.out.lock().unwrap().status = headers.status_code();
    }

    fn response_body_content(&mut self, _request: &mut dyn ClientWriter, data: &[u8]) {
        self.out.lock().unwrap().body.extend_from_slice(data);
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
        self.out.lock().unwrap().done = true;
    }
}

struct GetFactory {
    out: Arc<Mutex<Outcome>>,
}

impl ClientHandlerFactory for GetFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(GetOnce {
            out: Arc::clone(&self.out),
        })
    }
}

fn wait_done(out: &Arc<Mutex<Outcome>>, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    loop {
        if out.lock().unwrap().done {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Literal-IP dial skips DNS and completes the request.
#[test]
fn connect_http_literal_ip_roundtrip() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let addr = start_server(&rt);

    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory {
        out: Arc::clone(&out),
    });

    connect_http(
        &rt,
        &addr.ip().to_string(),
        addr.port(),
        factory,
        HttpLimits::default(),
        false,
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    assert!(wait_done(&out, Duration::from_secs(5)), "request timed out");
    let g = out.lock().unwrap();
    assert_eq!(g.status, 200);
    assert_eq!(g.body, b"hello-http-client");
}

/// Hostname dial resolves `localhost` (hosts file path) without blocking.
#[test]
fn connect_http_localhost_hostname_roundtrip() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let addr = start_server(&rt);

    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory {
        out: Arc::clone(&out),
    });

    let start = Instant::now();
    connect_http(
        &rt,
        "localhost",
        addr.port(),
        factory,
        HttpLimits::default(),
        false,
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();
    // connect_http must return immediately (async DNS), never park the caller.
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "connect_http blocked the caller"
    );

    assert!(wait_done(&out, Duration::from_secs(5)), "request timed out");
    let g = out.lock().unwrap();
    assert_eq!(g.status, 200);
    assert_eq!(g.body, b"hello-http-client");
}
