// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in integration tests: real loopback TCP round-trips for the async
//! HTTP client dial path ([`crate::client::connect_http`]).
//!
//! These are deliberately excluded from CI. Run them manually with:
//! `cargo test -p hopf-http --features integration`.

#![cfg(feature = "integration")]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

use crate::client::{connect_http, connect_http2_upgrade, HttpClientTimeouts};
use crate::h2::frame;
use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};
use crate::{
    CleartextHttpEndpoint, ClientHandler, ClientHandlerFactory, ClientWriter, H2Endpoint, Headers,
    HttpLimits,
};

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
// h2c-Upgrade-capable server (real hopf server stack, not the raw responder
// above) — needed to prove genuine interop for the client-side h2c dial.
// ---------------------------------------------------------------------------

struct FixedServerHandler;
impl ServerHandler for FixedServerHandler {
    fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}
    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        let mut h = Headers::new();
        h.set(":status", "200");
        response.headers(h);
        response.response_body_content(b"hello-h2c-client");
        response.end_response_body();
        response.complete();
    }
}
struct FixedServerFactory;
impl ServerHandlerFactory for FixedServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(FixedServerHandler)
    }
}

fn start_h2c_capable_server(rt: &Arc<Runtime>) -> SocketAddr {
    let factory: Arc<dyn ServerHandlerFactory> = Arc::new(FixedServerFactory);
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(CleartextHttpEndpoint::new(Arc::clone(&factory), HttpLimits::default()))
                as Box<dyn ProtocolHandler>
        }))
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
// Raw H2 server for SETTINGS-ACK-timeout tests
// ---------------------------------------------------------------------------

struct NoopServerHandler;

impl ServerHandler for NoopServerHandler {
    fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}
    fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
}

struct NoopServerFactory;

impl ServerHandlerFactory for NoopServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(NoopServerHandler)
    }
}

/// Cleartext prior-knowledge H2 server whose SETTINGS-ACK wait is shortened
/// to `ack_timeout`, so tests don't have to wait out the real 10s default.
fn start_h2_server(rt: &Arc<Runtime>, ack_timeout: Duration) -> SocketAddr {
    let factory: Arc<dyn ServerHandlerFactory> = Arc::new(NoopServerFactory);
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            let mut ep = H2Endpoint::server(Arc::clone(&factory), HttpLimits::default(), true);
            ep.set_settings_ack_timeout_for_test(ack_timeout);
            Box::new(ep) as Box<dyn ProtocolHandler>
        }))
        .unwrap();
    addr
}

/// Read one H2 frame (9-byte header + payload), or `None` on a clean EOF.
fn read_frame(stream: &mut TcpStream) -> Option<(frame::FrameHeader, Vec<u8>)> {
    let mut hdr_buf = [0u8; 9];
    match stream.read_exact(&mut hdr_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return None,
        Err(e) => panic!("read error: {e}"),
    }
    let hdr = frame::parse_frame_header(&hdr_buf);
    let mut payload = vec![0u8; hdr.length as usize];
    stream.read_exact(&mut payload).unwrap();
    Some((hdr, payload))
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

/// A peer that never ACKs the server's SETTINGS frame is closed with
/// `GOAWAY(SETTINGS_TIMEOUT)` (RFC 9113 §6.5.3).
#[test]
fn h2_settings_ack_timeout_closes_with_goaway() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let ack_timeout = Duration::from_millis(150);
    let addr = start_h2_server(&rt, ack_timeout);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let (settings_hdr, _) = read_frame(&mut stream).expect("server SETTINGS frame");
    assert_eq!(settings_hdr.ty, frame::TYPE_SETTINGS);
    assert_eq!(settings_hdr.flags & frame::FLAG_ACK, 0);

    // Never ACK it: the timer should fire and close the connection.
    let (goaway_hdr, payload) = read_frame(&mut stream).expect("GOAWAY frame");
    assert_eq!(goaway_hdr.ty, frame::TYPE_GOAWAY);
    let error_code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    assert_eq!(error_code, frame::ERROR_SETTINGS_TIMEOUT);

    let mut buf = [0u8; 1];
    let n = stream.read(&mut buf).unwrap();
    assert_eq!(n, 0, "expected connection close (EOF) after GOAWAY");
}

/// Acknowledging the server's SETTINGS frame in time cancels the timer — no
/// GOAWAY, no close.
#[test]
fn h2_settings_ack_in_time_cancels_timeout() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let ack_timeout = Duration::from_millis(150);
    let addr = start_h2_server(&rt, ack_timeout);

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    let (settings_hdr, _) = read_frame(&mut stream).expect("server SETTINGS frame");
    assert_eq!(settings_hdr.ty, frame::TYPE_SETTINGS);

    let mut ack = Vec::new();
    frame::write_settings_ack(&mut ack);
    stream.write_all(&ack).unwrap();

    // Wait well past the (shortened) timeout window; the connection must stay open.
    std::thread::sleep(ack_timeout * 3);
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).unwrap_err();
    assert!(
        matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        "expected no further data (still-open connection), got: {err:?}"
    );
}

/// End-to-end h2c Upgrade dial (RFC 7540 §3.2) against hopf's own
/// [`CleartextHttpEndpoint`] server — proves the client-side Upgrade
/// request, the server's `101` response, and the promoted real H2 exchange
/// all interoperate over a real socket, not just unit-level plumbing.
#[test]
fn h2c_upgrade_round_trip_over_real_socket() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let addr = start_h2c_capable_server(&rt);

    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory {
        out: Arc::clone(&out),
    });

    connect_http2_upgrade(
        &rt,
        &addr.ip().to_string(),
        addr.port(),
        factory,
        HttpLimits::default(),
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    assert!(wait_done(&out, Duration::from_secs(5)), "request timed out");
    let g = out.lock().unwrap();
    assert_eq!(g.status, 200);
    assert_eq!(g.body, b"hello-h2c-client");
}
