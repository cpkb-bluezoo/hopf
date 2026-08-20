// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Opt-in integration tests: real loopback TCP round-trips for the async
//! HTTP client dial path ([`crate::client::connect_http`]).
//!
//! These are deliberately excluded from CI. Run them manually with:
//! `cargo test -p hopf-http --features integration`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

use crate::client::{connect_auto, connect_http, connect_http2_upgrade, HttpClientTimeouts};
use crate::h2::frame;
use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};
use crate::{
    AltSvcCache, CleartextHttpEndpoint, ClientHandler, ClientHandlerFactory, ClientWriter,
    H2Endpoint, Headers, HttpClient, HttpClientSessionHandle, HttpConnectionHandler, HttpLimits,
    HttpRequest, HttpResponseHandler,
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

/// Poll `pred` until it's true or `max` elapses.
fn wait_for(mut pred: impl FnMut() -> bool, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    loop {
        if pred() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// ---------------------------------------------------------------------------
// Server that captures each request-body delivery separately (real hopf
// server stack) — used to prove client-side streaming/backpressure/poke
// behavior actually reaches the wire incrementally, not just "eventually".
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CapturedRequest {
    /// One entry per `request_body_content` call the server received.
    chunks: Vec<Vec<u8>>,
    complete: bool,
}

struct CapturingServerHandler {
    captured: Arc<Mutex<CapturedRequest>>,
    /// If false, the request is captured but never answered — used to
    /// exercise a client-side stage timeout against a real (if silent) peer.
    respond: bool,
}

impl ServerHandler for CapturingServerHandler {
    fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}

    fn request_body_content(&mut self, _response: &mut dyn ServerWriter, data: &[u8]) {
        self.captured.lock().unwrap().chunks.push(data.to_vec());
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        self.captured.lock().unwrap().complete = true;
        if !self.respond {
            return;
        }
        let mut h = Headers::new();
        h.set(":status", "200");
        response.headers(h);
        response.response_body_content(b"ok");
        response.end_response_body();
        response.complete();
    }
}

struct CapturingServerFactory {
    captured: Arc<Mutex<CapturedRequest>>,
    respond: bool,
}

impl ServerHandlerFactory for CapturingServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(CapturingServerHandler {
            captured: Arc::clone(&self.captured),
            respond: self.respond,
        })
    }
}

fn start_capturing_server(
    rt: &Arc<Runtime>,
    respond: bool,
) -> (SocketAddr, Arc<Mutex<CapturedRequest>>) {
    let captured = Arc::new(Mutex::new(CapturedRequest::default()));
    let factory: Arc<dyn ServerHandlerFactory> = Arc::new(CapturingServerFactory {
        captured: Arc::clone(&captured),
        respond,
    });
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(CleartextHttpEndpoint::new(Arc::clone(&factory), HttpLimits::default()))
                as Box<dyn ProtocolHandler>
        }))
        .unwrap();
    (addr, captured)
}

// ---------------------------------------------------------------------------
// Gumdrop `HttpClient`/`HttpConnectionHandler`/`HttpRequest` session API
// test scaffolding (issues #83, #85, #88 — the low-level `ClientHandler`
// SPI above never exercises this path at all).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct GumdropOutcome {
    status: u16,
    body: Vec<u8>,
    done: bool,
    failed: Option<io::ErrorKind>,
    on_error_called: bool,
    on_connected_called: bool,
}

fn wait_gumdrop_done(out: &Arc<Mutex<GumdropOutcome>>, max: Duration) -> bool {
    wait_for(|| out.lock().unwrap().done, max)
}

struct RecordingResponseHandler {
    out: Arc<Mutex<GumdropOutcome>>,
}

impl HttpResponseHandler for RecordingResponseHandler {
    fn ok(&mut self, status: u16) {
        self.out.lock().unwrap().status = status;
    }
    fn error(&mut self, status: u16) {
        self.out.lock().unwrap().status = status;
    }
    fn header(&mut self, _name: &str, _value: &str) {}
    fn response_body_content(&mut self, data: &[u8]) {
        self.out.lock().unwrap().body.extend_from_slice(data);
    }
    fn close(&mut self) {
        self.out.lock().unwrap().done = true;
    }
    fn failed(&mut self, err: io::Error) {
        let mut g = self.out.lock().unwrap();
        g.failed = Some(err.kind());
        g.done = true;
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

// ---------------------------------------------------------------------------
// Gumdrop HttpClient session API — #83, #84, #85, #88
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RequestSlot {
    conn_handle: Option<hopf_core::ConnHandle>,
    request: Option<HttpRequest>,
}

struct StashConn {
    slot: Arc<Mutex<RequestSlot>>,
    out: Arc<Mutex<GumdropOutcome>>,
}

impl HttpConnectionHandler for StashConn {
    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        self.out.lock().unwrap().on_connected_called = true;
        let conn_handle = session.conn_handle();
        let mut req = session.put("/upload");
        req.start_request_body(Box::new(RecordingResponseHandler {
            out: Arc::clone(&self.out),
        }))
        .unwrap();
        let mut slot = self.slot.lock().unwrap();
        slot.conn_handle = conn_handle;
        slot.request = Some(req);
    }
}

/// Stashing a [`hopf_core::ConnHandle`] from `on_connected` and using it to
/// `poke()` after each out-of-band `request_body_content` call delivers
/// each chunk to the peer promptly — proving true streaming, not "buffer
/// until some unrelated HTTP-side I/O event flushes it" (issue #83). The
/// chunk-by-chunk delivery driving this also end-to-end-proves #84/#85's
/// underlying mechanics for H1 (dedicated H2 coverage is unit-level in
/// `h2::endpoint::gumdrop_client_stream_tests`, which inspects wire frames
/// directly — real-socket H2 here would only re-prove the same thing).
#[test]
fn gumdrop_client_conn_handle_poke_streams_body_promptly() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, captured) = start_capturing_server(&rt, true);

    let slot = Arc::new(Mutex::new(RequestSlot::default()));
    let out = Arc::new(Mutex::new(GumdropOutcome::default()));
    HttpClient::new(addr.ip().to_string(), addr.port())
        .connect(
            &rt,
            Box::new(StashConn {
                slot: Arc::clone(&slot),
                out: Arc::clone(&out),
            }),
        )
        .unwrap();

    assert!(
        wait_for(|| slot.lock().unwrap().request.is_some(), Duration::from_secs(5)),
        "on_connected never stashed a request"
    );

    let chunks: [&[u8]; 3] = [b"chunk-one-", b"chunk-two-", b"chunk-three"];
    for (i, chunk) in chunks.iter().enumerate() {
        {
            let mut g = slot.lock().unwrap();
            let req = g.request.as_mut().unwrap();
            assert_eq!(req.request_body_content(chunk).unwrap(), chunk.len());
        }
        slot.lock().unwrap().conn_handle.as_ref().unwrap().poke();

        // This connection sits idle otherwise (no other traffic, no
        // response yet) — if delivery only happened at some unrelated
        // HTTP-side I/O event, this chunk would never show up on its own.
        assert!(
            wait_for(|| captured.lock().unwrap().chunks.len() > i, Duration::from_secs(2)),
            "chunk {i} did not reach the server promptly after poke()"
        );
    }
    {
        let mut g = slot.lock().unwrap();
        g.request.as_mut().unwrap().end_request_body().unwrap();
    }
    slot.lock().unwrap().conn_handle.as_ref().unwrap().poke();

    assert!(wait_gumdrop_done(&out, Duration::from_secs(5)), "response never completed");
    let g = out.lock().unwrap();
    assert_eq!(g.status, 200);
    drop(g);

    let cap = captured.lock().unwrap();
    assert!(cap.complete);
    assert_eq!(
        cap.chunks.len(),
        3,
        "each request_body_content+poke call should reach the server as its own delivery"
    );
    assert_eq!(cap.chunks.concat(), b"chunk-one-chunk-two-chunk-three".to_vec());
}

struct NeverRespondConn {
    out: Arc<Mutex<GumdropOutcome>>,
}

impl HttpConnectionHandler for NeverRespondConn {
    fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
        self.out.lock().unwrap().on_connected_called = true;
        session
            .get("/never-answered")
            .send(Box::new(RecordingResponseHandler {
                out: Arc::clone(&self.out),
            }))
            .unwrap();
    }
}

/// A real (if silent) peer that accepts the connection and the request but
/// never answers trips [`HttpClientTimeouts::stage`] — the request fails
/// via [`HttpResponseHandler::failed`] with a timeout, instead of hanging
/// forever (issue #88).
#[test]
fn gumdrop_client_stage_timeout_fails_the_request() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let (addr, captured) = start_capturing_server(&rt, false);

    let out = Arc::new(Mutex::new(GumdropOutcome::default()));
    HttpClient::new(addr.ip().to_string(), addr.port())
        .timeouts(HttpClientTimeouts {
            stage: Duration::from_millis(150),
            ..HttpClientTimeouts::default()
        })
        .connect(&rt, Box::new(NeverRespondConn { out: Arc::clone(&out) }))
        .unwrap();

    assert!(
        wait_gumdrop_done(&out, Duration::from_secs(5)),
        "stage timeout never fired"
    );
    let g = out.lock().unwrap();
    assert_eq!(
        g.failed,
        Some(io::ErrorKind::TimedOut),
        "expected HttpResponseHandler::failed with TimedOut"
    );
    assert_eq!(g.status, 0, "no successful response should have been recorded");
    drop(g);
    // The server did receive and complete the request — it just chose
    // (deliberately, for this test) never to answer it.
    assert!(wait_for(|| captured.lock().unwrap().complete, Duration::from_secs(2)));
}

struct ErrorRecordingConn {
    out: Arc<Mutex<GumdropOutcome>>,
}

impl HttpConnectionHandler for ErrorRecordingConn {
    fn on_connected(&mut self, _session: &mut HttpClientSessionHandle) {
        self.out.lock().unwrap().on_connected_called = true;
    }
    fn on_error(&mut self, _err: &io::Error) {
        self.out.lock().unwrap().on_error_called = true;
    }
}

/// A DNS lookup that resolves to no addresses (NODATA) invokes
/// [`HttpConnectionHandler::on_error`] — `on_connected` never fires, and
/// the call doesn't hang (issue #88). Uses a local loopback DNS stub
/// (never real upstream DNS) so this is deterministic and network-free,
/// mirroring `hopf-smtp`'s `simple_relay_rejects_whole_transaction_if_any_domain_fails`.
#[test]
fn gumdrop_client_dns_failure_invokes_on_error() {
    use hopf_dns::wire::{DnsMessage, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());

    // Always answers NOERROR/NODATA — no address, for any query.
    let stub = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = stub.recv_from(&mut buf) else {
                break;
            };
            let Ok(q) = DnsMessage::parse(&buf[..n]) else {
                continue;
            };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR | FLAG_RA;
            let bytes = resp.serialize().unwrap();
            let _ = stub.send_to(&bytes, peer);
        }
    });

    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    dns.add_server(stub_addr);
    dns.set_timeout(Duration::from_millis(500));
    dns.open().unwrap();

    let out = Arc::new(Mutex::new(GumdropOutcome::default()));
    HttpClient::new("nonexistent.hopf-http-test.invalid", 80)
        .resolver(dns)
        .connect(&rt, Box::new(ErrorRecordingConn { out: Arc::clone(&out) }))
        .unwrap();

    assert!(
        wait_for(|| out.lock().unwrap().on_error_called, Duration::from_secs(5)),
        "on_error was never invoked for an unresolvable host"
    );
    assert!(
        !out.lock().unwrap().on_connected_called,
        "on_connected must not fire when DNS resolution never succeeded"
    );
}

/// `connect_h3_by_name` must resolve hostnames through an injected
/// [`hopf_dns::DnsResolver`], the same as every other dial path in this
/// crate (`connect_http`/`connect_http2_upgrade`) — not silently fall back
/// to the OS resolver. Proven with a hostname that only resolves via a
/// local stub DNS server the injected resolver points at: the OS has no
/// idea about it, so this only succeeds if the injected resolver was
/// actually consulted.
#[test]
fn connect_h3_by_name_uses_the_injected_dns_resolver_not_the_os_resolver() {
    use hopf_dns::wire::{DnsMessage, DnsResourceRecord, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;
    use std::net::Ipv4Addr;

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());

    // Answers A queries with a TEST-NET-3 (RFC 5737) address: reserved,
    // never routable, and certainly not what any real DNS server would
    // return for this made-up hostname.
    let stub = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, peer)) = stub.recv_from(&mut buf) else {
                break;
            };
            let Ok(q) = DnsMessage::parse(&buf[..n]) else {
                continue;
            };
            let mut resp = q.response_template(0);
            resp.flags |= FLAG_QR | FLAG_RA;
            if let Some(question) = q.questions.first() {
                resp.answers.push(DnsResourceRecord::a(
                    &question.name,
                    60,
                    Ipv4Addr::new(203, 0, 113, 55),
                ));
            }
            let bytes = resp.serialize().unwrap();
            let _ = stub.send_to(&bytes, peer);
        }
    });

    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    dns.add_server(stub_addr);
    dns.set_timeout(Duration::from_millis(500));
    dns.open().unwrap();

    let (_server_cfg, pem) = hopf_quic::server_config_self_signed(&["localhost"], &[b"h3"]).unwrap();
    let client_config = hopf_quic::client_config_for_pem_bytes(&pem, &[b"h3"]).unwrap();

    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory { out: Arc::clone(&out) });

    let result = crate::client::connect_h3_by_name(
        &rt,
        "made-up-host.hopf-h3-resolver-test.invalid",
        4433,
        client_config,
        None,
        factory,
        HttpLimits::default(),
        Some(dns),
    );

    assert!(
        result.is_ok(),
        "connect_h3_by_name should have resolved via the injected DnsResolver, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// connect_auto: DNS HTTPS-record tier and Alt-Svc tier
// ---------------------------------------------------------------------------

struct H3Hello;
impl ServerHandler for H3Hello {
    fn headers(&mut self, response: &mut dyn ServerWriter, _: &Headers) {
        let body = b"hello-h3-via-connect-auto";
        let mut h = Headers::new();
        h.status(200);
        h.set("content-type", "text/plain");
        h.set("content-length", body.len().to_string());
        response.headers(h);
        response.start_response_body();
        response.response_body_content(body);
        response.end_response_body();
        response.complete();
    }
    fn request_complete(&mut self, _: &mut dyn ServerWriter) {}
}
struct H3HelloFactory;
impl ServerHandlerFactory for H3HelloFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(H3Hello)
    }
}

/// A DNS HTTPS record (RFC 9460) advertising `alpn=h3` lets `connect_auto`
/// reach the origin over QUIC directly — no TCP listener exists anywhere
/// in this test, so a fall-through to the TCP tier would simply hang
/// rather than silently "still working".
#[test]
fn connect_auto_uses_dns_https_record_to_reach_h3_with_no_tcp_fallback() {
    use hopf_dns::wire::{
        encode_svcb_alpn, DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA,
        SVCB_PARAM_ALPN, SVCB_PARAM_PORT,
    };
    use hopf_dns::DnsResolver;
    use hopf_quic::{client_config_for_pem_bytes, server_config_self_signed, ALPN_H3};
    use std::net::Ipv4Addr;

    const HOST: &str = "h3-https-record-test.invalid";

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());

    let (server_cfg, pem) = server_config_self_signed(&[HOST], &[ALPN_H3]).unwrap();
    let client_cfg = client_config_for_pem_bytes(&pem, &[ALPN_H3]).unwrap();
    let h3_server = crate::h3::listen_h3(
        "127.0.0.1:0".parse().unwrap(),
        server_cfg,
        Arc::new(H3HelloFactory),
        HttpLimits::default(),
    )
    .unwrap();
    let h3_port = h3_server.local_addr.port();

    // DNS: A -> 127.0.0.1; HTTPS -> alpn=h3, port=<the real h3 listener>;
    // AAAA -> NODATA. No MQTYPE-Response is ever attached, so
    // `query_batch` falls back to standalone per-type queries exactly as
    // it does against a plain RFC-10029-unaware resolver.
    let stub = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    std::thread::spawn(move || loop {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = stub.recv_from(&mut buf) else {
            break;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            continue;
        };
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            match question.qtype {
                Some(DnsType::A) => resp.answers.push(DnsResourceRecord::a(
                    &question.name,
                    60,
                    Ipv4Addr::new(127, 0, 0, 1),
                )),
                Some(DnsType::Https) => {
                    let params = vec![
                        (SVCB_PARAM_ALPN, encode_svcb_alpn(&["h3"])),
                        (SVCB_PARAM_PORT, h3_port.to_be_bytes().to_vec()),
                    ];
                    resp.answers.push(
                        DnsResourceRecord::https(&question.name, 60, 1, ".", &params).unwrap(),
                    );
                }
                _ => {} // AAAA: NODATA
            }
        }
        let bytes = resp.serialize().unwrap();
        let _ = stub.send_to(&bytes, peer);
    });

    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    dns.add_server(stub_addr);
    dns.set_timeout(Duration::from_millis(500));
    dns.open().unwrap();

    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory { out: Arc::clone(&out) });

    connect_auto(
        &rt,
        HOST,
        80, // origin port -- deliberately not the real h3 port; svcb_port must override it
        factory,
        HttpLimits::default(),
        false,
        HttpClientTimeouts::default(),
        Some(dns),
        Some(client_cfg),
        Arc::new(AltSvcCache::new()),
    )
    .unwrap();

    assert!(
        wait_done(&out, Duration::from_secs(5)),
        "connect_auto never completed a request via the DNS HTTPS-record tier"
    );
    assert_eq!(out.lock().unwrap().status, 200);
    assert_eq!(out.lock().unwrap().body, b"hello-h3-via-connect-auto");
    h3_server.shutdown();
}

/// Replies `200 OK` to every request, announcing h3 support via an
/// `Alt-Svc` response header on the *first* request only — later requests
/// (there shouldn't be any once the cache kicks in) would just repeat it.
struct AltSvcAnnouncingServer {
    buf: Vec<u8>,
    h3_port: u16,
}
impl ProtocolHandler for AltSvcAnnouncingServer {
    fn connected(&mut self, _: &mut dyn Endpoint) {}
    fn receive(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) {
        self.buf.extend_from_slice(data);
        *data = &[];
        if self.buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let body = b"hello-tcp-before-alt-svc-upgrade";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nAlt-Svc: h3=\":{}\"\r\nConnection: close\r\n\r\n",
                body.len(),
                self.h3_port
            );
            ep.send(resp.as_bytes());
            ep.send(body);
            ep.close();
        }
    }
    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

/// First connection to an origin with no DNS HTTPS record falls through to
/// plain TCP (tier 3) and observes an `Alt-Svc: h3=...` response header,
/// caching it. A *second* `connect_auto` call to the same origin, sharing
/// that cache, then reaches h3 directly via the tier-2 Alt-Svc lookup —
/// again with no TCP listener able to serve it, so a mistaken tier-3
/// fallback would simply hang.
#[test]
fn connect_auto_upgrades_to_h3_via_alt_svc_cache_on_the_next_connection() {
    use hopf_dns::wire::{DnsMessage, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA};
    use hopf_dns::DnsResolver;
    use hopf_quic::{client_config_for_pem_bytes, server_config_self_signed, ALPN_H3};
    use std::net::Ipv4Addr;

    const HOST: &str = "h3-alt-svc-test.invalid";

    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());

    let (server_cfg, pem) = server_config_self_signed(&[HOST], &[ALPN_H3]).unwrap();
    let client_cfg = client_config_for_pem_bytes(&pem, &[ALPN_H3]).unwrap();
    let h3_server = crate::h3::listen_h3(
        "127.0.0.1:0".parse().unwrap(),
        server_cfg,
        Arc::new(H3HelloFactory),
        HttpLimits::default(),
    )
    .unwrap();
    let h3_port = h3_server.local_addr.port();

    let (tcp_addr, _tcp_listener) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(AltSvcAnnouncingServer { buf: Vec::new(), h3_port }) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

    // DNS: A -> 127.0.0.1 only. No HTTPS record at all -- tier 1 must miss
    // on every call, so the h3 upgrade can only come from the Alt-Svc tier.
    let stub = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    stub.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let stub_addr = stub.local_addr().unwrap();
    std::thread::spawn(move || loop {
        let mut buf = [0u8; 512];
        let Ok((n, peer)) = stub.recv_from(&mut buf) else {
            break;
        };
        let Ok(q) = DnsMessage::parse(&buf[..n]) else {
            continue;
        };
        let mut resp = q.response_template(0);
        resp.flags |= FLAG_QR | FLAG_RA;
        if let Some(question) = q.questions.first() {
            if question.qtype == Some(DnsType::A) {
                resp.answers.push(DnsResourceRecord::a(
                    &question.name,
                    60,
                    Ipv4Addr::new(127, 0, 0, 1),
                ));
            }
        }
        let bytes = resp.serialize().unwrap();
        let _ = stub.send_to(&bytes, peer);
    });

    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    dns.add_server(stub_addr);
    dns.set_timeout(Duration::from_millis(500));
    dns.open().unwrap();

    let alt_svc_cache = Arc::new(AltSvcCache::new());

    // First connection: no HTTPS record, no cached Alt-Svc entry yet ->
    // tier 3, plain TCP, observing the Alt-Svc header on the response.
    let out1 = Arc::new(Mutex::new(Outcome::default()));
    let factory1: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory { out: Arc::clone(&out1) });
    connect_auto(
        &rt,
        HOST,
        tcp_addr.port(),
        factory1,
        HttpLimits::default(),
        false,
        HttpClientTimeouts::default(),
        Some(Arc::clone(&dns)),
        Some(Arc::clone(&client_cfg)),
        Arc::clone(&alt_svc_cache),
    )
    .unwrap();
    assert!(
        wait_done(&out1, Duration::from_secs(5)),
        "first connect_auto call (tier 3, plain TCP) never completed"
    );
    assert_eq!(out1.lock().unwrap().status, 200);
    assert_eq!(out1.lock().unwrap().body, b"hello-tcp-before-alt-svc-upgrade");
    assert!(
        alt_svc_cache.get(HOST, tcp_addr.port()).is_some(),
        "Alt-Svc header from the first response should have been cached"
    );

    // Second connection, same origin, same cache: must reach h3 via the
    // Alt-Svc tier -- no TCP server exists on any port the h3 listener
    // uses, so a wrong tier-3 fallback here would hang rather than pass.
    let out2 = Arc::new(Mutex::new(Outcome::default()));
    let factory2: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory { out: Arc::clone(&out2) });
    connect_auto(
        &rt,
        HOST,
        tcp_addr.port(),
        factory2,
        HttpLimits::default(),
        false,
        HttpClientTimeouts::default(),
        Some(dns),
        Some(client_cfg),
        alt_svc_cache,
    )
    .unwrap();
    assert!(
        wait_done(&out2, Duration::from_secs(5)),
        "second connect_auto call never completed via the Alt-Svc tier"
    );
    assert_eq!(out2.lock().unwrap().status, 200);
    assert_eq!(out2.lock().unwrap().body, b"hello-h3-via-connect-auto");
    h3_server.shutdown();
}
