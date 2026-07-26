// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client-side h2c Upgrade dial (RFC 7540 §3.2): send the request as
//! HTTP/1.1 with `Upgrade: h2c` + `HTTP2-Settings`, and switch to the H2
//! codec on a `101 Switching Protocols` response. If the peer doesn't
//! support (or accept) the upgrade, the exchange completes as plain
//! HTTP/1.1 instead — h2c Upgrade support is optional for servers.
//!
//! Mirrors the server-side sniffer in [`super::cleartext`], but from the
//! dialing side.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo};

use crate::h1::H1ClientCodec;
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{ClientHandler, ClientHandlerFactory, ClientWriter};

use super::base64url;
use super::endpoint::H2Endpoint;
use super::frame::SETTINGS_ENABLE_PUSH;

/// The client's initial SETTINGS payload, base64url-encoded for the
/// `HTTP2-Settings` header — the same `ENABLE_PUSH=0` settings
/// [`H2Endpoint::client`] sends in its cleartext connection preface.
fn initial_settings_base64url() -> String {
    let mut payload = Vec::with_capacity(6);
    payload.extend_from_slice(&SETTINGS_ENABLE_PUSH.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    base64url::encode(&payload)
}

// ---------------------------------------------------------------------------
// Header injection + upgrade detection, wrapping the app's real handler
// ---------------------------------------------------------------------------

/// Adds the three h2c Upgrade request headers (RFC 7540 §3.2) to whatever
/// headers the wrapped [`ClientHandler`] sends, then forwards unchanged.
struct InjectingWriter<'a> {
    inner: &'a mut dyn ClientWriter,
    settings_b64: &'a str,
}

impl ClientWriter for InjectingWriter<'_> {
    fn headers(&mut self, mut headers: Headers) {
        headers.add("Connection", "Upgrade, HTTP2-Settings");
        headers.add("Upgrade", "h2c");
        headers.add("HTTP2-Settings", self.settings_b64);
        self.inner.headers(headers);
    }
    fn start_request_body(&mut self) {
        self.inner.start_request_body();
    }
    fn request_body_content(&mut self, data: &[u8]) {
        self.inner.request_body_content(data);
    }
    fn end_request_body(&mut self) {
        self.inner.end_request_body();
    }
    fn complete_request(&mut self) {
        self.inner.complete_request();
    }
}

/// Wraps the app's real [`ClientHandler`]: injects the Upgrade headers on
/// `start`, forwards every other callback unchanged, and records whether
/// `101 Switching Protocols` arrived (via `upgraded`) so the owning
/// [`H2cUpgradeClientEndpoint`] knows to promote the connection to H2.
struct UpgradeProbeHandler {
    inner: Box<dyn ClientHandler>,
    settings_b64: String,
    upgraded: Arc<AtomicBool>,
}

impl ClientHandler for UpgradeProbeHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let mut w = InjectingWriter {
            inner: request,
            settings_b64: &self.settings_b64,
        };
        self.inner.start(&mut w);
    }
    fn informational_response(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.informational_response(request, headers);
    }
    fn switching_protocols(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {
        self.upgraded.store(true, Ordering::SeqCst);
    }
    fn response_headers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.response_headers(request, headers);
    }
    fn start_response_body(&mut self, request: &mut dyn ClientWriter) {
        self.inner.start_response_body(request);
    }
    fn response_body_content(&mut self, request: &mut dyn ClientWriter, data: &[u8]) {
        self.inner.response_body_content(request, data);
    }
    fn end_response_body(&mut self, request: &mut dyn ClientWriter) {
        self.inner.end_response_body(request);
    }
    fn response_trailers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        self.inner.response_trailers(request, headers);
    }
    fn response_complete(&mut self, request: &mut dyn ClientWriter) {
        self.inner.response_complete(request);
    }
    fn request_failed(&mut self, request: &mut dyn ClientWriter, err: &std::io::Error) {
        self.inner.request_failed(request, err);
    }
}

// ---------------------------------------------------------------------------
// H2cUpgradeClientEndpoint
// ---------------------------------------------------------------------------

enum Phase {
    /// Sending/awaiting the HTTP/1.1 upgrade request and response.
    H1(H1ClientCodec<UpgradeProbeHandler>),
    /// `101` accepted; full H2 connection.
    H2(H2Endpoint),
}

/// Client [`ProtocolHandler`] that dials via HTTP/1.1 h2c Upgrade
/// (RFC 7540 §3.2), promoting the connection to [`H2Endpoint`] if the peer
/// responds `101 Switching Protocols`, or completing as plain HTTP/1.1
/// otherwise.
///
/// The wrapped [`ClientHandler`] (from `factory.create_handler()`) is used
/// exactly once, the same as [`H2Endpoint::client`] — its `start()` builds
/// the (single) request that either becomes H2 stream 1 or a normal H1
/// exchange, transparently to the handler.
pub struct H2cUpgradeClientEndpoint {
    phase: Phase,
    upgraded: Arc<AtomicBool>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
}

impl H2cUpgradeClientEndpoint {
    /// Create a new h2c-Upgrade client dial. `secure` must be `false` — h2c
    /// Upgrade is a cleartext-only mechanism (RFC 9113 forbids the plaintext
    /// Upgrade path over TLS; use [`H2Endpoint::client`] with `secure = true`
    /// for TLS-ALPN dial instead).
    pub fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        let upgraded = Arc::new(AtomicBool::new(false));
        let probe = UpgradeProbeHandler {
            inner: factory.create_handler(),
            settings_b64: initial_settings_base64url(),
            upgraded: Arc::clone(&upgraded),
        };
        let mut codec = H1ClientCodec::new(probe, limits, false);
        codec.set_stream_id(1);
        Self {
            phase: Phase::H1(codec),
            upgraded,
            factory,
            limits,
        }
    }

    /// Promote from the H1 probe to a full H2 connection after observing
    /// `101 Switching Protocols`, sending the client preface + SETTINGS and
    /// feeding it whatever bytes arrived after the `101` response.
    fn promote_to_h2(&mut self, endpoint: &mut dyn Endpoint, remainder: &mut &[u8]) {
        let Phase::H1(codec) = &mut self.phase else {
            return;
        };
        let probe = codec.take_handler();
        let mut h2ep =
            H2Endpoint::client_after_h2c_upgrade(probe.inner, Arc::clone(&self.factory), self.limits);
        h2ep.connected(endpoint);
        if !remainder.is_empty() {
            h2ep.receive(endpoint, remainder);
        }
        self.phase = Phase::H2(h2ep);
    }
}

impl ProtocolHandler for H2cUpgradeClientEndpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Phase::H1(codec) = &mut self.phase {
            codec.on_connected();
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
        }
    }

    fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
        // h2c Upgrade is cleartext-only; this endpoint is never dialed over TLS.
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        match &mut self.phase {
            Phase::H1(codec) => {
                let _ = codec.receive(data);
                let out = codec.take_outbound();
                if !out.is_empty() {
                    endpoint.send(&out);
                }
                if self.upgraded.load(Ordering::SeqCst) {
                    self.promote_to_h2(endpoint, data);
                    return;
                }
                if codec.wants_close() {
                    endpoint.close();
                }
            }
            Phase::H2(ep) => ep.receive(endpoint, data),
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        match &mut self.phase {
            Phase::H1(codec) => {
                let _ = codec.close();
                let out = codec.take_outbound();
                if !out.is_empty() {
                    endpoint.send(&out);
                }
            }
            Phase::H2(ep) => ep.disconnected(endpoint),
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        match &mut self.phase {
            Phase::H1(_) => endpoint.close(),
            Phase::H2(ep) => ep.error(endpoint, err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::frame;
    use std::sync::Mutex;
    use std::time::Duration;

    /// Minimal [`Endpoint`] stub recording sent bytes / close calls.
    #[derive(Default)]
    struct RecordingEndpoint {
        sent: Vec<u8>,
        closed: bool,
    }
    impl Endpoint for RecordingEndpoint {
        fn send(&mut self, data: &[u8]) {
            self.sent.extend_from_slice(data);
        }
        fn is_open(&self) -> bool {
            !self.closed
        }
        fn is_closing(&self) -> bool {
            self.closed
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            unimplemented!("not exercised by these unit tests")
        }
        fn remote_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            unimplemented!("not exercised by these unit tests")
        }
        fn security_info(&self) -> &SecurityInfo {
            unimplemented!("not exercised by these unit tests")
        }
        fn start_tls(&mut self) -> Result<(), hopf_core::StartTlsError> {
            unimplemented!("not exercised by these unit tests")
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<hopf_core::WriteReadyCallback>) {}
        fn execute(&self, task: Box<dyn FnOnce() + Send>) {
            task();
        }
        fn schedule_timer(
            &self,
            _delay: Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> hopf_core::TimerHandle {
            // Never fires — these tests don't exercise the SETTINGS-ACK
            // timeout, only that arming it (via `H2Endpoint::connected`)
            // doesn't panic on a minimal `Endpoint`.
            hopf_core::TimerHandle::from_cancel(|| {})
        }
        fn handle(&self) -> hopf_core::ConnHandle {
            hopf_core::ConnHandle::from_execute(Arc::new(|task| task()))
        }
    }

    #[derive(Default)]
    struct Recorded {
        informational: Vec<u16>,
        switched: bool,
        final_status: Option<u16>,
        body: Vec<u8>,
        completed: bool,
    }

    struct RecordingHandler {
        rec: Arc<Mutex<Recorded>>,
    }
    impl ClientHandler for RecordingHandler {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "GET");
            h.set(":path", "/");
            h.set("host", "example.test");
            request.headers(h);
            request.complete_request();
        }
        fn informational_response(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().informational.push(headers.status_code());
        }
        fn switching_protocols(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {
            self.rec.lock().unwrap().switched = true;
        }
        fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().final_status = Some(headers.status_code());
        }
        fn response_body_content(&mut self, _request: &mut dyn ClientWriter, data: &[u8]) {
            self.rec.lock().unwrap().body.extend_from_slice(data);
        }
        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
            self.rec.lock().unwrap().completed = true;
        }
    }

    struct RecordingFactory {
        rec: Arc<Mutex<Recorded>>,
    }
    impl ClientHandlerFactory for RecordingFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            Box::new(RecordingHandler { rec: Arc::clone(&self.rec) })
        }
    }

    fn new_endpoint() -> (H2cUpgradeClientEndpoint, Arc<Mutex<Recorded>>) {
        let rec = Arc::new(Mutex::new(Recorded::default()));
        let factory: Arc<dyn ClientHandlerFactory> =
            Arc::new(RecordingFactory { rec: Arc::clone(&rec) });
        (H2cUpgradeClientEndpoint::new(factory, HttpLimits::default()), rec)
    }

    #[test]
    fn upgrade_request_carries_the_required_headers() {
        let (mut ep, _rec) = new_endpoint();
        let mut endpoint = RecordingEndpoint::default();
        ep.connected(&mut endpoint);

        let req = String::from_utf8(endpoint.sent).unwrap();
        assert!(req.starts_with("GET / HTTP/1.1\r\n"), "was: {req:?}");
        let lower = req.to_ascii_lowercase();
        assert!(lower.contains("connection: upgrade, http2-settings\r\n"), "was: {req:?}");
        assert!(lower.contains("upgrade: h2c\r\n"), "was: {req:?}");
        assert!(lower.contains("http2-settings:"), "was: {req:?}");
    }

    /// A `101` response promotes the connection to H2: the app handler never
    /// sees `response_headers`/`response_complete` for this request (those
    /// now arrive later via a real H2 stream 1), and the client preface +
    /// SETTINGS go out immediately.
    #[test]
    fn successful_upgrade_promotes_to_h2_and_sends_preface() {
        let (mut ep, rec) = new_endpoint();
        let mut endpoint = RecordingEndpoint::default();
        ep.connected(&mut endpoint);
        let request_len = endpoint.sent.len();

        let mut response: &[u8] =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
        ep.receive(&mut endpoint, &mut response);
        assert!(response.is_empty(), "the whole 101 response head must be consumed");

        assert!(matches!(ep.phase, Phase::H2(_)), "must have promoted to H2");
        assert!(ep.upgraded.load(Ordering::SeqCst));
        // The upgrade is transparent to the app-level handler: it never
        // sees `switching_protocols` itself (only the internal
        // `UpgradeProbeHandler` wrapper does) — its real response instead
        // arrives later via a genuine H2 stream 1.
        assert!(!rec.lock().unwrap().switched);
        assert!(rec.lock().unwrap().final_status.is_none(), "no H1 final response for this request");
        assert!(!rec.lock().unwrap().completed);

        let after_upgrade = &endpoint.sent[request_len..];
        assert!(
            after_upgrade.starts_with(super::super::endpoint::CLIENT_PREFACE),
            "expected the H2 client preface right after the 101 response"
        );
        let settings_bytes = &after_upgrade[super::super::endpoint::CLIENT_PREFACE.len()..];
        let header = frame::parse_frame_header(&settings_bytes[..9]);
        assert_eq!(header.ty, frame::TYPE_SETTINGS);
    }

    /// A normal (non-101) response means the peer doesn't support h2c: the
    /// exchange completes as plain HTTP/1.1, delivered to the same app
    /// handler exactly as [`crate::h1::H1Endpoint::client`] would.
    #[test]
    fn non_101_response_falls_back_to_plain_http1() {
        let (mut ep, rec) = new_endpoint();
        let mut endpoint = RecordingEndpoint::default();
        ep.connected(&mut endpoint);

        let mut response: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        ep.receive(&mut endpoint, &mut response);
        assert!(response.is_empty());

        assert!(matches!(ep.phase, Phase::H1(_)), "must stay on HTTP/1.1");
        let r = rec.lock().unwrap();
        assert!(!r.switched);
        assert_eq!(r.final_status, Some(200));
        assert_eq!(r.body, b"hello");
        assert!(r.completed);
    }
}
