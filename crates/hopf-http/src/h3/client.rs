// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 client connection and request-stream adapters.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler};
use hopf_quic::{
    connect_quic_hooks, QuicClientConfig, QuicConnApi, QuicConnection, QuicDriverHandle,
};

use crate::{
    ClientHandler, ClientHandlerFactory, ClientWriter, Headers, HttpLimits,
};

use super::endpoint::{H3PeerState, H3UniStream};
use super::{frame, qpack, H3FrameHandler, H3Parser};

/// HTTP/3 client connection installed in the QUIC hooks driver.
pub struct H3ClientConnection {
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    peer_state: Arc<Mutex<H3PeerState>>,
}

impl H3ClientConnection {
    /// Create an HTTP/3 client connection (one request Stream after handshake).
    pub fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            peer_state: Arc::new(Mutex::new(H3PeerState::default())),
        }
    }
}

impl QuicConnection for H3ClientConnection {
    fn connected(&mut self, api: &mut dyn QuicConnApi) {
        if let Some(stream) = api.open_uni() {
            let mut bytes = vec![0x00];
            frame::write_settings(&mut bytes);
            api.write(stream, &bytes);
        }
        for ty in [0x02u8, 0x03] {
            if let Some(stream) = api.open_uni() {
                api.write(stream, &[ty]);
            }
        }
        // Request stream — [`H3ClientStream`] starts the app request in `connected`.
        let _ = api.open_bi();
    }

    fn accept_bi(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3ClientStream::new(Arc::clone(&self.factory), self.limits))
    }

    fn accept_uni(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3UniStream::new(Arc::clone(&self.peer_state)))
    }
}

/// Dial an HTTP/3 peer (ALPN `h3`).
pub fn connect_h3(
    addr: SocketAddr,
    client_config: Arc<QuicClientConfig>,
    server_name: impl Into<String>,
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
) -> io::Result<QuicDriverHandle> {
    let connection_factory = Arc::new(move || {
        Box::new(H3ClientConnection::new(Arc::clone(&factory), limits)) as Box<dyn QuicConnection>
    });
    connect_quic_hooks(addr, client_config, server_name, connection_factory)
}

/// Buffered outbound request during [`ClientHandler::start`].
struct H3ClientWriter {
    request_headers: Option<Headers>,
    body: Vec<u8>,
    done: bool,
}

impl H3ClientWriter {
    fn new() -> Self {
        Self {
            request_headers: None,
            body: Vec::new(),
            done: false,
        }
    }
}

impl ClientWriter for H3ClientWriter {
    fn headers(&mut self, mut headers: Headers) {
        if !headers.contains(":scheme") {
            headers.add_pseudo(":scheme", "https");
        }
        if !headers.contains(":authority") {
            if let Some(host) = headers.get("host").map(|s| s.to_string()) {
                headers.add_pseudo(":authority", host);
            }
        }
        self.request_headers = Some(headers);
    }

    fn start_request_body(&mut self) {}

    fn request_body_content(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    fn end_request_body(&mut self) {
        self.done = true;
    }

    fn complete_request(&mut self) {
        self.done = true;
    }
}

struct NullClientWriter;

impl ClientWriter for NullClientWriter {
    fn headers(&mut self, _: Headers) {}
    fn start_request_body(&mut self) {}
    fn request_body_content(&mut self, _: &[u8]) {}
    fn end_request_body(&mut self) {}
    fn complete_request(&mut self) {}
}

/// Validate a response header list's `:status` pseudo-header (RFC 9114
/// §4.3.2): present, first, and a well-formed 3-digit numeric value. No
/// other pseudo-header is legal in a response.
fn validate_response_status(pairs: &[(String, String)]) -> Result<(), ()> {
    let mut iter = pairs.iter();
    let Some((name, value)) = iter.next() else {
        return Err(());
    };
    if name != ":status" {
        return Err(());
    }
    if value.len() != 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    if iter.any(|(n, _)| n.starts_with(':')) {
        return Err(());
    }
    Ok(())
}

/// One outbound H3 request / inbound response on a bidirectional QUIC stream.
struct H3ClientStream {
    factory: Arc<dyn ClientHandlerFactory>,
    #[allow(dead_code)]
    limits: HttpLimits,
    parser: H3Parser,
    handler: Option<Box<dyn ClientHandler>>,
    response_headers_received: bool,
    response_body_started: bool,
    started: bool,
    /// Set when the response HEADERS failed `:status` validation — checked
    /// in `receive()`'s tail, where an `Endpoint` is available to abort
    /// the stream.
    malformed: bool,
}

impl H3ClientStream {
    fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            parser: H3Parser::new(),
            handler: None,
            response_headers_received: false,
            response_body_started: false,
            started: false,
            malformed: false,
        }
    }

    fn start_request(&mut self, endpoint: &mut dyn Endpoint) {
        if self.started {
            return;
        }
        self.started = true;

        let mut handler = self.factory.create_handler();
        let mut writer = H3ClientWriter::new();
        handler.start(&mut writer);

        let headers = writer.request_headers.take().unwrap_or_default();
        let body = writer.body;
        let done = writer.done;

        let mut out = Vec::new();
        let block = qpack::encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
        frame::write_headers(&mut out, &block);
        if !body.is_empty() {
            frame::write_data(&mut out, &body);
        }
        endpoint.send(&out);
        if done {
            endpoint.close();
        }

        self.handler = Some(handler);
    }

    fn finish_response(&mut self) {
        let mut w = NullClientWriter;
        if let Some(handler) = &mut self.handler {
            if self.response_body_started {
                handler.end_response_body(&mut w);
            }
            handler.response_complete(&mut w);
        }
    }
}

impl H3FrameHandler for H3ClientStream {
    fn data_frame(&mut self, payload: &[u8]) {
        let mut w = NullClientWriter;
        if let Some(handler) = &mut self.handler {
            if !payload.is_empty() {
                if !self.response_body_started {
                    self.response_body_started = true;
                    handler.start_response_body(&mut w);
                }
                handler.response_body_content(&mut w, payload);
            }
        }
    }

    fn headers_frame(&mut self, payload: &[u8]) {
        let Ok(pairs) = qpack::decode(payload) else {
            return;
        };
        if pairs.len() > self.limits.max_header_count {
            return;
        }

        let mut w = NullClientWriter;
        if !self.response_headers_received && validate_response_status(&pairs).is_err() {
            // RFC 9114 §4.3.2: malformed response → stream error. Tell the
            // app the request failed, then abort the stream in
            // `receive()`'s tail rather than silently hang it.
            if let Some(handler) = &mut self.handler {
                handler.request_failed(
                    &mut w,
                    &io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed H3 response: missing or invalid :status",
                    ),
                );
            }
            self.malformed = true;
            return;
        }

        let mut headers = Headers::new();
        for (name, value) in pairs {
            headers.add(name, value);
        }
        if let Some(handler) = &mut self.handler {
            if self.response_headers_received {
                if self.response_body_started {
                    handler.end_response_body(&mut w);
                    self.response_body_started = false;
                }
                handler.response_trailers(&mut w, &headers);
            } else {
                self.response_headers_received = true;
                handler.response_headers(&mut w, &headers);
            }
        }
    }

    fn settings_frame(&mut self, _: &[u8]) {}
    fn goaway_frame(&mut self, _: &[u8]) {}
    fn frame_error(&mut self, _: &str) {}
}

impl ProtocolHandler for H3ClientStream {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.start_request(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let mut parser = std::mem::take(&mut self.parser);
        parser.push(data, self);
        self.parser = parser;
        *data = &[];
        if self.malformed {
            // RFC 9114 §4.3.2: a malformed response is a stream error, not
            // a connection error — only this one request is affected.
            endpoint.abort(frame::H3_MESSAGE_ERROR);
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.finish_response();
    }

    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

#[cfg(test)]
mod status_validation_tests {
    use super::*;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingEndpoint {
        closed: bool,
        abort_code: Option<u32>,
    }
    impl Endpoint for RecordingEndpoint {
        fn send(&mut self, _data: &[u8]) {}
        fn is_open(&self) -> bool {
            !self.closed
        }
        fn is_closing(&self) -> bool {
            self.closed
        }
        fn close(&mut self) {
            self.closed = true;
        }
        fn abort(&mut self, error_code: u32) {
            self.closed = true;
            self.abort_code = Some(error_code);
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            unimplemented!("not exercised by these unit tests")
        }
        fn remote_addr(&self) -> std::io::Result<SocketAddr> {
            unimplemented!("not exercised by these unit tests")
        }
        fn security_info(&self) -> &hopf_core::SecurityInfo {
            unimplemented!("not exercised by these unit tests")
        }
        fn start_tls(&mut self) -> Result<(), hopf_core::StartTlsError> {
            unimplemented!("not exercised by these unit tests")
        }
        fn pause_read(&mut self) {}
        fn resume_read(&mut self) {}
        fn on_write_ready(&mut self, _callback: Option<hopf_core::WriteReadyCallback>) {}
        fn execute(&self, _task: Box<dyn FnOnce() + Send>) {
            unimplemented!("not exercised by these unit tests")
        }
        fn schedule_timer(
            &self,
            _delay: Duration,
            _callback: Box<dyn FnOnce() + Send>,
        ) -> hopf_core::TimerHandle {
            unimplemented!("not exercised by these unit tests")
        }
        fn handle(&self) -> hopf_core::ConnHandle {
            unimplemented!("not exercised by these unit tests")
        }
    }

    #[derive(Default)]
    struct Recorded {
        status: Option<u16>,
        failed: usize,
        trailers: Vec<(String, String)>,
    }

    struct RecordingHandler {
        rec: Arc<Mutex<Recorded>>,
    }
    impl ClientHandler for RecordingHandler {
        fn start(&mut self, _request: &mut dyn ClientWriter) {}
        fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().status = Some(headers.status_code());
        }
        fn response_trailers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            let mut r = self.rec.lock().unwrap();
            for h in headers.iter() {
                r.trailers.push((h.name.clone(), h.value.clone()));
            }
        }
        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {}
        fn request_failed(&mut self, _request: &mut dyn ClientWriter, _err: &io::Error) {
            self.rec.lock().unwrap().failed += 1;
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

    fn encode(pairs: &[(&str, &str)]) -> Vec<u8> {
        qpack::encode(pairs.iter().copied())
    }

    /// A stream with a handler already installed (via `start_request`, as
    /// `connected()` would do), ready to feed response HEADERS into.
    fn stream_with_recorder() -> (H3ClientStream, Arc<Mutex<Recorded>>) {
        let rec = Arc::new(Mutex::new(Recorded::default()));
        let factory: Arc<dyn ClientHandlerFactory> =
            Arc::new(RecordingFactory { rec: Arc::clone(&rec) });
        let mut stream = H3ClientStream::new(factory, HttpLimits::default());
        let mut ep = RecordingEndpoint::default();
        stream.start_request(&mut ep);
        (stream, rec)
    }

    #[test]
    fn valid_status_dispatches_response_headers() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[(":status", "200"), ("content-type", "text/plain")]);
        stream.headers_frame(&payload);

        assert!(!stream.malformed);
        assert_eq!(rec.lock().unwrap().status, Some(200));
        assert_eq!(rec.lock().unwrap().failed, 0);
    }

    #[test]
    fn missing_status_marks_malformed_and_fails_the_request() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[("content-type", "text/plain")]);
        stream.headers_frame(&payload);

        assert!(stream.malformed);
        assert_eq!(rec.lock().unwrap().status, None, "must never dispatch a malformed response");
        assert_eq!(rec.lock().unwrap().failed, 1);

        let mut ep = RecordingEndpoint::default();
        let mut empty: &[u8] = &[];
        stream.receive(&mut ep, &mut empty);
        assert!(ep.closed);
        assert_eq!(
            ep.abort_code,
            Some(frame::H3_MESSAGE_ERROR),
            "must be a stream error (RFC 9114 §4.3.2), not a connection-wide close"
        );
    }

    #[test]
    fn non_numeric_status_rejected() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[(":status", "abc")]);
        stream.headers_frame(&payload);
        assert!(stream.malformed);
        assert_eq!(rec.lock().unwrap().failed, 1);
    }

    #[test]
    fn extra_pseudo_header_in_response_rejected() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[(":status", "200"), (":path", "/")]);
        stream.headers_frame(&payload);
        assert!(stream.malformed);
        assert_eq!(rec.lock().unwrap().failed, 1);
    }

    #[test]
    fn trailers_are_not_run_through_status_validation() {
        let (mut stream, rec) = stream_with_recorder();
        let first = encode(&[(":status", "200")]);
        stream.headers_frame(&first);
        assert!(!stream.malformed);

        let trailers = encode(&[("grpc-status", "0")]);
        stream.headers_frame(&trailers);

        assert!(!stream.malformed, "trailers have no :status and must not be validated as one");
        assert_eq!(rec.lock().unwrap().trailers, vec![("grpc-status".to_string(), "0".to_string())]);
    }
}
