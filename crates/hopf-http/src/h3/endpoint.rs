// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 server connection and request-stream adapters.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler};
use hopf_quic::{
    listen_quic_hooks, QuicConnApi, QuicConnection, QuicDriverHandle, QuicListenHooksConfig,
    QuicServerConfig,
};

use crate::stream::{
    ProtocolUpgradeHandler, ServerHandler, ServerHandlerFactory, ServerResponseHandle, ServerWriter,
};
use crate::{Headers, HttpLimits};

use super::response::{ArcH3ResponseControl, H3ResponseControl, H3SessionWriter};
use super::{frame, qpack, H3FrameHandler, H3Parser};

/// HTTP/3 connection state installed in the QUIC hooks driver.
pub struct H3ServerConnection {
    factory: Arc<dyn ServerHandlerFactory>,
    limits: HttpLimits,
    peer_state: Arc<Mutex<H3PeerState>>,
    /// The control stream's `QuicConnApi` key, saved from `connected()` so
    /// `disconnecting()` can write a final GOAWAY on the same stream.
    control_stream_key: Option<u64>,
    /// Count of client-initiated bidirectional streams accepted so far.
    /// RFC 9000 §2.1: such stream IDs are sequential multiples of 4 (0, 4,
    /// 8, ...), so `(count - 1) * 4` is the exact ID of the most recently
    /// accepted request without needing the raw QUIC `StreamId` at this
    /// layer.
    accepted_bi_streams: Arc<AtomicU64>,
}

impl H3ServerConnection {
    /// Create an HTTP/3 server connection.
    pub fn new(factory: Arc<dyn ServerHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            peer_state: Arc::new(Mutex::new(H3PeerState::default())),
            control_stream_key: None,
            accepted_bi_streams: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl QuicConnection for H3ServerConnection {
    fn connected(&mut self, api: &mut dyn QuicConnApi) {
        if let Some(stream) = api.open_uni() {
            let mut bytes = vec![0x00]; // control stream type
            frame::write_settings(&mut bytes);
            api.write(stream, &bytes);
            self.control_stream_key = Some(stream);
        }
        // RFC 9204 requires both critical QPACK streams even with dynamic QPACK disabled.
        for ty in [0x02, 0x03] {
            if let Some(stream) = api.open_uni() {
                api.write(stream, &[ty]);
            }
        }
    }

    fn accept_bi(&mut self) -> Box<dyn ProtocolHandler> {
        self.accepted_bi_streams.fetch_add(1, Ordering::SeqCst);
        Box::new(H3RequestStream::new(Arc::clone(&self.factory), self.limits))
    }

    /// Send a final GOAWAY on the control stream, announcing the last
    /// client-initiated stream this connection will have processed (RFC
    /// 9114 §5.2), before the driver tears everything down. Not a true
    /// graceful drain — in-flight streams are still abandoned — but tells
    /// the peer not to expect responses to anything opened after this.
    fn disconnecting(&mut self, api: &mut dyn QuicConnApi) {
        let Some(key) = self.control_stream_key else {
            return;
        };
        let count = self.accepted_bi_streams.load(Ordering::SeqCst);
        if count == 0 {
            return; // nothing accepted yet; no meaningful last-stream-id to announce
        }
        let last_stream_id = (count - 1) * 4;
        let mut bytes = Vec::new();
        frame::write_goaway(&mut bytes, last_stream_id);
        api.write(key, &bytes);
    }

    fn accept_uni(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3UniStream::new(Arc::clone(&self.peer_state)))
    }
}

/// Listen for HTTP/3 connections using QUIC hooks.
pub fn listen_h3(
    addr: SocketAddr,
    server_config: Arc<QuicServerConfig>,
    factory: Arc<dyn ServerHandlerFactory>,
    limits: HttpLimits,
) -> io::Result<QuicDriverHandle> {
    let connection_factory = Arc::new(move || {
        Box::new(H3ServerConnection::new(Arc::clone(&factory), limits)) as Box<dyn QuicConnection>
    });
    listen_quic_hooks(QuicListenHooksConfig::new(
        addr,
        server_config,
        connection_factory,
    ))
}

/// Per-request buffered response.
struct H3Writer {
    control: Arc<H3ResponseControl>,
}

impl H3Writer {
    fn new() -> Self {
        Self {
            control: H3ResponseControl::new(),
        }
    }

    fn session_writer(&mut self) -> H3SessionWriter {
        self.control.writer()
    }

    fn flush(&mut self, endpoint: &mut dyn Endpoint) {
        let upgraded = self.control.shared.lock().unwrap().upgraded;
        let headers = {
            let mut shared = self.control.shared.lock().unwrap();
            shared.needs_flush = false;
            shared.headers.take()
        };
        let body = {
            let mut shared = self.control.shared.lock().unwrap();
            std::mem::take(&mut shared.body)
        };
        let trailers = {
            let mut shared = self.control.shared.lock().unwrap();
            if shared.complete && !upgraded {
                shared.trailers.take()
            } else {
                None
            }
        };
        let complete = {
            let shared = self.control.shared.lock().unwrap();
            shared.complete && !upgraded
        };
        let headers_sent = self.control.shared.lock().unwrap().headers_sent;

        let mut out = Vec::new();
        if let Some(mut headers) = headers {
            if !headers.contains(":status") {
                headers.status(200);
            }
            if !headers.contains("date") {
                headers.set("Date", crate::utils::http_date_now());
            }
            let block = qpack::encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
            frame::write_headers(&mut out, &block);
            self.control.shared.lock().unwrap().headers_sent = true;
        } else if !headers_sent && body.is_empty() && trailers.is_none() {
            return;
        }
        if !body.is_empty() {
            frame::write_data(&mut out, &body);
        }
        if let Some(trailers) = trailers {
            let block =
                qpack::encode(trailers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
            frame::write_headers(&mut out, &block);
        }
        if !out.is_empty() {
            endpoint.send(&out);
        }
        if complete {
            endpoint.close();
        }
    }

    fn flush_if_ready(&mut self, endpoint: &mut dyn Endpoint) {
        let ready = {
            let shared = self.control.shared.lock().unwrap();
            shared.headers.is_some()
                || shared.trailers.is_some()
                || shared.needs_flush
                || (shared.headers_sent && !shared.body.is_empty())
        };
        if ready {
            self.flush(endpoint);
        }
    }
}

impl ServerWriter for H3Writer {
    fn headers(&mut self, headers: Headers) {
        self.session_writer().headers(headers);
    }
    fn start_response_body(&mut self) {}
    fn response_body_content(&mut self, data: &[u8]) {
        self.session_writer().response_body_content(data);
    }
    fn end_response_body(&mut self) {
        self.session_writer().end_response_body();
    }
    fn trailers(&mut self, headers: Headers) {
        self.session_writer().trailers(headers);
    }
    fn complete(&mut self) {
        self.session_writer().complete();
    }

    fn upgrade(
        &mut self,
        headers: Headers,
        handler: Box<dyn ProtocolUpgradeHandler>,
    ) -> bool {
        self.session_writer().upgrade(headers, handler)
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        self.control.conn_handle()
    }

    fn response_handle(&self) -> crate::stream::ServerResponseHandle {
        ServerResponseHandle::new(ArcH3ResponseControl::new(Arc::clone(&self.control)))
    }

    fn pause_request_body(&mut self) {
        self.session_writer().pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.session_writer().resume_request_body();
    }
}

/// A peer-initiated HTTP/3 request stream.
struct H3RequestStream {
    factory: Arc<dyn ServerHandlerFactory>,
    #[allow(dead_code)]
    limits: HttpLimits,
    parser: H3Parser,
    handler: Option<Box<dyn ServerHandler>>,
    writer: H3Writer,
    body_started: bool,
    paused_body: Vec<u8>,
    needs_protocol_flush: Arc<Mutex<bool>>,
    upgraded: Option<Box<dyn ProtocolUpgradeHandler>>,
    /// Set when the request HEADERS failed pseudo-header validation (RFC
    /// 9114 §4.3.1) — checked in `receive()`'s tail, where an `Endpoint` is
    /// available to abort the stream.
    malformed: bool,
}

impl H3RequestStream {
    fn new(factory: Arc<dyn ServerHandlerFactory>, limits: HttpLimits) -> Self {
        let needs_protocol_flush = Arc::new(Mutex::new(false));
        let stream = Self {
            factory,
            limits,
            parser: H3Parser::new(),
            handler: None,
            writer: H3Writer::new(),
            body_started: false,
            paused_body: Vec::new(),
            needs_protocol_flush: Arc::clone(&needs_protocol_flush),
            upgraded: None,
            malformed: false,
        };
        let flag = Arc::clone(&needs_protocol_flush);
        stream.writer.control.set_flush(Some(Arc::new(move || {
            *flag.lock().unwrap() = true;
        })));
        stream
    }

    fn bind_execute_conn(&mut self) {
        let flag = Arc::clone(&self.needs_protocol_flush);
        self.writer.control.bind_conn(ConnHandle::from_execute(Arc::new(
            move |task| {
                task();
                *flag.lock().unwrap() = true;
            },
        )));
    }

    fn maybe_flush_after_deferred(&mut self, endpoint: &mut dyn Endpoint) {
        self.deliver_paused_body();
        if let Some(up) = self.upgraded.as_mut() {
            let out = up.take_outbound();
            if !out.is_empty() {
                self.writer
                    .control
                    .shared
                    .lock()
                    .unwrap()
                    .body
                    .extend_from_slice(&out);
            }
        }
        self.writer.flush_if_ready(endpoint);
    }

    fn deliver_request_body(&mut self, payload: &[u8]) {
        if let Some(up) = self.upgraded.as_mut() {
            if !payload.is_empty() {
                up.receive(payload);
            }
            let out = up.take_outbound();
            if !out.is_empty() {
                self.writer
                    .control
                    .shared
                    .lock()
                    .unwrap()
                    .body
                    .extend_from_slice(&out);
            }
            return;
        }
        if self.writer.control.body_paused() {
            if !payload.is_empty() {
                self.paused_body.extend_from_slice(payload);
            }
            return;
        }
        if let Some(handler) = &mut self.handler {
            if !self.body_started {
                handler.start_request_body(&mut self.writer);
                self.body_started = true;
            }
            handler.request_body_content(&mut self.writer, payload);
        }
    }

    fn deliver_paused_body(&mut self) {
        if self.writer.control.body_paused() {
            return;
        }
        let body = std::mem::take(&mut self.paused_body);
        if !body.is_empty() {
            self.deliver_request_body(&body);
        }
    }

    fn finish_request(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(up) = self.upgraded.as_mut() {
            up.closed();
            let out = up.take_outbound();
            if !out.is_empty() {
                self.writer
                    .control
                    .shared
                    .lock()
                    .unwrap()
                    .body
                    .extend_from_slice(&out);
            }
            self.writer.flush(endpoint);
            return;
        }
        if let Some(handler) = &mut self.handler {
            if self.body_started {
                handler.end_request_body(&mut self.writer);
            }
            handler.request_complete(&mut self.writer);
            if let Some(up) = self.writer.control.take_upgrade() {
                self.upgraded = Some(up);
            }
        }
        self.writer.flush(endpoint);
    }
}

impl H3FrameHandler for H3RequestStream {
    fn data_frame(&mut self, payload: &[u8]) {
        self.deliver_request_body(payload);
    }

    fn headers_frame(&mut self, payload: &[u8]) {
        let Ok(pairs) = qpack::decode(payload) else {
            return;
        };
        if pairs.len() > self.limits.max_header_count {
            return;
        }

        if let Some(handler) = &mut self.handler {
            // Second HEADERS after the request handler exists = request
            // trailers (RFC 9114 §4.1).
            let mut trailers = Headers::new();
            for (name, value) in pairs {
                trailers.add(name, value);
            }
            handler.request_trailers(&mut self.writer, &trailers);
            return;
        }

        if crate::pseudo_headers::validate_request_pseudo_headers(&pairs).is_err() {
            // RFC 9114 §4.3.1: malformed request → stream error
            // (H3_MESSAGE_ERROR). `malformed` is checked in `receive()`'s
            // tail, where an `Endpoint` is available to abort the stream.
            self.malformed = true;
            return;
        }

        let mut headers = Headers::new();
        for (name, value) in pairs {
            headers.add(name, value);
        }
        let mut handler = self.factory.create_handler();
        handler.headers(&mut self.writer, &headers);
        if let Some(up) = self.writer.control.take_upgrade() {
            self.upgraded = Some(up);
        }
        self.handler = Some(handler);
    }

    fn settings_frame(&mut self, _: &[u8]) {}
    fn goaway_frame(&mut self, _: &[u8]) {}
    fn frame_error(&mut self, _: &str) {}
}

impl ProtocolHandler for H3RequestStream {
    fn connected(&mut self, _: &mut dyn Endpoint) {
        self.bind_execute_conn();
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.bind_execute_conn();
        let mut parser = std::mem::take(&mut self.parser);
        parser.push(data, self);
        self.parser = parser;
        *data = &[];
        if self.malformed {
            // RFC 9114 §4.3.1: a malformed request is a stream error, not
            // a connection error — only this one request is affected.
            endpoint.abort(frame::H3_MESSAGE_ERROR);
            return;
        }
        self.maybe_flush_after_deferred(endpoint);
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        self.bind_execute_conn();
        self.finish_request(endpoint);
    }

    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

/// RFC 9114 §6.2 / RFC 9204 §4.2 unidirectional stream type identifiers.
const STREAM_TYPE_CONTROL: u64 = 0x00;
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x02;
const STREAM_TYPE_QPACK_DECODER: u64 = 0x03;

/// Per-connection unidirectional-stream bookkeeping, shared across every
/// [`H3UniStream`] accepted on the same connection.
///
/// Lets each new uni stream detect a duplicate control or QPACK critical
/// stream (RFC 9114 §6.2.1, RFC 9204 §4.2), and records the peer's parsed
/// SETTINGS (RFC 9114 §7.2.4) once their control stream sends one.
#[derive(Default)]
pub(crate) struct H3PeerState {
    control_seen: bool,
    qpack_encoder_seen: bool,
    qpack_decoder_seen: bool,
    /// `true` once the peer's SETTINGS frame advertised
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` (RFC 9220).
    #[allow(dead_code)] // not yet consulted anywhere — see conformance.html
    pub(crate) peer_enable_connect_protocol: bool,
    /// Set once the peer's GOAWAY frame arrives (RFC 9114 §5.2): the ID it
    /// carried (the peer's last client-initiated bidirectional stream, if
    /// sent by a server; a push ID, if sent by a client — moot here since
    /// hopf never pushes).
    pub(crate) goaway_received: Option<u64>,
}

/// What an [`H3UniStream`] does with bytes once its type byte is known.
enum UniKind {
    /// Type byte not read yet.
    Unclassified,
    /// The (first, valid) control stream — bytes route through the H3
    /// frame parser so SETTINGS/GOAWAY get processed.
    Control(H3Parser),
    /// Anything else: a QPACK critical stream (dynamic table is disabled,
    /// so there's nothing to decode from it), a duplicate critical stream,
    /// or an unknown/reserved type (RFC 9114 §9 requires tolerating these).
    Discard,
}

/// Reads the RFC 9114 §6.2 type-byte prefix of a peer unidirectional
/// stream, then either parses it (control stream) or discards it.
pub(crate) struct H3UniStream {
    peer_state: Arc<Mutex<H3PeerState>>,
    kind: UniKind,
    /// Buffered bytes while the type-byte varint is still incomplete —
    /// values above the standard single-byte types (e.g. GREASE, RFC 9114
    /// §7.2.8) legitimately span multiple bytes.
    pending_type: Vec<u8>,
    /// Set when a connection-level protocol violation is detected (RFC
    /// 9114 §8.1) — checked in `receive()`'s tail, where an `Endpoint` is
    /// available to actually close the connection.
    connection_error: Option<u32>,
}

impl H3UniStream {
    pub(crate) fn new(peer_state: Arc<Mutex<H3PeerState>>) -> Self {
        Self {
            peer_state,
            kind: UniKind::Unclassified,
            pending_type: Vec::new(),
            connection_error: None,
        }
    }

    /// Classify by type byte, updating shared connection state. Returns
    /// `true` if this is a duplicate critical stream that RFC 9114 wants
    /// treated as a connection error (`H3_STREAM_CREATION_ERROR`).
    fn classify(&mut self, ty: u64) -> bool {
        let mut state = self.peer_state.lock().unwrap();
        match ty {
            STREAM_TYPE_CONTROL if !state.control_seen => {
                state.control_seen = true;
                drop(state);
                self.kind = UniKind::Control(H3Parser::new());
                false
            }
            STREAM_TYPE_QPACK_ENCODER if !state.qpack_encoder_seen => {
                state.qpack_encoder_seen = true;
                self.kind = UniKind::Discard;
                false
            }
            STREAM_TYPE_QPACK_DECODER if !state.qpack_decoder_seen => {
                state.qpack_decoder_seen = true;
                self.kind = UniKind::Discard;
                false
            }
            STREAM_TYPE_CONTROL | STREAM_TYPE_QPACK_ENCODER | STREAM_TYPE_QPACK_DECODER => {
                self.kind = UniKind::Discard;
                true
            }
            _ => {
                // Unknown/reserved type (includes GREASE) — tolerate per RFC 9114 §9.
                self.kind = UniKind::Discard;
                false
            }
        }
    }
}

impl H3FrameHandler for H3UniStream {
    fn data_frame(&mut self, _payload: &[u8]) {
        // RFC 9114 §7.2/§4.1: DATA never appears on the control stream.
        self.connection_error.get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn headers_frame(&mut self, _payload: &[u8]) {
        // Same — HEADERS is a request/response-stream-only frame type.
        self.connection_error.get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn settings_frame(&mut self, payload: &[u8]) {
        let mut enable_connect_protocol = None;
        for (id, val) in frame::parse_settings(payload) {
            if id == frame::SETTINGS_ENABLE_CONNECT_PROTOCOL {
                enable_connect_protocol = Some(val != 0);
            }
        }
        if let Some(v) = enable_connect_protocol {
            self.peer_state.lock().unwrap().peer_enable_connect_protocol = v;
        }
    }
    fn goaway_frame(&mut self, payload: &[u8]) {
        if let Some(id) = frame::parse_goaway(payload) {
            self.peer_state.lock().unwrap().goaway_received = Some(id);
        }
    }
    fn frame_error(&mut self, _message: &str) {
        self.connection_error.get_or_insert(frame::H3_FRAME_ERROR);
    }
}

impl ProtocolHandler for H3UniStream {
    fn connected(&mut self, _: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if matches!(self.kind, UniKind::Unclassified) {
            self.pending_type.extend_from_slice(data);
            *data = &[];
            let Some((ty, ty_len)) = super::varint::decode(&self.pending_type) else {
                return; // need more bytes
            };
            let remainder = self.pending_type.split_off(ty_len);
            self.pending_type.clear();

            if self.classify(ty) {
                // RFC 9114 §6.2.1 / RFC 9204 §4.2: a duplicate control or
                // QPACK critical stream is a connection error.
                endpoint.close_connection(frame::H3_STREAM_CREATION_ERROR);
                return;
            }

            if !remainder.is_empty() {
                let mut rem: &[u8] = &remainder;
                self.receive(endpoint, &mut rem);
            }
            return;
        }

        if let UniKind::Control(_) = &self.kind {
            // Detach the parser first — it needs `&mut self` as its
            // `H3FrameHandler` sink, which would otherwise overlap with
            // the `&mut self.kind` borrow holding it.
            let UniKind::Control(mut parser) = std::mem::replace(&mut self.kind, UniKind::Discard)
            else {
                unreachable!()
            };
            parser.push(data, self);
            self.kind = UniKind::Control(parser);
        }
        *data = &[];

        if let Some(code) = self.connection_error.take() {
            endpoint.close_connection(code);
        }
    }

    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

#[cfg(test)]
mod uni_stream_tests {
    use super::*;
    use std::time::Duration;

    /// Minimal [`Endpoint`] stub recording `close()`/`abort()`/
    /// `close_connection()` calls and their error codes.
    #[derive(Default)]
    struct RecordingEndpoint {
        closed: bool,
        abort_code: Option<u32>,
        close_connection_code: Option<u32>,
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
        fn close_connection(&mut self, error_code: u32) {
            self.closed = true;
            self.close_connection_code = Some(error_code);
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

    fn shared_state() -> Arc<Mutex<H3PeerState>> {
        Arc::new(Mutex::new(H3PeerState::default()))
    }

    #[test]
    fn control_stream_settings_are_parsed_and_stored() {
        let state = shared_state();
        let mut uni = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();

        let mut bytes = vec![0x00]; // control stream type
        frame::write_settings(&mut bytes); // ENABLE_CONNECT_PROTOCOL=1
        let mut data: &[u8] = &bytes;
        uni.receive(&mut ep, &mut data);

        assert!(data.is_empty());
        assert!(!ep.closed);
        let s = state.lock().unwrap();
        assert!(s.control_seen);
        assert!(s.peer_enable_connect_protocol);
    }

    /// The type byte and the SETTINGS frame bytes arriving in separate
    /// `receive()` calls must still parse correctly.
    #[test]
    fn control_stream_type_and_settings_split_across_receives() {
        let state = shared_state();
        let mut uni = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();

        let mut settings_bytes = Vec::new();
        frame::write_settings(&mut settings_bytes);

        let mut type_byte: &[u8] = &[0x00];
        uni.receive(&mut ep, &mut type_byte);
        assert!(state.lock().unwrap().control_seen, "type byte alone must classify the stream");

        for byte in &settings_bytes {
            let mut one: &[u8] = std::slice::from_ref(byte);
            uni.receive(&mut ep, &mut one);
        }

        assert!(state.lock().unwrap().peer_enable_connect_protocol);
    }

    #[test]
    fn qpack_encoder_and_decoder_streams_are_recognized_and_discarded() {
        let state = shared_state();

        let mut encoder = H3UniStream::new(Arc::clone(&state));
        let mut ep1 = RecordingEndpoint::default();
        let mut d1: &[u8] = &[0x02];
        encoder.receive(&mut ep1, &mut d1);
        assert!(!ep1.closed);
        assert!(state.lock().unwrap().qpack_encoder_seen);

        let mut decoder = H3UniStream::new(Arc::clone(&state));
        let mut ep2 = RecordingEndpoint::default();
        let mut d2: &[u8] = &[0x03];
        decoder.receive(&mut ep2, &mut d2);
        assert!(!ep2.closed);
        assert!(state.lock().unwrap().qpack_decoder_seen);
    }

    /// A second control stream from the same peer is a protocol violation
    /// (RFC 9114 §6.2.1) — today's best available response is to stop
    /// reading it (real connection-level rejection needs QUIC-transport
    /// work tracked separately).
    #[test]
    fn duplicate_control_stream_closes() {
        let state = shared_state();
        {
            let mut first = H3UniStream::new(Arc::clone(&state));
            let mut ep = RecordingEndpoint::default();
            let mut d: &[u8] = &[0x00];
            first.receive(&mut ep, &mut d);
            assert!(!ep.closed);
        }

        let mut second = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();
        let mut d: &[u8] = &[0x00];
        second.receive(&mut ep, &mut d);
        assert!(ep.closed, "a duplicate control stream must be rejected");
        assert_eq!(
            ep.close_connection_code,
            Some(frame::H3_STREAM_CREATION_ERROR),
            "must be a connection error (RFC 9114 §6.2.1), not just a stream close"
        );
    }

    #[test]
    fn duplicate_qpack_encoder_stream_closes() {
        let state = shared_state();
        {
            let mut first = H3UniStream::new(Arc::clone(&state));
            let mut ep = RecordingEndpoint::default();
            let mut d: &[u8] = &[0x02];
            first.receive(&mut ep, &mut d);
        }

        let mut second = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();
        let mut d: &[u8] = &[0x02];
        second.receive(&mut ep, &mut d);
        assert!(ep.closed);
        assert_eq!(ep.close_connection_code, Some(frame::H3_STREAM_CREATION_ERROR));
    }

    /// Unknown/reserved/GREASE stream types (RFC 9114 §9, §7.2.8) must be
    /// tolerated, not treated as an error, even when the type varint spans
    /// multiple bytes.
    #[test]
    fn unknown_multi_byte_stream_type_is_tolerated() {
        let state = shared_state();
        let mut uni = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();

        // A 2-byte QUIC varint encoding of a large "reserved" type value.
        let mut bytes = Vec::new();
        super::super::varint::encode(&mut bytes, 1000);
        bytes.extend_from_slice(b"whatever-payload-comes-next");
        let mut data: &[u8] = &bytes;
        uni.receive(&mut ep, &mut data);

        assert!(data.is_empty());
        assert!(!ep.closed);
        let s = state.lock().unwrap();
        assert!(!s.control_seen);
        assert!(!s.qpack_encoder_seen);
        assert!(!s.qpack_decoder_seen);
    }

    /// A DATA frame on the control stream is a connection error (RFC 9114
    /// §7.2/§4.1: only SETTINGS/GOAWAY/etc. belong there).
    #[test]
    fn data_frame_on_control_stream_is_a_connection_error() {
        let state = shared_state();
        let mut uni = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();

        let mut type_byte: &[u8] = &[0x00];
        uni.receive(&mut ep, &mut type_byte);
        assert!(!ep.closed);

        let mut bad_frame = Vec::new();
        frame::write_data(&mut bad_frame, b"not allowed here");
        let mut data: &[u8] = &bad_frame;
        uni.receive(&mut ep, &mut data);

        assert!(ep.closed);
        assert_eq!(ep.close_connection_code, Some(frame::H3_FRAME_UNEXPECTED));
    }

    /// GOAWAY on the control stream is parsed and stored in the shared
    /// [`H3PeerState`] (RFC 9114 §5.2).
    #[test]
    fn goaway_on_control_stream_is_recorded() {
        let state = shared_state();
        let mut uni = H3UniStream::new(Arc::clone(&state));
        let mut ep = RecordingEndpoint::default();

        let mut type_byte: &[u8] = &[0x00];
        uni.receive(&mut ep, &mut type_byte);

        let mut goaway_frame = Vec::new();
        frame::write_goaway(&mut goaway_frame, 8);
        let mut data: &[u8] = &goaway_frame;
        uni.receive(&mut ep, &mut data);

        assert!(!ep.closed, "GOAWAY reception alone doesn't close anything");
        assert_eq!(state.lock().unwrap().goaway_received, Some(8));
    }
}

#[cfg(test)]
mod request_validation_tests {
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
        opened: usize,
        trailers: Vec<(String, String)>,
        completed: usize,
    }

    struct RecordingHandler {
        rec: Arc<Mutex<Recorded>>,
    }
    impl ServerHandler for RecordingHandler {
        fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {
            self.rec.lock().unwrap().opened += 1;
        }
        fn request_trailers(&mut self, _response: &mut dyn ServerWriter, headers: &Headers) {
            let mut r = self.rec.lock().unwrap();
            for h in headers.iter() {
                r.trailers.push((h.name.clone(), h.value.clone()));
            }
        }
        fn request_complete(&mut self, _response: &mut dyn ServerWriter) {
            self.rec.lock().unwrap().completed += 1;
        }
    }

    struct RecordingFactory {
        rec: Arc<Mutex<Recorded>>,
    }
    impl ServerHandlerFactory for RecordingFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            Box::new(RecordingHandler { rec: Arc::clone(&self.rec) })
        }
    }

    fn encode(pairs: &[(&str, &str)]) -> Vec<u8> {
        qpack::encode(pairs.iter().copied())
    }

    fn stream_with_recorder() -> (H3RequestStream, Arc<Mutex<Recorded>>) {
        let rec = Arc::new(Mutex::new(Recorded::default()));
        let factory: Arc<dyn ServerHandlerFactory> =
            Arc::new(RecordingFactory { rec: Arc::clone(&rec) });
        (H3RequestStream::new(factory, HttpLimits::default()), rec)
    }

    #[test]
    fn valid_request_headers_open_the_handler() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "x")]);
        stream.headers_frame(&payload);

        assert!(stream.handler.is_some());
        assert!(!stream.malformed);
        assert_eq!(rec.lock().unwrap().opened, 1);
    }

    #[test]
    fn malformed_request_headers_close_the_stream() {
        let (mut stream, rec) = stream_with_recorder();
        // Missing :path.
        let payload = encode(&[(":method", "GET"), (":scheme", "https")]);
        stream.headers_frame(&payload);

        assert!(stream.malformed);
        assert!(stream.handler.is_none(), "the app must never see a malformed request");
        assert_eq!(rec.lock().unwrap().opened, 0);

        let mut ep = RecordingEndpoint::default();
        let mut empty: &[u8] = &[];
        stream.receive(&mut ep, &mut empty);
        assert!(ep.closed, "receive() must close the stream once malformed is set");
        assert_eq!(
            ep.abort_code,
            Some(frame::H3_MESSAGE_ERROR),
            "must be a stream error (RFC 9114 §4.3.1), not a connection-wide close"
        );
    }

    #[test]
    fn second_headers_frame_delivered_as_request_trailers() {
        let (mut stream, rec) = stream_with_recorder();
        let first = encode(&[(":method", "POST"), (":scheme", "https"), (":path", "/"), (":authority", "x")]);
        stream.headers_frame(&first);
        assert_eq!(rec.lock().unwrap().opened, 1);

        let trailers = encode(&[("grpc-status", "0"), ("grpc-message", "ok")]);
        stream.headers_frame(&trailers);

        let r = rec.lock().unwrap();
        assert_eq!(
            r.trailers,
            vec![("grpc-status".to_string(), "0".to_string()), ("grpc-message".to_string(), "ok".to_string())]
        );
        assert!(!stream.malformed, "trailers must not be run through request pseudo-header validation");
    }
}

#[cfg(test)]
mod connection_lifecycle_tests {
    use super::*;

    /// Records every `open_uni`/`open_bi`/`write`/`finish` call, mirroring
    /// what a real `QuicConnApi` implementation would apply — enough to
    /// verify what [`H3ServerConnection`] writes without a real driver.
    #[derive(Default)]
    struct RecordingConnApi {
        next_key: u64,
        writes: Vec<(u64, Vec<u8>)>,
    }
    impl QuicConnApi for RecordingConnApi {
        fn open_uni(&mut self) -> Option<u64> {
            let key = self.next_key;
            self.next_key += 1;
            Some(key)
        }
        fn open_bi(&mut self) -> Option<u64> {
            let key = self.next_key;
            self.next_key += 1;
            Some(key)
        }
        fn write(&mut self, stream_key: u64, data: &[u8]) {
            self.writes.push((stream_key, data.to_vec()));
        }
        fn finish(&mut self, _stream_key: u64) {}
    }

    struct NoopServerFactory;
    impl ServerHandlerFactory for NoopServerFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }

    fn control_stream_writes(api: &RecordingConnApi) -> Vec<&[u8]> {
        // `connected()` always opens the control stream first (key 0).
        api.writes.iter().filter(|(k, _)| *k == 0).map(|(_, d)| d.as_slice()).collect()
    }

    /// `disconnecting()` announces the true last-accepted client stream ID
    /// (RFC 9000 §2.1: client-initiated bidi IDs are 0, 4, 8, ...) rather
    /// than a placeholder.
    #[test]
    fn disconnecting_sends_goaway_with_last_accepted_stream_id() {
        let mut conn = H3ServerConnection::new(Arc::new(NoopServerFactory), HttpLimits::default());
        let mut api = RecordingConnApi::default();
        conn.connected(&mut api); // control stream (key 0) + 2 QPACK streams

        let _ = conn.accept_bi(); // 1st request -> stream id 0
        let _ = conn.accept_bi(); // 2nd request -> stream id 4
        let _ = conn.accept_bi(); // 3rd request -> stream id 8

        conn.disconnecting(&mut api);

        let control_writes = control_stream_writes(&api);
        let goaway_bytes = control_writes.last().expect("a GOAWAY must have been written");
        let (ty, ty_len) = super::super::varint::decode(goaway_bytes).unwrap();
        assert_eq!(ty, frame::GOAWAY);
        let (len, len_len) = super::super::varint::decode(&goaway_bytes[ty_len..]).unwrap();
        let payload = &goaway_bytes[ty_len + len_len..ty_len + len_len + len as usize];
        assert_eq!(frame::parse_goaway(payload), Some(8));
    }

    /// With no requests ever accepted, there's nothing meaningful to
    /// announce, so no GOAWAY is sent at all.
    #[test]
    fn disconnecting_with_no_accepted_streams_sends_nothing() {
        let mut conn = H3ServerConnection::new(Arc::new(NoopServerFactory), HttpLimits::default());
        let mut api = RecordingConnApi::default();
        conn.connected(&mut api);
        let writes_before = api.writes.len();

        conn.disconnecting(&mut api);

        assert_eq!(api.writes.len(), writes_before, "no new write should occur");
    }
}

#[cfg(all(test, feature = "integration"))]
mod smoke {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use hopf_quic::{
        client_config_for_pem_bytes, server_config_self_signed, ALPN_H3,
    };

    use crate::h3::connect_h3;
    use crate::{
        ClientHandler, ClientHandlerFactory, ClientWriter, Headers, HttpLimits, ServerHandler,
        ServerHandlerFactory, ServerWriter,
    };

    struct Hello;
    impl ServerHandler for Hello {
        fn headers(&mut self, response: &mut dyn ServerWriter, _: &Headers) {
            let body = b"Hello, world\n";
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

    #[derive(Default)]
    struct Outcome {
        status: u16,
        body: Vec<u8>,
        done: bool,
        date: Option<String>,
    }

    struct GetOnce {
        out: Arc<Mutex<Outcome>>,
    }

    impl ClientHandler for GetOnce {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "GET");
            h.set(":path", "/");
            h.set("host", "localhost");
            request.headers(h);
            request.complete_request();
        }
        fn response_headers(&mut self, _: &mut dyn ClientWriter, headers: &Headers) {
            let mut out = self.out.lock().unwrap();
            out.status = headers.status_code();
            out.date = headers.get("date").map(str::to_string);
        }
        fn response_body_content(&mut self, _: &mut dyn ClientWriter, data: &[u8]) {
            self.out.lock().unwrap().body.extend_from_slice(data);
        }
        fn response_complete(&mut self, _: &mut dyn ClientWriter) {
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

    #[test]
    fn h3_get_hello_over_quic() {
        let (server_cfg, pem) = server_config_self_signed(&["localhost"], &[ALPN_H3]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[ALPN_H3]).unwrap();

        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits2 = Arc::clone(&hits);
        struct CountingFactory(Arc<std::sync::atomic::AtomicUsize>);
        impl ServerHandlerFactory for CountingFactory {
            fn create_handler(&self) -> Box<dyn ServerHandler> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::new(Hello)
            }
        }
        let server = listen_h3(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(CountingFactory(hits2)),
            HttpLimits::default(),
        )
        .unwrap();

        let out = Arc::new(Mutex::new(Outcome::default()));
        let _client = connect_h3(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(GetFactory {
                out: Arc::clone(&out),
            }),
            HttpLimits::default(),
        )
        .unwrap();

        for _ in 0..200 {
            if out.lock().unwrap().done {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "server never saw a request"
        );
        let g = out.lock().unwrap();
        assert!(g.done, "client never completed");
        assert_eq!(g.status, 200);
        assert_eq!(g.body.as_slice(), b"Hello, world\n");
        assert!(
            g.date.as_deref().is_some_and(|d| d.ends_with(" GMT")),
            "response missing Date header: {:?}",
            g.date
        );
        server.shutdown();
    }
}
