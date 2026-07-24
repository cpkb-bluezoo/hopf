// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 endpoint [`ProtocolHandler`] implementation — server and client roles.
//!
//! # Server construction
//!
//! | Scenario | Constructor |
//! |---|---|
//! | TLS ALPN `h2` | [`H2Endpoint::server`] |
//! | Cleartext prior-knowledge (preface sniffed externally) | [`H2Endpoint::server`] with `send_settings_on_connected = true` |
//! | Cleartext h2c Upgrade (101 sent, preface consumed) | [`H2Endpoint::server_after_h2c_upgrade`] |
//!
//! # Client construction
//!
//! | Scenario | Constructor |
//! |---|---|
//! | Cleartext prior-knowledge | [`H2Endpoint::client`] with `secure = false` |
//! | TLS | [`H2Endpoint::client`] with `secure = true` |
//!
//! # Not yet implemented
//!
//! - PUSH_PROMISE / server push — see TODO comments.
//! - PRIORITY frames are deprecated in RFC 9113 and ignored.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo};

use super::hpack::{Decoder, Encoder};
use super::response::{ArcH2ResponseControl, H2ResponseControl, H2SessionWriter};
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{
    ClientHandler, ClientHandlerFactory, ClientWriter, ProtocolUpgradeHandler, ServerHandler,
    ServerHandlerFactory, ServerResponseHandle, ServerWriter,
};

use super::flow::FlowControl;
use super::frame::{
    self, ERROR_COMPRESSION_ERROR, ERROR_FLOW_CONTROL_ERROR, ERROR_FRAME_SIZE_ERROR,
    ERROR_PROTOCOL_ERROR, ERROR_REFUSED_STREAM, FLAG_END_HEADERS, FLAG_END_STREAM,
    SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_ENABLE_PUSH, SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
};
use super::parser::{H2FrameHandler, H2Parser};

/// 24-byte HTTP/2 client connection preface (RFC 9113 §3.4).
pub(crate) const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default maximum frame size (bytes).
const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

/// Default maximum header list size (bytes, advisory).
const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 8_192;

/// Default maximum concurrent streams we advertise to the client.
const MAX_CONCURRENT_STREAMS: u32 = 100;

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnState {
    /// Waiting for the 24-byte client connection preface.
    ExpectPreface,
    /// Preface consumed; waiting for the first (non-ACK) SETTINGS from peer.
    ExpectSettings,
    /// Normal operation.
    Open,
    /// GOAWAY sent; draining existing streams.
    GoAway,
}

// ---------------------------------------------------------------------------
// Role-specific state
// ---------------------------------------------------------------------------

enum H2Role {
    Server {
        factory: Arc<dyn ServerHandlerFactory>,
        /// Upgrade-request headers to deliver on stream 1 once SETTINGS exchange completes.
        pending_upgrade: Option<Headers>,
        /// If true, `connected()` calls `send_server_settings` (cleartext prior-knowledge).
        send_settings_on_connected: bool,
    },
    Client {
        factory: Arc<dyn ClientHandlerFactory>,
        /// If true this is a TLS connection; affects default `:scheme` and kickoff timing.
        secure: bool,
        /// Next odd stream ID to allocate.
        next_stream_id: u32,
    },
}

/// Stream IDs queued by deferred [`ResponseControl::execute`] flush callbacks.
struct H2DeferredFlush {
    streams: Mutex<Vec<u32>>,
}

// ---------------------------------------------------------------------------
// Server-side per-stream state
// ---------------------------------------------------------------------------

/// Buffered response for one H2 stream (server role).
struct H2StreamWriter {
    control: Arc<H2ResponseControl>,
}

impl H2StreamWriter {
    fn new(stream_id: u32) -> Self {
        Self {
            control: H2ResponseControl::new(stream_id),
        }
    }

    fn session_writer(&mut self) -> H2SessionWriter {
        self.control.writer()
    }
}

impl ServerWriter for H2StreamWriter {
    fn headers(&mut self, headers: Headers) {
        self.session_writer().headers(headers);
    }

    fn start_response_body(&mut self) {
        self.session_writer().start_response_body();
    }

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
        ServerResponseHandle::new(ArcH2ResponseControl::new(Arc::clone(&self.control)))
    }

    fn pause_request_body(&mut self) {
        self.session_writer().pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.session_writer().resume_request_body();
    }
}

/// Live state for one HTTP/2 stream (server role).
struct H2ServerStream {
    #[allow(dead_code)]
    id: u32,
    handler: Box<dyn ServerHandler>,
    writer: H2StreamWriter,
    half_closed_remote: bool,
    /// Request body withheld while [`H2WriterShared::body_paused`].
    paused_body: Vec<u8>,
    paused_end_stream: bool,
    /// Active WebSocket / protocol upgrade on this stream.
    upgraded: Option<Box<dyn ProtocolUpgradeHandler>>,
}

// ---------------------------------------------------------------------------
// Client-side per-stream state
// ---------------------------------------------------------------------------

/// Buffered outbound request during `ClientHandler::start` (client role).
struct H2ClientStreamWriter {
    #[allow(dead_code)]
    stream_id: u32,
    request_headers: Option<Headers>,
    body: Vec<u8>,
    done: bool,
    scheme: &'static str,
}

impl H2ClientStreamWriter {
    fn new(stream_id: u32, scheme: &'static str) -> Self {
        Self {
            stream_id,
            request_headers: None,
            body: Vec::new(),
            done: false,
            scheme,
        }
    }
}

impl ClientWriter for H2ClientStreamWriter {
    fn headers(&mut self, mut headers: Headers) {
        if !headers.contains(":scheme") {
            headers.add(":scheme", self.scheme);
        }
        if !headers.contains(":authority") {
            if let Some(host) = headers.get("host").map(|s| s.to_string()) {
                headers.add(":authority", host);
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

/// No-op [`ClientWriter`] passed to response callbacks (no more outbound data).
struct NullClientWriter;

impl ClientWriter for NullClientWriter {
    fn headers(&mut self, _headers: Headers) {}
    fn start_request_body(&mut self) {}
    fn request_body_content(&mut self, _data: &[u8]) {}
    fn end_request_body(&mut self) {}
    fn complete_request(&mut self) {}
}

/// Live state for one outbound H2 stream (client role).
struct H2ClientStream {
    #[allow(dead_code)]
    id: u32,
    handler: Box<dyn ClientHandler>,
    response_headers_received: bool,
    response_body_started: bool,
}

// ---------------------------------------------------------------------------
// H2Endpoint
// ---------------------------------------------------------------------------

/// HTTP/2 connection endpoint — handles both server and client roles.
///
/// Register as a [`ProtocolHandler`] with the reactor. Use the appropriate
/// constructor for the connection scenario; see the module docs for a table.
pub struct H2Endpoint {
    role: H2Role,
    #[allow(dead_code)]
    limits: HttpLimits,

    state: ConnState,
    /// Push frame parser (owns the inbound byte buffer).
    parser: H2Parser,
    out: Vec<u8>,

    decoder: Decoder,
    encoder: Encoder,

    peer_max_frame_size: usize,
    peer_initial_window_size: i32,

    flow: FlowControl,

    /// Active server-role streams (client-initiated, odd IDs).
    server_streams: HashMap<u32, H2ServerStream>,

    /// Active client-role streams (self-initiated, odd IDs).
    client_streams: HashMap<u32, H2ClientStream>,

    /// Server role: highest stream ID received from the client (used in GOAWAY).
    /// Client role: highest stream ID we have opened.
    last_stream_id: u32,

    continuation_stream_id: u32,
    continuation_end_stream: bool,
    /// Owned scratch for CONTINUATION field-block reassembly (temporary until
    /// HPACK can consume fragments incrementally).
    continuation_block: Vec<u8>,

    deferred_flush: Arc<H2DeferredFlush>,
}

impl H2Endpoint {
    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /// Create an H2 **server** endpoint for a TLS ALPN `h2` connection, or for
    /// a cleartext connection after the 24-byte client preface has already been
    /// sniffed and consumed externally.
    ///
    /// For TLS, `send_settings_on_connected` should be `false`; server SETTINGS
    /// are sent from [`ProtocolHandler::security_established`].
    ///
    /// For cleartext prior-knowledge, set `send_settings_on_connected = true`;
    /// server SETTINGS are then sent from [`ProtocolHandler::connected`].
    pub fn server(
        factory: Arc<dyn ServerHandlerFactory>,
        limits: HttpLimits,
        send_settings_on_connected: bool,
    ) -> Self {
        Self::make(
            H2Role::Server {
                factory,
                pending_upgrade: None,
                send_settings_on_connected,
            },
            limits,
        )
    }

    /// Create an H2 **server** endpoint for an h2c Upgrade connection.
    ///
    /// Call this after:
    /// 1. The `101 Switching Protocols` response has been sent.
    /// 2. The 24-byte client connection preface has been consumed.
    ///
    /// `upgrade_headers` must contain the H2 pseudo-headers (`:method`, `:path`,
    /// `:scheme`, `:authority`) derived from the original HTTP/1.1 request.
    /// They are delivered to a new [`ServerHandler`] on stream 1 once the
    /// SETTINGS exchange completes, without waiting for a HEADERS frame.
    ///
    /// After creating, call [`H2Endpoint::send_server_settings`] and then feed
    /// any remaining buffered bytes with [`ProtocolHandler::receive`].
    pub fn server_after_h2c_upgrade(
        factory: Arc<dyn ServerHandlerFactory>,
        limits: HttpLimits,
        upgrade_headers: Headers,
    ) -> Self {
        let mut ep = Self::make(
            H2Role::Server {
                factory,
                pending_upgrade: Some(upgrade_headers),
                send_settings_on_connected: false,
            },
            limits,
        );
        // Upgrade implies the client already used stream 1; later requests must
        // use IDs ≥ 3.
        ep.last_stream_id = 1;
        ep
    }

    /// Create an H2 **client** endpoint.
    ///
    /// On connection, the endpoint writes the client connection preface and a
    /// SETTINGS frame (with `ENABLE_PUSH=0`). For `secure = false` (cleartext
    /// prior-knowledge) this happens in [`ProtocolHandler::connected`]; for
    /// `secure = true` (TLS) it happens in
    /// [`ProtocolHandler::security_established`].
    pub fn client(
        factory: Arc<dyn ClientHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        Self::make(
            H2Role::Client {
                factory,
                secure,
                next_stream_id: 1,
            },
            limits,
        )
    }

    fn make(role: H2Role, limits: HttpLimits) -> Self {
        Self {
            role,
            limits,
            state: ConnState::ExpectPreface,
            parser: H2Parser::with_max_frame_size(DEFAULT_MAX_FRAME_SIZE),
            out: Vec::new(),
            decoder: Decoder::new(4096),
            encoder: Encoder::new(4096),
            peer_max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            peer_initial_window_size: super::flow::INITIAL_WINDOW_SIZE,
            flow: FlowControl::new(),
            server_streams: HashMap::new(),
            client_streams: HashMap::new(),
            last_stream_id: 0,
            continuation_stream_id: 0,
            continuation_end_stream: false,
            continuation_block: Vec::new(),
            deferred_flush: Arc::new(H2DeferredFlush {
                streams: Mutex::new(Vec::new()),
            }),
        }
    }

    fn bind_server_stream_controls(&mut self, endpoint: &dyn Endpoint) {
        let H2Role::Server { .. } = &self.role else {
            return;
        };
        let conn = endpoint.handle();
        let df = Arc::clone(&self.deferred_flush);
        for stream in self.server_streams.values_mut() {
            stream.writer.control.bind_conn(conn.clone());
            let df = Arc::clone(&df);
            let sid = stream.id;
            stream.writer.control.set_flush(Some(Arc::new(move || {
                df.streams.lock().unwrap().push(sid);
            })));
        }
    }

    fn drain_deferred_flush(&mut self) {
        let ids: Vec<u32> = {
            let mut g = self.deferred_flush.streams.lock().unwrap();
            std::mem::take(&mut *g)
        };
        for id in ids {
            self.deliver_paused_request_body(id);
            self.flush_one_server_stream(id);
        }
    }

    fn deliver_server_request_body(
        stream: &mut H2ServerStream,
        data: &[u8],
        end_stream: bool,
    ) {
        if stream.writer.control.body_paused() {
            if !data.is_empty() {
                stream.paused_body.extend_from_slice(data);
            }
            if end_stream {
                stream.paused_end_stream = true;
            }
            return;
        }
        if !data.is_empty() {
            stream.handler.start_request_body(&mut stream.writer);
            stream
                .handler
                .request_body_content(&mut stream.writer, data);
        }
        if end_stream {
            stream.handler.end_request_body(&mut stream.writer);
            stream.handler.request_complete(&mut stream.writer);
            stream.half_closed_remote = true;
        }
    }

    fn deliver_paused_request_body(&mut self, stream_id: u32) {
        let Some(stream) = self.server_streams.get_mut(&stream_id) else {
            return;
        };
        if stream.writer.control.body_paused() {
            return;
        }
        let body = std::mem::take(&mut stream.paused_body);
        let end = stream.paused_end_stream;
        stream.paused_end_stream = false;
        if body.is_empty() && !end {
            return;
        }
        Self::deliver_server_request_body(stream, &body, end);
    }

    // -----------------------------------------------------------------------
    // Public helpers
    // -----------------------------------------------------------------------

    /// Write and send the server connection preface (a SETTINGS frame).
    ///
    /// For TLS, call this from [`ProtocolHandler::security_established`].
    /// For cleartext prior-knowledge or h2c upgrade, call this immediately
    /// after the client preface has been consumed.
    ///
    /// After this call the endpoint transitions to `ExpectSettings`
    /// (cleartext, preface pre-consumed) or `ExpectPreface` (TLS, client
    /// preface still expected).
    pub fn send_server_settings(&mut self, endpoint: &mut dyn Endpoint) {
        frame::write_settings(
            &mut self.out,
            &[
                (SETTINGS_MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS),
                (SETTINGS_MAX_HEADER_LIST_SIZE, DEFAULT_MAX_HEADER_LIST_SIZE),
                (
                    SETTINGS_INITIAL_WINDOW_SIZE,
                    super::flow::INITIAL_WINDOW_SIZE as u32,
                ),
                (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            ],
            false,
        );

        // Cleartext: the client preface was consumed externally, so skip straight
        // to waiting for client SETTINGS.  TLS: we still need to see the preface.
        let preface_consumed = match &self.role {
            H2Role::Server {
                send_settings_on_connected,
                pending_upgrade,
                ..
            } => *send_settings_on_connected || pending_upgrade.is_some(),
            H2Role::Client { .. } => false,
        };
        self.state = if preface_consumed {
            ConnState::ExpectSettings
        } else {
            ConnState::ExpectPreface
        };

        endpoint.send(&self.out);
        self.out.clear();
    }

    // -----------------------------------------------------------------------
    // Client kickoff
    // -----------------------------------------------------------------------

    fn send_client_preface_and_settings(&mut self, endpoint: &mut dyn Endpoint) {
        self.out.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut self.out, &[(SETTINGS_ENABLE_PUSH, 0)], false);
        self.state = ConnState::ExpectSettings;
        endpoint.send(&self.out);
        self.out.clear();
    }

    /// Allocate the next client stream, call `factory.create_handler`,
    /// invoke `handler.start`, and flush the buffered request to `self.out`.
    fn start_client_request(&mut self) {
        let (stream_id, scheme) = match &mut self.role {
            H2Role::Client {
                next_stream_id,
                secure,
                ..
            } => {
                let id = *next_stream_id;
                *next_stream_id += 2;
                let s: &'static str = if *secure { "https" } else { "http" };
                (id, s)
            }
            _ => return,
        };

        let mut handler = match &self.role {
            H2Role::Client { factory, .. } => factory.create_handler(),
            _ => return,
        };

        let mut writer = H2ClientStreamWriter::new(stream_id, scheme);
        handler.start(&mut writer);

        let headers = writer.request_headers.take().unwrap_or_default();
        let body = std::mem::take(&mut writer.body);
        let end_stream = writer.done;

        let block = self
            .encoder
            .encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));

        let no_body = body.is_empty();
        let end_stream_flag = if no_body && end_stream {
            FLAG_END_STREAM
        } else {
            0
        };
        frame::write_headers(&mut self.out, &block, end_stream_flag, stream_id);

        self.flow
            .open_stream(stream_id, self.peer_initial_window_size);

        if !body.is_empty() {
            let max_frame = self.peer_max_frame_size;
            let mut offset = 0;
            while offset < body.len() {
                let end = (offset + max_frame).min(body.len());
                let chunk = &body[offset..end];
                let is_last = end == body.len();
                let data_flags = if is_last && end_stream {
                    FLAG_END_STREAM
                } else {
                    0
                };
                frame::write_data(&mut self.out, chunk, data_flags, stream_id);
                offset = end;
            }
        }

        self.last_stream_id = stream_id;
        self.client_streams.insert(
            stream_id,
            H2ClientStream {
                id: stream_id,
                handler,
                response_headers_received: false,
                response_body_started: false,
            },
        );
    }

    // -----------------------------------------------------------------------
    // Upgrade stream delivery
    // -----------------------------------------------------------------------

    /// After SETTINGS exchange completes, deliver the h2c upgrade request
    /// to stream 1 without expecting a client HEADERS frame.
    fn deliver_upgrade_stream(&mut self, upgrade_headers: Headers) {
        const STREAM_ID: u32 = 1;
        self.flow
            .open_stream(STREAM_ID, self.peer_initial_window_size);

        let handler = match &self.role {
            H2Role::Server { factory, .. } => factory.create_handler(),
            _ => return,
        };

        let writer = H2StreamWriter::new(STREAM_ID);
        let mut stream = H2ServerStream {
            id: STREAM_ID,
            handler,
            writer,
            half_closed_remote: true,
            paused_body: Vec::new(),
            paused_end_stream: false,
            upgraded: None,
        };

        stream.handler.headers(&mut stream.writer, &upgrade_headers);
        if let Some(up) = stream.writer.control.take_upgrade() {
            stream.upgraded = Some(up);
        }
        stream.handler.request_complete(&mut stream.writer);
        if let Some(up) = stream.writer.control.take_upgrade() {
            stream.upgraded = Some(up);
        }

        self.server_streams.insert(STREAM_ID, stream);
    }

    // -----------------------------------------------------------------------
    // Frame dispatch (slice payloads — no Vec copies on the hot path)
    // -----------------------------------------------------------------------

    fn on_settings(&mut self, flags: u8, payload: &[u8]) {
        if flags & frame::FLAG_ACK != 0 {
            return;
        }

        if payload.len() % 6 != 0 {
            self.send_goaway(ERROR_FRAME_SIZE_ERROR);
            return;
        }

        let old_initial = self.peer_initial_window_size;

        let mut i = 0;
        while i + 6 <= payload.len() {
            let id = u16::from_be_bytes([payload[i], payload[i + 1]]);
            let val = u32::from_be_bytes([
                payload[i + 2],
                payload[i + 3],
                payload[i + 4],
                payload[i + 5],
            ]);
            i += 6;

            match id {
                SETTINGS_HEADER_TABLE_SIZE => {
                    self.decoder.set_max_table_size(val as usize);
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if val < 16_384 || val > 16_777_215 {
                        self.send_goaway(ERROR_PROTOCOL_ERROR);
                        return;
                    }
                    self.peer_max_frame_size = val as usize;
                    self.parser.set_max_frame_size(val as usize);
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if val > 0x7fff_ffff {
                        self.send_goaway(ERROR_FLOW_CONTROL_ERROR);
                        return;
                    }
                    let new_initial = val as i32;
                    self.flow
                        .apply_initial_window_size_change(new_initial, old_initial);
                    self.peer_initial_window_size = new_initial;
                }
                _ => { /* unknown setting — ignore per §6.5.2 */ }
            }
        }

        frame::write_settings_ack(&mut self.out);

        if self.state == ConnState::ExpectSettings {
            self.state = ConnState::Open;

            // Server: deliver any pending upgrade request on stream 1.
            let pending = if let H2Role::Server {
                pending_upgrade, ..
            } = &mut self.role
            {
                pending_upgrade.take()
            } else {
                None
            };
            if let Some(hdrs) = pending {
                self.deliver_upgrade_stream(hdrs);
            }

            // Client: kick off the first request now that the connection is open.
            if matches!(self.role, H2Role::Client { .. }) {
                self.start_client_request();
            }
        }
    }

    fn on_headers(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        if stream_id == 0 {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }

        let block_fragment = frame::strip_headers_payload(payload, flags);

        if flags & FLAG_END_HEADERS == 0 {
            self.continuation_stream_id = stream_id;
            self.continuation_end_stream = flags & FLAG_END_STREAM != 0;
            self.continuation_block.clear();
            self.continuation_block.extend_from_slice(block_fragment);
            return;
        }

        self.dispatch_headers_block(stream_id, block_fragment, flags & FLAG_END_STREAM != 0);
    }

    fn on_continuation(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        if stream_id != self.continuation_stream_id {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }
        self.continuation_block.extend_from_slice(payload);

        if flags & FLAG_END_HEADERS != 0 {
            let end_stream = self.continuation_end_stream;
            let block = std::mem::take(&mut self.continuation_block);
            self.continuation_stream_id = 0;
            self.continuation_end_stream = false;
            self.dispatch_headers_block(stream_id, &block, end_stream);
        }
    }

    fn dispatch_headers_block(&mut self, stream_id: u32, block: &[u8], end_stream: bool) {
        match &self.role {
            H2Role::Server { .. } => {
                self.process_server_headers_block(stream_id, block, end_stream)
            }
            H2Role::Client { .. } => {
                self.process_client_response_headers(stream_id, block, end_stream)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Server: inbound request HEADERS
    // -----------------------------------------------------------------------

    fn process_server_headers_block(&mut self, stream_id: u32, block: &[u8], end_stream: bool) {
        // Stream IDs must be odd (client-initiated) and strictly greater than any previous.
        if stream_id == 0 || stream_id % 2 == 0 || stream_id <= self.last_stream_id {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }
        if self.server_streams.len() >= MAX_CONCURRENT_STREAMS as usize {
            frame::write_rst_stream(&mut self.out, stream_id, ERROR_REFUSED_STREAM);
            return;
        }

        self.last_stream_id = stream_id;

        let pairs = match self.decoder.decode(block) {
            Ok(p) => p,
            Err(_) => {
                self.send_goaway(ERROR_COMPRESSION_ERROR);
                return;
            }
        };

        let mut headers = Headers::new();
        for (name, value) in pairs {
            headers.add(name, value);
        }

        self.flow
            .open_stream(stream_id, self.peer_initial_window_size);

        let handler = match &self.role {
            H2Role::Server { factory, .. } => factory.create_handler(),
            _ => return,
        };

        let writer = H2StreamWriter::new(stream_id);
        let mut stream = H2ServerStream {
            id: stream_id,
            handler,
            writer,
            half_closed_remote: end_stream,
            paused_body: Vec::new(),
            paused_end_stream: false,
            upgraded: None,
        };

        stream.handler.headers(&mut stream.writer, &headers);
        if let Some(up) = stream.writer.control.take_upgrade() {
            stream.upgraded = Some(up);
        }
        if end_stream && stream.upgraded.is_none() {
            stream.handler.request_complete(&mut stream.writer);
            if let Some(up) = stream.writer.control.take_upgrade() {
                stream.upgraded = Some(up);
            }
        }

        self.server_streams.insert(stream_id, stream);
    }

    // -----------------------------------------------------------------------
    // Client: inbound response HEADERS
    // -----------------------------------------------------------------------

    fn process_client_response_headers(&mut self, stream_id: u32, block: &[u8], end_stream: bool) {
        let pairs = match self.decoder.decode(block) {
            Ok(p) => p,
            Err(_) => {
                self.send_goaway(ERROR_COMPRESSION_ERROR);
                return;
            }
        };

        let mut headers = Headers::new();
        for (name, value) in pairs {
            headers.add(name, value);
        }

        let mut w = NullClientWriter;
        if let Some(stream) = self.client_streams.get_mut(&stream_id) {
            if stream.response_headers_received {
                if stream.response_body_started {
                    stream.handler.end_response_body(&mut w);
                    stream.response_body_started = false;
                }
                stream.handler.response_trailers(&mut w, &headers);
            } else {
                stream.response_headers_received = true;
                stream.handler.response_headers(&mut w, &headers);
            }
            if end_stream {
                if stream.response_body_started {
                    stream.handler.end_response_body(&mut w);
                }
                stream.handler.response_complete(&mut w);
                self.flow.close_stream(stream_id);
                self.client_streams.remove(&stream_id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // DATA frames
    // -----------------------------------------------------------------------

    fn on_data(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        match &self.role {
            H2Role::Server { .. } => self.on_server_data(stream_id, flags, payload),
            H2Role::Client { .. } => self.on_client_data(stream_id, flags, payload),
        }
    }

    fn on_server_data(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        if stream_id == 0 {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }

        let data = frame::strip_data_payload(payload, flags);
        let len = data.len();

        let (conn_upd, stream_upd) = self.flow.on_data_received(stream_id, len);
        if conn_upd > 0 {
            frame::write_window_update(&mut self.out, 0, conn_upd);
        }
        if stream_upd > 0 {
            frame::write_window_update(&mut self.out, stream_id, stream_upd);
        }

        let end_stream = flags & FLAG_END_STREAM != 0;
        if let Some(stream) = self.server_streams.get_mut(&stream_id) {
            if let Some(up) = stream.upgraded.as_mut() {
                if !data.is_empty() {
                    up.receive(data);
                }
                if end_stream {
                    up.closed();
                }
                // Queue any immediate outbound frames into the response body buffer.
                let out = up.take_outbound();
                if !out.is_empty() {
                    stream
                        .writer
                        .control
                        .shared
                        .lock()
                        .unwrap()
                        .body
                        .extend_from_slice(&out);
                }
                return;
            }
            if !stream.half_closed_remote {
                Self::deliver_server_request_body(stream, data, end_stream);
            }
        }
    }

    fn on_client_data(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        if stream_id == 0 {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }

        let data = frame::strip_data_payload(payload, flags);
        let len = data.len();

        let (conn_upd, stream_upd) = self.flow.on_data_received(stream_id, len);
        if conn_upd > 0 {
            frame::write_window_update(&mut self.out, 0, conn_upd);
        }
        if stream_upd > 0 {
            frame::write_window_update(&mut self.out, stream_id, stream_upd);
        }

        let end_stream = flags & FLAG_END_STREAM != 0;
        let mut w = NullClientWriter;
        if let Some(stream) = self.client_streams.get_mut(&stream_id) {
            if !data.is_empty() {
                if !stream.response_body_started {
                    stream.response_body_started = true;
                    stream.handler.start_response_body(&mut w);
                }
                stream.handler.response_body_content(&mut w, data);
            }
            if end_stream {
                if stream.response_body_started {
                    stream.handler.end_response_body(&mut w);
                }
                stream.handler.response_complete(&mut w);
                self.flow.close_stream(stream_id);
                self.client_streams.remove(&stream_id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // PUSH_PROMISE
    // -----------------------------------------------------------------------

    fn on_push_promise(&mut self, stream_id: u32, _flags: u8, _payload: &[u8]) {
        match &self.role {
            H2Role::Server { .. } => {
                // Servers must not receive PUSH_PROMISE (RFC 9113 §8.4).
                self.send_goaway(ERROR_PROTOCOL_ERROR);
            }
            H2Role::Client { .. } => {
                // TODO: server push — RST_STREAM REFUSED_STREAM for now.
                if stream_id != 0 {
                    frame::write_rst_stream(&mut self.out, stream_id, ERROR_REFUSED_STREAM);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Other control frames
    // -----------------------------------------------------------------------

    fn on_ping(&mut self, flags: u8, payload: &[u8]) {
        if payload.len() != 8 {
            self.send_goaway(ERROR_FRAME_SIZE_ERROR);
            return;
        }
        if flags & frame::FLAG_ACK == 0 {
            let mut opaque = [0u8; 8];
            opaque.copy_from_slice(payload);
            frame::write_ping(&mut self.out, &opaque, true);
        }
    }

    fn on_rst_stream(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.send_goaway(ERROR_FRAME_SIZE_ERROR);
            return;
        }
        self.server_streams.remove(&stream_id);
        self.client_streams.remove(&stream_id);
        self.flow.close_stream(stream_id);
    }

    fn on_goaway(&mut self) {
        self.state = ConnState::GoAway;
    }

    fn on_window_update(&mut self, stream_id: u32, payload: &[u8]) {
        if payload.len() != 4 {
            self.send_goaway(ERROR_FRAME_SIZE_ERROR);
            return;
        }
        let increment =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
        if increment == 0 {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }
        self.flow.on_window_update(stream_id, increment);
    }

    fn send_goaway(&mut self, error_code: u32) {
        frame::write_goaway(&mut self.out, self.last_stream_id, error_code);
        self.state = ConnState::GoAway;
    }

    // -----------------------------------------------------------------------
    // Server response flush
    // -----------------------------------------------------------------------

    fn flush_server_streams(&mut self) {
        let stream_ids: Vec<u32> = self.server_streams.keys().copied().collect();
        for id in stream_ids {
            self.flush_one_server_stream(id);
        }
    }

    fn flush_one_server_stream(&mut self, stream_id: u32) {
        // Pull upgrade outbound into the body buffer first.
        if let Some(stream) = self.server_streams.get_mut(&stream_id) {
            if let Some(up) = stream.upgraded.as_mut() {
                let out = up.take_outbound();
                if !out.is_empty() {
                    stream
                        .writer
                        .control
                        .shared
                        .lock()
                        .unwrap()
                        .body
                        .extend_from_slice(&out);
                }
            }
        }

        let (headers, trailers, body, done, already_sent, upgraded) = {
            let stream = match self.server_streams.get_mut(&stream_id) {
                Some(s) => s,
                None => return,
            };
            let mut shared = stream.writer.control.shared.lock().unwrap();
            shared.needs_flush = false;
            let upgraded = shared.upgraded || stream.upgraded.is_some();
            if shared.response_headers.is_none()
                && !shared.headers_sent
                && body_empty(&shared)
                && shared.trailers.is_none()
            {
                return;
            }
            let headers = shared.response_headers.take();
            let trailers = if shared.done && !upgraded {
                shared.trailers.take()
            } else {
                None
            };
            let body = std::mem::take(&mut shared.body);
            let done = shared.done && !upgraded;
            let already_sent = shared.headers_sent;
            if headers.is_some() {
                shared.headers_sent = true;
            }
            (headers, trailers, body, done, already_sent, upgraded)
        };

        let has_trailers = trailers.is_some();
        let headers_this_flush = headers.is_some();

        if let Some(headers) = headers {
            if !already_sent {
                let block = self
                    .encoder
                    .encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));

                let end_stream_no_body = done && body.is_empty() && !upgraded && !has_trailers;
                let extra_flags = if end_stream_no_body {
                    FLAG_END_STREAM
                } else {
                    0
                };
                frame::write_headers(&mut self.out, &block, extra_flags, stream_id);
            }
        } else if !already_sent {
            return;
        }

        let max_frame = self.peer_max_frame_size;
        let mut end_stream_sent = headers_this_flush
            && !already_sent
            && done
            && body.is_empty()
            && !upgraded
            && !has_trailers;

        if !body.is_empty() {
            let mut offset = 0;
            while offset < body.len() {
                let end = (offset + max_frame).min(body.len());
                let chunk = &body[offset..end];
                let is_last = end == body.len();
                let data_flags = if is_last && done && !upgraded && !has_trailers {
                    end_stream_sent = true;
                    FLAG_END_STREAM
                } else {
                    0
                };
                let avail = self.flow.available_send(stream_id);
                let send_len = chunk.len().min(avail.max(chunk.len()));
                frame::write_data(&mut self.out, &chunk[..send_len], data_flags, stream_id);
                self.flow.consume_send(stream_id, send_len);
                offset = end;
            }
        }

        if let Some(trailers) = trailers {
            let block = self
                .encoder
                .encode(trailers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
            frame::write_headers(&mut self.out, &block, FLAG_END_STREAM, stream_id);
        } else if done && !upgraded && !end_stream_sent {
            // Headers were sent on a prior flush; body empty this flush; no trailers.
            frame::write_data(&mut self.out, &[], FLAG_END_STREAM, stream_id);
        }

        if done && !upgraded {
            self.flow.close_stream(stream_id);
            self.server_streams.remove(&stream_id);
        }
    }
}

fn body_empty(shared: &super::response::H2WriterShared) -> bool {
    shared.body.is_empty()
}

// ---------------------------------------------------------------------------
// H2FrameHandler — zero-copy event pipeline into the endpoint
// ---------------------------------------------------------------------------

impl H2FrameHandler for H2Endpoint {
    fn data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        self.on_data(stream_id, flags, payload);
    }

    fn headers_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        self.on_headers(stream_id, flags, payload);
    }

    fn priority_frame(&mut self, _stream_id: u32, _payload: &[u8]) {
        /* TODO: priority (deprecated) */
    }

    fn rst_stream_frame(&mut self, stream_id: u32, payload: &[u8]) {
        self.on_rst_stream(stream_id, payload);
    }

    fn settings_frame(&mut self, flags: u8, payload: &[u8]) {
        self.on_settings(flags, payload);
    }

    fn push_promise_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        self.on_push_promise(stream_id, flags, payload);
    }

    fn ping_frame(&mut self, flags: u8, payload: &[u8]) {
        self.on_ping(flags, payload);
    }

    fn goaway_frame(&mut self, _payload: &[u8]) {
        self.on_goaway();
    }

    fn window_update_frame(&mut self, stream_id: u32, payload: &[u8]) {
        self.on_window_update(stream_id, payload);
    }

    fn continuation_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        self.on_continuation(stream_id, flags, payload);
    }

    fn frame_error(&mut self, error_code: u32, _stream_id: u32, _message: &str) {
        self.send_goaway(error_code);
    }
}

// ---------------------------------------------------------------------------
// ProtocolHandler impl
// ---------------------------------------------------------------------------

impl ProtocolHandler for H2Endpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.bind_server_stream_controls(endpoint);
        match &self.role {
            H2Role::Server {
                send_settings_on_connected: true,
                ..
            } => {
                self.send_server_settings(endpoint);
            }
            H2Role::Client { secure: false, .. } => {
                self.send_client_preface_and_settings(endpoint);
            }
            _ => {}
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, _info: &SecurityInfo) {
        self.bind_server_stream_controls(endpoint);
        match &self.role {
            H2Role::Server {
                send_settings_on_connected: false,
                ..
            } => {
                self.send_server_settings(endpoint);
            }
            H2Role::Client { secure: true, .. } => {
                self.send_client_preface_and_settings(endpoint);
            }
            _ => {}
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.bind_server_stream_controls(endpoint);
        // Take the parser so frame callbacks can borrow `self` without overlapping
        // the parser buffer.
        let mut parser = std::mem::take(&mut self.parser);
        let mut buf = parser.take_buf();
        buf.extend_from_slice(data);
        *data = &[];

        if self.state == ConnState::ExpectPreface {
            if buf.len() < CLIENT_PREFACE.len() {
                parser.set_buf(buf);
                self.parser = parser;
                return;
            }
            if &buf[..CLIENT_PREFACE.len()] != CLIENT_PREFACE {
                frame::write_goaway(&mut self.out, 0, ERROR_PROTOCOL_ERROR);
                endpoint.send(&self.out);
                self.out.clear();
                endpoint.close();
                self.parser = parser;
                return;
            }
            buf.drain(..CLIENT_PREFACE.len());
            self.state = ConnState::ExpectSettings;
        }

        parser.set_buf(buf);
        if self.state != ConnState::GoAway {
            parser.drain(self);
        }
        self.parser = parser;

        self.drain_deferred_flush();
        self.flush_server_streams();

        if !self.out.is_empty() {
            endpoint.send(&self.out);
            self.out.clear();
        }

        if self.state == ConnState::GoAway {
            endpoint.close();
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.server_streams.clear();
        self.client_streams.clear();
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
}
