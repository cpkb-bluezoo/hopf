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
use std::time::Duration;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo, TimerHandle};

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
    ERROR_PROTOCOL_ERROR, ERROR_REFUSED_STREAM, ERROR_SETTINGS_TIMEOUT, FLAG_END_HEADERS,
    FLAG_END_STREAM, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_ENABLE_PUSH,
    SETTINGS_HEADER_TABLE_SIZE, SETTINGS_INITIAL_WINDOW_SIZE, SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_MAX_FRAME_SIZE, SETTINGS_MAX_HEADER_LIST_SIZE,
};
use super::parser::{H2FrameHandler, H2Parser};

/// 24-byte HTTP/2 client connection preface (RFC 9113 §3.4).
pub(crate) const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default maximum frame size (bytes).
const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

/// Default maximum header list size (bytes, advisory).
const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 8_192;

/// How long to wait for the peer to ACK our initial SETTINGS frame before
/// closing with SETTINGS_TIMEOUT (RFC 9113 §6.5.3).
const SETTINGS_ACK_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Request-body bytes not yet sent because the flow-control window was
    /// exhausted; retried on every subsequent `receive()` (e.g. once the
    /// peer's WINDOW_UPDATE arrives), see `flush_client_streams()`.
    pending_body: Vec<u8>,
    /// Whether the final byte of `pending_body` (once fully sent) should
    /// carry END_STREAM.
    pending_end_stream: bool,
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
    limits: HttpLimits,

    state: ConnState,
    /// Push frame parser (owns the inbound byte buffer).
    parser: H2Parser,
    out: Vec<u8>,

    decoder: Decoder,
    encoder: Encoder,

    peer_max_frame_size: usize,
    peer_initial_window_size: i32,
    /// Peer's `SETTINGS_ENABLE_PUSH` (RFC 9113 §6.5.2 default: enabled).
    /// hopf never sends PUSH_PROMISE today, so this has no consumer yet —
    /// tracked so a future push implementation has it available and so an
    /// out-of-range value (anything but 0 or 1) is rejected as a protocol
    /// error rather than silently ignored.
    #[allow(dead_code)]
    peer_enable_push: bool,
    /// Peer's `SETTINGS_MAX_CONCURRENT_STREAMS` (RFC 9113 §6.5.2 default:
    /// unlimited). Guards client-initiated stream creation in
    /// `start_client_request()`.
    peer_max_concurrent_streams: Option<u32>,
    /// Fires if the peer never ACKs our initial SETTINGS frame; cancelled
    /// in `on_settings()` once the ACK arrives.
    settings_ack_timer: Option<TimerHandle>,
    /// How long to wait for that ACK; overridable (see
    /// `set_settings_ack_timeout_for_test`) so tests don't wait 10 real
    /// seconds for the timeout path.
    settings_ack_timeout: Duration,

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
            peer_enable_push: true,
            peer_max_concurrent_streams: None,
            settings_ack_timer: None,
            settings_ack_timeout: SETTINGS_ACK_TIMEOUT,
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
                (
                    SETTINGS_MAX_CONCURRENT_STREAMS,
                    self.limits.max_concurrent_streams,
                ),
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
        self.arm_settings_ack_timer(endpoint);
    }

    /// Schedule (replacing any prior timer) a close-with-SETTINGS_TIMEOUT if
    /// the peer doesn't ACK the SETTINGS frame just sent within
    /// [`SETTINGS_ACK_TIMEOUT`] (RFC 9113 §6.5.3). Cancelled by
    /// `on_settings()` once an ACK arrives.
    fn arm_settings_ack_timer(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(timer) = self.settings_ack_timer.take() {
            timer.cancel();
        }
        let handle = endpoint.handle();
        let timer = endpoint.schedule_timer(
            self.settings_ack_timeout,
            Box::new(move || {
                handle.with_endpoint(|ep| {
                    let mut goaway = Vec::new();
                    frame::write_goaway(&mut goaway, 0, ERROR_SETTINGS_TIMEOUT);
                    ep.send(&goaway);
                    ep.close();
                });
            }),
        );
        self.settings_ack_timer = Some(timer);
    }

    /// Override the SETTINGS-ACK wait ([`SETTINGS_ACK_TIMEOUT`] by default)
    /// — for tests only, so the timeout path doesn't require waiting out
    /// the real production duration.
    #[cfg(test)]
    pub(crate) fn set_settings_ack_timeout_for_test(&mut self, timeout: Duration) {
        self.settings_ack_timeout = timeout;
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
        self.arm_settings_ack_timer(endpoint);
    }

    /// Allocate the next client stream, call `factory.create_handler`,
    /// invoke `handler.start`, and flush the buffered request to `self.out`.
    fn start_client_request(&mut self) {
        if let Some(limit) = self.peer_max_concurrent_streams {
            if self.client_streams.len() as u32 >= limit {
                // The peer's SETTINGS_MAX_CONCURRENT_STREAMS forbids opening
                // another stream right now. hopf's H2 client is currently
                // one-request-per-connection, so there's nowhere to queue
                // this — matches the low-level Stream API design (the
                // caller controls dial timing); a future multi-stream
                // client would retry here once a stream closes.
                return;
            }
        }

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

        // Send as much of the body as the (fresh, just-opened) flow-control
        // window allows; whatever's left is retried by
        // `flush_client_streams()` on every subsequent `receive()` call
        // (e.g. once the peer's WINDOW_UPDATE arrives).
        let remaining = self.write_data_flow_controlled(stream_id, &body, end_stream);
        let pending_end_stream = !remaining.is_empty() && end_stream;

        self.last_stream_id = stream_id;
        self.client_streams.insert(
            stream_id,
            H2ClientStream {
                id: stream_id,
                handler,
                response_headers_received: false,
                response_body_started: false,
                pending_body: remaining,
                pending_end_stream,
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
            if let Some(timer) = self.settings_ack_timer.take() {
                timer.cancel();
            }
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
                SETTINGS_ENABLE_PUSH => {
                    if val > 1 {
                        self.send_goaway(ERROR_PROTOCOL_ERROR);
                        return;
                    }
                    self.peer_enable_push = val == 1;
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    self.peer_max_concurrent_streams = Some(val);
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
        if self.server_streams.len() >= self.limits.max_concurrent_streams as usize {
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

    /// Write as much of `body` as the current flow-control window for
    /// `stream_id` allows, in `max_frame`-sized (or smaller) DATA frames.
    /// Returns the unsent remainder — empty once everything was written.
    /// The final frame carries END_STREAM only when the remainder ends up
    /// empty and `end_stream` was requested (RFC 9113 §5.2, §6.9).
    fn write_data_flow_controlled(
        &mut self,
        stream_id: u32,
        body: &[u8],
        end_stream: bool,
    ) -> Vec<u8> {
        if body.is_empty() {
            return Vec::new();
        }
        let max_frame = self.peer_max_frame_size;
        let mut offset = 0;
        while offset < body.len() {
            let avail = self.flow.available_send(stream_id);
            if avail == 0 {
                break;
            }
            let end = (offset + max_frame.min(avail)).min(body.len());
            let chunk = &body[offset..end];
            let is_last = end == body.len();
            let flags = if is_last && end_stream {
                FLAG_END_STREAM
            } else {
                0
            };
            frame::write_data(&mut self.out, chunk, flags, stream_id);
            self.flow.consume_send(stream_id, chunk.len());
            offset = end;
        }
        if offset >= body.len() {
            Vec::new()
        } else {
            body[offset..].to_vec()
        }
    }

    /// Retry any client request body left unsent by a prior flow-control
    /// stall. Called at the same point as `flush_server_streams()`, so it
    /// runs on every `receive()` — including one that just processed the
    /// peer's WINDOW_UPDATE.
    fn flush_client_streams(&mut self) {
        let stream_ids: Vec<u32> = self
            .client_streams
            .iter()
            .filter(|(_, s)| !s.pending_body.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for id in stream_ids {
            let (body, end_stream) = match self.client_streams.get_mut(&id) {
                Some(s) => (std::mem::take(&mut s.pending_body), s.pending_end_stream),
                None => continue,
            };
            let remaining = self.write_data_flow_controlled(id, &body, end_stream);
            if let Some(s) = self.client_streams.get_mut(&id) {
                s.pending_body = remaining;
            }
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

        let (headers, mut trailers, body, done, already_sent, upgraded) = {
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

        if let Some(mut headers) = headers {
            if !already_sent {
                if !headers.contains("date") {
                    headers.set("Date", crate::utils::http_date_now());
                }
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

        let end_stream_wanted = done && !upgraded && !has_trailers;
        let mut end_stream_sent =
            headers_this_flush && !already_sent && body.is_empty() && end_stream_wanted;

        let remaining_body = self.write_data_flow_controlled(stream_id, &body, end_stream_wanted);
        let body_fully_sent = remaining_body.is_empty();
        if body_fully_sent && !body.is_empty() && end_stream_wanted {
            end_stream_sent = true;
        }

        if body_fully_sent {
            if let Some(trailers) = trailers.take() {
                let block = self
                    .encoder
                    .encode(trailers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
                frame::write_headers(&mut self.out, &block, FLAG_END_STREAM, stream_id);
            } else if done && !upgraded && !end_stream_sent {
                // Headers were sent on a prior flush; body empty this flush; no trailers.
                frame::write_data(&mut self.out, &[], FLAG_END_STREAM, stream_id);
            }
        }

        if body_fully_sent && done && !upgraded {
            self.flow.close_stream(stream_id);
            self.server_streams.remove(&stream_id);
        } else if !body_fully_sent {
            // Flow control exhausted mid-body — requeue whatever's left
            // unsent (and any trailers, which must follow the body) for the
            // next flush, triggered by any subsequent incoming frame (e.g.
            // the peer's WINDOW_UPDATE).
            if let Some(stream) = self.server_streams.get_mut(&stream_id) {
                let mut shared = stream.writer.control.shared.lock().unwrap();
                let mut requeued = remaining_body;
                requeued.extend_from_slice(&shared.body);
                shared.body = requeued;
                if let Some(t) = trailers {
                    shared.trailers = Some(t);
                }
            }
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
        self.flush_client_streams();

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

#[cfg(test)]
mod flow_control_tests {
    use super::*;
    use crate::stream::{ServerHandler, ServerHandlerFactory};

    struct NoopFactory;
    impl ServerHandlerFactory for NoopFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }

    fn test_endpoint() -> H2Endpoint {
        H2Endpoint::server(Arc::new(NoopFactory), HttpLimits::default(), false)
    }

    /// `ep.out` must contain exactly one DATA frame; return its payload length
    /// and flags.
    fn single_data_frame(out: &[u8]) -> (usize, u8) {
        assert!(out.len() >= 9, "no frame header in output: {out:?}");
        let header = frame::parse_frame_header(&out[..9]);
        assert_eq!(header.ty, 0x0, "expected a DATA frame, got type {}", header.ty);
        assert_eq!(out.len(), 9 + header.length as usize, "unexpected trailing bytes");
        (header.length as usize, header.flags)
    }

    /// The bug this guards against: `send_len` must never exceed the peer's
    /// advertised window, even when the body is bigger than it.
    #[test]
    fn flow_control_caps_send_at_available_window() {
        let mut ep = test_endpoint();
        ep.flow.open_stream(1, 10); // only 10 bytes of send window
        let body = vec![b'x'; 25];

        let remaining = ep.write_data_flow_controlled(1, &body, true);

        assert_eq!(remaining.len(), 15, "must not send more than the window allows");
        assert_eq!(ep.flow.available_send(1), 0);
        let (len, flags) = single_data_frame(&ep.out);
        assert_eq!(len, 10);
        assert_eq!(flags & FLAG_END_STREAM, 0, "more body is still pending, no END_STREAM yet");
    }

    /// Once the peer's WINDOW_UPDATE reopens the window, the remainder sends
    /// and the final frame carries END_STREAM.
    #[test]
    fn flow_control_sends_remainder_once_window_reopens() {
        let mut ep = test_endpoint();
        ep.flow.open_stream(1, 10);
        let body = vec![b'x'; 25];
        let remaining = ep.write_data_flow_controlled(1, &body, true);
        ep.out.clear();

        ep.flow.on_window_update(1, 15);
        let remaining2 = ep.write_data_flow_controlled(1, &remaining, true);

        assert!(remaining2.is_empty(), "the whole body should now be sent");
        let (len, flags) = single_data_frame(&ep.out);
        assert_eq!(len, 15);
        assert_ne!(flags & FLAG_END_STREAM, 0, "final chunk must carry END_STREAM");
    }

    /// A body that fits entirely within the window in one call sends as a
    /// single frame with no remainder, matching the pre-fix common case.
    #[test]
    fn flow_control_sends_whole_body_when_window_is_sufficient() {
        let mut ep = test_endpoint();
        ep.flow.open_stream(1, 1000);
        let body = vec![b'y'; 50];

        let remaining = ep.write_data_flow_controlled(1, &body, true);

        assert!(remaining.is_empty());
        let (len, flags) = single_data_frame(&ep.out);
        assert_eq!(len, 50);
        assert_ne!(flags & FLAG_END_STREAM, 0);
    }

    /// A completely exhausted window (0 bytes available) must send nothing
    /// at all and return the whole body as the remainder.
    #[test]
    fn flow_control_sends_nothing_when_window_is_zero() {
        let mut ep = test_endpoint();
        ep.flow.open_stream(1, 0);
        let body = vec![b'z'; 5];

        let remaining = ep.write_data_flow_controlled(1, &body, true);

        assert_eq!(remaining, body);
        assert!(ep.out.is_empty());
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    use crate::stream::{ClientHandler, ClientHandlerFactory, ClientWriter};

    fn settings_payload(entries: &[(u16, u32)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(entries.len() * 6);
        for (id, val) in entries {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&val.to_be_bytes());
        }
        out
    }

    struct NoopServerFactory;
    impl ServerHandlerFactory for NoopServerFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }

    fn server_endpoint() -> H2Endpoint {
        H2Endpoint::server(Arc::new(NoopServerFactory), HttpLimits::default(), false)
    }

    #[test]
    fn settings_enable_push_stored() {
        let mut ep = server_endpoint();
        assert!(ep.peer_enable_push, "RFC 9113 default is enabled");
        ep.on_settings(0, &settings_payload(&[(SETTINGS_ENABLE_PUSH, 0)]));
        assert!(!ep.peer_enable_push);
        ep.on_settings(0, &settings_payload(&[(SETTINGS_ENABLE_PUSH, 1)]));
        assert!(ep.peer_enable_push);
    }

    #[test]
    fn settings_enable_push_out_of_range_is_protocol_error() {
        let mut ep = server_endpoint();
        ep.on_settings(0, &settings_payload(&[(SETTINGS_ENABLE_PUSH, 2)]));
        assert_eq!(ep.state, ConnState::GoAway);
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, 0x7, "expected a GOAWAY frame");
    }

    #[test]
    fn settings_max_concurrent_streams_stored() {
        let mut ep = server_endpoint();
        assert_eq!(ep.peer_max_concurrent_streams, None, "unlimited until advertised");
        ep.on_settings(0, &settings_payload(&[(SETTINGS_MAX_CONCURRENT_STREAMS, 5)]));
        assert_eq!(ep.peer_max_concurrent_streams, Some(5));
    }

    /// `HttpLimits::max_concurrent_streams` (not a hardcoded constant) governs
    /// how many client-initiated streams the server role accepts before
    /// refusing new ones with `RST_STREAM(REFUSED_STREAM)`.
    #[test]
    fn own_max_concurrent_streams_limit_is_configurable_and_enforced() {
        let limits = HttpLimits {
            max_concurrent_streams: 0,
            ..HttpLimits::default()
        };
        let mut ep = H2Endpoint::server(Arc::new(NoopServerFactory), limits, false);
        ep.process_server_headers_block(1, &[], false);
        assert!(ep.server_streams.is_empty(), "stream must not be admitted");
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_RST_STREAM);
    }

    struct OnceFactory {
        started: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ClientHandlerFactory for OnceFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            Box::new(OnceHandler {
                started: Arc::clone(&self.started),
            })
        }
    }
    struct OnceHandler {
        started: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ClientHandler for OnceHandler {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            self.started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut h = Headers::new();
            h.set(":method", "GET");
            h.set(":path", "/");
            h.set("host", "example.test");
            request.headers(h);
            request.complete_request();
        }
        fn response_headers(&mut self, _: &mut dyn ClientWriter, _: &Headers) {}
        fn response_complete(&mut self, _: &mut dyn ClientWriter) {}
    }

    #[test]
    fn start_client_request_refuses_when_peer_allows_zero_streams() {
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut ep = H2Endpoint::client(
            Arc::new(OnceFactory {
                started: Arc::clone(&started),
            }),
            HttpLimits::default(),
            false,
        );
        ep.peer_max_concurrent_streams = Some(0);

        ep.start_client_request();

        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(ep.client_streams.is_empty());
    }

    #[test]
    fn start_client_request_proceeds_within_peer_limit() {
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut ep = H2Endpoint::client(
            Arc::new(OnceFactory {
                started: Arc::clone(&started),
            }),
            HttpLimits::default(),
            false,
        );
        ep.peer_max_concurrent_streams = Some(1);

        ep.start_client_request();

        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(ep.client_streams.len(), 1);
    }
}
