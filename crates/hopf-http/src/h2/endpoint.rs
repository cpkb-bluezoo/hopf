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
    ClientHandler, ClientHandlerFactory, ClientWriter, ConnectionInfo, ProtocolUpgradeHandler,
    ServerHandler, ServerHandlerFactory, ServerResponseHandle, ServerWriter,
};

use super::flow::FlowControl;
use super::frame::{
    self, ERROR_COMPRESSION_ERROR, ERROR_ENHANCE_YOUR_CALM, ERROR_FLOW_CONTROL_ERROR,
    ERROR_FRAME_SIZE_ERROR, ERROR_NO_ERROR, ERROR_PROTOCOL_ERROR, ERROR_REFUSED_STREAM,
    ERROR_SETTINGS_TIMEOUT, ERROR_STREAM_CLOSED, FLAG_END_HEADERS, FLAG_END_STREAM,
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
// Per-stream lifecycle state (RFC 9113 §5.1, collapsed to what hopf needs
// to distinguish)
// ---------------------------------------------------------------------------

/// A stream's lifecycle relative to `server_streams`/`client_streams` and
/// `last_stream_id`, computed on demand rather than tracked separately —
/// stream IDs are monotonically increasing and never reused (RFC 9113
/// §5.1.1), so "used, now finished" (`Closed`) is fully determined by
/// comparing against `last_stream_id` without needing an ever-growing set
/// of every ID ever closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// This ID has never been used by the peer — receiving most frame
    /// types for it is a connection error (RFC 9113 §5.1).
    Idle,
    /// Currently tracked in `server_streams`/`client_streams`.
    Open,
    /// This ID was used and has since finished (normal completion or
    /// RST_STREAM) — late frames get a stream error (RST_STREAM
    /// STREAM_CLOSED) rather than being silently dropped or misdiagnosed
    /// as referencing a stream that was never opened.
    Closed,
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
        /// When false, the session layer opens streams itself (see
        /// [`Self::open_client_stream`]) as requests become ready, instead
        /// of this auto-kickoff.
        auto_kickoff_first_request: bool,
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

    fn connection_info(&self) -> ConnectionInfo {
        self.control.connection_info()
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
            headers.add_pseudo(":scheme", self.scheme);
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

    /// Server role: `true` once [`H2Endpoint::shutdown_gracefully`] has sent
    /// the initial `GOAWAY(2^31-1)`. New streams are refused while this is
    /// set; the final GOAWAY (with the true last-stream-id) and connection
    /// close happen once `server_streams` drains to empty.
    graceful_shutdown: bool,

    deferred_flush: Arc<H2DeferredFlush>,

    /// Remote/local address and TLS metadata, captured once and handed to
    /// each server stream's [`H2ResponseControl`] as it's (re)bound.
    connection_info: ConnectionInfo,
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
                auto_kickoff_first_request: true,
            },
            limits,
        )
    }

    /// Client endpoint for the Gumdrop [`HttpRequest`](crate::HttpRequest) session API.
    ///
    /// Does not auto-send the first stream; the session layer opens it via
    /// [`Self::open_client_stream`] / [`Self::feed_client_stream_body`] as
    /// the application submits and streams a request.
    pub(crate) fn client_session(
        factory: Arc<dyn ClientHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        Self::make(
            H2Role::Client {
                factory,
                secure,
                next_stream_id: 1,
                auto_kickoff_first_request: false,
            },
            limits,
        )
    }

    /// Create an H2 **client** endpoint for a connection just promoted from
    /// HTTP/1.1 via h2c Upgrade (RFC 7540 §3.2).
    ///
    /// `handler` is the [`ClientHandler`] whose `start()` already ran and
    /// whose request already went out as the HTTP/1.1 Upgrade request — RFC
    /// 7540 §3.2 assigns that request stream ID 1, so its response now
    /// arrives via H2 framing on stream 1 instead of more HTTP/1.1 bytes.
    /// Call [`ProtocolHandler::connected`] on the result immediately (it
    /// sends the client preface + SETTINGS), then feed it whatever bytes
    /// were buffered after the `101` response.
    pub fn client_after_h2c_upgrade(
        handler: Box<dyn ClientHandler>,
        factory: Arc<dyn ClientHandlerFactory>,
        limits: HttpLimits,
    ) -> Self {
        let mut ep = Self::make(
            H2Role::Client {
                factory,
                secure: false,
                next_stream_id: 3,
                auto_kickoff_first_request: false,
            },
            limits,
        );
        ep.last_stream_id = 1;
        ep.flow.open_stream(1, ep.peer_initial_window_size);
        ep.client_streams.insert(
            1,
            H2ClientStream {
                id: 1,
                handler,
                response_headers_received: false,
                response_body_started: false,
                pending_body: Vec::new(),
                pending_end_stream: false,
            },
        );
        ep
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
            graceful_shutdown: false,
            deferred_flush: Arc::new(H2DeferredFlush {
                streams: Mutex::new(Vec::new()),
            }),
            connection_info: ConnectionInfo::default(),
        }
    }

    fn bind_server_stream_controls(&mut self, endpoint: &dyn Endpoint) {
        let H2Role::Server { .. } = &self.role else {
            return;
        };
        let conn = endpoint.handle();
        self.connection_info = ConnectionInfo::new(
            endpoint.remote_addr().ok(),
            endpoint.local_addr().ok(),
            endpoint.security_info().clone(),
        );
        let df = Arc::clone(&self.deferred_flush);
        for stream in self.server_streams.values_mut() {
            stream.writer.control.bind_conn(conn.clone());
            stream
                .writer
                .control
                .bind_connection_info(self.connection_info.clone());
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
    #[cfg(all(test, feature = "integration"))]
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

    pub(crate) fn client_connection_ready(&self) -> bool {
        matches!(self.state, ConnState::Open)
    }

    pub(crate) fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

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

    /// Open a new client stream and send its HEADERS frame only — no
    /// request body touched.
    ///
    /// Companion to [`Self::feed_client_stream_body`]: together they let the
    /// Gumdrop [`crate::HttpRequest`] session API open a stream as soon as
    /// `start_request_body` is called and emit DATA frames incrementally as
    /// `request_body_content` is called, instead of
    /// [`Self::start_client_request`]'s one-shot "hand me the whole body
    /// now" contract (which the lower-level [`ClientHandler`] SPI still
    /// uses unchanged). `headers` must already carry all four pseudo-headers.
    /// Returns `None` if the connection isn't ready to open a stream right
    /// now (not yet past the preface/SETTINGS exchange, or the peer's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` is currently exhausted) — the
    /// caller should retry on a later `receive()`/poke.
    pub(crate) fn open_client_stream(
        &mut self,
        headers: Headers,
        handler: Box<dyn ClientHandler>,
        bodyless: bool,
        endpoint: &mut dyn Endpoint,
    ) -> Option<u32> {
        if !self.client_connection_ready() {
            return None;
        }
        if let Some(limit) = self.peer_max_concurrent_streams {
            if self.client_streams.len() as u32 >= limit {
                return None;
            }
        }
        let stream_id = match &mut self.role {
            H2Role::Client { next_stream_id, .. } => {
                let id = *next_stream_id;
                *next_stream_id += 2;
                id
            }
            _ => return None,
        };

        let block = self
            .encoder
            .encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
        let flags = if bodyless { FLAG_END_STREAM } else { 0 };
        frame::write_headers(&mut self.out, &block, flags, stream_id);

        self.flow
            .open_stream(stream_id, self.peer_initial_window_size);
        self.last_stream_id = stream_id;
        self.client_streams.insert(
            stream_id,
            H2ClientStream {
                id: stream_id,
                handler,
                response_headers_received: false,
                response_body_started: false,
                pending_body: Vec::new(),
                pending_end_stream: false,
            },
        );

        if !self.out.is_empty() {
            endpoint.send(&self.out);
            self.out.clear();
        }
        Some(stream_id)
    }

    /// Queue more DATA for a stream already opened by
    /// [`Self::open_client_stream`], sending as much as the current
    /// flow-control window allows and stashing the rest for the automatic
    /// retry in [`Self::flush_client_streams`]. `end_stream` marks this as
    /// the final call for the stream — safe to call with `data` empty just
    /// to flush a previously-signalled end-of-stream.
    pub(crate) fn feed_client_stream_body(
        &mut self,
        stream_id: u32,
        data: &[u8],
        end_stream: bool,
        endpoint: &mut dyn Endpoint,
    ) {
        if let Some(stream) = self.client_streams.get_mut(&stream_id) {
            stream.pending_body.extend_from_slice(data);
            stream.pending_end_stream |= end_stream;
        }
        self.flush_client_streams();
        if !self.out.is_empty() {
            endpoint.send(&self.out);
            self.out.clear();
        }
    }

    /// Bytes still queued (not yet sent due to flow control) for a client
    /// stream opened by [`Self::open_client_stream`]. `0` for an unknown
    /// stream id (already closed, or never opened).
    pub(crate) fn client_stream_pending_len(&self, stream_id: u32) -> usize {
        self.client_streams
            .get(&stream_id)
            .map(|s| s.pending_body.len())
            .unwrap_or(0)
    }

    /// Notify every in-flight client stream's [`ClientHandler`] that the
    /// connection failed, via [`ClientHandler::request_failed`], before
    /// dropping it — otherwise a reset/disconnect mid-request silently
    /// drops the response handler with no callback at all (the client-role
    /// counterpart of `flush_server_streams`-adjacent server bookkeeping;
    /// see issue #88).
    fn fail_client_streams(&mut self, err: &std::io::Error) {
        for (_, mut stream) in std::mem::take(&mut self.client_streams) {
            stream.handler.request_failed(&mut NullClientWriter, err);
        }
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
                    // This describes the peer's own decoder table, i.e.
                    // what our encoder may reference — never our decoder's
                    // ceiling (see hpack::Decoder::local_max).
                    self.encoder.set_max_size(val as usize);
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

            // Client: kick off the first request when using the legacy factory API.
            if matches!(
                self.role,
                H2Role::Client {
                    auto_kickoff_first_request: true,
                    ..
                }
            ) {
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
        if self.graceful_shutdown || self.server_streams.len() >= self.limits.max_concurrent_streams as usize {
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

        // RFC 9113 §6.5.2: reject a decoded header list that exceeds what we
        // advertised via SETTINGS_MAX_HEADER_LIST_SIZE, or HttpLimits' own
        // field-count cap. This is a stream error, not a connection error —
        // HPACK state itself is still consistent.
        if pairs.len() > self.limits.max_header_count
            || header_list_size(&pairs) > DEFAULT_MAX_HEADER_LIST_SIZE as usize
        {
            frame::write_rst_stream(&mut self.out, stream_id, ERROR_ENHANCE_YOUR_CALM);
            return;
        }

        // RFC 9113 §8.3.1 (pseudo-header presence/ordering/uniqueness) and
        // §8.2.2 (connection-specific fields, TE) — both malformed-request
        // stream errors.
        if validate_request_header_block(&pairs).is_err() {
            frame::write_rst_stream(&mut self.out, stream_id, ERROR_PROTOCOL_ERROR);
            return;
        }

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
            // RFC 9113 §8.1 / RFC 9110 §15.2: a 1xx HEADERS is an interim
            // response — never terminal, never trailers. The real final
            // response HEADERS still follows on the same stream.
            if !stream.response_headers_received && (100..200).contains(&headers.status_code()) {
                stream.handler.informational_response(&mut w, &headers);
                return;
            }
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

    /// Classify `stream_id` for the endpoint's own role (RFC 9113 §5.1) —
    /// see [`StreamState`].
    fn stream_state(&self, stream_id: u32) -> StreamState {
        match &self.role {
            H2Role::Server { .. } => {
                if self.server_streams.contains_key(&stream_id) {
                    StreamState::Open
                } else if stream_id == 0 || stream_id % 2 == 0 || stream_id > self.last_stream_id {
                    StreamState::Idle
                } else {
                    StreamState::Closed
                }
            }
            H2Role::Client { .. } => {
                if self.client_streams.contains_key(&stream_id) {
                    StreamState::Open
                } else if stream_id == 0 || stream_id > self.last_stream_id {
                    StreamState::Idle
                } else {
                    StreamState::Closed
                }
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
        if stream_id == 0 || self.stream_state(stream_id) == StreamState::Idle {
            // RFC 9113 §5.1: any frame but HEADERS/PRIORITY on an idle
            // stream is a connection error.
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }

        let data = frame::strip_data_payload(payload, flags);
        let len = data.len();

        // Connection-level flow control must still be accounted for even if
        // the stream itself has since closed — the peer already spent these
        // bytes against the shared connection window.
        let (conn_upd, stream_upd) = self.flow.on_data_received(stream_id, len);
        if conn_upd > 0 {
            frame::write_window_update(&mut self.out, 0, conn_upd);
        }
        if stream_upd > 0 {
            frame::write_window_update(&mut self.out, stream_id, stream_upd);
        }

        if self.stream_state(stream_id) == StreamState::Closed {
            // RFC 9113 §6.1: DATA on a stream that isn't open or
            // half-closed(local) gets a stream error, not silence.
            frame::write_rst_stream(&mut self.out, stream_id, ERROR_STREAM_CLOSED);
            return;
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
                let wants_close = up.wants_close();
                // Queue any immediate outbound frames into the response body buffer.
                let out = up.take_outbound();
                {
                    let mut shared = stream.writer.control.shared.lock().unwrap();
                    if !out.is_empty() {
                        shared.body.extend_from_slice(&out);
                    }
                    // Extended CONNECT: end the stream after a WS Close / protocol error.
                    if wants_close {
                        shared.done = true;
                    }
                }
                return;
            }
            if !stream.half_closed_remote {
                Self::deliver_server_request_body(stream, data, end_stream);
            }
        }
    }

    fn on_client_data(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
        if stream_id == 0 || self.stream_state(stream_id) == StreamState::Idle {
            // RFC 9113 §5.1: any frame but HEADERS/PRIORITY on an idle
            // stream is a connection error.
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }

        let data = frame::strip_data_payload(payload, flags);
        let len = data.len();

        // Connection-level flow control must still be accounted for even if
        // the stream itself has since closed — the peer already spent these
        // bytes against the shared connection window.
        let (conn_upd, stream_upd) = self.flow.on_data_received(stream_id, len);
        if conn_upd > 0 {
            frame::write_window_update(&mut self.out, 0, conn_upd);
        }
        if stream_upd > 0 {
            frame::write_window_update(&mut self.out, stream_id, stream_upd);
        }

        if self.stream_state(stream_id) == StreamState::Closed {
            // RFC 9113 §6.1: DATA on a stream that isn't open or
            // half-closed(local) gets a stream error, not silence.
            frame::write_rst_stream(&mut self.out, stream_id, ERROR_STREAM_CLOSED);
            return;
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
        // RFC 9113 §6.4: RST_STREAM MUST NOT be sent for an idle stream;
        // receiving one is a connection error. A RST_STREAM for an
        // already-closed stream is explicitly tolerated (no reply needed).
        if self.stream_state(stream_id) == StreamState::Idle {
            self.send_goaway(ERROR_PROTOCOL_ERROR);
            return;
        }
        self.server_streams.remove(&stream_id);
        self.client_streams.remove(&stream_id);
        self.flow.close_stream(stream_id);
    }

    fn on_goaway(&mut self, payload: &[u8]) {
        self.state = ConnState::GoAway;

        // Client role: fail in-flight requests above the peer's announced
        // last-stream-id instead of leaving them to hang forever (RFC 9113
        // §6.8 — those streams were never processed by the peer).
        if matches!(self.role, H2Role::Client { .. }) && payload.len() >= 8 {
            let last_stream_id =
                u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
            let stale: Vec<u32> = self
                .client_streams
                .keys()
                .copied()
                .filter(|id| *id > last_stream_id)
                .collect();
            let mut w = NullClientWriter;
            for id in stale {
                if let Some(mut stream) = self.client_streams.remove(&id) {
                    self.flow.close_stream(id);
                    stream.handler.request_failed(
                        &mut w,
                        &std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "connection closed via GOAWAY before response completed",
                        ),
                    );
                }
            }
        }
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

    /// Begin RFC 9113 §6.8's recommended two-phase graceful shutdown
    /// (server role only): send an immediate `GOAWAY(2^31-1, NO_ERROR)` to
    /// tell the peer to stop opening new streams, while in-flight server
    /// streams keep draining normally. Once every stream finishes, a final
    /// `GOAWAY` with the true last-stream-id is sent and the connection is
    /// closed — see the drain check at the end of
    /// [`ProtocolHandler::receive`](H2Endpoint::receive).
    ///
    /// A no-op if already shutting down, or called for the client role.
    pub fn shutdown_gracefully(&mut self, endpoint: &mut dyn Endpoint) {
        if self.graceful_shutdown || !matches!(self.role, H2Role::Server { .. }) {
            return;
        }
        self.graceful_shutdown = true;
        frame::write_goaway(&mut self.out, u32::MAX >> 1, ERROR_NO_ERROR);
        endpoint.send(&self.out);
        self.out.clear();
        if self.server_streams.is_empty() {
            self.finish_graceful_shutdown(endpoint);
        }
    }

    /// Send the final GOAWAY (true last-stream-id) and close, once a
    /// graceful shutdown's in-flight streams have all drained.
    fn finish_graceful_shutdown(&mut self, endpoint: &mut dyn Endpoint) {
        self.send_goaway(ERROR_NO_ERROR);
        endpoint.send(&self.out);
        self.out.clear();
        endpoint.close();
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
            // A zero-length body with `end_stream` still needs its own
            // (empty) DATA frame to actually signal end-of-stream — the
            // Gumdrop session API's incremental body feed can reach this
            // with nothing new to send but the stream now finished (see
            // `feed_client_stream_body`). Callers with a known-bodyless
            // request from the start put END_STREAM on HEADERS instead and
            // never reach this with `end_stream` set.
            if end_stream {
                frame::write_data(&mut self.out, &[], FLAG_END_STREAM, stream_id);
            }
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
        // Streams with an empty backlog but a still-pending END_STREAM need
        // a pass too — that's an explicit "no more body, but still need to
        // send the empty final DATA frame" state from
        // `feed_client_stream_body`.
        let stream_ids: Vec<u32> = self
            .client_streams
            .iter()
            .filter(|(_, s)| !s.pending_body.is_empty() || s.pending_end_stream)
            .map(|(id, _)| *id)
            .collect();
        for id in stream_ids {
            let (body, end_stream) = match self.client_streams.get_mut(&id) {
                Some(s) => (std::mem::take(&mut s.pending_body), s.pending_end_stream),
                None => continue,
            };
            let remaining = self.write_data_flow_controlled(id, &body, end_stream);
            if let Some(s) = self.client_streams.get_mut(&id) {
                let sent_end_stream = remaining.is_empty();
                s.pending_body = remaining;
                if sent_end_stream {
                    s.pending_end_stream = false;
                }
            }
        }
    }

    fn flush_one_server_stream(&mut self, stream_id: u32) {
        // Pull upgrade outbound into the body buffer first.
        if let Some(stream) = self.server_streams.get_mut(&stream_id) {
            if let Some(up) = stream.upgraded.as_mut() {
                let wants_close = up.wants_close();
                let out = up.take_outbound();
                let mut shared = stream.writer.control.shared.lock().unwrap();
                if !out.is_empty() {
                    shared.body.extend_from_slice(&out);
                }
                if wants_close {
                    shared.done = true;
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
            let upgrade_closing = upgraded
                && stream
                    .upgraded
                    .as_ref()
                    .map(|u| u.wants_close())
                    .unwrap_or(false)
                && shared.done;
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
            // Normal responses: END_STREAM when done. Upgraded streams stay open
            // unless the upgrade handler requested close (WS Close / protocol error).
            let done = (shared.done && !upgraded) || upgrade_closing;
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

/// Aggregate a decoded header list's size using RFC 7541 §4.1's accounting
/// model (name length + value length + 32 bytes overhead, per entry) — the
/// same model `SETTINGS_MAX_HEADER_LIST_SIZE` bounds.
fn header_list_size(pairs: &[(String, String)]) -> usize {
    pairs.iter().map(|(name, value)| name.len() + value.len() + 32).sum()
}

/// Header fields whose framing role HTTP/2 carries out-of-band, so the field
/// itself is forbidden on the wire (RFC 9113 §8.2.2).
const CONNECTION_SPECIFIC_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Validate a decoded request header list against RFC 9113 §8.3.1
/// (pseudo-header presence/ordering/uniqueness, including RFC 8441 Extended
/// CONNECT — shared with HTTP/3, see [`crate::pseudo_headers`]) and §8.2.2
/// (connection-specific fields, `TE` value, HTTP/2-only). `Err(())` means
/// the request is malformed and must be rejected with a stream error.
fn validate_request_header_block(pairs: &[(String, String)]) -> Result<(), ()> {
    crate::pseudo_headers::validate_request_pseudo_headers(pairs)?;

    for (name, value) in pairs {
        if name.starts_with(':') {
            continue;
        }
        if CONNECTION_SPECIFIC_HEADERS.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            return Err(());
        }
        if name.eq_ignore_ascii_case("te") && !value.eq_ignore_ascii_case("trailers") {
            return Err(());
        }
    }

    Ok(())
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

    fn goaway_frame(&mut self, payload: &[u8]) {
        self.on_goaway(payload);
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

        if self.graceful_shutdown && self.server_streams.is_empty() && self.state != ConnState::GoAway {
            self.finish_graceful_shutdown(endpoint);
        }

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
        self.fail_client_streams(&std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed",
        ));
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        self.fail_client_streams(&std::io::Error::new(err.kind(), err.to_string()));
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

#[cfg(test)]
mod validation_tests {
    use super::*;
    use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};

    fn encode_headers(pairs: &[(&str, &str)]) -> Vec<u8> {
        super::super::hpack::Encoder::new(4096).encode(pairs.iter().copied())
    }

    struct RecordingHandler {
        opened: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ServerHandler for RecordingHandler {
        fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {
            self.opened.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
    }
    struct RecordingFactory {
        opened: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ServerHandlerFactory for RecordingFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            Box::new(RecordingHandler {
                opened: Arc::clone(&self.opened),
            })
        }
    }

    fn server_endpoint_with_limits(limits: HttpLimits) -> (H2Endpoint, Arc<std::sync::atomic::AtomicUsize>) {
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ep = H2Endpoint::server(
            Arc::new(RecordingFactory {
                opened: Arc::clone(&opened),
            }),
            limits,
            false,
        );
        (ep, opened)
    }

    fn rst_stream_error_code(out: &[u8]) -> u32 {
        assert_eq!(out.len(), 13, "expected exactly one RST_STREAM frame");
        let header = frame::parse_frame_header(&out[..9]);
        assert_eq!(header.ty, frame::TYPE_RST_STREAM);
        u32::from_be_bytes([out[9], out[10], out[11], out[12]])
    }

    #[test]
    fn valid_request_headers_open_a_stream() {
        let (mut ep, opened) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "example.test"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert!(ep.out.is_empty(), "no error frame expected");
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(ep.server_streams.contains_key(&1));
    }

    #[test]
    fn missing_pseudo_header_is_rejected() {
        let (mut ep, opened) = server_endpoint_with_limits(HttpLimits::default());
        // :path is missing.
        let block = encode_headers(&[(":method", "GET"), (":scheme", "https")]);
        ep.process_server_headers_block(1, &block, false);
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!ep.server_streams.contains_key(&1));
        assert_eq!(rst_stream_error_code(&ep.out), ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn duplicate_pseudo_header_is_rejected() {
        let (mut ep, _) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[
            (":method", "GET"),
            (":method", "POST"),
            (":scheme", "https"),
            (":path", "/"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert_eq!(rst_stream_error_code(&ep.out), ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn pseudo_header_after_regular_header_is_rejected() {
        let (mut ep, _) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[
            (":method", "GET"),
            ("x-early", "value"),
            (":scheme", "https"),
            (":path", "/"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert_eq!(rst_stream_error_code(&ep.out), ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn connection_specific_header_is_rejected() {
        let (mut ep, _) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("connection", "keep-alive"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert_eq!(rst_stream_error_code(&ep.out), ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn te_trailers_is_accepted_other_te_values_rejected() {
        let (mut ep, opened) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("te", "trailers"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert!(ep.out.is_empty());
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 1);

        let (mut ep2, _) = server_endpoint_with_limits(HttpLimits::default());
        let block2 = encode_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("te", "gzip"),
        ]);
        ep2.process_server_headers_block(3, &block2, false);
        assert_eq!(rst_stream_error_code(&ep2.out), ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn extended_connect_with_protocol_is_accepted() {
        let (mut ep, opened) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":path", "/chat"),
            (":authority", "example.test"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert!(ep.out.is_empty());
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn plain_connect_requires_authority_and_forbids_scheme_path() {
        let (mut ep, opened) = server_endpoint_with_limits(HttpLimits::default());
        let block = encode_headers(&[(":method", "CONNECT"), (":authority", "example.test:443")]);
        ep.process_server_headers_block(1, &block, false);
        assert!(ep.out.is_empty());
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 1);

        let (mut ep2, _) = server_endpoint_with_limits(HttpLimits::default());
        let block2 = encode_headers(&[
            (":method", "CONNECT"),
            (":authority", "example.test:443"),
            (":scheme", "https"),
        ]);
        ep2.process_server_headers_block(3, &block2, false);
        assert_eq!(rst_stream_error_code(&ep2.out), ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn too_many_header_fields_rejected_enhance_your_calm() {
        let limits = HttpLimits {
            max_header_count: 3,
            ..HttpLimits::default()
        };
        let (mut ep, opened) = server_endpoint_with_limits(limits);
        let block = encode_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            (":authority", "example.test"),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(rst_stream_error_code(&ep.out), ERROR_ENHANCE_YOUR_CALM);
    }

    #[test]
    fn oversized_header_list_rejected_enhance_your_calm() {
        let (mut ep, opened) = server_endpoint_with_limits(HttpLimits::default());
        let big_value = "x".repeat(9_000);
        let block = encode_headers(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("x-big", &big_value),
        ]);
        ep.process_server_headers_block(1, &block, false);
        assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(rst_stream_error_code(&ep.out), ERROR_ENHANCE_YOUR_CALM);
    }
}

/// Minimal [`Endpoint`] stub recording sent bytes / close calls, for tests
/// that don't need real I/O, timers, or reactor plumbing.
#[cfg(test)]
#[derive(Default)]
struct RecordingEndpoint {
    sent: Vec<u8>,
    closed: bool,
}

#[cfg(test)]
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
    fn execute(&self, _task: Box<dyn FnOnce() + Send>) {
        unimplemented!("not exercised by these unit tests")
    }
    fn schedule_timer(&self, _delay: Duration, _callback: Box<dyn FnOnce() + Send>) -> TimerHandle {
        unimplemented!("not exercised by these unit tests")
    }
    fn handle(&self) -> hopf_core::ConnHandle {
        unimplemented!("not exercised by these unit tests")
    }
}

#[cfg(test)]
mod graceful_shutdown_tests {
    use super::*;
    use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};

    struct NoopServerFactory;
    impl ServerHandlerFactory for NoopServerFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }

    fn server_endpoint() -> H2Endpoint {
        H2Endpoint::server(Arc::new(NoopServerFactory), HttpLimits::default(), false)
    }

    /// With no in-flight streams, `shutdown_gracefully` sends both GOAWAY
    /// phases back-to-back (the "stop opening streams" signal, then
    /// immediately the final one) and closes.
    #[test]
    fn shutdown_with_no_streams_closes_immediately() {
        let mut ep = server_endpoint();
        let mut endpoint = RecordingEndpoint::default();
        ep.shutdown_gracefully(&mut endpoint);

        assert!(endpoint.closed);
        assert_eq!(endpoint.sent.len(), 34, "expected two back-to-back GOAWAY frames");
        let first = frame::parse_frame_header(&endpoint.sent[..9]);
        assert_eq!(first.ty, frame::TYPE_GOAWAY);
        let first_last_stream_id =
            u32::from_be_bytes([endpoint.sent[9], endpoint.sent[10], endpoint.sent[11], endpoint.sent[12]]);
        assert_eq!(first_last_stream_id, u32::MAX >> 1);

        let second = frame::parse_frame_header(&endpoint.sent[17..26]);
        assert_eq!(second.ty, frame::TYPE_GOAWAY);
        let second_last_stream_id = u32::from_be_bytes([
            endpoint.sent[26],
            endpoint.sent[27],
            endpoint.sent[28],
            endpoint.sent[29],
        ]);
        assert_eq!(second_last_stream_id, 0, "no streams were ever opened");
        assert_eq!(ep.state, ConnState::GoAway);
    }

    /// With a stream still open, the first call sends only the "stop
    /// opening streams" GOAWAY(2^31-1) and does not close; new streams are
    /// refused with RST_STREAM(REFUSED_STREAM) in the meantime.
    #[test]
    fn shutdown_with_open_stream_defers_close_and_refuses_new_streams() {
        let mut ep = server_endpoint();
        ep.server_streams.insert(
            1,
            H2ServerStream {
                id: 1,
                handler: Box::new(NoopHandler),
                writer: H2StreamWriter::new(1),
                half_closed_remote: true,
                paused_body: Vec::new(),
                paused_end_stream: false,
                upgraded: None,
            },
        );

        let mut endpoint = RecordingEndpoint::default();
        ep.shutdown_gracefully(&mut endpoint);

        assert!(!endpoint.closed, "must wait for the open stream to drain");
        assert_eq!(endpoint.sent.len(), 17, "expected exactly one GOAWAY frame");
        let last_stream_id =
            u32::from_be_bytes([endpoint.sent[9], endpoint.sent[10], endpoint.sent[11], endpoint.sent[12]]);
        assert_eq!(last_stream_id, u32::MAX >> 1);
        assert_ne!(ep.state, ConnState::GoAway);

        // A racing new stream is refused while draining.
        ep.process_server_headers_block(3, &[], false);
        assert!(!ep.server_streams.contains_key(&3));
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_RST_STREAM);
    }

    struct NoopHandler;
    impl ServerHandler for NoopHandler {
        fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}
        fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
    }
}

#[cfg(test)]
mod client_goaway_tests {
    use super::*;
    use crate::stream::{ClientHandler, ClientHandlerFactory, ClientWriter};

    struct NoopClientFactory;
    impl ClientHandlerFactory for NoopClientFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }

    fn client_endpoint() -> H2Endpoint {
        H2Endpoint::client(Arc::new(NoopClientFactory), HttpLimits::default(), false)
    }

    struct FailTrackingHandler {
        failed: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ClientHandler for FailTrackingHandler {
        fn start(&mut self, _request: &mut dyn ClientWriter) {}
        fn response_headers(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {}
        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
            panic!("response_complete must not fire for a GOAWAY'd stream");
        }
        fn request_failed(&mut self, _request: &mut dyn ClientWriter, _err: &std::io::Error) {
            self.failed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn goaway_payload(last_stream_id: u32, error_code: u32) -> Vec<u8> {
        let mut out = Vec::new();
        frame::write_goaway(&mut out, last_stream_id, error_code);
        out[9..].to_vec()
    }

    fn insert_client_stream(ep: &mut H2Endpoint, id: u32, failed: &Arc<std::sync::atomic::AtomicUsize>) {
        ep.client_streams.insert(
            id,
            H2ClientStream {
                id,
                handler: Box::new(FailTrackingHandler {
                    failed: Arc::clone(failed),
                }),
                response_headers_received: false,
                response_body_started: false,
                pending_body: Vec::new(),
                pending_end_stream: false,
            },
        );
        ep.flow.open_stream(id, crate::h2::flow::INITIAL_WINDOW_SIZE);
    }

    /// Streams above the peer's announced last-stream-id are failed with
    /// `request_failed`, not silently left to hang.
    #[test]
    fn goaway_fails_streams_above_last_stream_id() {
        let mut ep = client_endpoint();
        let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        insert_client_stream(&mut ep, 1, &failed);
        insert_client_stream(&mut ep, 3, &failed);
        insert_client_stream(&mut ep, 5, &failed);

        ep.on_goaway(&goaway_payload(3, ERROR_NO_ERROR));

        assert_eq!(failed.load(std::sync::atomic::Ordering::SeqCst), 1, "only stream 5 is above last_stream_id=3");
        assert!(ep.client_streams.contains_key(&1));
        assert!(ep.client_streams.contains_key(&3));
        assert!(!ep.client_streams.contains_key(&5));
        assert_eq!(ep.state, ConnState::GoAway);
    }

    /// `last_stream_id = 0` (e.g. the peer never processed anything) fails
    /// every in-flight stream.
    #[test]
    fn goaway_with_zero_last_stream_id_fails_everything() {
        let mut ep = client_endpoint();
        let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        insert_client_stream(&mut ep, 1, &failed);
        insert_client_stream(&mut ep, 3, &failed);

        ep.on_goaway(&goaway_payload(0, ERROR_PROTOCOL_ERROR));

        assert_eq!(failed.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(ep.client_streams.is_empty());
    }
}

#[cfg(test)]
mod state_machine_tests {
    use super::*;
    use crate::stream::{ClientHandler, ClientHandlerFactory, ServerHandler, ServerHandlerFactory};

    struct NoopServerFactory;
    impl ServerHandlerFactory for NoopServerFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }
    fn server_endpoint() -> H2Endpoint {
        H2Endpoint::server(Arc::new(NoopServerFactory), HttpLimits::default(), false)
    }

    struct NoopClientFactory;
    impl ClientHandlerFactory for NoopClientFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }
    fn client_endpoint() -> H2Endpoint {
        H2Endpoint::client(Arc::new(NoopClientFactory), HttpLimits::default(), false)
    }

    #[test]
    fn stream_state_idle_for_id_never_seen() {
        let ep = server_endpoint();
        assert_eq!(ep.stream_state(1), StreamState::Idle);
        assert_eq!(ep.stream_state(99), StreamState::Idle);
    }

    #[test]
    fn stream_state_open_while_tracked() {
        let mut ep = server_endpoint();
        ep.last_stream_id = 1;
        ep.server_streams.insert(
            1,
            H2ServerStream {
                id: 1,
                handler: Box::new(NoopServerHandler),
                writer: H2StreamWriter::new(1),
                half_closed_remote: true,
                paused_body: Vec::new(),
                paused_end_stream: false,
                upgraded: None,
            },
        );
        assert_eq!(ep.stream_state(1), StreamState::Open);
    }

    #[test]
    fn stream_state_closed_once_used_id_is_no_longer_tracked() {
        let mut ep = server_endpoint();
        // Simulate stream 3 having been opened and since finished: it
        // advanced last_stream_id but no longer has a HashMap entry.
        ep.last_stream_id = 3;
        assert_eq!(ep.stream_state(1), StreamState::Closed);
        assert_eq!(ep.stream_state(3), StreamState::Closed);
        assert_eq!(ep.stream_state(5), StreamState::Idle, "above last_stream_id");
    }

    struct NoopServerHandler;
    impl ServerHandler for NoopServerHandler {
        fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}
        fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
    }

    #[test]
    fn data_on_idle_server_stream_is_a_connection_error() {
        let mut ep = server_endpoint();
        ep.on_data(3, 0, b"unexpected");
        assert_eq!(ep.state, ConnState::GoAway);
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_GOAWAY);
        let error_code = u32::from_be_bytes([ep.out[13], ep.out[14], ep.out[15], ep.out[16]]);
        assert_eq!(error_code, ERROR_PROTOCOL_ERROR);
    }

    #[test]
    fn data_on_closed_server_stream_gets_rst_stream_closed() {
        let mut ep = server_endpoint();
        ep.last_stream_id = 3;
        ep.on_data(3, 0, b"late data");
        assert_ne!(ep.state, ConnState::GoAway, "connection stays open");
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_RST_STREAM);
        let error_code = u32::from_be_bytes([ep.out[9], ep.out[10], ep.out[11], ep.out[12]]);
        assert_eq!(error_code, ERROR_STREAM_CLOSED);
    }

    #[test]
    fn data_on_open_server_stream_is_delivered_normally() {
        let mut ep = server_endpoint();
        ep.last_stream_id = 1;
        ep.server_streams.insert(
            1,
            H2ServerStream {
                id: 1,
                handler: Box::new(NoopServerHandler),
                writer: H2StreamWriter::new(1),
                half_closed_remote: false,
                paused_body: Vec::new(),
                paused_end_stream: false,
                upgraded: None,
            },
        );
        ep.on_data(1, 0, b"hello");
        assert!(ep.out.is_empty(), "no error frame for an open stream");
        assert!(ep.server_streams.contains_key(&1), "stream must survive");
    }

    #[test]
    fn rst_stream_on_idle_server_stream_is_a_connection_error() {
        let mut ep = server_endpoint();
        ep.on_rst_stream(3, &[0, 0, 0, 0]);
        assert_eq!(ep.state, ConnState::GoAway);
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_GOAWAY);
    }

    #[test]
    fn rst_stream_on_closed_server_stream_is_tolerated_silently() {
        let mut ep = server_endpoint();
        ep.last_stream_id = 3;
        ep.on_rst_stream(3, &[0, 0, 0, 0]);
        assert_ne!(ep.state, ConnState::GoAway);
        assert!(ep.out.is_empty(), "no reply needed for a late RST_STREAM");
    }

    #[test]
    fn data_on_idle_client_stream_is_a_connection_error() {
        let mut ep = client_endpoint();
        ep.on_data(3, 0, b"unexpected");
        assert_eq!(ep.state, ConnState::GoAway);
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_GOAWAY);
    }

    #[test]
    fn data_on_closed_client_stream_gets_rst_stream_closed() {
        let mut ep = client_endpoint();
        ep.last_stream_id = 1;
        ep.on_data(1, 0, b"late data");
        assert_ne!(ep.state, ConnState::GoAway);
        let header = frame::parse_frame_header(&ep.out[..9]);
        assert_eq!(header.ty, frame::TYPE_RST_STREAM);
        let error_code = u32::from_be_bytes([ep.out[9], ep.out[10], ep.out[11], ep.out[12]]);
        assert_eq!(error_code, ERROR_STREAM_CLOSED);
    }
}

#[cfg(test)]
mod client_informational_response_tests {
    use super::*;
    use crate::stream::{ClientHandler, ClientHandlerFactory, ClientWriter};

    fn encode_headers(pairs: &[(&str, &str)]) -> Vec<u8> {
        super::super::hpack::Encoder::new(4096).encode(pairs.iter().copied())
    }

    struct NoopClientFactory;
    impl ClientHandlerFactory for NoopClientFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            unimplemented!("not exercised by these unit tests")
        }
    }
    fn client_endpoint() -> H2Endpoint {
        H2Endpoint::client(Arc::new(NoopClientFactory), HttpLimits::default(), false)
    }

    #[derive(Default)]
    struct Recorded {
        informational_statuses: Vec<u16>,
        final_status: Option<u16>,
        trailers_seen: usize,
        completed: usize,
    }

    struct RecordingHandler {
        rec: Arc<std::sync::Mutex<Recorded>>,
    }
    impl ClientHandler for RecordingHandler {
        fn start(&mut self, _request: &mut dyn ClientWriter) {}
        fn informational_response(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().informational_statuses.push(headers.status_code());
        }
        fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().final_status = Some(headers.status_code());
        }
        fn response_trailers(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {
            self.rec.lock().unwrap().trailers_seen += 1;
        }
        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
            self.rec.lock().unwrap().completed += 1;
        }
    }

    fn insert_stream(ep: &mut H2Endpoint, id: u32, rec: &Arc<std::sync::Mutex<Recorded>>) {
        ep.client_streams.insert(
            id,
            H2ClientStream {
                id,
                handler: Box::new(RecordingHandler { rec: Arc::clone(rec) }),
                response_headers_received: false,
                response_body_started: false,
                pending_body: Vec::new(),
                pending_end_stream: false,
            },
        );
    }

    /// A `100 Continue` (or `103 Early Hints`) HEADERS frame is surfaced via
    /// `informational_response` and does not consume the "first HEADERS"
    /// slot — the real final response still lands on `response_headers`,
    /// not `response_trailers`.
    #[test]
    fn interim_1xx_then_final_response_dispatch_correctly() {
        let mut ep = client_endpoint();
        let rec = Arc::new(std::sync::Mutex::new(Recorded::default()));
        insert_stream(&mut ep, 1, &rec);

        let interim = encode_headers(&[(":status", "100")]);
        ep.process_client_response_headers(1, &interim, false);

        let final_headers = encode_headers(&[(":status", "200")]);
        ep.process_client_response_headers(1, &final_headers, true);

        let r = rec.lock().unwrap();
        assert_eq!(r.informational_statuses, vec![100]);
        assert_eq!(r.final_status, Some(200));
        assert_eq!(r.trailers_seen, 0, "the final response must not be mistaken for trailers");
        assert_eq!(r.completed, 1);
    }

    /// Multiple interim responses (e.g. 103 Early Hints then 100 Continue)
    /// are each surfaced individually before the real final response.
    #[test]
    fn multiple_interim_responses_all_surfaced() {
        let mut ep = client_endpoint();
        let rec = Arc::new(std::sync::Mutex::new(Recorded::default()));
        insert_stream(&mut ep, 1, &rec);

        ep.process_client_response_headers(1, &encode_headers(&[(":status", "103")]), false);
        ep.process_client_response_headers(1, &encode_headers(&[(":status", "100")]), false);
        ep.process_client_response_headers(1, &encode_headers(&[(":status", "200")]), true);

        let r = rec.lock().unwrap();
        assert_eq!(r.informational_statuses, vec![103, 100]);
        assert_eq!(r.final_status, Some(200));
        assert_eq!(r.completed, 1);
    }

    /// A real (non-1xx) final response is unaffected — no informational
    /// callback fires, and a genuine second HEADERS frame after it is
    /// still treated as trailers.
    #[test]
    fn no_interim_response_final_headers_then_trailers() {
        let mut ep = client_endpoint();
        let rec = Arc::new(std::sync::Mutex::new(Recorded::default()));
        insert_stream(&mut ep, 1, &rec);

        ep.process_client_response_headers(1, &encode_headers(&[(":status", "200")]), false);
        ep.process_client_response_headers(1, &encode_headers(&[("grpc-status", "0")]), true);

        let r = rec.lock().unwrap();
        assert!(r.informational_statuses.is_empty());
        assert_eq!(r.final_status, Some(200));
        assert_eq!(r.trailers_seen, 1);
        assert_eq!(r.completed, 1);
    }

}

/// [`open_client_stream`](H2Endpoint::open_client_stream) /
/// [`feed_client_stream_body`](H2Endpoint::feed_client_stream_body) —
/// the low-level halves behind the Gumdrop session API's incremental H2
/// body streaming (issue #84: headers open the stream promptly, DATA
/// frames go out per `request_body_content` call instead of being
/// buffered until `end_request_body`).
#[cfg(test)]
mod gumdrop_client_stream_tests {
    use super::*;

    struct NoopClientFactory;
    impl ClientHandlerFactory for NoopClientFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            unimplemented!("open_client_stream takes a handler directly; unused here")
        }
    }

    struct NoopClientHandler;
    impl ClientHandler for NoopClientHandler {
        fn start(&mut self, _request: &mut dyn ClientWriter) {
            unimplemented!("constructed pre-started; never goes through start()")
        }
        fn response_headers(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {}
        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {}
    }

    fn open_client() -> H2Endpoint {
        let mut ep = H2Endpoint::client(Arc::new(NoopClientFactory), HttpLimits::default(), false);
        ep.state = ConnState::Open;
        ep
    }

    fn request_headers() -> Headers {
        let mut h = Headers::new();
        h.set(":method", "PUT");
        h.set(":path", "/upload");
        h.set(":scheme", "http");
        h.set(":authority", "ex.com");
        h
    }

    /// (payload length, END_STREAM set) for every DATA frame in `bytes`.
    fn data_frames(bytes: &[u8]) -> Vec<(usize, bool)> {
        let mut out = Vec::new();
        let mut offset = 0;
        while offset + 9 <= bytes.len() {
            let header = frame::parse_frame_header(&bytes[offset..offset + 9]);
            let payload_end = offset + 9 + header.length as usize;
            if header.ty == frame::TYPE_DATA {
                out.push((header.length as usize, header.flags & FLAG_END_STREAM != 0));
            }
            offset = payload_end;
        }
        out
    }

    #[test]
    fn open_client_stream_sends_headers_without_touching_body() {
        let mut ep = open_client();
        let mut endpoint = RecordingEndpoint::default();

        let stream_id = ep
            .open_client_stream(request_headers(), Box::new(NoopClientHandler), false, &mut endpoint)
            .expect("stream opens");

        assert_eq!(stream_id, 1);
        assert!(ep.client_streams.contains_key(&1));
        assert!(
            data_frames(&endpoint.sent).is_empty(),
            "no DATA frame before any body is fed"
        );
        let header = frame::parse_frame_header(&endpoint.sent[..9]);
        assert_eq!(header.ty, frame::TYPE_HEADERS);
        assert_eq!(
            header.flags & FLAG_END_STREAM,
            0,
            "stream must stay open — a body is coming"
        );
    }

    #[test]
    fn feed_client_stream_body_emits_one_data_frame_per_call_before_end() {
        let mut ep = open_client();
        let mut endpoint = RecordingEndpoint::default();
        let stream_id = ep
            .open_client_stream(request_headers(), Box::new(NoopClientHandler), false, &mut endpoint)
            .unwrap();
        endpoint.sent.clear();

        ep.feed_client_stream_body(stream_id, b"chunk one ", false, &mut endpoint);
        ep.feed_client_stream_body(stream_id, b"chunk two ", false, &mut endpoint);
        ep.feed_client_stream_body(stream_id, b"chunk three", true, &mut endpoint);

        let frames = data_frames(&endpoint.sent);
        assert_eq!(
            frames,
            vec![
                (b"chunk one ".len(), false),
                (b"chunk two ".len(), false),
                (b"chunk three".len(), true),
            ],
            "each feed_client_stream_body call must reach the wire as its own DATA \
             frame before end_request_body, not get buffered until the end (#84)"
        );
    }

    #[test]
    fn feed_client_stream_body_sends_empty_end_stream_frame_when_body_already_flushed() {
        let mut ep = open_client();
        let mut endpoint = RecordingEndpoint::default();
        let stream_id = ep
            .open_client_stream(request_headers(), Box::new(NoopClientHandler), false, &mut endpoint)
            .unwrap();

        ep.feed_client_stream_body(stream_id, b"only chunk", false, &mut endpoint);
        endpoint.sent.clear();
        ep.feed_client_stream_body(stream_id, b"", true, &mut endpoint);

        assert_eq!(
            data_frames(&endpoint.sent),
            vec![(0, true)],
            "a final empty-body end_request_body call must still send a DATA frame \
             carrying END_STREAM, not silently no-op"
        );
    }

    #[test]
    fn open_client_stream_returns_none_when_connection_not_ready() {
        let mut ep = H2Endpoint::client(Arc::new(NoopClientFactory), HttpLimits::default(), false);
        // Left at the default pre-handshake state.
        let mut endpoint = RecordingEndpoint::default();

        let result =
            ep.open_client_stream(request_headers(), Box::new(NoopClientHandler), false, &mut endpoint);

        assert!(result.is_none());
        assert!(ep.client_streams.is_empty());
    }
}
