// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 client connection and request-stream adapters.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler};
use hopf_quic::{
    connect_quic_hooks, DatagramDecode, QuicClientConfig, QuicConnApi, QuicConnection,
    QuicDriverHandle,
};

use crate::{
    ClientHandler, ClientHandlerFactory, ClientWriter, Headers, HttpLimits, ProtocolUpgradeHandler,
};

use super::endpoint::{decode_h3_datagram, H3PeerState, H3UniStream};
use super::{frame, message_body, qpack, stream_phase, H3FrameHandler, H3Parser};

/// Client-initiated stream factories queued to be opened on a live H3
/// connection — FIFO: each [`QuicConnApi::open_bi`] call recorded by
/// [`H3ClientConnection::drain_pending_opens`] is matched, in order, to the
/// next `accept_bi` call the driver makes for it (see
/// [`crate::client::h3_session`] for the multi-request session that
/// populates this from outside the driver thread).
pub(crate) type PendingOpens = Arc<Mutex<std::collections::VecDeque<Arc<dyn ClientHandlerFactory>>>>;
/// One-shot "the QUIC handshake completed" signal — see
/// [`H3ClientConnection::connected`].
pub(crate) type OnReady = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// HTTP/3 client connection installed in the QUIC hooks driver.
pub struct H3ClientConnection {
    limits: HttpLimits,
    peer_state: Arc<Mutex<H3PeerState>>,
    qpack: Arc<qpack::H3Qpack>,
    qpack_encoder_stream_key: Option<u64>,
    qpack_decoder_stream_key: Option<u64>,
    pending_opens: PendingOpens,
    on_ready: OnReady,
}

impl H3ClientConnection {
    /// Create an HTTP/3 client connection that eagerly opens exactly one
    /// request stream once connected, driving it from `factory` — the
    /// shape every existing caller ([`connect_h3`]) still wants. For a
    /// connection whose requests are decided over time (a session issuing
    /// many sequential requests), see [`connect_h3_session`].
    pub fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        let pending_opens: PendingOpens = Arc::new(Mutex::new(std::collections::VecDeque::from([factory])));
        Self::with_shared_state(pending_opens, Arc::new(Mutex::new(None)), limits)
    }

    pub(crate) fn with_shared_state(pending_opens: PendingOpens, on_ready: OnReady, limits: HttpLimits) -> Self {
        Self {
            limits,
            peer_state: Arc::new(Mutex::new(H3PeerState::default())),
            qpack: Arc::new(qpack::H3Qpack::new()),
            qpack_encoder_stream_key: None,
            qpack_decoder_stream_key: None,
            pending_opens,
            on_ready,
        }
    }

    /// Record one `open_bi` per factory currently queued (whatever's
    /// queued *now* — anything pushed after this call waits for the next
    /// `drive` tick, prompted via [`hopf_quic::QuicDriverHandle::poke_hooks`]).
    /// `hopf-quic`'s driver attaches each recorded open to the next
    /// [`Self::accept_bi`] call it makes for this connection, in the same
    /// order, so factories are handed out FIFO.
    fn drain_pending_opens(&mut self, api: &mut dyn QuicConnApi) {
        // RFC 9114 §5.2: after a peer GOAWAY, MUST NOT initiate new requests.
        if self.peer_state.lock().unwrap().goaway_received.is_some() {
            return;
        }
        let count = self.pending_opens.lock().unwrap().len();
        for _ in 0..count {
            let _ = api.open_bi();
        }
    }

    /// Write any QPACK instruction bytes queued since the last flush onto
    /// our own encoder/decoder uni streams — the only opportunity to do so
    /// outside `connected()` (see [`hopf_quic::QuicConnection::drive`]).
    fn flush_qpack(&self, api: &mut dyn QuicConnApi) {
        let (enc, dec) = self.qpack.take_pending();
        if let (Some(key), false) = (self.qpack_encoder_stream_key, enc.is_empty()) {
            api.write(key, &enc);
        }
        if let (Some(key), false) = (self.qpack_decoder_stream_key, dec.is_empty()) {
            api.write(key, &dec);
        }
    }
}

impl QuicConnection for H3ClientConnection {
    fn connected(&mut self, api: &mut dyn QuicConnApi) {
        if let Some(stream) = api.open_uni() {
            let mut bytes = vec![0x00];
            frame::write_settings(
                &mut bytes,
                qpack::MAX_TABLE_CAPACITY as u64,
                0, // SETTINGS_QPACK_BLOCKED_STREAMS — non-blocking encoder
                frame::DEFAULT_MAX_FIELD_SECTION_SIZE,
            );
            api.write(stream, &bytes);
        }
        if let Some(stream) = api.open_uni() {
            api.write(stream, &[0x02]); // QPACK encoder stream type
            self.qpack_encoder_stream_key = Some(stream);
        }
        if let Some(stream) = api.open_uni() {
            api.write(stream, &[0x03]); // QPACK decoder stream type
            self.qpack_decoder_stream_key = Some(stream);
        }
        self.flush_qpack(api);
        // Request stream(s) — whatever's queued so far (the single seed
        // factory for [`Self::new`]'s callers, or nothing yet for a
        // session that hasn't issued its first request).
        self.drain_pending_opens(api);
        if let Some(cb) = self.on_ready.lock().unwrap().take() {
            cb();
        }
    }

    fn accept_bi(&mut self, stream_id: u64) -> Box<dyn ProtocolHandler> {
        // RFC 9114: clients MUST NOT accept server-initiated bidirectional
        // streams (IDs where stream_id % 4 == 1).
        if stream_id % 4 != 0 {
            return Box::new(RejectServerInitiatedBiStream);
        }
        let factory = self
            .pending_opens
            .lock()
            .unwrap()
            .pop_front()
            .expect("accept_bi called without a matching queued factory — drain_pending_opens/open_bi calls must stay 1:1 with queued factories");
        Box::new(H3ClientStream::new(
            factory,
            self.limits,
            stream_id,
            Arc::clone(&self.qpack),
            Arc::clone(&self.peer_state),
        ))
    }

    fn accept_uni(&mut self, _stream_id: u64) -> Box<dyn ProtocolHandler> {
        Box::new(H3UniStream::new(Arc::clone(&self.peer_state), Arc::clone(&self.qpack), true))
    }

    fn drive(&mut self, api: &mut dyn QuicConnApi) {
        self.flush_qpack(api);
        self.drain_pending_opens(api);
    }

    fn decode_datagram(&mut self, data: &[u8]) -> DatagramDecode {
        decode_h3_datagram(&self.peer_state, data)
    }
}

/// Dial an HTTP/3 peer (ALPN `h3`), eagerly opening exactly one request
/// stream driven by `factory` once connected.
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

/// Dial an HTTP/3 peer for session-based use, where the caller decides
/// requests over time rather than eagerly at connect time (see
/// [`crate::client::h3_session::H3HttpClientSession`]).
///
/// No stream is opened here — the caller pushes factories onto the
/// returned queue and calls [`QuicDriverHandle::poke_hooks`] each time
/// (the connection may not even be established yet; queued factories are
/// opened once it is, same as [`connect_h3`]'s single eager stream).
/// `on_ready` fires exactly once, from the driver thread, the moment the
/// QUIC/TLS handshake completes — the caller's cue that issuing requests
/// is now meaningful (nothing stops it earlier either, they'd just wait in
/// the queue).
pub(crate) fn connect_h3_session(
    addr: SocketAddr,
    client_config: Arc<QuicClientConfig>,
    server_name: impl Into<String>,
    limits: HttpLimits,
    on_ready: Box<dyn FnOnce() + Send>,
) -> io::Result<(QuicDriverHandle, PendingOpens)> {
    let pending_opens: PendingOpens = Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let pending_opens2 = Arc::clone(&pending_opens);
    let on_ready_slot: OnReady = Arc::new(Mutex::new(Some(on_ready)));
    let handle = connect_quic_hooks(
        addr,
        client_config,
        server_name,
        Arc::new(move || {
            Box::new(H3ClientConnection::with_shared_state(
                Arc::clone(&pending_opens2),
                Arc::clone(&on_ready_slot),
                limits,
            )) as Box<dyn QuicConnection>
        }),
    )?;
    Ok((handle, pending_opens))
}

/// Buffered outbound request during [`ClientHandler::start`].
struct H3ClientWriter {
    request_headers: Option<Headers>,
    body: Vec<u8>,
    trailers: Option<Headers>,
    done: bool,
}

/// Outbound request held while waiting for peer SETTINGS so Extended
/// CONNECT can consult [`H3PeerState::peer_enable_connect_protocol`].
struct PendingOutbound {
    headers: Headers,
    body: Vec<u8>,
    trailers: Option<Headers>,
    done: bool,
}

/// True when this is Extended CONNECT (`CONNECT` + `:protocol`, RFC 9220).
fn is_extended_connect(headers: &Headers) -> bool {
    headers
        .get(":method")
        .is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"))
        && headers.get(":protocol").is_some()
}

const EXTENDED_CONNECT_NOT_ENABLED: &str =
    "peer does not support Extended CONNECT (RFC 9220): SETTINGS_ENABLE_CONNECT_PROTOCOL was not advertised";

impl H3ClientWriter {
    fn new() -> Self {
        Self {
            request_headers: None,
            body: Vec::new(),
            trailers: None,
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
        // H3 has no connection-specific fields at all (RFC 9114 §4.2) and
        // no equivalent of H2's client-initiated graceful shutdown to act
        // on `Connection: close` with — the caller building the request
        // has no reason to know that, so this just quietly disappears
        // rather than reaching the wire as a protocol violation.
        crate::utils::strip_connection_specific_request_headers(&mut headers);
        self.request_headers = Some(headers);
    }

    fn start_request_body(&mut self) {}

    fn request_body_content(&mut self, data: &[u8]) {
        self.body.extend_from_slice(data);
    }

    fn end_request_body(&mut self) {
        self.done = true;
    }

    fn trailers(&mut self, headers: Headers) {
        self.trailers = Some(headers);
        self.done = true;
    }

    fn complete_request(&mut self) {
        self.done = true;
    }

    fn version(&self) -> crate::version::HttpVersion {
        crate::version::HttpVersion::Http3
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        // `start()` never needs a working cross-thread handle — see
        // `ClientWriter::conn_handle`'s own doc comment.
        hopf_core::ConnHandle::from_execute(Arc::new(|task| task()))
    }
}

struct NullClientWriter;

impl ClientWriter for NullClientWriter {
    fn headers(&mut self, _: Headers) {}
    fn start_request_body(&mut self) {}
    fn request_body_content(&mut self, _: &[u8]) {}
    fn end_request_body(&mut self) {}
    fn complete_request(&mut self) {}

    fn version(&self) -> crate::version::HttpVersion {
        crate::version::HttpVersion::Http3
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        // Only reached for a request that's already failed/completed — not
        // a meaningful connection to hand out; see
        // `ClientWriter::conn_handle`'s own doc comment.
        hopf_core::ConnHandle::from_execute(Arc::new(|task| task()))
    }
}

/// [`ClientWriter`] passed to
/// [`ClientHandler::switching_protocols`](crate::stream::ClientHandler::switching_protocols)
/// on a client stream — the request is already fully sent by this point, so
/// everything except [`ClientWriter::upgrade`] is a no-op.
struct H3ClientUpgradeWriter<'a> {
    pending: &'a mut Option<Box<dyn ProtocolUpgradeHandler>>,
    conn: hopf_core::ConnHandle,
}

impl ClientWriter for H3ClientUpgradeWriter<'_> {
    fn headers(&mut self, _: Headers) {}
    fn start_request_body(&mut self) {}
    fn request_body_content(&mut self, _: &[u8]) {}
    fn end_request_body(&mut self) {}
    fn complete_request(&mut self) {}

    fn upgrade(&mut self, handler: Box<dyn ProtocolUpgradeHandler>) -> bool {
        if self.pending.is_some() {
            return false;
        }
        *self.pending = Some(handler);
        true
    }

    fn version(&self) -> crate::version::HttpVersion {
        crate::version::HttpVersion::Http3
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        self.conn.clone()
    }
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

/// Rejects server-initiated bidirectional streams on an HTTP/3 client.
struct RejectServerInitiatedBiStream;

impl ProtocolHandler for RejectServerInitiatedBiStream {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        endpoint.close_connection(frame::H3_STREAM_CREATION_ERROR);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, _: &mut &[u8]) {
        endpoint.close_connection(frame::H3_STREAM_CREATION_ERROR);
    }

    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

/// One outbound H3 request / inbound response on a bidirectional QUIC stream.
struct H3ClientStream {
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    stream_id: u64,
    qpack: Arc<qpack::H3Qpack>,
    peer_state: Arc<Mutex<H3PeerState>>,
    parser: H3Parser,
    handler: Option<Box<dyn ClientHandler>>,
    response_headers_received: bool,
    response_body_started: bool,
    started: bool,
    /// Set when the response HEADERS failed `:status` validation — checked
    /// in `receive()`'s tail, where an `Endpoint` is available to abort
    /// the stream.
    malformed: bool,
    /// Set when a HEADERS payload failed to QPACK-decode — checked in
    /// `receive()`'s tail, where an `Endpoint` is available to close the
    /// connection (RFC 9204 §4.5.1: `QPACK_DECOMPRESSION_FAILED`).
    qpack_error: bool,
    /// Oversized response field section — stream error `H3_EXCESSIVE_LOAD`.
    excessive_load: bool,
    /// Connection-level frame violations (e.g. unsolicited PUSH_PROMISE).
    connection_error: Option<u32>,
    /// Outbound request deferred until peer SETTINGS makes
    /// `peer_enable_connect_protocol` known (Extended CONNECT only).
    pending_outbound: Option<PendingOutbound>,
    body_tracker: message_body::MessageBodyTracker,
    message_phase: stream_phase::StreamMessagePhase,
    /// Whether the outbound request was Extended CONNECT (RFC 8441/9220) —
    /// only such a request's first `2xx` response is treated as a protocol
    /// switch rather than an ordinary response.
    is_extended_connect: bool,
    /// Installed once the app calls `ClientWriter::upgrade` from
    /// `switching_protocols` — subsequent DATA frames (and native QUIC
    /// datagrams) on this stream go to it instead of `handler`.
    upgraded: Option<Box<dyn ProtocolUpgradeHandler>>,
    /// Whether the upgraded stream carries Capsule Protocol framing (RFC
    /// 9297 §3.4) rather than raw DATA-frame bytes.
    capsule_mode: bool,
    capsule_parser: crate::capsule::CapsuleParser,
    /// See [`ClientWriter::conn_handle`] — a synchronous no-op handle until
    /// [`ProtocolHandler::connected`] binds the real one.
    conn: hopf_core::ConnHandle,
}

impl H3ClientStream {
    fn new(
        factory: Arc<dyn ClientHandlerFactory>,
        limits: HttpLimits,
        stream_id: u64,
        qpack: Arc<qpack::H3Qpack>,
        peer_state: Arc<Mutex<H3PeerState>>,
    ) -> Self {
        Self {
            factory,
            limits,
            stream_id,
            qpack,
            peer_state,
            parser: H3Parser::new(),
            handler: None,
            response_headers_received: false,
            response_body_started: false,
            started: false,
            malformed: false,
            qpack_error: false,
            excessive_load: false,
            connection_error: None,
            pending_outbound: None,
            body_tracker: message_body::MessageBodyTracker::default(),
            message_phase: stream_phase::StreamMessagePhase::default(),
            is_extended_connect: false,
            upgraded: None,
            capsule_mode: false,
            capsule_parser: crate::capsule::CapsuleParser::new(),
            conn: hopf_core::ConnHandle::from_execute(Arc::new(|task| task())),
        }
    }

    fn emit_request(&mut self, endpoint: &mut dyn Endpoint, pending: &PendingOutbound) {
        let req_pairs: Vec<(String, String)> = pending
            .headers
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect();
        if crate::pseudo_headers::validate_request_pseudo_headers(&req_pairs).is_err() {
            if let Some(handler) = &mut self.handler {
                handler.request_failed(
                    &mut NullClientWriter,
                    &io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed H3 request pseudo-headers",
                    ),
                );
            }
            endpoint.abort(frame::H3_MESSAGE_ERROR);
            return;
        }
        if let Some(trailers) = &pending.trailers {
            let trailer_pairs: Vec<(String, String)> = trailers
                .iter()
                .map(|h| (h.name.clone(), h.value.clone()))
                .collect();
            if crate::utils::field_section_contains_pseudo_headers(&trailer_pairs) {
                if let Some(handler) = &mut self.handler {
                    handler.request_failed(
                        &mut NullClientWriter,
                        &io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed H3 request trailers: pseudo-headers forbidden",
                        ),
                    );
                }
                endpoint.abort(frame::H3_MESSAGE_ERROR);
                return;
            }
        }

        let req_size = frame::field_section_size(
            pending
                .headers
                .iter()
                .map(|h| (h.name.as_str(), h.value.as_str())),
        );
        if let Some(max) = self.peer_state.lock().unwrap().peer_max_field_section_size {
            if req_size as u64 > max {
                if let Some(handler) = &mut self.handler {
                    handler.request_failed(
                        &mut NullClientWriter,
                        &io::Error::new(
                            io::ErrorKind::InvalidData,
                            "request field section exceeds peer SETTINGS_MAX_FIELD_SECTION_SIZE",
                        ),
                    );
                }
                endpoint.abort(frame::H3_EXCESSIVE_LOAD);
                return;
            }
        }

        let mut out = Vec::new();
        let block = self.qpack.encode_field_section(
            self.stream_id,
            pending
                .headers
                .iter()
                .map(|h| (h.name.as_str(), h.value.as_str())),
        );
        frame::write_headers(&mut out, &block);
        if !pending.body.is_empty() {
            frame::write_data(&mut out, &pending.body);
        }
        if let Some(trailers) = &pending.trailers {
            let block = self.qpack.encode_field_section(
                self.stream_id,
                trailers.iter().map(|h| (h.name.as_str(), h.value.as_str())),
            );
            frame::write_headers(&mut out, &block);
        }
        if !out.is_empty() {
            endpoint.send(&out);
        }
        if pending.done {
            endpoint.close();
        }
    }

    fn fail_extended_connect_disabled(&mut self) {
        if let Some(handler) = &mut self.handler {
            handler.request_failed(
                &mut NullClientWriter,
                &io::Error::new(io::ErrorKind::Unsupported, EXTENDED_CONNECT_NOT_ENABLED),
            );
        }
    }

    fn start_request(&mut self, endpoint: &mut dyn Endpoint) {
        if self.started {
            return;
        }

        // Resume a previously deferred Extended CONNECT once SETTINGS is known.
        if self.handler.is_some() {
            if self.pending_outbound.is_none() {
                return;
            }
            let enable = self.peer_state.lock().unwrap().peer_enable_connect_protocol;
            match enable {
                None => return,
                Some(false) => {
                    self.pending_outbound = None;
                    self.started = true;
                    self.fail_extended_connect_disabled();
                    return;
                }
                Some(true) => {
                    let pending = self.pending_outbound.take().unwrap();
                    self.emit_request(endpoint, &pending);
                    self.started = true;
                    return;
                }
            }
        }

        let mut handler = self.factory.create_handler();
        let mut writer = H3ClientWriter::new();
        handler.start(&mut writer);

        let pending = PendingOutbound {
            headers: writer.request_headers.take().unwrap_or_default(),
            body: writer.body,
            trailers: writer.trailers,
            done: writer.done,
        };

        if is_extended_connect(&pending.headers) {
            self.is_extended_connect = true;
            let enable = self.peer_state.lock().unwrap().peer_enable_connect_protocol;
            match enable {
                Some(false) => {
                    self.handler = Some(handler);
                    self.started = true;
                    self.fail_extended_connect_disabled();
                    return;
                }
                None => {
                    // RFC 9220 / RFC 8441 §4: MUST NOT send Extended CONNECT
                    // before peer SETTINGS is known. Defer and poke when it arrives.
                    let handle = endpoint.handle();
                    self.peer_state
                        .lock()
                        .unwrap()
                        .settings_waiters
                        .push(Box::new(move || {
                            handle.poke();
                        }));
                    self.handler = Some(handler);
                    self.pending_outbound = Some(pending);
                    return;
                }
                Some(true) => {}
            }
        }

        self.handler = Some(handler);
        self.emit_request(endpoint, &pending);
        self.started = true;
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
        if !self.message_phase.data_allowed() {
            // RFC 9114 §4.1: DATA before response HEADERS is a connection error.
            self.connection_error
                .get_or_insert(frame::H3_FRAME_UNEXPECTED);
            return;
        }
        if self
            .body_tracker
            .add_data(payload.len() as u64)
            .is_err()
        {
            self.malformed = true;
            return;
        }
        if self.upgraded.is_some() {
            if self.capsule_mode {
                if !payload.is_empty() {
                    match self.capsule_parser.push(payload) {
                        Ok(capsules) => {
                            if let Some(up) = self.upgraded.as_mut() {
                                for c in capsules {
                                    if c.ty == crate::capsule::CAPSULE_DATAGRAM {
                                        if up.wants_datagrams() {
                                            up.datagram_received(&c.value);
                                        }
                                    } else {
                                        up.capsule_received(c.ty, &c.value);
                                    }
                                }
                            }
                        }
                        Err(()) => {
                            self.malformed = true;
                        }
                    }
                }
            } else if let Some(up) = self.upgraded.as_mut() {
                if !payload.is_empty() {
                    up.receive(payload);
                }
            }
            return;
        }
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
        if self.message_phase == stream_phase::StreamMessagePhase::AfterTrailers {
            self.connection_error
                .get_or_insert(frame::H3_FRAME_UNEXPECTED);
            return;
        }

        let Ok(pairs) = self.qpack.decode_field_section(self.stream_id, payload) else {
            self.qpack_error = true;
            return;
        };
        if pairs.len() > self.limits.max_header_count
            || frame::field_section_size_owned(&pairs)
                > frame::DEFAULT_MAX_FIELD_SECTION_SIZE as usize
        {
            self.excessive_load = true;
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

        // RFC 9114 §4.2: uppercase field names and connection-specific fields
        // → malformed.
        if !crate::utils::http_binary_field_names_are_lowercase(&pairs)
            || !crate::utils::http_connection_specific_fields_are_valid(&pairs)
        {
            if let Some(handler) = &mut self.handler {
                handler.request_failed(
                    &mut w,
                    &io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed H3 response: invalid field name or value",
                    ),
                );
            }
            self.malformed = true;
            return;
        }

        let mut headers = Headers::new();
        for (name, value) in &pairs {
            headers.add(name.clone(), value.clone());
        }
        if let Some(handler) = &mut self.handler {
            // RFC 9114 §4.1 / RFC 9110 §15.2: a 1xx HEADERS is an interim
            // response — never terminal, never trailers. The real final
            // response HEADERS still follows on the same stream.
            if !self.response_headers_received && (100..200).contains(&headers.status_code()) {
                if message_body::MessageBodyTracker::check_interim_no_content(&pairs).is_err()
                    || self.body_tracker.finish_message().is_err()
                {
                    handler.request_failed(
                        &mut w,
                        &io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed H3 response: interim response must not have content",
                        ),
                    );
                    self.malformed = true;
                    return;
                }
                handler.informational_response(&mut w, &headers);
                return;
            }
            if self.response_headers_received {
                if self.message_phase != stream_phase::StreamMessagePhase::InMessage {
                    self.connection_error
                        .get_or_insert(frame::H3_FRAME_UNEXPECTED);
                    return;
                }
                if self.body_tracker.finish_message().is_err() {
                    handler.request_failed(
                        &mut w,
                        &io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed H3 response: Content-Length does not match DATA",
                        ),
                    );
                    self.malformed = true;
                    return;
                }
                if crate::utils::field_section_contains_pseudo_headers(&pairs) {
                    handler.request_failed(
                        &mut w,
                        &io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed H3 response trailers: pseudo-headers forbidden",
                        ),
                    );
                    self.malformed = true;
                    return;
                }
                if self.response_body_started {
                    handler.end_response_body(&mut w);
                    self.response_body_started = false;
                }
                handler.response_trailers(&mut w, &headers);
                self.message_phase = self.message_phase.opened_trailers();
            } else {
                if self.message_phase != stream_phase::StreamMessagePhase::AwaitingHeaders {
                    self.connection_error
                        .get_or_insert(frame::H3_FRAME_UNEXPECTED);
                    return;
                }
                let forbid =
                    crate::utils::http_response_status_must_not_have_content(headers.status_code());
                if self.body_tracker.begin_message(&pairs, forbid).is_err() {
                    handler.request_failed(
                        &mut w,
                        &io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed H3 response: invalid Content-Length",
                        ),
                    );
                    self.malformed = true;
                    return;
                }
                self.response_headers_received = true;
                if self.is_extended_connect && (200..300).contains(&headers.status_code()) {
                    self.capsule_mode = crate::capsule::capsule_protocol_enabled(&headers);
                    let mut uw = H3ClientUpgradeWriter {
                        pending: &mut self.upgraded,
                        conn: self.conn.clone(),
                    };
                    handler.switching_protocols(&mut uw, &headers);
                } else {
                    handler.response_headers(&mut w, &headers);
                }
                self.message_phase = self.message_phase.opened_message();
            }
        }
    }

    fn settings_frame(&mut self, _: &[u8]) {
        self.connection_error
            .get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn goaway_frame(&mut self, _: &[u8]) {
        self.connection_error
            .get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn cancel_push_frame(&mut self, _: &[u8]) {
        self.connection_error
            .get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn push_promise_frame(&mut self, _: &[u8]) {
        // hopf never sends MAX_PUSH_ID, so any PUSH_PROMISE is
        // H3_ID_ERROR (RFC 9114 §7.2.5).
        self.connection_error.get_or_insert(frame::H3_ID_ERROR);
    }
    fn max_push_id_frame(&mut self, _: &[u8]) {
        self.connection_error
            .get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn reserved_http2_frame(&mut self, _: u64) {
        // RFC 9114 §7.2.8 — same on every stream type.
        self.connection_error
            .get_or_insert(frame::H3_FRAME_UNEXPECTED);
    }
    fn frame_error(&mut self, _: &str) {
        self.connection_error.get_or_insert(frame::H3_FRAME_ERROR);
    }
}

impl ProtocolHandler for H3ClientStream {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.conn = endpoint.handle();
        self.start_request(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        // Resume Extended CONNECT deferred until peer SETTINGS (poke from
        // the control-stream SETTINGS waiter lands here with empty data).
        if !self.started {
            self.start_request(endpoint);
        }
        let mut parser = std::mem::take(&mut self.parser);
        parser.push(data, self);
        self.parser = parser;
        *data = &[];
        if let Some(up) = self.upgraded.as_mut() {
            let wants_close = up.wants_close();
            let out = up.take_outbound();
            if !out.is_empty() {
                let mut framed = Vec::with_capacity(out.len() + 8);
                frame::write_data(&mut framed, &out);
                endpoint.send(&framed);
            }
            if wants_close {
                endpoint.close();
                return;
            }
        }
        if self.qpack_error {
            // RFC 9204 §4.5.1: a field section this decoder can't process
            // desynchronizes the whole connection's QPACK state, not just
            // this stream.
            endpoint.close_connection(frame::QPACK_DECOMPRESSION_FAILED);
            return;
        }
        if let Some(code) = self.connection_error.take() {
            endpoint.close_connection(code);
            return;
        }
        if self.excessive_load {
            let mut w = NullClientWriter;
            if let Some(handler) = &mut self.handler {
                handler.request_failed(
                    &mut w,
                    &io::Error::new(
                        io::ErrorKind::InvalidData,
                        "response field section exceeds SETTINGS_MAX_FIELD_SECTION_SIZE",
                    ),
                );
            }
            endpoint.abort(frame::H3_EXCESSIVE_LOAD);
            return;
        }
        if self.malformed {
            // RFC 9114 §4.3.2: a malformed response is a stream error, not
            // a connection error — only this one request is affected.
            endpoint.abort(frame::H3_MESSAGE_ERROR);
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(up) = self.upgraded.as_mut() {
            up.closed();
            return;
        }
        if self.body_tracker.finish_message().is_err() {
            self.malformed = true;
            if let Some(handler) = &mut self.handler {
                handler.request_failed(
                    &mut NullClientWriter,
                    &io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "connection closed before the response completed",
                    ),
                );
            }
            endpoint.abort(frame::H3_MESSAGE_ERROR);
            return;
        }
        self.finish_response();
    }

    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {
        // Abnormal QUIC teardown replaces disconnected() — still cancel
        // QPACK refs and finish the response so the client handler sees
        // completion.
        // RFC 9204 §4.4.2: this stream won't be acknowledged now — let the
        // peer's encoder release any dynamic-table references it held open
        // for it.
        self.qpack.cancel_stream(self.stream_id);
        if let Some(up) = self.upgraded.as_mut() {
            up.closed();
            return;
        }
        self.finish_response();
    }

    fn datagram_received(&mut self, endpoint: &mut dyn Endpoint, data: &[u8]) {
        if let Some(up) = self.upgraded.as_mut() {
            if up.wants_datagrams() {
                up.datagram_received(data);
                return;
            }
            endpoint.abort(super::datagram::H3_DATAGRAM_ERROR);
            return;
        }
        if let Some(handler) = self.handler.as_mut() {
            if handler.wants_datagrams() {
                handler.datagram_received(data);
                return;
            }
        }
        endpoint.abort(super::datagram::H3_DATAGRAM_ERROR);
    }
}

#[cfg(test)]
mod status_validation_tests {
    use super::*;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingEndpoint {
        closed: bool,
        abort_code: Option<u32>,
        close_connection_code: Option<u32>,
        sent: Vec<u8>,
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
            // Task-only: poke from SETTINGS waiters is a no-op in these
            // unit tests — callers re-enter `start_request` / `receive`
            // explicitly after flipping `peer_enable_connect_protocol`.
            hopf_core::ConnHandle::from_execute(std::sync::Arc::new(|task| task()))
        }
    }

    #[derive(Default)]
    struct Recorded {
        status: Option<u16>,
        failed: usize,
        trailers: Vec<(String, String)>,
        informational_statuses: Vec<u16>,
    }

    struct RecordingHandler {
        rec: Arc<Mutex<Recorded>>,
    }
    impl ClientHandler for RecordingHandler {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "GET");
            h.set(":scheme", "https");
            h.set(":path", "/");
            h.set(":authority", "example.com");
            request.headers(h);
        }
        fn informational_response(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec
                .lock()
                .unwrap()
                .informational_statuses
                .push(headers.status_code());
        }
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
        let qpack = Arc::new(qpack::H3Qpack::new());
        let mut stream = H3ClientStream::new(
            factory,
            HttpLimits::default(),
            0,
            qpack,
            Arc::new(Mutex::new(H3PeerState::default())),
        );
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

    /// `Connection` (and the rest of RFC 9114 §4.2's connection-specific
    /// set) is meaningless on H3 — no half-duplex TCP-style close to
    /// signal — so it's just dropped rather than reaching the wire as a
    /// protocol violation. Unlike H2, there's no local behavior to honor
    /// it with either.
    #[test]
    fn writer_strips_connection_specific_headers() {
        let mut writer = H3ClientWriter::new();
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set(":path", "/");
        h.set(":authority", "example.test");
        h.set("connection", "close");
        h.set("transfer-encoding", "chunked");
        writer.headers(h);

        let sent = writer.request_headers.as_ref().unwrap();
        assert!(sent.get("connection").is_none());
        assert!(sent.get("transfer-encoding").is_none());
        assert_eq!(sent.get(":method"), Some("GET"), "unrelated headers must survive untouched");
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

    /// The peer disconnects (QUIC connection lost, stream reset, etc.)
    /// mid-response — headers announced a 5-byte body, but the connection
    /// drops before any of it (or the peer's FIN) arrives. The app must be
    /// told the request failed, not left hanging forever: a caller blocked
    /// on this request has no other signal to wait on.
    #[test]
    fn disconnect_mid_response_fails_the_request() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[(":status", "200"), ("content-length", "5")]);
        stream.headers_frame(&payload);
        assert_eq!(rec.lock().unwrap().status, Some(200), "headers alone should still dispatch normally");

        let mut ep = RecordingEndpoint::default();
        stream.disconnected(&mut ep);

        assert_eq!(
            rec.lock().unwrap().failed,
            1,
            "app handler must be told the request failed once the promised body never arrived"
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

    #[test]
    fn connection_specific_header_in_response_is_malformed() {
        let (mut stream, rec) = stream_with_recorder();
        let payload = encode(&[(":status", "200"), ("connection", "close")]);
        stream.headers_frame(&payload);
        assert!(stream.malformed);
        assert_eq!(rec.lock().unwrap().failed, 1);
        assert_eq!(rec.lock().unwrap().status, None);
    }

    #[test]
    fn connection_specific_field_in_response_trailers_is_malformed() {
        let (mut stream, rec) = stream_with_recorder();
        stream.headers_frame(&encode(&[(":status", "200")]));
        stream.headers_frame(&encode(&[("transfer-encoding", "chunked")]));
        assert!(stream.malformed);
        assert_eq!(rec.lock().unwrap().failed, 1);
        assert!(rec.lock().unwrap().trailers.is_empty());
    }

    #[test]
    fn content_length_must_match_response_data_on_fin() {
        let (mut stream, rec) = stream_with_recorder();
        stream.headers_frame(&encode(&[(":status", "200"), ("content-length", "5")]));
        stream.data_frame(b"hello");
        assert!(!stream.malformed);

        let mut ep = RecordingEndpoint::default();
        stream.disconnected(&mut ep);
        assert!(!ep.closed);
        assert_eq!(rec.lock().unwrap().status, Some(200));
    }

    #[test]
    fn short_response_body_vs_content_length_aborts_stream() {
        let (mut stream, rec) = stream_with_recorder();
        stream.headers_frame(&encode(&[(":status", "200"), ("content-length", "5")]));
        stream.data_frame(b"hi");

        let mut ep = RecordingEndpoint::default();
        stream.disconnected(&mut ep);
        assert!(stream.malformed);
        assert!(ep.closed);
        assert_eq!(ep.abort_code, Some(frame::H3_MESSAGE_ERROR));
        assert_eq!(
            rec.lock().unwrap().failed,
            1,
            "a truncated response must reach the app as request_failed, not leave it hanging"
        );
    }

    #[test]
    fn response_204_must_not_include_data() {
        let (mut stream, rec) = stream_with_recorder();
        stream.headers_frame(&encode(&[(":status", "204")]));
        stream.data_frame(b"x");
        assert!(stream.malformed);
        assert_eq!(rec.lock().unwrap().status, Some(204));
    }

    #[test]
    fn data_before_response_headers_is_frame_unexpected() {
        let (mut stream, rec) = stream_with_recorder();
        stream.data_frame(b"early");
        assert_eq!(rec.lock().unwrap().status, None);

        let mut ep = RecordingEndpoint::default();
        let mut empty: &[u8] = &[];
        stream.receive(&mut ep, &mut empty);
        assert_eq!(ep.close_connection_code, Some(frame::H3_FRAME_UNEXPECTED));
    }

    #[test]
    fn settings_on_client_stream_is_frame_unexpected() {
        let (mut stream, _rec) = stream_with_recorder();
        let mut frame_bytes = Vec::new();
        frame::write_settings(&mut frame_bytes, 0, 0, frame::DEFAULT_MAX_FIELD_SECTION_SIZE);

        let mut ep = RecordingEndpoint::default();
        let mut data: &[u8] = &frame_bytes;
        stream.receive(&mut ep, &mut data);
        assert_eq!(ep.close_connection_code, Some(frame::H3_FRAME_UNEXPECTED));
    }

    #[test]
    fn third_response_headers_is_frame_unexpected() {
        let (mut stream, _rec) = stream_with_recorder();
        stream.headers_frame(&encode(&[(":status", "200")]));
        stream.headers_frame(&encode(&[("grpc-status", "0")]));

        let mut ep = RecordingEndpoint::default();
        let third = encode(&[("grpc-message", "late")]);
        let mut data: &[u8] = &third;
        stream.receive(&mut ep, &mut data);
        assert_eq!(ep.close_connection_code, Some(frame::H3_FRAME_UNEXPECTED));
    }

    /// A `100 Continue` / `103 Early Hints` HEADERS frame is surfaced via
    /// `informational_response` and does not consume the "first HEADERS"
    /// slot — the real final response still lands on `response_headers`,
    /// not `response_trailers` (RFC 9114 §4.1).
    #[test]
    fn interim_1xx_then_final_response_dispatch_correctly() {
        let (mut stream, rec) = stream_with_recorder();

        stream.headers_frame(&encode(&[(":status", "100")]));
        stream.headers_frame(&encode(&[(":status", "200"), ("content-type", "text/plain")]));

        let r = rec.lock().unwrap();
        assert_eq!(r.informational_statuses, vec![100]);
        assert_eq!(r.status, Some(200));
        assert!(r.trailers.is_empty(), "final response must not be mistaken for trailers");
        assert!(stream.response_headers_received);
    }

    /// Multiple interim responses (e.g. 103 then 100) are all surfaced
    /// before the final response.
    #[test]
    fn multiple_interim_responses_all_surfaced() {
        let (mut stream, rec) = stream_with_recorder();

        stream.headers_frame(&encode(&[(":status", "103"), ("link", "</style.css>; rel=preload")]));
        stream.headers_frame(&encode(&[(":status", "100")]));
        stream.headers_frame(&encode(&[(":status", "200")]));

        let r = rec.lock().unwrap();
        assert_eq!(r.informational_statuses, vec![103, 100]);
        assert_eq!(r.status, Some(200));
        assert!(r.trailers.is_empty());
    }

    /// A final response with no preceding 1xx is unaffected.
    #[test]
    fn no_interim_response_final_headers_then_trailers() {
        let (mut stream, rec) = stream_with_recorder();

        stream.headers_frame(&encode(&[(":status", "200")]));
        stream.headers_frame(&encode(&[("grpc-status", "0")]));

        let r = rec.lock().unwrap();
        assert!(r.informational_statuses.is_empty());
        assert_eq!(r.status, Some(200));
        assert_eq!(r.trailers, vec![("grpc-status".to_string(), "0".to_string())]);
    }

    #[test]
    fn pseudo_header_in_response_trailers_is_malformed() {
        let (mut stream, rec) = stream_with_recorder();
        stream.headers_frame(&encode(&[(":status", "200")]));
        stream.headers_frame(&encode(&[(":status", "0")]));

        assert!(stream.malformed);
        assert!(rec.lock().unwrap().trailers.is_empty());

        let mut ep = RecordingEndpoint::default();
        let mut empty: &[u8] = &[];
        stream.receive(&mut ep, &mut empty);
        assert_eq!(ep.abort_code, Some(frame::H3_MESSAGE_ERROR));
    }

    #[test]
    fn server_initiated_bi_stream_closes_connection() {
        let pending: PendingOpens = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let on_ready: OnReady = Arc::new(Mutex::new(None));
        let mut conn = H3ClientConnection::with_shared_state(
            pending,
            on_ready,
            HttpLimits::default(),
        );
        let mut handler = conn.accept_bi(1);
        let mut ep = RecordingEndpoint::default();
        handler.connected(&mut ep);
        assert_eq!(
            ep.close_connection_code,
            Some(frame::H3_STREAM_CREATION_ERROR)
        );
    }

    /// hopf never sends MAX_PUSH_ID, so PUSH_PROMISE on a request stream is
    /// a connection error of type H3_ID_ERROR (RFC 9114 §7.2.5).
    #[test]
    fn push_promise_on_request_stream_is_id_error() {
        let (mut stream, _rec) = stream_with_recorder();
        let mut ep = RecordingEndpoint::default();

        let mut bytes = Vec::new();
        frame::write_push_promise(&mut bytes, 0, b"");
        let mut data: &[u8] = &bytes;
        stream.receive(&mut ep, &mut data);

        assert!(ep.closed);
        assert_eq!(ep.close_connection_code, Some(frame::H3_ID_ERROR));
    }

    /// Collects frame types and HEADERS payloads from a client-encoded request.
    #[derive(Default)]
    struct FrameLog {
        types: Vec<u64>,
        headers_payloads: Vec<Vec<u8>>,
        data: Vec<u8>,
    }
    impl H3FrameHandler for FrameLog {
        fn data_frame(&mut self, payload: &[u8]) {
            self.types.push(frame::DATA);
            self.data.extend_from_slice(payload);
        }
        fn headers_frame(&mut self, payload: &[u8]) {
            self.types.push(frame::HEADERS);
            self.headers_payloads.push(payload.to_vec());
        }
        fn settings_frame(&mut self, _: &[u8]) {}
        fn goaway_frame(&mut self, _: &[u8]) {}
        fn cancel_push_frame(&mut self, _: &[u8]) {}
        fn push_promise_frame(&mut self, _: &[u8]) {}
        fn max_push_id_frame(&mut self, _: &[u8]) {}
        fn frame_error(&mut self, msg: &str) {
            panic!("frame error: {msg}");
        }
    }

    struct TrailerSender;
    impl ClientHandler for TrailerSender {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "POST");
            h.set(":path", "/rpc");
            h.set("host", "example.com");
            request.headers(h);
            request.start_request_body();
            request.request_body_content(b"ping");
            request.end_request_body();
            let mut t = Headers::new();
            t.set("grpc-status", "0");
            t.set("grpc-message", "ok");
            request.trailers(t);
        }
        fn response_headers(&mut self, _: &mut dyn ClientWriter, _: &Headers) {}
        fn response_complete(&mut self, _: &mut dyn ClientWriter) {}
    }

    struct TrailerFactory;
    impl ClientHandlerFactory for TrailerFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            Box::new(TrailerSender)
        }
    }

    #[test]
    fn client_sends_request_trailers_as_second_headers_before_fin() {
        let factory: Arc<dyn ClientHandlerFactory> = Arc::new(TrailerFactory);
        let qpack = Arc::new(qpack::H3Qpack::new());
        let mut stream = H3ClientStream::new(
            factory,
            HttpLimits::default(),
            0,
            Arc::clone(&qpack),
            Arc::new(Mutex::new(H3PeerState::default())),
        );
        let mut ep = RecordingEndpoint::default();
        stream.start_request(&mut ep);

        assert!(ep.closed, "trailers complete the request → stream FIN");
        assert!(!ep.sent.is_empty());

        let mut log = FrameLog::default();
        let mut parser = H3Parser::new();
        parser.push(&ep.sent, &mut log);

        assert_eq!(
            log.types,
            vec![frame::HEADERS, frame::DATA, frame::HEADERS],
            "HEADERS + DATA + trailer HEADERS"
        );
        assert_eq!(log.data, b"ping");
        assert_eq!(log.headers_payloads.len(), 2);

        let trailers = qpack
            .decode_field_section(0, &log.headers_payloads[1])
            .expect("trailer QPACK block");
        assert!(trailers.iter().any(|(n, v)| n == "grpc-status" && v == "0"));
        assert!(trailers.iter().any(|(n, v)| n == "grpc-message" && v == "ok"));
    }

    /// Extended CONNECT request builder (RFC 9220).
    struct ExtConnectFactory {
        failed: Arc<Mutex<usize>>,
    }
    impl ClientHandlerFactory for ExtConnectFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            let failed = Arc::clone(&self.failed);
            Box::new(ExtConnectCounting { failed })
        }
    }
    struct ExtConnectCounting {
        failed: Arc<Mutex<usize>>,
    }
    impl ClientHandler for ExtConnectCounting {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "CONNECT");
            h.set(":protocol", "websocket");
            h.set(":scheme", "https");
            h.set(":authority", "example.com");
            h.set(":path", "/chat");
            request.headers(h);
            request.complete_request();
        }
        fn response_headers(&mut self, _: &mut dyn ClientWriter, _: &Headers) {}
        fn response_complete(&mut self, _: &mut dyn ClientWriter) {}
        fn request_failed(&mut self, _: &mut dyn ClientWriter, err: &io::Error) {
            assert!(
                err.to_string().contains("SETTINGS_ENABLE_CONNECT_PROTOCOL"),
                "unexpected failure: {err}"
            );
            *self.failed.lock().unwrap() += 1;
        }
    }

    fn ext_connect_stream(
        peer_enable: Option<bool>,
    ) -> (H3ClientStream, Arc<Mutex<usize>>, RecordingEndpoint) {
        let failed = Arc::new(Mutex::new(0usize));
        let factory: Arc<dyn ClientHandlerFactory> = Arc::new(ExtConnectFactory {
            failed: Arc::clone(&failed),
        });
        let peer_state = Arc::new(Mutex::new({
            let mut s = H3PeerState::default();
            s.peer_enable_connect_protocol = peer_enable;
            s
        }));
        let stream = H3ClientStream::new(
            factory,
            HttpLimits::default(),
            0,
            Arc::new(qpack::H3Qpack::new()),
            peer_state,
        );
        (stream, failed, RecordingEndpoint::default())
    }

    /// Issue #261: when the peer's SETTINGS omitted (or set to 0)
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL, Extended CONNECT must fail fast.
    #[test]
    fn extended_connect_rejected_when_peer_did_not_advertise() {
        let (mut stream, failed, mut ep) = ext_connect_stream(Some(false));
        stream.start_request(&mut ep);
        assert!(ep.sent.is_empty(), "must not send Extended CONNECT");
        assert_eq!(*failed.lock().unwrap(), 1);
        assert!(stream.started);
    }

    #[test]
    fn extended_connect_sent_when_peer_advertised() {
        let (mut stream, failed, mut ep) = ext_connect_stream(Some(true));
        stream.start_request(&mut ep);
        assert!(!ep.sent.is_empty(), "must send once peer advertised support");
        assert_eq!(*failed.lock().unwrap(), 0);
        assert!(stream.started);
    }

    /// Before SETTINGS, Extended CONNECT is deferred; a later SETTINGS=0 fails it.
    #[test]
    fn extended_connect_deferred_until_settings_then_rejected() {
        let (mut stream, failed, mut ep) = ext_connect_stream(None);
        stream.start_request(&mut ep);
        assert!(ep.sent.is_empty());
        assert!(!stream.started);
        assert_eq!(*failed.lock().unwrap(), 0);
        assert_eq!(stream.peer_state.lock().unwrap().settings_waiters.len(), 1);

        stream.peer_state.lock().unwrap().peer_enable_connect_protocol = Some(false);
        stream.start_request(&mut ep);
        assert!(ep.sent.is_empty());
        assert_eq!(*failed.lock().unwrap(), 1);
        assert!(stream.started);
    }

    /// Before SETTINGS, Extended CONNECT is deferred; SETTINGS=1 then sends it.
    #[test]
    fn extended_connect_deferred_until_settings_then_sent() {
        let (mut stream, failed, mut ep) = ext_connect_stream(None);
        stream.start_request(&mut ep);
        assert!(ep.sent.is_empty());
        assert!(!stream.started);

        stream.peer_state.lock().unwrap().peer_enable_connect_protocol = Some(true);
        // Simulate the SETTINGS waiter poke → empty receive.
        let mut empty: &[u8] = &[];
        stream.receive(&mut ep, &mut empty);
        assert!(!ep.sent.is_empty());
        assert_eq!(*failed.lock().unwrap(), 0);
        assert!(stream.started);
    }
}

#[cfg(test)]
mod goaway_enforcement_tests {
    use super::*;

    #[derive(Default)]
    struct RecordingConnApi {
        open_bi_calls: usize,
        next_key: u64,
    }
    impl QuicConnApi for RecordingConnApi {
        fn open_uni(&mut self) -> Option<u64> {
            let key = self.next_key;
            self.next_key += 1;
            Some(key)
        }
        fn open_bi(&mut self) -> Option<u64> {
            self.open_bi_calls += 1;
            let key = self.next_key;
            self.next_key += 1;
            Some(key)
        }
        fn write(&mut self, _stream_key: u64, _data: &[u8]) {}
        fn finish(&mut self, _stream_key: u64) {}
    }

    struct NoopFactory;
    impl ClientHandlerFactory for NoopFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            unimplemented!("not exercised")
        }
    }

    /// After a peer GOAWAY, the client must not open further request streams
    /// (RFC 9114 §5.2).
    #[test]
    fn drain_pending_opens_stops_after_goaway_received() {
        let pending: PendingOpens = Arc::new(Mutex::new(std::collections::VecDeque::from([
            Arc::new(NoopFactory) as Arc<dyn ClientHandlerFactory>,
            Arc::new(NoopFactory) as Arc<dyn ClientHandlerFactory>,
        ])));
        let mut conn =
            H3ClientConnection::with_shared_state(Arc::clone(&pending), Arc::new(Mutex::new(None)), HttpLimits::default());
        let mut api = RecordingConnApi::default();

        conn.drain_pending_opens(&mut api);
        assert_eq!(api.open_bi_calls, 2, "both queued factories open before GOAWAY");

        conn.peer_state.lock().unwrap().goaway_received = Some(0);
        // Re-queue more requests as a session would after GOAWAY.
        pending.lock().unwrap().push_back(Arc::new(NoopFactory));
        pending.lock().unwrap().push_back(Arc::new(NoopFactory));
        conn.drain_pending_opens(&mut api);
        assert_eq!(
            api.open_bi_calls, 2,
            "no further open_bi after GOAWAY received"
        );
        assert_eq!(pending.lock().unwrap().len(), 4); // 2 unmatched from first drain + 2 new
    }
}

#[cfg(test)]
mod client_upgrade_tests {
    use super::*;
    use std::time::Duration;

    #[derive(Default)]
    struct RecordingEndpoint {
        closed: bool,
        abort_code: Option<u32>,
        sent: Vec<u8>,
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
        fn abort(&mut self, error_code: u32) {
            self.closed = true;
            self.abort_code = Some(error_code);
        }
        fn close_connection(&mut self, _error_code: u32) {
            self.closed = true;
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
            hopf_core::ConnHandle::from_execute(std::sync::Arc::new(|task| task()))
        }
    }

    /// Records bytes handed to it via shared state so a test can inspect it
    /// after the handler itself has moved into a `Box<dyn
    /// ProtocolUpgradeHandler>`.
    #[derive(Default)]
    struct RecordingUpgrade {
        received: Vec<u8>,
        outbound: Vec<u8>,
        closed: bool,
    }

    struct RecordingUpgradeHandler(Arc<Mutex<RecordingUpgrade>>);

    impl ProtocolUpgradeHandler for RecordingUpgradeHandler {
        fn receive(&mut self, data: &[u8]) {
            self.0.lock().unwrap().received.extend_from_slice(data);
        }
        fn take_outbound(&mut self) -> Vec<u8> {
            std::mem::take(&mut self.0.lock().unwrap().outbound)
        }
        fn closed(&mut self) {
            self.0.lock().unwrap().closed = true;
        }
        fn wants_datagrams(&self) -> bool {
            true
        }
        fn datagram_received(&mut self, data: &[u8]) {
            self.0.lock().unwrap().received.extend_from_slice(data);
        }
    }

    #[derive(Default)]
    struct Recorded {
        switched: bool,
        final_status: Option<u16>,
        completed: usize,
        request_failed_called: bool,
    }

    struct UpgradingHandler {
        rec: Arc<Mutex<Recorded>>,
        upgrade: Arc<Mutex<RecordingUpgrade>>,
    }
    impl ClientHandler for UpgradingHandler {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "CONNECT");
            h.set(":protocol", "connect-udp");
            h.set(":scheme", "https");
            h.set(":authority", "example.com");
            h.set(":path", "/.well-known/masque/udp/target.example/443/");
            request.headers(h);
            request.complete_request();
        }
        fn switching_protocols(&mut self, request: &mut dyn ClientWriter, _headers: &Headers) {
            self.rec.lock().unwrap().switched = true;
            assert!(request.upgrade(Box::new(RecordingUpgradeHandler(Arc::clone(&self.upgrade)))));
        }
        fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().final_status = Some(headers.status_code());
        }
        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
            self.rec.lock().unwrap().completed += 1;
        }
        fn request_failed(&mut self, _request: &mut dyn ClientWriter, _err: &io::Error) {
            self.rec.lock().unwrap().request_failed_called = true;
        }
    }

    struct UpgradingFactory {
        rec: Arc<Mutex<Recorded>>,
        upgrade: Arc<Mutex<RecordingUpgrade>>,
    }
    impl ClientHandlerFactory for UpgradingFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            Box::new(UpgradingHandler {
                rec: Arc::clone(&self.rec),
                upgrade: Arc::clone(&self.upgrade),
            })
        }
    }

    fn encode(pairs: &[(&str, &str)]) -> Vec<u8> {
        qpack::encode(pairs.iter().copied())
    }

    /// An Extended CONNECT stream, already sent (peer advertised
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`), ready to feed a response into.
    fn ext_connect_stream() -> (
        H3ClientStream,
        Arc<Mutex<Recorded>>,
        Arc<Mutex<RecordingUpgrade>>,
        RecordingEndpoint,
    ) {
        let rec = Arc::new(Mutex::new(Recorded::default()));
        let upgrade = Arc::new(Mutex::new(RecordingUpgrade::default()));
        let factory: Arc<dyn ClientHandlerFactory> = Arc::new(UpgradingFactory {
            rec: Arc::clone(&rec),
            upgrade: Arc::clone(&upgrade),
        });
        let peer_state = Arc::new(Mutex::new({
            let mut s = H3PeerState::default();
            s.peer_enable_connect_protocol = Some(true);
            s
        }));
        let mut stream = H3ClientStream::new(
            factory,
            HttpLimits::default(),
            0,
            Arc::new(qpack::H3Qpack::new()),
            peer_state,
        );
        let mut ep = RecordingEndpoint::default();
        stream.start_request(&mut ep);
        assert!(stream.started);
        (stream, rec, upgrade, ep)
    }

    /// A `2xx` response to an Extended CONNECT request fires
    /// `switching_protocols` (never `response_headers`/`response_complete`),
    /// and installing a [`ProtocolUpgradeHandler`] via `ClientWriter::upgrade`
    /// routes subsequent DATA frames — and native QUIC datagrams — to it
    /// instead of the original handler.
    #[test]
    fn successful_extended_connect_installs_upgrade_handler_and_relays_data() {
        let (mut stream, rec, upgrade, mut ep) = ext_connect_stream();

        stream.headers_frame(&encode(&[(":status", "200")]));

        assert!(rec.lock().unwrap().switched);
        assert!(rec.lock().unwrap().final_status.is_none(), "must not be treated as an ordinary response");
        assert_eq!(rec.lock().unwrap().completed, 0);

        stream.data_frame(b"hello from the peer");
        assert_eq!(upgrade.lock().unwrap().received, b"hello from the peer");

        // Draining outbound bytes happens in `receive()`'s tail; an empty
        // poke exercises it without needing real wire-framed input.
        upgrade.lock().unwrap().outbound = b"reply".to_vec();
        ep.sent.clear();
        let mut empty: &[u8] = &[];
        stream.receive(&mut ep, &mut empty);
        assert!(
            ep.sent.windows(5).any(|w| w == b"reply"),
            "outbound bytes must go out as a DATA frame: {:?}",
            ep.sent
        );

        // Native QUIC datagrams also route to the upgrade handler once
        // installed, not the original `ClientHandler`.
        stream.datagram_received(&mut ep, b"dgram");
        assert_eq!(upgrade.lock().unwrap().received, b"hello from the peerdgram");
    }

    /// A non-2xx response to an Extended CONNECT request (the peer declined)
    /// is treated as an ordinary response, not a protocol switch.
    #[test]
    fn declined_extended_connect_is_an_ordinary_response() {
        let (mut stream, rec, _upgrade, _ep) = ext_connect_stream();

        stream.headers_frame(&encode(&[(":status", "403")]));

        assert!(!rec.lock().unwrap().switched);
        assert_eq!(rec.lock().unwrap().final_status, Some(403));
    }

    /// Connection teardown after a successful upgrade notifies the
    /// [`ProtocolUpgradeHandler`], not the original request handler.
    #[test]
    fn disconnection_after_upgrade_closes_the_upgrade_handler() {
        let (mut stream, rec, upgrade, mut ep) = ext_connect_stream();
        stream.headers_frame(&encode(&[(":status", "200")]));
        assert!(rec.lock().unwrap().switched);

        stream.disconnected(&mut ep);

        assert!(upgrade.lock().unwrap().closed);
        assert!(!rec.lock().unwrap().request_failed_called, "the original ClientHandler must not see request_failed once upgraded");
    }
}
