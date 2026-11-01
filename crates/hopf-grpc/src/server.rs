// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC server binding to Hopf [`ServerHandler`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use hopf_core::TimerHandle;
use hopf_http::{
    ConnectionInfo, Headers, ServerHandler, ServerHandlerFactory, ServerResponseHandle,
    ServerWriter,
};
use rjsonparser::Parser as JsonParser;
use loopbuf::LoopBuf;
use rprotobuf::{Parser as ProtoParser, Writer as ProtoWriter};

use hopf_http::ContentCoding;

use crate::codec::{parse_grpc_content_type, GrpcCodec};
use crate::compression::{
    accept_encoding_header, compress, select_encoding, MessageAccum, MessageCoding,
    DEFAULT_COMPRESSION_THRESHOLD, DEFAULT_ENCODINGS,
};
use crate::framing::{frame, frame_compressed, GrpcFrameParser, DEFAULT_MAX_MESSAGE_SIZE};
use crate::proto::{
    JsonModelAdapter, JsonModelSerializer, ProtoFile, ProtoMessageHandler, ProtoModelAdapter,
    ProtoModelSerializer, ProtoParseError, ScalarValue,
};

use crate::compression::{
    GRPC_STATUS_DEADLINE_EXCEEDED, GRPC_STATUS_INTERNAL, GRPC_STATUS_UNIMPLEMENTED,
};
use crate::metadata::GrpcMetadata;
use crate::timeout::parse as parse_grpc_timeout;

/// A trailers-only response: HTTP 200 with the gRPC status in the headers
/// and no body (gRPC HTTP/2 protocol). `accept_encoding` is what this
/// server decodes, which every response says.
fn write_trailers_only(
    response: &mut dyn ServerWriter,
    ct: &str,
    accept_encoding: &str,
    status: i32,
    message: &str,
    initial_metadata: &GrpcMetadata,
) {
    let mut h = Headers::new();
    h.status(200);
    h.set("content-type", ct);
    h.set("grpc-accept-encoding", accept_encoding);
    initial_metadata.apply_to(&mut h);
    h.set("grpc-status", status.to_string());
    h.set("grpc-message", message);
    response.headers(h);
    response.complete();
}

/// Application SPI for RPC handling.
///
/// A unary-only service implements [`start_unary_call`](Self::start_unary_call);
/// one that serves streaming RPCs implements [`start_call`](Self::start_call)
/// and returns `true` from [`streaming_supported`](Self::streaming_supported).
pub trait GrpcService: Send + Sync {
    /// Begin a unary call; return a request event handler, or `None` if
    /// unimplemented. Default: unimplemented.
    fn start_unary_call(
        &self,
        path: &str,
        response: GrpcResponseChannel,
    ) -> Option<Box<dyn ProtoMessageHandler>> {
        let _ = (path, response);
        None
    }

    /// Begin a call of any kind (unary or streaming in either direction);
    /// return its handler, or `None` if unimplemented. Default: a unary call
    /// through [`start_unary_call`](Self::start_unary_call).
    fn start_call(&self, path: &str, call: GrpcCall) -> Option<Box<dyn GrpcCallHandler>> {
        self.start_unary_call(path, call)
            .map(|h| Box::new(UnaryShim(h)) as Box<dyn GrpcCallHandler>)
    }

    /// Whether streaming RPCs may be started through
    /// [`start_call`](Self::start_call). Default: `false`, so a streaming
    /// method is answered `UNIMPLEMENTED`.
    fn streaming_supported(&self) -> bool {
        false
    }
}

/// Handler for the request side of one call: the request messages as
/// [`ProtoMessageHandler`] events (one `start_message` / `end_message` pair
/// per message), then the client's half-close, or the call's cancellation.
pub trait GrpcCallHandler: ProtoMessageHandler {
    /// The client finished sending: no more request messages will arrive.
    fn end_requests(&mut self) {}

    /// The call was cancelled: the peer reset the stream, or the connection
    /// went away. Nothing more can be sent.
    fn cancelled(&mut self) {}
}

impl ProtoMessageHandler for Box<dyn GrpcCallHandler> {
    fn set_locator(&mut self, locator: &dyn crate::proto::ProtoLocator) {
        (**self).set_locator(locator);
    }
    fn start_message(&mut self, type_name: &str) -> Result<(), ProtoParseError> {
        (**self).start_message(type_name)
    }
    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        (**self).end_message()
    }
    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        (**self).field(name, value)
    }
    fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), ProtoParseError> {
        (**self).start_field(name, type_name)
    }
    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        (**self).end_field()
    }
}

/// A unary request handler as a call handler: no half-close or
/// cancellation hooks.
struct UnaryShim(Box<dyn ProtoMessageHandler>);

impl ProtoMessageHandler for UnaryShim {
    fn set_locator(&mut self, locator: &dyn crate::proto::ProtoLocator) {
        self.0.set_locator(locator);
    }
    fn start_message(&mut self, type_name: &str) -> Result<(), ProtoParseError> {
        self.0.start_message(type_name)
    }
    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        self.0.end_message()
    }
    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        self.0.field(name, value)
    }
    fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), ProtoParseError> {
        self.0.start_field(name, type_name)
    }
    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        self.0.end_field()
    }
}

impl GrpcCallHandler for UnaryShim {}

/// Shares one [`GrpcCallHandler`] between the decode adapter and a deadline timer.
struct SharedCallHandler(Arc<Mutex<Box<dyn GrpcCallHandler>>>);

impl ProtoMessageHandler for SharedCallHandler {
    fn set_locator(&mut self, locator: &dyn crate::proto::ProtoLocator) {
        self.0.lock().unwrap().set_locator(locator);
    }
    fn start_message(&mut self, type_name: &str) -> Result<(), ProtoParseError> {
        self.0.lock().unwrap().start_message(type_name)
    }
    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        self.0.lock().unwrap().end_message()
    }
    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        self.0.lock().unwrap().field(name, value)
    }
    fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), ProtoParseError> {
        self.0.lock().unwrap().start_field(name, type_name)
    }
    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        self.0.lock().unwrap().end_field()
    }
}

impl GrpcCallHandler for SharedCallHandler {
    fn end_requests(&mut self) {
        self.0.lock().unwrap().end_requests();
    }
    fn cancelled(&mut self) {
        self.0.lock().unwrap().cancelled();
    }
}

/// Ends a call whose client deadline expired (runs on the connection thread).
fn fire_call_deadline(
    fired: &AtomicBool,
    cancelled_sent: &AtomicBool,
    channel: &GrpcResponseChannel,
    handler: &Arc<Mutex<Box<dyn GrpcCallHandler>>>,
    response: &mut dyn ServerWriter,
) {
    if fired.swap(true, Ordering::AcqRel) {
        return;
    }
    channel.close_with(GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
    channel.flush_into(response);
    if !cancelled_sent.swap(true, Ordering::AcqRel) {
        handler.lock().unwrap().cancelled();
    }
}

fn timeout_delay(timeout_nanos: u64) -> Duration {
    let mut millis = timeout_nanos / 1_000_000;
    if timeout_nanos % 1_000_000 != 0 {
        millis += 1;
    }
    Duration::from_millis(millis)
}

/// Handle to one call, for sending its response messages and ending it.
/// The same type as the unary [`GrpcResponseChannel`]: a unary call sends
/// one message, a streaming call any number followed by
/// [`close`](GrpcResponseChannel::close).
pub type GrpcCall = GrpcResponseChannel;

/// Cloneable handle to one call's response side: messages are queued and
/// written in order, headers with the first, the status in the trailers
/// when the call is closed. Writes made after the request has completed
/// (from another thread, say) are flushed through the stream's
/// [`ServerResponseHandle`].
#[derive(Clone)]
pub struct GrpcResponseChannel {
    inner: Arc<Mutex<ChannelInner>>,
}

struct ChannelInner {
    proto_file: Arc<ProtoFile>,
    response_type_name: Option<String>,
    codec: GrpcCodec,
    /// A unary response: the first message also ends the call.
    unary: bool,
    queue: VecDeque<QueuedItem>,
    messages_sent: usize,
    /// The end of the call has been queued (or it was cancelled): nothing
    /// more is accepted.
    closed: bool,
    cancelled: bool,
    headers_sent: bool,
    finished: bool,
    /// What this server decodes, which every response says.
    accept_encoding: String,
    response_coding: Option<ContentCoding>,
    compression_threshold: usize,
    /// Flushes writes made once the request has completed.
    handle: Option<ServerResponseHandle>,
    detached: bool,
    request_metadata: GrpcMetadata,
    response_metadata: GrpcMetadata,
    trailing_metadata: GrpcMetadata,
    deadline: Option<SystemTime>,
    connection_info: ConnectionInfo,
}

enum QueuedItem {
    /// A serialised response message, framed (and compressed) when sent.
    Message(Vec<u8>),
    /// The end of the call: the status for the trailers.
    Close { status: i32, message: String },
}

impl GrpcResponseChannel {
    fn new(
        proto_file: Arc<ProtoFile>,
        response_type_name: Option<String>,
        codec: GrpcCodec,
        unary: bool,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChannelInner {
                proto_file,
                response_type_name,
                codec,
                unary,
                queue: VecDeque::new(),
                messages_sent: 0,
                closed: false,
                cancelled: false,
                headers_sent: false,
                finished: false,
                accept_encoding: String::new(),
                response_coding: None,
                compression_threshold: DEFAULT_COMPRESSION_THRESHOLD,
                handle: None,
                detached: false,
                request_metadata: GrpcMetadata::new(),
                response_metadata: GrpcMetadata::new(),
                trailing_metadata: GrpcMetadata::new(),
                deadline: None,
                connection_info: ConnectionInfo::default(),
            })),
        }
    }

    fn set_call_context(
        &self,
        request_metadata: GrpcMetadata,
        deadline: Option<SystemTime>,
        connection_info: ConnectionInfo,
    ) {
        let mut g = self.inner.lock().unwrap();
        g.request_metadata = request_metadata;
        g.deadline = deadline;
        g.connection_info = connection_info;
    }

    fn configure(&self, accept_encoding: String, coding: Option<ContentCoding>, threshold: usize) {
        let mut g = self.inner.lock().unwrap();
        g.accept_encoding = accept_encoding;
        g.response_coding = coding;
        g.compression_threshold = threshold;
    }

    fn bind(&self, handle: ServerResponseHandle) {
        self.inner.lock().unwrap().handle = Some(handle);
    }

    /// The request has completed: from now on a queued write is flushed
    /// through the response handle rather than by the next request event.
    fn detach(&self) {
        let pending = {
            let mut g = self.inner.lock().unwrap();
            g.detached = true;
            !g.queue.is_empty()
        };
        if pending {
            self.schedule_flush();
        }
    }

    /// The peer reset the stream or the connection went away.
    fn cancel(&self) {
        let mut g = self.inner.lock().unwrap();
        g.closed = true;
        g.cancelled = true;
        g.queue.clear();
    }

    fn schedule_flush(&self) {
        let handle = self.inner.lock().unwrap().handle.clone();
        if let Some(handle) = handle {
            let channel = self.clone();
            handle.execute(move |w| channel.flush_into(w));
        }
    }

    fn enqueue(&self, item: QueuedItem) -> bool {
        let detached = {
            let mut g = self.inner.lock().unwrap();
            if g.closed {
                return false;
            }
            match &item {
                QueuedItem::Message(_) => g.messages_sent += 1,
                QueuedItem::Close { .. } => g.closed = true,
            }
            g.queue.push_back(item);
            g.detached
        };
        if detached {
            self.schedule_flush();
        }
        true
    }

    /// Write every queued message and, if queued, the end of the call.
    fn flush_into(&self, response: &mut dyn ServerWriter) {
        loop {
            let (item, ct, accept, coding, threshold, headers_sent, response_md, trailing_md) = {
                let mut g = self.inner.lock().unwrap();
                if g.finished || g.cancelled {
                    return;
                }
                let Some(item) = g.queue.pop_front() else {
                    return;
                };
                if matches!(item, QueuedItem::Close { .. }) {
                    g.finished = true;
                }
                let was_sent = g.headers_sent;
                g.headers_sent = true;
                (
                    item,
                    g.codec.content_type(),
                    g.accept_encoding.clone(),
                    g.response_coding,
                    g.compression_threshold,
                    was_sent,
                    g.response_metadata.clone(),
                    g.trailing_metadata.clone(),
                )
            };
            match item {
                QueuedItem::Message(message) => {
                    if !headers_sent {
                        let mut h = Headers::new();
                        h.status(200);
                        h.set("content-type", ct);
                        h.set("grpc-accept-encoding", &accept);
                        if let Some(coding) = coding {
                            // messages that are big enough are compressed
                            // with it, each flagged on its own
                            h.set("grpc-encoding", coding.token());
                        }
                        response_md.apply_to(&mut h);
                        response.headers(h);
                        response.start_response_body();
                    }
                    response.response_body_content(&frame_message(&message, coding, threshold));
                }
                QueuedItem::Close { status, message } => {
                    if !headers_sent {
                        // Nothing was sent: a trailers-only response.
                        self.inner.lock().unwrap().headers_sent = false;
                        write_trailers_only(response, ct, &accept, status, &message, &response_md);
                        return;
                    }
                    response.end_response_body();
                    let mut t = Headers::new();
                    t.set("grpc-status", status.to_string());
                    if !message.is_empty() {
                        t.set("grpc-message", &message);
                    }
                    trailing_md.apply_to(&mut t);
                    response.trailers(t);
                    response.complete();
                    return;
                }
            }
        }
    }

    /// Negotiated response codec (`Proto` or `Json`).
    pub fn codec(&self) -> GrpcCodec {
        self.inner.lock().unwrap().codec
    }

    /// Open an event-driven encoder for the next response message. Refused
    /// once the call is closed, or for a second message of a unary call.
    pub fn open_message(
        &self,
        message_type_name: Option<&str>,
    ) -> Result<GrpcResponseMessage, String> {
        let g = self.inner.lock().unwrap();
        if g.closed {
            return Err("call already closed".into());
        }
        if g.unary && g.messages_sent > 0 {
            return Err("response already sent".into());
        }
        let type_name = message_type_name
            .map(str::to_string)
            .or_else(|| g.response_type_name.clone())
            .ok_or_else(|| "unknown response message type".to_string())?;
        let proto_file = Arc::clone(&g.proto_file);
        let codec = g.codec;
        drop(g);
        Ok(GrpcResponseMessage {
            type_name,
            body: match codec {
                GrpcCodec::Proto => ResponseBody::Proto {
                    serializer: ProtoModelSerializer::new((*proto_file).clone()),
                    writer: ProtoWriter::new(),
                    ring: LoopBuf::with_capacity(RESPONSE_RING_BYTES),
                },
                GrpcCodec::Json => ResponseBody::Json {
                    serializer: JsonModelSerializer::new((*proto_file).clone()),
                    writer: rjsonparser::Writer::new(),
                    ring: LoopBuf::with_capacity(RESPONSE_RING_BYTES),
                },
            },
            started: false,
            open_fields: 0,
            channel: self.clone(),
        })
    }

    /// End the call with a gRPC error after whatever was sent (a
    /// trailers-only response if nothing was).
    pub fn send_error(&self, status: i32, message: &str) {
        self.close_with(status, message);
    }

    /// Internal error → status 13.
    pub fn send_error_cause(&self, _cause: &dyn std::error::Error) {
        self.send_error(13, "Internal error");
    }

    /// End a streaming call successfully: `grpc-status: 0` in the trailers
    /// after every message sent so far.
    pub fn close(&self) {
        self.close_with(0, "");
    }

    /// End the call with a status, after every message sent so far. A
    /// second close is ignored.
    pub fn close_with(&self, status: i32, message: &str) {
        self.enqueue(QueuedItem::Close { status, message: message.to_string() });
    }

    /// Whether the call is still open for messages.
    pub fn is_open(&self) -> bool {
        !self.inner.lock().unwrap().closed
    }

    /// Stop delivering request messages for a while (read backpressure).
    pub fn pause_requests(&self) {
        if let Some(h) = &self.inner.lock().unwrap().handle {
            h.pause_request_body();
        }
    }

    /// Resume after [`pause_requests`](Self::pause_requests).
    pub fn resume_requests(&self) {
        if let Some(h) = &self.inner.lock().unwrap().handle {
            h.resume_request_body();
        }
    }

    /// Metadata the client sent (protocol headers excluded).
    pub fn request_metadata(&self) -> GrpcMetadata {
        self.inner.lock().unwrap().request_metadata.clone()
    }

    /// Run `f` with mutable access to initial response metadata.
    pub fn with_response_metadata<R>(&self, f: impl FnOnce(&mut GrpcMetadata) -> R) -> R {
        f(&mut self.inner.lock().unwrap().response_metadata)
    }

    /// Run `f` with mutable access to trailing response metadata.
    pub fn with_trailing_metadata<R>(&self, f: impl FnOnce(&mut GrpcMetadata) -> R) -> R {
        f(&mut self.inner.lock().unwrap().trailing_metadata)
    }

    /// Client deadline from `grpc-timeout`, if any.
    pub fn deadline(&self) -> Option<SystemTime> {
        self.inner.lock().unwrap().deadline
    }

    /// Peer and TLS information for this connection.
    pub fn connection_info(&self) -> ConnectionInfo {
        self.inner.lock().unwrap().connection_info.clone()
    }
}

/// Frames a response message, compressed when the call has a response
/// coding, the message is at least the threshold, and it shrinks.
fn frame_message(message: &[u8], coding: Option<ContentCoding>, threshold: usize) -> Vec<u8> {
    if let Some(coding) = coding {
        if message.len() >= threshold {
            if let Ok(Some(packed)) = compress(coding, message) {
                return frame_compressed(&packed);
            }
        }
    }
    frame(message)
}

/// What a response message's ring starts with. A message is framed whole,
/// so the ring holds all of it; it is doubled when a write does not fit.
const RESPONSE_RING_BYTES: usize = 16 * 1024;

/// The most a response message's ring is grown to.
const MAX_RESPONSE_RING_BYTES: usize = 256 * 1024 * 1024;

enum ResponseBody {
    Proto {
        serializer: ProtoModelSerializer,
        writer: ProtoWriter,
        ring: LoopBuf,
    },
    Json {
        serializer: JsonModelSerializer,
        writer: rjsonparser::Writer,
        ring: LoopBuf,
    },
}

impl ResponseBody {
    /// Replaces the ring with one twice the size holding the same bytes.
    /// What the writers have noted of it (where each embedded message's
    /// length goes) is by position in the bytes, so it carries over.
    fn grow(&mut self) -> Result<(), String> {
        let ring = match self {
            ResponseBody::Proto { ring, .. } | ResponseBody::Json { ring, .. } => ring,
        };
        let capacity = ring.capacity();
        if capacity >= MAX_RESPONSE_RING_BYTES {
            return Err("response message too large".into());
        }
        let mut bigger = LoopBuf::with_capacity(capacity * 2);
        let (a, b) = ring.readable_spans();
        bigger.extend_from_slice(a);
        bigger.extend_from_slice(b);
        *ring = bigger;
        Ok(())
    }
}

/// Room left in the ring for the key, brackets and separators a structural
/// event writes around its value.
const ROOM_FOR_STRUCTURE: usize = 512;

impl ResponseBody {
    /// Grows the ring until `bytes` more fit. A write that is several writer
    /// calls (a key, then a value) is not atomic as a whole: one that ran
    /// out of room part-way would, repeated, write its first part twice. With
    /// the room made first, it cannot.
    fn reserve(&mut self, bytes: usize) -> Result<(), String> {
        loop {
            let ring = match self {
                ResponseBody::Proto { ring, .. } | ResponseBody::Json { ring, .. } => &*ring,
            };
            if ring.capacity() - ring.len() >= bytes {
                return Ok(());
            }
            self.grow()?;
        }
    }

    /// The most `value` can take to write: exact for the JSON text of a
    /// string, and the base64 of bytes, so that a large value does not make
    /// the ring larger than it needs to be.
    fn room_for(&self, value: &ScalarValue) -> usize {
        let json = matches!(self, ResponseBody::Json { .. });
        ROOM_FOR_STRUCTURE
            + match value {
                ScalarValue::String(s) if json => s
                    .bytes()
                    .map(|b| match b {
                        b'"' | b'\\' => 2,
                        0..=0x1f => 6,
                        _ => 1,
                    })
                    .sum(),
                ScalarValue::String(s) => s.len(),
                ScalarValue::Bytes(b) if json => b.len().div_ceil(3) * 4,
                ScalarValue::Bytes(b) => b.len(),
                _ => 0,
            }
    }
}

/// Whether a write failed for want of room, rather than for being invalid:
/// the ring is full (`WouldBlock`) or smaller than the write (`InvalidInput`,
/// worded as the writers do, which is how it differs from a NaN in JSON).
fn too_small(e: &loopbuf::WriteError) -> bool {
    e.is_would_block()
        || (e.kind() == std::io::ErrorKind::InvalidInput
            && e.to_string().contains("whole capacity"))
}

/// Runs `write` against the ring, growing it and running it again while it
/// does not fit. The writers' calls are atomic, so a run that failed left
/// nothing behind.
fn write_growing<R>(
    body: &mut ResponseBody,
    mut write: impl FnMut(&mut ResponseBody) -> Result<R, loopbuf::WriteError>,
) -> Result<R, String> {
    loop {
        match write(body) {
            Ok(r) => return Ok(r),
            Err(e) if too_small(&e) => {
                if body.grow().is_err() {
                    return Err(e.to_string());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Encoder handle for one unary response message.
pub struct GrpcResponseMessage {
    type_name: String,
    body: ResponseBody,
    started: bool,
    /// Nested messages started with [`Self::start_field`] and not yet ended.
    open_fields: usize,
    channel: GrpcResponseChannel,
}

impl GrpcResponseMessage {
    /// Protobuf wire serializer (only when the negotiated codec is [`GrpcCodec::Proto`]).
    pub fn serializer(&mut self) -> Result<&mut ProtoModelSerializer, String> {
        match &mut self.body {
            ResponseBody::Proto { serializer, .. } => Ok(serializer),
            ResponseBody::Json { .. } => {
                Err("protobuf serializer unavailable for application/grpc+json".into())
            }
        }
    }

    /// Protobuf wire writer and the ring it writes into (only when the
    /// negotiated codec is [`GrpcCodec::Proto`]). A write that does not fit
    /// the ring fails with a would-block error and writes nothing: call
    /// [`Self::grow`] and repeat it.
    pub fn writer(&mut self) -> Result<(&mut ProtoWriter, &mut LoopBuf), String> {
        self.ensure_started()?;
        match &mut self.body {
            ResponseBody::Proto { writer, ring, .. } => Ok((writer, ring)),
            ResponseBody::Json { .. } => {
                Err("protobuf writer unavailable for application/grpc+json".into())
            }
        }
    }

    /// Doubles the room for the message, keeping what has been written.
    pub fn grow(&mut self) -> Result<(), String> {
        self.body.grow()
    }

    /// Writes a scalar field, or one element of a repeated field (call it
    /// once per element, with the elements together). Inside
    /// [`Self::start_field`] it is a field of that message.
    pub fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), String> {
        self.ensure_started()?;
        self.body.reserve(self.body.room_for(&value))?;
        write_growing(&mut self.body, |body| match body {
            ResponseBody::Proto {
                serializer,
                writer,
                ring,
            } => serializer.field(writer, ring, name, value.clone()),
            ResponseBody::Json {
                serializer,
                writer,
                ring,
            } => serializer.field(writer, ring, name, value.clone()),
        })
    }

    /// Starts a nested message field: its fields follow, until
    /// [`Self::end_field`]. Also one element of a repeated message field
    /// (start one per element, together), and, for a map field, one entry:
    /// write its `"key"`, then its `"value"` with [`Self::field`] or, for a
    /// message value, another `start_field("value", ..)`; the type name given
    /// for the entry itself is not used. The same calls write either
    /// encoding (`application/grpc` or `application/grpc+json`).
    ///
    /// A field the message does not have is skipped, with everything inside it.
    pub fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), String> {
        self.ensure_started()?;
        self.body.reserve(ROOM_FOR_STRUCTURE)?;
        match &mut self.body {
            ResponseBody::Proto { serializer, .. } => {
                serializer.start_field(name, type_name).map_err(|e| e.to_string())?;
            }
            ResponseBody::Json { .. } => {
                write_growing(&mut self.body, |body| match body {
                    ResponseBody::Json { serializer, writer, ring } => serializer.start_field(writer, ring, name, type_name),
                    ResponseBody::Proto { .. } => Ok(()),
                })?;
            }
        }
        self.open_fields += 1;
        Ok(())
    }

    /// Ends the nested message (or map entry) [`Self::start_field`] began.
    pub fn end_field(&mut self) -> Result<(), String> {
        if self.open_fields == 0 {
            return Err("end_field without a start_field".into());
        }
        self.body.reserve(ROOM_FOR_STRUCTURE)?;
        match &mut self.body {
            ResponseBody::Proto { .. } => {
                write_growing(&mut self.body, |body| match body {
                    ResponseBody::Proto { serializer, writer, ring } => serializer.end_field(writer, ring),
                    ResponseBody::Json { .. } => Ok(()),
                })?;
            }
            ResponseBody::Json { .. } => {
                write_growing(&mut self.body, |body| match body {
                    ResponseBody::Json { serializer, writer, ring } => serializer.end_field(writer, ring),
                    ResponseBody::Proto { .. } => Ok(()),
                })?;
            }
        }
        self.open_fields -= 1;
        Ok(())
    }

    pub fn complete(mut self) -> Result<(), String> {
        if self.open_fields > 0 {
            return Err(format!("{} start_field call(s) were never ended", self.open_fields));
        }
        self.ensure_started()?;
        let bytes = match &mut self.body {
            ResponseBody::Proto {
                serializer,
                writer,
                ring,
            } => {
                serializer.end_message();
                let mut out = Vec::with_capacity(ring.len() + 16);
                writer.drain_to(ring, &mut out).map_err(|e| e.to_string())?;
                out
            }
            ResponseBody::Json { .. } => {
                write_growing(&mut self.body, |body| match body {
                    ResponseBody::Json {
                        serializer,
                        writer,
                        ring,
                    } => serializer.end_message(writer, ring),
                    ResponseBody::Proto { .. } => Ok(()),
                })?;
                match &self.body {
                    ResponseBody::Json { ring, .. } => {
                        let (a, b) = ring.readable_spans();
                        [a, b].concat()
                    }
                    ResponseBody::Proto { .. } => Vec::new(),
                }
            }
        };
        let unary = self.channel.inner.lock().unwrap().unary;
        if !self.channel.enqueue(QueuedItem::Message(bytes)) {
            return Err("call already closed".into());
        }
        if unary {
            self.channel.close();
        }
        Ok(())
    }

    fn ensure_started(&mut self) -> Result<(), String> {
        if self.started {
            return Ok(());
        }
        match &mut self.body {
            ResponseBody::Proto { serializer, .. } => {
                serializer
                    .start_message(&self.type_name)
                    .map_err(|e| e.to_string())?;
            }
            ResponseBody::Json { .. } => {
                let type_name = self.type_name.clone();
                write_growing(&mut self.body, |body| match body {
                    ResponseBody::Json {
                        serializer,
                        writer,
                        ring,
                    } => serializer.start_message(writer, ring, &type_name),
                    ResponseBody::Proto { .. } => Ok(()),
                })?;
            }
        }
        self.started = true;
        Ok(())
    }
}

/// Factory that routes `POST` + supported gRPC Content-Types to [`GrpcHandler`].
pub struct GrpcHandlerFactory {
    proto_file: Arc<ProtoFile>,
    service: Arc<dyn GrpcService>,
    max_message_size: u64,
    encodings: Vec<ContentCoding>,
    compress_responses: bool,
    compression_threshold: usize,
}

impl GrpcHandlerFactory {
    pub fn new(proto_file: ProtoFile, service: Arc<dyn GrpcService>) -> Self {
        Self {
            proto_file: Arc::new(proto_file),
            service,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            encodings: DEFAULT_ENCODINGS.to_vec(),
            compress_responses: true,
            compression_threshold: DEFAULT_COMPRESSION_THRESHOLD,
        }
    }

    /// Whether to compress response messages, with the first of
    /// [`encodings`](Self::encodings) that the request's
    /// `grpc-accept-encoding` lists (default on).
    pub fn compress_responses(mut self, on: bool) -> Self {
        self.compress_responses = on;
        self
    }

    /// Response messages smaller than this many bytes are sent as they
    /// are (default [`DEFAULT_COMPRESSION_THRESHOLD`]).
    pub fn compression_threshold(mut self, bytes: usize) -> Self {
        self.compression_threshold = bytes;
        self
    }

    pub fn set_max_message_size(&mut self, max_message_size: u64) {
        self.max_message_size = crate::framing::effective_max_message_size(max_message_size);
    }

    /// The compression algorithms the server decodes in requests and lists
    /// in `grpc-accept-encoding`, besides `identity`, which is always
    /// allowed. The default is `gzip` and `deflate`, the algorithms of the
    /// gRPC specification; add [`ContentCoding::Brotli`] to allow `br`, an
    /// extension that only works with a client that has it as well.
    pub fn encodings(mut self, encodings: &[ContentCoding]) -> Self {
        self.encodings = encodings
            .iter()
            .copied()
            .filter(|c| *c != ContentCoding::Identity)
            .collect();
        self
    }
}

impl ServerHandlerFactory for GrpcHandlerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(GrpcHandler {
            proto_file: Arc::clone(&self.proto_file),
            service: Arc::clone(&self.service),
            max_message_size: self.max_message_size,
            encodings: self.encodings.clone(),
            compress_responses: self.compress_responses,
            compression_threshold: self.compression_threshold,
            request_coding: MessageCoding::Identity,
            response_coding: None,
            path: String::new(),
            request_type_name: None,
            response_type_name: None,
            client_streaming: false,
            server_streaming: false,
            codec: GrpcCodec::Proto,
            content_ok: false,
            body_started: false,
            body_rejected: false,
            channel: None,
            decode: None,
            request_metadata: GrpcMetadata::new(),
            timeout_nanos: None,
            deadline_timer: None,
            deadline_fired: Arc::new(AtomicBool::new(false)),
            deadline_cancelled_sent: Arc::new(AtomicBool::new(false)),
            call_handler: None,
        })
    }
}

enum MessageDecoder {
    Proto(ProtoModelAdapter<Box<dyn GrpcCallHandler>>),
    Json(JsonModelAdapter<Box<dyn GrpcCallHandler>>),
}

impl MessageDecoder {
    fn handler_mut(&mut self) -> &mut Box<dyn GrpcCallHandler> {
        match self {
            MessageDecoder::Proto(a) => a.handler_mut(),
            MessageDecoder::Json(a) => a.handler_mut(),
        }
    }

    fn start_root_message(&mut self, type_name: &str) -> Result<(), ProtoParseError> {
        match self {
            MessageDecoder::Proto(a) => a.start_root_message(type_name),
            MessageDecoder::Json(a) => a.start_root_message(type_name),
        }
    }
}

struct DecodeState {
    decoder: MessageDecoder,
    frame_parser: Option<GrpcFrameParser<MessageAccum>>,
    /// At least one request message has been decoded.
    message_done: bool,
    /// The decoder has a root message open for the message being gathered.
    root_open: bool,
}

struct GrpcHandler {
    proto_file: Arc<ProtoFile>,
    service: Arc<dyn GrpcService>,
    max_message_size: u64,
    encodings: Vec<ContentCoding>,
    compress_responses: bool,
    compression_threshold: usize,
    request_coding: MessageCoding,
    response_coding: Option<ContentCoding>,
    path: String,
    request_type_name: Option<String>,
    response_type_name: Option<String>,
    client_streaming: bool,
    server_streaming: bool,
    codec: GrpcCodec,
    content_ok: bool,
    body_started: bool,
    body_rejected: bool,
    channel: Option<GrpcResponseChannel>,
    decode: Option<DecodeState>,
    request_metadata: GrpcMetadata,
    timeout_nanos: Option<u64>,
    deadline_timer: Option<TimerHandle>,
    deadline_fired: Arc<AtomicBool>,
    deadline_cancelled_sent: Arc<AtomicBool>,
    call_handler: Option<Arc<Mutex<Box<dyn GrpcCallHandler>>>>,
}

impl GrpcHandler {
    fn stopped(&self) -> bool {
        self.body_rejected || self.deadline_fired.load(Ordering::Acquire)
    }

    fn stop_deadline(&mut self) {
        if let Some(timer) = self.deadline_timer.take() {
            timer.cancel();
        }
    }

    fn flush_pending(&mut self, response: &mut dyn ServerWriter) {
        if let Some(channel) = &self.channel {
            channel.flush_into(response);
        }
    }

    fn reject_http(&mut self, response: &mut dyn ServerWriter, code: u16, message: &str) {
        if self.body_rejected {
            return;
        }
        self.body_rejected = true;
        let mut h = Headers::new();
        h.status(code);
        h.set("content-type", "text/plain");
        response.headers(h);
        response.start_response_body();
        response.response_body_content(message.as_bytes());
        response.end_response_body();
        response.complete();
    }

    /// Fails the call with a gRPC status. Once the service has been
    /// invoked this goes through its channel, after whatever it already
    /// sent; before, as a trailers-only response.
    fn reject_grpc(&mut self, response: &mut dyn ServerWriter, status: i32, message: &str) {
        if self.body_rejected {
            return;
        }
        self.body_rejected = true;
        self.stop_deadline();
        match &self.channel {
            Some(channel) => {
                channel.close_with(status, message);
                self.flush_pending(response);
            }
            None => {
                let accept = accept_encoding_header(&self.encodings);
                write_trailers_only(
                    response,
                    self.codec.content_type(),
                    &accept,
                    status,
                    message,
                    &GrpcMetadata::new(),
                )
            }
        }
    }

    fn new_frame_parser(&self) -> GrpcFrameParser<MessageAccum> {
        let mut parser = GrpcFrameParser::new(MessageAccum::new(
            self.request_coding.clone(),
            self.max_message_size,
        ));
        parser.set_max_message_size(self.max_message_size);
        parser
    }

    /// Decodes the gathered request message into the call's handler.
    /// A failure is the gRPC status to answer with and its message.
    fn finish_frame_message(&mut self) -> Result<(), (i32, String)> {
        let internal = |e: String| (GRPC_STATUS_INTERNAL, e);
        let next_parser = self.new_frame_parser();
        let decode = self
            .decode
            .as_mut()
            .ok_or_else(|| internal("no decode state".into()))?;
        let parser = decode
            .frame_parser
            .take()
            .ok_or_else(|| internal("no frame parser".into()))?;
        let accum = parser.into_handler();
        if let Some(err) = accum.error {
            return Err(err);
        }
        let slice = accum.buf.as_slice();
        match &mut decode.decoder {
            MessageDecoder::Proto(adapter) => {
                {
                    let mut pb = ProtoParser::new(&mut *adapter);
                    pb.parse(slice).map_err(|e| internal(e.to_string()))?;
                }
                adapter
                    .end_root_message()
                    .map_err(|e: ProtoParseError| internal(e.to_string()))?;
            }
            MessageDecoder::Json(adapter) => {
                {
                    let mut jp = JsonParser::new(&mut *adapter);
                    jp.parse(slice).map_err(|e| internal(e.to_string()))?;
                }
                adapter
                    .end_root_message()
                    .map_err(|e: ProtoParseError| internal(e.to_string()))?;
            }
        }
        decode.message_done = true;
        decode.root_open = false;
        decode.frame_parser = Some(next_parser);
        Ok(())
    }
}

impl ServerHandler for GrpcHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let method = headers.get(":method").unwrap_or("");
        let path = headers.get(":path").unwrap_or("").to_string();
        let ct = headers.get("content-type").unwrap_or("");
        let Some(codec) = parse_grpc_content_type(ct) else {
            self.reject_http(response, 415, "gRPC requires POST application/grpc");
            return;
        };
        if method != "POST" {
            self.reject_http(response, 415, "gRPC requires POST application/grpc");
            return;
        }
        if !path.starts_with('/') || path.len() < 2 || !path[1..].contains('/') {
            self.reject_http(response, 404, "Invalid gRPC path");
            return;
        }

        self.path = path.clone();
        self.codec = codec;
        self.content_ok = true;
        if let Some(rpc) = self.proto_file.get_rpc_by_path(&path) {
            self.request_type_name = Some(rpc.input_type_name.clone());
            self.response_type_name = Some(rpc.output_type_name.clone());
            self.client_streaming = rpc.client_streaming;
            self.server_streaming = rpc.server_streaming;
        }

        self.request_coding =
            MessageCoding::resolve(headers.get("grpc-encoding"), &self.encodings);
        if let MessageCoding::Unsupported(token) = &self.request_coding {
            // the call never reaches the service; the response says what
            // would have been understood
            let message = format!("Unsupported grpc-encoding: {token}");
            self.reject_grpc(response, GRPC_STATUS_UNIMPLEMENTED, &message);
            return;
        }
        if self.compress_responses {
            self.response_coding =
                select_encoding(&self.encodings, headers.get("grpc-accept-encoding"));
        }

        self.request_metadata = GrpcMetadata::collect_from_headers(headers);
        self.timeout_nanos = headers
            .get("grpc-timeout")
            .and_then(parse_grpc_timeout);
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.stopped() || !self.content_ok {
            return;
        }
        self.body_started = true;

        if self.request_type_name.is_none() {
            self.reject_http(response, 404, "Unknown RPC");
            return;
        }
        if (self.client_streaming || self.server_streaming) && !self.service.streaming_supported() {
            self.reject_grpc(response, GRPC_STATUS_UNIMPLEMENTED, "Streaming RPCs are not supported");
            return;
        }

        let channel = GrpcResponseChannel::new(
            Arc::clone(&self.proto_file),
            self.response_type_name.clone(),
            self.codec,
            !self.server_streaming,
        );
        channel.configure(
            accept_encoding_header(&self.encodings),
            self.response_coding,
            self.compression_threshold,
        );
        channel.bind(response.response_handle());
        let deadline = self.timeout_nanos.map(|nanos| {
            SystemTime::now() + Duration::from_nanos(nanos.min(u64::MAX))
        });
        channel.set_call_context(
            self.request_metadata.clone(),
            deadline,
            response.connection_info(),
        );
        let handler = self.service.start_call(&self.path, channel.clone());
        self.channel = Some(channel.clone());
        let Some(handler) = handler else {
            self.reject_grpc(response, GRPC_STATUS_UNIMPLEMENTED, "Unimplemented");
            return;
        };
        let shared = Arc::new(Mutex::new(handler));
        self.call_handler = Some(Arc::clone(&shared));
        if let Some(nanos) = self.timeout_nanos {
            let fired = Arc::clone(&self.deadline_fired);
            let cancelled_sent = Arc::clone(&self.deadline_cancelled_sent);
            let ch = channel.clone();
            let handler_ref = Arc::clone(&shared);
            let rh = response.response_handle();
            let delay = timeout_delay(nanos);
            self.deadline_timer = Some(response.conn_handle().schedule_timer(
                delay,
                Box::new(move || {
                    rh.execute(move |w| {
                        fire_call_deadline(
                            &fired,
                            &cancelled_sent,
                            &ch,
                            &handler_ref,
                            w,
                        );
                    });
                }),
            ));
        }
        let request_type = self.request_type_name.clone().unwrap();
        let mut decoder = match self.codec {
            GrpcCodec::Proto => MessageDecoder::Proto(ProtoModelAdapter::new(
                (*self.proto_file).clone(),
                Box::new(SharedCallHandler(Arc::clone(&shared))) as Box<dyn GrpcCallHandler>,
            )),
            GrpcCodec::Json => MessageDecoder::Json(JsonModelAdapter::new(
                (*self.proto_file).clone(),
                Box::new(SharedCallHandler(Arc::clone(&shared))) as Box<dyn GrpcCallHandler>,
            )),
        };
        if let Err(e) = decoder.start_root_message(&request_type) {
            self.reject_grpc(response, GRPC_STATUS_INTERNAL, &format!("Invalid request type: {e}"));
            return;
        }
        self.decode = Some(DecodeState {
            decoder,
            frame_parser: Some(self.new_frame_parser()),
            message_done: false,
            root_open: true,
        });
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, mut data: &[u8]) {
        if self.stopped() || !self.body_started || data.is_empty() {
            return;
        }
        // One frame at a time: a streaming call decodes each message into
        // the handler as it completes; a unary call carries exactly one
        // message, so anything after it is a protocol violation, not a
        // second message to silently drop (issue #197).
        while !data.is_empty() {
            let already_done = self.decode.as_ref().map(|d| d.message_done).unwrap_or(false);
            if already_done && !self.client_streaming {
                self.reject_grpc(response, GRPC_STATUS_INTERNAL, "Too many request messages");
                return;
            }
            let request_type = self.request_type_name.clone().unwrap_or_default();
            let ended = {
                let Some(decode) = self.decode.as_mut() else {
                    return;
                };
                if !decode.root_open {
                    if let Err(e) = decode.decoder.start_root_message(&request_type) {
                        self.reject_grpc(response, GRPC_STATUS_INTERNAL, &format!("Invalid request type: {e}"));
                        return;
                    }
                    decode.root_open = true;
                }
                let Some(parser) = decode.frame_parser.as_mut() else {
                    return;
                };
                let consumed = parser.receive_until_frame(data);
                data = &data[consumed..];
                if let Some((status, err)) = parser.handler_mut().error.take() {
                    self.reject_grpc(response, status, &err);
                    return;
                }
                parser.handler_mut().ended
            };
            if !ended {
                break;
            }
            if let Err((status, e)) = self.finish_frame_message() {
                self.reject_grpc(response, status, &e);
                return;
            }
        }
        self.flush_pending(response);
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.body_rejected {
            return;
        }
        if !self.body_started && self.client_streaming && self.content_ok && !self.stopped() {
            // A client-streaming call may send no messages: the body is
            // empty, so nothing started the call before its end.
            self.start_request_body(response);
        }
        if !self.body_started {
            self.reject_grpc(response, GRPC_STATUS_INTERNAL, "Missing request body");
            return;
        }
        if self.body_rejected {
            return;
        }
        let (partial, done) = self
            .decode
            .as_ref()
            .map(|d| {
                (
                    d.frame_parser.as_ref().map(|p| p.has_partial_frame()).unwrap_or(false),
                    d.message_done,
                )
            })
            .unwrap_or((false, false));
        if partial || (!done && !self.client_streaming) {
            self.reject_grpc(response, GRPC_STATUS_INTERNAL, "Incomplete gRPC frame");
            return;
        }
        // The client half-closed: no more request messages.
        if let Some(decode) = self.decode.as_mut() {
            decode.decoder.handler_mut().end_requests();
        }
        self.flush_pending(response);
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        self.stop_deadline();
        self.flush_pending(response);
        if let Some(channel) = &self.channel {
            channel.detach();
        }
    }

    fn aborted(&mut self, _response: &mut dyn ServerWriter, _err: &std::io::Error) {
        if let Some(channel) = &self.channel {
            channel.cancel();
        }
        if let Some(decode) = self.decode.as_mut() {
            decode.decoder.handler_mut().cancelled();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::parse_grpc_content_type;
    use crate::proto::ProtoFileParser;
    use hopf_core::ConnHandle;
    use hopf_http::ServerResponseHandle;

    #[test]
    fn accepts_proto_and_json_content_types() {
        assert!(parse_grpc_content_type("application/grpc").is_some());
        assert!(parse_grpc_content_type("application/grpc+proto").is_some());
        assert!(parse_grpc_content_type("Application/gRPC+Proto").is_some());
        assert!(parse_grpc_content_type("application/grpc; charset=utf-8").is_some());
        assert!(parse_grpc_content_type("application/grpc+proto; charset=utf-8").is_some());
        assert!(parse_grpc_content_type("  application/grpc  ").is_some());
        assert_eq!(
            parse_grpc_content_type("application/grpc+json"),
            Some(GrpcCodec::Json)
        );
        assert_eq!(
            parse_grpc_content_type("APPLICATION/GRPC+JSON; charset=utf-8"),
            Some(GrpcCodec::Json)
        );
    }

    #[test]
    fn rejects_unsupported_content_types() {
        assert!(parse_grpc_content_type("application/grpc+thrift").is_none());
        assert!(parse_grpc_content_type("application/grpc-web").is_none());
        assert!(parse_grpc_content_type("application/grpc-web+proto").is_none());
        assert!(parse_grpc_content_type("application/json").is_none());
        assert!(parse_grpc_content_type("").is_none());
        assert!(parse_grpc_content_type("text/plain").is_none());
    }

    const TEST_PROTO: &str = r#"
        syntax = "proto3";
        package test;
        message Msg { string text = 1; }
        service TestSvc {
          rpc Call (Msg) returns (Msg);
          rpc ServerStream (Msg) returns (stream Msg);
          rpc ClientStream (stream Msg) returns (Msg);
          rpc Bidi (stream Msg) returns (stream Msg);
        }
    "#;

    /// Wire-encoded `Msg { text: "x" }`.
    fn test_message_payload() -> Vec<u8> {
        vec![0x0A, 0x01, b'x'] // field 1 (tag 0x0A = 1<<3|2), len 1, "x"
    }

    struct NoopHandler;
    impl ProtoMessageHandler for NoopHandler {
        fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn field(&mut self, _name: &str, _value: ScalarValue) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
    }

    struct NoopService;
    impl GrpcService for NoopService {
        fn start_unary_call(
            &self,
            _path: &str,
            _response: GrpcResponseChannel,
        ) -> Option<Box<dyn ProtoMessageHandler>> {
            Some(Box::new(NoopHandler))
        }
    }

    #[derive(Default)]
    struct MockWriter {
        headers: Option<Headers>,
        trailers: Option<Headers>,
        body: Vec<u8>,
    }

    impl MockWriter {
        fn status(&self) -> Option<u16> {
            self.headers.as_ref().map(Headers::status_code)
        }

        /// `grpc-status` from the trailers, or from the headers of a
        /// trailers-only response.
        fn grpc_status(&self) -> Option<i32> {
            self.trailers
                .as_ref()
                .or(self.headers.as_ref())
                .and_then(|h| h.get("grpc-status"))
                .and_then(|s| s.parse().ok())
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.headers.as_ref().and_then(|h| h.get(name))
        }
    }

    impl ServerWriter for MockWriter {
        fn headers(&mut self, headers: Headers) {
            self.headers = Some(headers);
        }
        fn start_response_body(&mut self) {}
        fn response_body_content(&mut self, data: &[u8]) {
            self.body.extend_from_slice(data);
        }
        fn end_response_body(&mut self) {}
        fn trailers(&mut self, headers: Headers) {
            self.trailers = Some(headers);
        }
        fn complete(&mut self) {}
        fn conn_handle(&self) -> ConnHandle {
            ConnHandle::from_execute(Arc::new(|task| task()))
        }
        fn response_handle(&self) -> ServerResponseHandle {
            ServerResponseHandle::detached(ConnHandle::from_execute(Arc::new(|task| task())))
        }
        fn pause_request_body(&mut self) {}
        fn resume_request_body(&mut self) {}
    }

    /// One length-prefixed, uncompressed gRPC frame wrapping `payload`.
    fn grpc_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8];
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn unary_handler() -> Box<dyn ServerHandler> {
        let proto = ProtoFileParser::parse(TEST_PROTO).unwrap();
        let factory = GrpcHandlerFactory::new(proto, Arc::new(NoopService));
        factory.create_handler()
    }

    struct MetadataEchoHandler {
        call: GrpcCall,
    }

    impl ProtoMessageHandler for MetadataEchoHandler {
        fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            let mut msg = self.call.open_message(None).unwrap();
            msg.field("text", ScalarValue::String("ok".into())).unwrap();
            msg.complete().unwrap();
            Ok(())
        }
        fn field(&mut self, _name: &str, _value: ScalarValue) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
    }

    impl GrpcCallHandler for MetadataEchoHandler {}

    struct MetadataEchoService {
        captured: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl GrpcService for MetadataEchoService {
        fn start_call(&self, _path: &str, call: GrpcCall) -> Option<Box<dyn GrpcCallHandler>> {
            assert_eq!(call.request_metadata().get("x-token"), Some("secret"));
            *self.captured.lock().unwrap() = call.request_metadata().get_binary("x-auth-bin");
            assert!(call.deadline().is_some());
            call.with_response_metadata(|md| {
                md.add_binary("x-resp-bin", b"ok").unwrap();
            });
            Some(Box::new(MetadataEchoHandler { call }))
        }
    }

    #[test]
    fn request_metadata_bin_and_deadline_reach_the_call() {
        let captured = Arc::new(Mutex::new(None));
        let proto = ProtoFileParser::parse(TEST_PROTO).unwrap();
        let factory = GrpcHandlerFactory::new(
            proto,
            Arc::new(MetadataEchoService {
                captured: Arc::clone(&captured),
            }),
        );
        let mut handler = factory.create_handler();
        let mut w = MockWriter::default();

        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", "/test.TestSvc/Call");
        h.set("content-type", "application/grpc");
        h.set("x-token", "secret");
        h.set("x-auth-bin", &crate::proto::base64::encode(&[0xAB]));
        h.set("grpc-timeout", "50m");
        handler.headers(&mut w, &h);
        handler.start_request_body(&mut w);
        handler.request_body_content(&mut w, &grpc_frame(&test_message_payload()));
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);

        assert_eq!(*captured.lock().unwrap(), Some(vec![0xAB]));
        assert_eq!(w.grpc_status(), Some(0));
        assert!(w
            .headers
            .as_ref()
            .and_then(|h| h.get("x-resp-bin"))
            .is_some());
    }

    #[test]
    fn server_deadline_ends_call_with_deadline_exceeded() {
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));

        struct SlowHandler {
            cancelled: Arc<std::sync::atomic::AtomicBool>,
        }

        impl ProtoMessageHandler for SlowHandler {
            fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
                Ok(())
            }
            fn end_message(&mut self) -> Result<(), ProtoParseError> {
                Ok(())
            }
            fn field(&mut self, _name: &str, _value: ScalarValue) -> Result<(), ProtoParseError> {
                Ok(())
            }
            fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
                Ok(())
            }
            fn end_field(&mut self) -> Result<(), ProtoParseError> {
                Ok(())
            }
        }

        impl GrpcCallHandler for SlowHandler {
            fn cancelled(&mut self) {
                self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let proto = Arc::new(ProtoFileParser::parse(TEST_PROTO).unwrap());
        let channel = GrpcResponseChannel::new(
            Arc::clone(&proto),
            Some("test.Msg".into()),
            GrpcCodec::Proto,
            true,
        );
        channel.configure("identity".into(), None, DEFAULT_COMPRESSION_THRESHOLD);
        let shared: Arc<Mutex<Box<dyn GrpcCallHandler>>> = Arc::new(Mutex::new(Box::new(
            SlowHandler {
                cancelled: Arc::clone(&cancelled),
            },
        )));
        let mut w = MockWriter::default();
        let fired = Arc::new(AtomicBool::new(false));
        let cancelled_sent = Arc::new(AtomicBool::new(false));
        fire_call_deadline(
            &fired,
            &cancelled_sent,
            &channel,
            &shared,
            &mut w,
        );

        assert_eq!(w.grpc_status(), Some(GRPC_STATUS_DEADLINE_EXCEEDED));
        assert!(cancelled.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// Issue #197: a unary request carrying a *second* complete gRPC
    /// message frame must be rejected, not silently discarded -
    /// `GrpcService` has no streaming variant, so any bytes after the
    /// first frame completes are a genuine protocol violation. The
    /// rejection is a gRPC one (HTTP 200, trailers-only, INTERNAL), as a
    /// gRPC client expects, not an HTTP 400.
    #[test]
    fn second_frame_in_a_unary_request_is_rejected() {
        let mut handler = unary_handler();
        let mut w = MockWriter::default();

        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", "/test.TestSvc/Call");
        h.set("content-type", "application/grpc");
        handler.headers(&mut w, &h);
        handler.start_request_body(&mut w);
        assert_eq!(w.status(), None, "no response expected yet");

        let msg = grpc_frame(&test_message_payload());
        handler.request_body_content(&mut w, &msg);
        assert_eq!(w.status(), None, "first frame alone must not reject the request");

        // A second complete frame — the actual bug: this used to be
        // silently discarded instead of rejected.
        handler.request_body_content(&mut w, &msg);
        assert_eq!(w.status(), Some(200), "a second frame in a unary request must be rejected with a gRPC status: {:?}", w.status());
        assert_eq!(w.grpc_status(), Some(13), "expected INTERNAL");
        assert!(w.body.is_empty(), "a trailers-only response has no body");
        assert!(
            !w.header("grpc-message").unwrap_or("").is_empty(),
            "a rejection should carry an explanatory grpc-message"
        );
    }

    /// A frame with a compression flag that is neither 0 nor 1 is not
    /// gRPC: INTERNAL, as a gRPC status rather than an HTTP error.
    #[test]
    fn corrupt_frame_is_internal() {
        let mut handler = echo_factory().create_handler();
        let mut framed = grpc_frame(&test_message_payload());
        framed[0] = 2;
        let w = run_unary(&mut *handler, &[], &framed);
        assert_eq!(w.status(), Some(200));
        assert_eq!(w.grpc_status(), Some(13));
    }

    /// A message over the configured size limit is RESOURCE_EXHAUSTED.
    #[test]
    fn oversized_message_is_resource_exhausted() {
        let mut factory = echo_factory();
        factory.set_max_message_size(8);
        let mut handler = factory.create_handler();
        let w = run_unary(&mut *handler, &[], &grpc_frame(&[0u8; 9]));
        assert_eq!(w.status(), Some(200));
        assert_eq!(w.grpc_status(), Some(8));
    }

    /// A message that is not valid protobuf is INTERNAL.
    #[test]
    fn undecodable_message_is_internal() {
        let mut handler = echo_factory().create_handler();
        // field 1 with wire type 7, which does not exist
        let w = run_unary(&mut *handler, &[], &grpc_frame(&[0x0F, 0x00]));
        assert_eq!(w.status(), Some(200));
        assert_eq!(w.grpc_status(), Some(13));
    }

    /// A request body that ends part-way through a frame is INTERNAL.
    #[test]
    fn truncated_frame_is_internal() {
        let mut handler = echo_factory().create_handler();
        let framed = grpc_frame(&test_message_payload());
        let w = run_unary(&mut *handler, &[], &framed[..framed.len() - 1]);
        assert_eq!(w.status(), Some(200));
        assert_eq!(w.grpc_status(), Some(13));
    }

    /// A single-frame unary request must still work normally — the fix
    /// must not reject the first (only) frame.
    #[test]
    fn single_frame_unary_request_is_not_rejected() {
        let mut handler = unary_handler();
        let mut w = MockWriter::default();

        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", "/test.TestSvc/Call");
        h.set("content-type", "application/grpc");
        handler.headers(&mut w, &h);
        handler.start_request_body(&mut w);

        let msg = grpc_frame(&test_message_payload());
        handler.request_body_content(&mut w, &msg);
        handler.end_request_body(&mut w);

        assert_ne!(w.status(), Some(400), "a single well-formed frame must not be rejected: {:?} body={:?}", w.status(), String::from_utf8_lossy(&w.body));
    }

    /// Service whose request handler answers with `Msg { text: "echo:" +
    /// <request text> }` as soon as the request message ends, so a test
    /// can see what the service was given.
    struct EchoService;

    struct EchoHandler {
        channel: GrpcResponseChannel,
        text: String,
    }

    impl ProtoMessageHandler for EchoHandler {
        fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            let mut m = self.channel.open_message(None).unwrap();
            m.field("text", ScalarValue::String(format!("echo:{}", self.text))).unwrap();
            m.complete().unwrap();
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
            if name == "text" {
                if let ScalarValue::String(s) = value {
                    self.text = s;
                }
            }
            Ok(())
        }
        fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
    }

    impl GrpcService for EchoService {
        fn start_unary_call(
            &self,
            _path: &str,
            response: GrpcResponseChannel,
        ) -> Option<Box<dyn ProtoMessageHandler>> {
            Some(Box::new(EchoHandler {
                channel: response,
                text: String::new(),
            }))
        }
    }

    fn echo_factory() -> GrpcHandlerFactory {
        let proto = ProtoFileParser::parse(TEST_PROTO).unwrap();
        GrpcHandlerFactory::new(proto, Arc::new(EchoService))
    }

    /// Wire-encoded `Msg { text }`.
    fn msg(text: &str) -> Vec<u8> {
        let mut out = vec![0x0A];
        let mut n = text.len();
        while n >= 0x80 {
            out.push((n as u8 & 0x7F) | 0x80);
            n >>= 7;
        }
        out.push(n as u8);
        out.extend_from_slice(text.as_bytes());
        out
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut d = hopf_http::Decoder::new(ContentCoding::Gzip, 1 << 20).unwrap();
        let mut out = Vec::new();
        d.push(data, &mut |o| out.extend_from_slice(o)).unwrap();
        d.finish().unwrap();
        out
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = hopf_http::Encoder::new(ContentCoding::Gzip).unwrap();
        let mut out = Vec::new();
        e.push(data, &mut |o| out.extend_from_slice(o)).unwrap();
        e.finish(&mut |o| out.extend_from_slice(o)).unwrap();
        out
    }

    /// One gRPC frame with the compressed flag set.
    fn compressed_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = grpc_frame(payload);
        out[0] = 1;
        out
    }

    /// Runs one unary request through `handler`: headers, then `body` as a
    /// single chunk, then end of body and request completion.
    fn run_unary(handler: &mut dyn ServerHandler, extra: &[(&str, &str)], body: &[u8]) -> MockWriter {
        let mut w = MockWriter::default();
        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", "/test.TestSvc/Call");
        h.set("content-type", "application/grpc");
        for (k, v) in extra {
            h.set(*k, *v);
        }
        handler.headers(&mut w, &h);
        if w.status().is_none() {
            handler.start_request_body(&mut w);
            handler.request_body_content(&mut w, body);
            handler.end_request_body(&mut w);
        }
        handler.request_complete(&mut w);
        w
    }

    /// An empty request message (all default fields) is a zero-length
    /// frame: the header alone must complete it and the call must succeed.
    #[test]
    fn unary_call_with_empty_request_message_succeeds() {
        let mut handler = echo_factory().create_handler();
        let w = run_unary(&mut *handler, &[], &grpc_frame(b""));
        assert_eq!(
            w.status(),
            Some(200),
            "empty message rejected: body={:?}",
            String::from_utf8_lossy(&w.body)
        );
        assert_eq!(w.grpc_status(), Some(0));
        assert_eq!(w.body, grpc_frame(&msg("echo:")));
    }

    #[test]
    fn server_decodes_gzip_compressed_request() {
        let mut handler = echo_factory().create_handler();
        let body = compressed_frame(&gzip(&msg("hello")));
        let w = run_unary(&mut *handler, &[("grpc-encoding", "gzip")], &body);
        assert_eq!(w.status(), Some(200), "{:?}", w.headers);
        assert_eq!(w.grpc_status(), Some(0), "{:?}", w.headers);
        assert_eq!(w.body, grpc_frame(&msg("echo:hello")));
    }

    /// A request in an encoding the server does not offer is answered
    /// UNIMPLEMENTED before the service sees it, with the encodings it
    /// would have understood.
    #[test]
    fn unsupported_request_encoding_is_unimplemented() {
        for token in ["snappy", "br"] {
            let mut handler = echo_factory().create_handler();
            let body = compressed_frame(&gzip(&msg("hello")));
            let w = run_unary(&mut *handler, &[("grpc-encoding", token)], &body);
            assert_eq!(w.status(), Some(200), "{token}: {:?}", w.headers);
            assert_eq!(w.grpc_status(), Some(12), "{token}: {:?}", w.headers);
            assert_eq!(w.header("grpc-accept-encoding"), Some("identity,gzip,deflate"));
            assert!(w.body.is_empty());
        }
    }

    #[test]
    fn brotli_request_is_decoded_when_enabled() {
        let factory = echo_factory().encodings(&[ContentCoding::Brotli, ContentCoding::Gzip]);
        let mut handler = factory.create_handler();
        let mut e = hopf_http::Encoder::new(ContentCoding::Brotli).unwrap();
        let mut packed = Vec::new();
        e.push(&msg("hi"), &mut |o| packed.extend_from_slice(o)).unwrap();
        e.finish(&mut |o| packed.extend_from_slice(o)).unwrap();
        let w = run_unary(&mut *handler, &[("grpc-encoding", "br")], &compressed_frame(&packed));
        assert_eq!(w.grpc_status(), Some(0), "{:?}", w.headers);
        assert_eq!(w.header("grpc-accept-encoding"), Some("identity,br,gzip"));
        assert_eq!(w.body, grpc_frame(&msg("echo:hi")));
    }

    #[test]
    fn compressed_message_without_grpc_encoding_is_internal() {
        for extra in [&[][..], &[("grpc-encoding", "identity")][..]] {
            let mut handler = echo_factory().create_handler();
            let body = compressed_frame(&gzip(&msg("hello")));
            let w = run_unary(&mut *handler, extra, &body);
            assert_eq!(w.status(), Some(200));
            assert_eq!(w.grpc_status(), Some(13), "{:?}", w.headers);
        }
    }

    /// A small compressed message that expands beyond the message limit is
    /// RESOURCE_EXHAUSTED: a decompression bomb must not get through.
    #[test]
    fn compressed_message_over_limit_is_resource_exhausted() {
        let mut factory = echo_factory();
        factory.set_max_message_size(64);
        let mut handler = factory.create_handler();
        let packed = gzip(&vec![0u8; 4096]);
        assert!(packed.len() < 64);
        let w = run_unary(&mut *handler, &[("grpc-encoding", "gzip")], &compressed_frame(&packed));
        assert_eq!(w.status(), Some(200));
        assert_eq!(w.grpc_status(), Some(8), "{:?}", w.headers);
    }

    #[test]
    fn corrupt_compressed_message_is_internal() {
        let mut handler = echo_factory().create_handler();
        let body = compressed_frame(b"this is not gzip");
        let w = run_unary(&mut *handler, &[("grpc-encoding", "gzip")], &body);
        assert_eq!(w.status(), Some(200));
        assert_eq!(w.grpc_status(), Some(13), "{:?}", w.headers);
    }

    #[test]
    fn server_compresses_large_response_when_client_accepts_gzip() {
        let mut handler = echo_factory().create_handler();
        let text = "a".repeat(600);
        let w = run_unary(
            &mut *handler,
            &[("grpc-accept-encoding", "deflate,gzip")],
            &grpc_frame(&msg(&text)),
        );
        assert_eq!(w.grpc_status(), Some(0), "{:?}", w.headers);
        assert_eq!(w.header("grpc-encoding"), Some("gzip"));
        assert_eq!(w.body[0], 1, "compressed flag");
        let len = u32::from_be_bytes(w.body[1..5].try_into().unwrap()) as usize;
        assert_eq!(len, w.body.len() - 5);
        assert!(len < 600, "not smaller: {len}");
        assert_eq!(gunzip(&w.body[5..]), msg(&format!("echo:{text}")));
    }

    #[test]
    fn server_does_not_compress_when_client_accepts_nothing() {
        let text = "a".repeat(600);
        let mut handler = echo_factory().create_handler();
        let w = run_unary(&mut *handler, &[], &grpc_frame(&msg(&text)));
        assert_eq!(w.grpc_status(), Some(0));
        assert_eq!(w.header("grpc-encoding"), None);
        assert_eq!(w.body, grpc_frame(&msg(&format!("echo:{text}"))));

        let mut handler = echo_factory().create_handler();
        let w = run_unary(
            &mut *handler,
            &[("grpc-accept-encoding", "identity,snappy")],
            &grpc_frame(&msg(&text)),
        );
        assert_eq!(w.header("grpc-encoding"), None);
        assert_eq!(w.body, grpc_frame(&msg(&format!("echo:{text}"))));
    }

    #[test]
    fn server_does_not_compress_below_threshold_or_when_off() {
        let mut handler = echo_factory().create_handler();
        let w = run_unary(
            &mut *handler,
            &[("grpc-accept-encoding", "gzip")],
            &grpc_frame(&msg("small")),
        );
        assert_eq!(w.grpc_status(), Some(0));
        assert_eq!(w.body, grpc_frame(&msg("echo:small")), "{:?}", w.body);

        let text = "a".repeat(600);
        let mut handler = echo_factory().compress_responses(false).create_handler();
        let w = run_unary(
            &mut *handler,
            &[("grpc-accept-encoding", "gzip")],
            &grpc_frame(&msg(&text)),
        );
        assert_eq!(w.header("grpc-encoding"), None);
        assert_eq!(w.body, grpc_frame(&msg(&format!("echo:{text}"))));

        // a lower threshold compresses the small message too
        let mut handler = echo_factory().compression_threshold(1).create_handler();
        let w = run_unary(
            &mut *handler,
            &[("grpc-accept-encoding", "gzip")],
            &grpc_frame(&msg(&"ab".repeat(40))),
        );
        assert_eq!(w.header("grpc-encoding"), Some("gzip"));
        assert_eq!(w.body[0], 1, "compressed flag");
        assert_eq!(gunzip(&w.body[5..]), msg(&format!("echo:{}", "ab".repeat(40))));
    }

    /// Every response says what the server decodes.
    #[test]
    fn responses_carry_grpc_accept_encoding() {
        let mut handler = echo_factory().create_handler();
        let w = run_unary(&mut *handler, &[], &grpc_frame(&msg("x")));
        assert_eq!(w.grpc_status(), Some(0));
        assert_eq!(w.header("grpc-accept-encoding"), Some("identity,gzip,deflate"));

        let mut handler = echo_factory().create_handler();
        let w = run_unary(&mut *handler, &[], &grpc_frame(&[0x0F, 0x00]));
        assert_eq!(w.grpc_status(), Some(13));
        assert_eq!(w.header("grpc-accept-encoding"), Some("identity,gzip,deflate"));
    }

    /// A streaming service: `ServerStream` answers one request with three
    /// messages, `ClientStream` answers the half-close with the joined
    /// texts, `Bidi` echoes each message and closes on half-close.
    #[derive(Default)]
    struct Flags {
        cancelled: std::sync::atomic::AtomicBool,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Server,
        Client,
        Bidi,
    }

    struct StreamingEcho {
        flags: Arc<Flags>,
    }

    struct StreamingHandler {
        call: GrpcCall,
        mode: Mode,
        text: String,
        received: Vec<String>,
        flags: Arc<Flags>,
    }

    fn send_text(call: &GrpcCall, text: &str) {
        let mut m = call.open_message(None).unwrap();
        m.field("text", ScalarValue::String(text.to_string())).unwrap();
        m.complete().unwrap();
    }

    impl ProtoMessageHandler for StreamingHandler {
        fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
            self.text.clear();
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            self.received.push(self.text.clone());
            match self.mode {
                Mode::Server => {
                    for i in 1..=3 {
                        send_text(&self.call, &format!("echo:{}#{i}", self.text));
                    }
                    self.call.close();
                }
                Mode::Client => {}
                Mode::Bidi => send_text(&self.call, &format!("echo:{}", self.text)),
            }
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
            if name == "text" {
                if let ScalarValue::String(s) = value {
                    self.text = s;
                }
            }
            Ok(())
        }
        fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
    }

    impl GrpcCallHandler for StreamingHandler {
        fn end_requests(&mut self) {
            match self.mode {
                Mode::Client => {
                    send_text(&self.call, &self.received.join(","));
                    self.call.close();
                }
                Mode::Bidi => self.call.close(),
                Mode::Server => {}
            }
        }
        fn cancelled(&mut self) {
            self.flags.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl GrpcService for StreamingEcho {
        fn streaming_supported(&self) -> bool {
            true
        }
        fn start_call(&self, path: &str, call: GrpcCall) -> Option<Box<dyn GrpcCallHandler>> {
            let mode = if path.ends_with("/ServerStream") {
                Mode::Server
            } else if path.ends_with("/ClientStream") {
                Mode::Client
            } else if path.ends_with("/Bidi") {
                Mode::Bidi
            } else {
                return None;
            };
            Some(Box::new(StreamingHandler {
                call,
                mode,
                text: String::new(),
                received: Vec::new(),
                flags: Arc::clone(&self.flags),
            }))
        }
    }

    fn streaming_handler() -> (Box<dyn ServerHandler>, Arc<Flags>) {
        let flags = Arc::new(Flags::default());
        let proto = ProtoFileParser::parse(TEST_PROTO).unwrap();
        let factory = GrpcHandlerFactory::new(proto, Arc::new(StreamingEcho { flags: Arc::clone(&flags) }));
        (factory.create_handler(), flags)
    }

    fn start_call(handler: &mut dyn ServerHandler, w: &mut MockWriter, method: &str) {
        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", &format!("/test.TestSvc/{method}"));
        h.set("content-type", "application/grpc");
        handler.headers(w, &h);
        handler.start_request_body(w);
    }

    /// The `Msg.text` of every frame in a response body.
    fn texts_in(body: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = body;
        while rest.len() >= 5 {
            let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
            let payload = &rest[5..5 + len];
            assert_eq!(payload[0], 0x0A, "field 1, length-delimited");
            let (mut n, mut i, mut shift) = (0usize, 1usize, 0);
            loop {
                let b = payload[i];
                n |= ((b & 0x7F) as usize) << shift;
                i += 1;
                if b & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            out.push(String::from_utf8(payload[i..i + n].to_vec()).unwrap());
            rest = &rest[5 + len..];
        }
        out
    }

    /// Server streaming: one request, three response messages, then the
    /// OK status in the trailers.
    #[test]
    fn server_streaming_sends_three_messages_then_ok_trailers() {
        let (mut handler, _) = streaming_handler();
        let mut w = MockWriter::default();
        start_call(&mut *handler, &mut w, "ServerStream");
        handler.request_body_content(&mut w, &grpc_frame(&msg("hi")));
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);
        assert_eq!(w.status(), Some(200), "{:?}", w.headers);
        assert_eq!(texts_in(&w.body), vec!["echo:hi#1", "echo:hi#2", "echo:hi#3"]);
        assert_eq!(w.grpc_status(), Some(0));
        assert!(w.trailers.is_some(), "status must be in trailers, after the messages");
    }

    /// Client streaming: three request messages, half-close, one response.
    #[test]
    fn client_streaming_half_close_yields_one_response() {
        let (mut handler, _) = streaming_handler();
        let mut w = MockWriter::default();
        start_call(&mut *handler, &mut w, "ClientStream");
        for t in ["a", "b", "c"] {
            handler.request_body_content(&mut w, &grpc_frame(&msg(t)));
            assert!(w.body.is_empty(), "no response before the half-close");
        }
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);
        assert_eq!(texts_in(&w.body), vec!["a,b,c"]);
        assert_eq!(w.grpc_status(), Some(0));
    }

    /// A response message bigger than the ring it starts with is written
    /// whole: the ring grows (more than once here) and keeps what it held.
    #[test]
    fn response_message_larger_than_the_initial_ring_is_written_whole() {
        let big = "x".repeat(3 * RESPONSE_RING_BYTES + 5);
        let (mut handler, _) = streaming_handler();
        let mut w = MockWriter::default();
        start_call(&mut *handler, &mut w, "ClientStream");
        handler.request_body_content(&mut w, &grpc_frame(&msg(&big)));
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);
        assert_eq!(texts_in(&w.body), vec![big]);
        assert_eq!(w.grpc_status(), Some(0));
    }

    /// A client-streaming call may send no messages at all: the request
    /// body is then empty, and only its end is seen, never its start. The
    /// call still runs, sees the half-close at once and answers.
    #[test]
    fn client_streaming_with_no_messages_gets_its_response() {
        let (mut handler, _) = streaming_handler();
        let mut w = MockWriter::default();
        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", "/test.TestSvc/ClientStream");
        h.set("content-type", "application/grpc");
        handler.headers(&mut w, &h);
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);
        assert_eq!(w.status(), Some(200), "{:?}", w.headers);
        assert_eq!(w.grpc_status(), Some(0), "{:?}", w.trailers);
        assert!(!w.body.is_empty(), "the response message is missing");
    }

    /// Bidirectional: each request message is echoed as it arrives, and
    /// the half-close ends the call.
    #[test]
    fn bidirectional_echo() {
        let (mut handler, _) = streaming_handler();
        let mut w = MockWriter::default();
        start_call(&mut *handler, &mut w, "Bidi");
        handler.request_body_content(&mut w, &grpc_frame(&msg("one")));
        assert_eq!(texts_in(&w.body), vec!["echo:one"]);
        handler.request_body_content(&mut w, &grpc_frame(&msg("two")));
        assert_eq!(texts_in(&w.body), vec!["echo:one", "echo:two"]);
        assert!(w.trailers.is_none(), "not ended yet");
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);
        assert_eq!(w.grpc_status(), Some(0));
    }

    /// A peer reset mid-call reaches the handler's `cancelled`.
    #[test]
    fn peer_reset_mid_call_reaches_cancelled() {
        let (mut handler, flags) = streaming_handler();
        let mut w = MockWriter::default();
        start_call(&mut *handler, &mut w, "Bidi");
        handler.request_body_content(&mut w, &grpc_frame(&msg("one")));
        handler.aborted(&mut w, &std::io::Error::new(std::io::ErrorKind::ConnectionReset, "RST_STREAM"));
        assert!(flags.cancelled.load(std::sync::atomic::Ordering::SeqCst), "cancelled() not called");
    }

    // -- nested messages, repeated fields and maps in a response (issue #513) --------

    const NESTED_PROTO: &str = r#"
        syntax = "proto3";
        package test;
        message Inner { int32 v = 1; }
        message Req { }
        message Rep {
            repeated string names = 1; Inner one = 2; map<string, int32> counts = 3;
            repeated Inner inners = 4; map<string, Inner> by_name = 5; string note = 6;
            google.protobuf.Timestamp at = 7; google.protobuf.Duration took = 8;
            google.protobuf.Struct extra = 9;
        }
        service Svc { rpc Call (Req) returns (Rep); }
    "#;

    /// A service that answers every call by running a script on the response.
    struct ScriptedHandler {
        channel: GrpcResponseChannel,
        script: Arc<dyn Fn(&mut GrpcResponseMessage) -> Result<(), String> + Send + Sync>,
        failed: Arc<Mutex<Option<String>>>,
    }

    impl ProtoMessageHandler for ScriptedHandler {
        fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            let mut m = self.channel.open_message(None).unwrap();
            if let Err(e) = (self.script)(&mut m) {
                *self.failed.lock().unwrap() = Some(e);
                return Ok(());
            }
            if let Err(e) = m.complete() {
                *self.failed.lock().unwrap() = Some(e);
            }
            Ok(())
        }
        fn field(&mut self, _name: &str, _value: ScalarValue) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
    }

    struct ScriptedService {
        script: Arc<dyn Fn(&mut GrpcResponseMessage) -> Result<(), String> + Send + Sync>,
        failed: Arc<Mutex<Option<String>>>,
    }

    impl GrpcService for ScriptedService {
        fn start_unary_call(&self, _path: &str, response: GrpcResponseChannel) -> Option<Box<dyn ProtoMessageHandler>> {
            Some(Box::new(ScriptedHandler { channel: response, script: Arc::clone(&self.script), failed: Arc::clone(&self.failed) }))
        }
    }

    /// The response payload (unframed) of a unary call answered by `script`,
    /// in `content_type`, and what went wrong in the script if anything.
    fn respond(content_type: &str, script: impl Fn(&mut GrpcResponseMessage) -> Result<(), String> + Send + Sync + 'static) -> (Vec<u8>, Option<String>) {
        let failed = Arc::new(Mutex::new(None));
        let proto = ProtoFileParser::parse(NESTED_PROTO).unwrap();
        let factory = GrpcHandlerFactory::new(
            proto,
            Arc::new(ScriptedService { script: Arc::new(script), failed: Arc::clone(&failed) }),
        );
        let mut handler = factory.create_handler();
        let mut w = MockWriter::default();
        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", "/test.Svc/Call");
        h.set("content-type", content_type);
        handler.headers(&mut w, &h);
        handler.start_request_body(&mut w);
        let request: &[u8] = if content_type.ends_with("json") { b"{}" } else { b"" };
        handler.request_body_content(&mut w, &grpc_frame(request));
        handler.end_request_body(&mut w);
        handler.request_complete(&mut w);
        let payload = w.body.get(5..).unwrap_or_default().to_vec();
        let failed = failed.lock().unwrap().clone();
        (payload, failed)
    }

    fn text(s: &str) -> ScalarValue {
        ScalarValue::String(s.into())
    }

    /// A handler's way of writing a `Rep`, the same for both encodings.
    fn write_rep(m: &mut GrpcResponseMessage) -> Result<(), String> {
        m.field("names", text("a"))?;
        m.field("names", text("b"))?;
        m.start_field("one", "test.Inner")?;
        m.field("v", ScalarValue::I32(5))?;
        m.end_field()?;
        m.start_field("counts", "")?;
        m.field("key", text("x"))?;
        m.field("value", ScalarValue::I32(1))?;
        m.end_field()?;
        m.start_field("counts", "")?;
        m.field("key", text("y"))?;
        m.field("value", ScalarValue::I32(2))?;
        m.end_field()?;
        for v in [1, 2] {
            m.start_field("inners", "test.Inner")?;
            m.field("v", ScalarValue::I32(v))?;
            m.end_field()?;
        }
        m.start_field("by_name", "")?;
        m.field("key", text("k"))?;
        m.start_field("value", "test.Inner")?;
        m.field("v", ScalarValue::I32(9))?;
        m.end_field()?;
        m.end_field()?;
        Ok(())
    }

    #[test]
    fn a_handler_writes_nested_repeated_and_map_fields_as_json() {
        let (payload, failed) = respond("application/grpc+json", write_rep);
        assert_eq!(failed, None);
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            r#"{"names":["a","b"],"one":{"v":5},"counts":{"x":1,"y":2},"inners":[{"v":1},{"v":2}],"byName":{"k":{"v":9}}}"#
        );
    }

    #[test]
    fn the_same_calls_write_them_as_protobuf() {
        fn len(field: u8, body: &[u8]) -> Vec<u8> {
            [vec![field << 3 | 2, body.len() as u8], body.to_vec()].concat()
        }
        let (payload, failed) = respond("application/grpc", write_rep);
        assert_eq!(failed, None);
        let expected = [
            len(1, b"a"),
            len(1, b"b"),
            len(2, &[0x08, 5]),
            len(3, &[len(1, b"x"), vec![0x10, 1]].concat()),
            len(3, &[len(1, b"y"), vec![0x10, 2]].concat()),
            len(4, &[0x08, 1]),
            len(4, &[0x08, 2]),
            len(5, &[len(1, b"k"), len(2, &[0x08, 9])].concat()),
        ]
        .concat();
        assert_eq!(payload, expected);
    }

    #[test]
    fn values_far_bigger_than_the_ring_are_written_whole_inside_nested_messages() {
        // The ring starts at 16 KiB; a repeated field of long strings and a
        // map with thousands of entries make it grow in the middle of the
        // multi-part writes (a key then its value, a bracket then an element).
        fn big(m: &mut GrpcResponseMessage) -> Result<(), String> {
            for i in 0..3 {
                m.field("names", ScalarValue::String(format!("{i}{}", "x".repeat(40_000))))?;
            }
            for i in 0..2_000 {
                m.start_field("counts", "")?;
                m.field("key", ScalarValue::String(format!("key-{i}")))?;
                m.field("value", ScalarValue::I32(i))?;
                m.end_field()?;
            }
            m.start_field("one", "test.Inner")?;
            m.field("v", ScalarValue::I32(1))?;
            m.end_field()
        }
        let (json, failed) = respond("application/grpc+json", big);
        assert_eq!(failed, None);
        let json = String::from_utf8(json).unwrap();
        assert!(json.starts_with(&format!(r#"{{"names":["0{}","1"#, "x".repeat(40_000))), "starts wrong");
        assert!(json.contains(r#""key-0":0,"key-1":1,"#) && json.contains(r#""key-1999":1999}"#));
        assert!(json.ends_with(r#""one":{"v":1}}"#));
        assert_eq!(json.matches("key-").count(), 2_000);

        let (pb, failed) = respond("application/grpc", big);
        assert_eq!(failed, None);
        assert!(pb.len() > 120_000 + 2_000 * 8, "{}", pb.len());
        assert!(pb.ends_with(&[0x12, 2, 0x08, 1]), "the last field is `one`");
    }

    #[test]
    fn a_nested_message_left_open_is_refused_at_complete_not_written_broken() {
        for ct in ["application/grpc+json", "application/grpc"] {
            let (payload, failed) = respond(ct, |m| {
                m.start_field("one", "test.Inner")?;
                m.field("v", ScalarValue::I32(1))
            });
            assert!(failed.as_deref().is_some_and(|f| f.contains("never ended")), "{ct}: {failed:?}");
            assert!(payload.is_empty(), "{ct}: nothing was sent");
        }
    }

    #[test]
    fn ending_a_field_that_was_not_started_is_an_error() {
        for ct in ["application/grpc+json", "application/grpc"] {
            let (_, failed) = respond(ct, |m| m.end_field());
            assert!(failed.as_deref().is_some_and(|f| f.contains("without a start_field")), "{ct}: {failed:?}");
        }
    }

    #[test]
    fn a_field_the_response_type_does_not_have_is_skipped_in_either_encoding() {
        for (ct, expected) in [("application/grpc+json", r#"{"names":["a"]}"#.as_bytes().to_vec()), ("application/grpc", vec![0x0a, 1, b'a'])] {
            let (payload, failed) = respond(ct, |m| {
                m.start_field("nope", "test.Inner")?;
                m.field("v", ScalarValue::I32(1))?;
                m.end_field()?;
                m.field("names", text("a"))
            });
            assert_eq!(failed, None, "{ct}");
            assert_eq!(payload, expected, "{ct}");
        }
    }

    #[test]
    fn a_long_value_is_written_once_whatever_the_size_of_the_ring() {
        // A key and then a value that does not fit the ring: the value's
        // write is repeated after the ring grows, and the key must not be.
        for ct in ["application/grpc+json", "application/grpc"] {
            let (payload, failed) = respond(ct, |m| {
                m.field("note", ScalarValue::String("n".repeat(100_000)))?;
                m.start_field("counts", "")?;
                m.field("key", ScalarValue::String("k".repeat(100_000)))?;
                m.field("value", ScalarValue::I32(1))?;
                m.end_field()
            });
            assert_eq!(failed, None, "{ct}");
            if ct.ends_with("json") {
                let json = String::from_utf8(payload).unwrap();
                assert_eq!(json.matches(r#""note""#).count(), 1, "the key was written twice");
                assert!(json.starts_with(&format!(r#"{{"note":"{}","counts":{{"{}":1}}}}"#, "n".repeat(100_000), "k".repeat(100_000))));
            } else {
                assert_eq!(payload.len(), 2 + 3 + 100_000 + 3 + (1 + 3 + 100_000 + 2), "{}", payload.len());
            }
        }
    }

    #[test]
    fn a_timestamp_and_a_duration_are_json_strings_in_json_and_messages_in_protobuf() {
        let script = |m: &mut GrpcResponseMessage| {
            m.start_field("at", "google.protobuf.Timestamp")?;
            m.field("seconds", ScalarValue::I64(63_108_020))?;
            m.field("nanos", ScalarValue::I32(21_000_000))?;
            m.end_field()?;
            m.start_field("took", "google.protobuf.Duration")?;
            m.field("seconds", ScalarValue::I64(1))?;
            m.field("nanos", ScalarValue::I32(500_000_000))?;
            m.end_field()
        };
        let (json, failed) = respond("application/grpc+json", script);
        assert_eq!(failed, None);
        assert_eq!(String::from_utf8(json).unwrap(), r#"{"at":"1972-01-01T10:00:20.021Z","took":"1.500s"}"#);

        let (pb, failed) = respond("application/grpc", script);
        assert_eq!(failed, None);
        // field 7 (Timestamp): seconds = 63108020, nanos = 21000000; field 8 (Duration)
        let varint = |mut v: u64| {
            let mut out = Vec::new();
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    return out;
                }
                out.push(b | 0x80);
            }
        };
        let ts = [vec![0x08], varint(63_108_020), vec![0x10], varint(21_000_000)].concat();
        let dur = [vec![0x08, 1, 0x10], varint(500_000_000)].concat();
        let expected = [vec![7 << 3 | 2, ts.len() as u8], ts, vec![8 << 3 | 2, dur.len() as u8], dur].concat();
        assert_eq!(pb, expected);
    }

    #[test]
    fn a_struct_is_plain_json_in_json_and_a_map_of_values_in_protobuf() {
        let script = |m: &mut GrpcResponseMessage| {
            const V: &str = "google.protobuf.Value";
            m.start_field("extra", "google.protobuf.Struct")?;
            m.start_field("fields", "fields.MapEntry")?;
            m.field("key", text("n"))?;
            m.start_field("value", V)?;
            m.field("number_value", ScalarValue::F64(1.5))?;
            m.end_field()?;
            m.end_field()?;
            m.start_field("fields", "fields.MapEntry")?;
            m.field("key", text("tags"))?;
            m.start_field("value", V)?;
            m.start_field("list_value", "google.protobuf.ListValue")?;
            m.start_field("values", V)?;
            m.field("string_value", text("a"))?;
            m.end_field()?;
            m.end_field()?;
            m.end_field()?;
            m.end_field()?;
            m.end_field()
        };
        let (json, failed) = respond("application/grpc+json", script);
        assert_eq!(failed, None);
        assert_eq!(String::from_utf8(json).unwrap(), r#"{"extra":{"n":1.5,"tags":["a"]}}"#);

        let (pb, failed) = respond("application/grpc", script);
        assert_eq!(failed, None);
        // Struct (field 9): two `fields` entries (field 1), each a key and a Value.
        let len = |field: u8, body: &[u8]| [vec![field << 3 | 2, body.len() as u8], body.to_vec()].concat();
        let n_value = [vec![2 << 3 | 1], 1.5f64.to_le_bytes().to_vec()].concat(); // number_value = 2, fixed64
        let a_value = len(3, b"a"); // string_value = 3
        let tags_value = len(6, &len(1, &a_value)); // list_value = 6, values = 1
        let entry = |key: &[u8], value: &[u8]| len(1, &[len(1, key), len(2, value)].concat());
        let expected = len(9, &[entry(b"n", &n_value), entry(b"tags", &tags_value)].concat());
        assert_eq!(pb, expected);
    }
}
