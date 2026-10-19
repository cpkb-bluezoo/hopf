// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC server binding to Hopf [`ServerHandler`].

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hopf_http::{Headers, ServerHandler, ServerHandlerFactory, ServerResponseHandle, ServerWriter};
use rjsonparser::Parser as JsonParser;
use rprotobuf::{Buffer, Parser as ProtoParser, Writer as ProtoWriter};

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

use crate::compression::{GRPC_STATUS_INTERNAL, GRPC_STATUS_UNIMPLEMENTED};

/// A trailers-only response: HTTP 200 with the gRPC status in the headers
/// and no body (gRPC HTTP/2 protocol). `accept_encoding` is what this
/// server decodes, which every response says.
fn write_trailers_only(
    response: &mut dyn ServerWriter,
    ct: &str,
    accept_encoding: &str,
    status: i32,
    message: &str,
) {
    let mut h = Headers::new();
    h.status(200);
    h.set("content-type", ct);
    h.set("grpc-accept-encoding", accept_encoding);
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
            })),
        }
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
            let (item, ct, accept, coding, threshold, headers_sent) = {
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
                        response.headers(h);
                        response.start_response_body();
                    }
                    response.response_body_content(&frame_message(&message, coding, threshold));
                }
                QueuedItem::Close { status, message } => {
                    if !headers_sent {
                        // Nothing was sent: a trailers-only response.
                        self.inner.lock().unwrap().headers_sent = false;
                        write_trailers_only(response, ct, &accept, status, &message);
                        return;
                    }
                    response.end_response_body();
                    let mut t = Headers::new();
                    t.set("grpc-status", status.to_string());
                    if !message.is_empty() {
                        t.set("grpc-message", &message);
                    }
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
                    writer: ProtoWriter::buffer(4096),
                },
                GrpcCodec::Json => ResponseBody::Json {
                    serializer: JsonModelSerializer::new((*proto_file).clone()),
                    writer: rjsonparser::Writer::buffer(4096),
                },
            },
            started: false,
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

enum ResponseBody {
    Proto {
        serializer: ProtoModelSerializer,
        writer: ProtoWriter<Buffer>,
    },
    Json {
        serializer: JsonModelSerializer,
        writer: rjsonparser::Writer<Vec<u8>>,
    },
}

/// Encoder handle for one unary response message.
pub struct GrpcResponseMessage {
    type_name: String,
    body: ResponseBody,
    started: bool,
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

    /// Protobuf wire writer (only when the negotiated codec is [`GrpcCodec::Proto`]).
    pub fn writer(&mut self) -> Result<&mut ProtoWriter<Buffer>, String> {
        self.ensure_started()?;
        match &mut self.body {
            ResponseBody::Proto { writer, .. } => Ok(writer),
            ResponseBody::Json { .. } => {
                Err("protobuf writer unavailable for application/grpc+json".into())
            }
        }
    }

    pub fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), String> {
        self.ensure_started()?;
        match &mut self.body {
            ResponseBody::Proto {
                serializer,
                writer,
            } => serializer
                .field(writer, name, value)
                .map_err(|e| e.to_string()),
            ResponseBody::Json {
                serializer,
                writer,
            } => serializer
                .field(writer, name, value)
                .map_err(|e| e.to_string()),
        }
    }

    pub fn complete(mut self) -> Result<(), String> {
        self.ensure_started()?;
        let bytes = match &mut self.body {
            ResponseBody::Proto {
                serializer,
                writer,
            } => {
                serializer.end_message();
                std::mem::replace(writer, ProtoWriter::buffer(0)).finish()
            }
            ResponseBody::Json {
                serializer,
                writer,
            } => {
                serializer
                    .end_message(writer)
                    .map_err(|e| e.to_string())?;
                std::mem::replace(writer, rjsonparser::Writer::buffer(0))
                    .finish()
                    .map_err(|e| e.to_string())?
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
            ResponseBody::Json {
                serializer,
                writer,
            } => {
                serializer
                    .start_message(writer, &self.type_name)
                    .map_err(|e| e.to_string())?;
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
}

impl GrpcHandler {
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
        match &self.channel {
            Some(channel) => {
                channel.close_with(status, message);
                self.flush_pending(response);
            }
            None => {
                let accept = accept_encoding_header(&self.encodings);
                write_trailers_only(response, self.codec.content_type(), &accept, status, message)
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
        let mut slice = accum.buf.as_slice();
        match &mut decode.decoder {
            MessageDecoder::Proto(adapter) => {
                {
                    let mut pb = ProtoParser::new(adapter);
                    pb.receive(&mut slice).map_err(|e| internal(e.to_string()))?;
                    pb.close().map_err(|e| internal(e.to_string()))?;
                }
                adapter
                    .end_root_message()
                    .map_err(|e: ProtoParseError| internal(e.to_string()))?;
            }
            MessageDecoder::Json(adapter) => {
                {
                    let mut jp = JsonParser::new(adapter);
                    jp.receive(&mut slice).map_err(|e| internal(e.to_string()))?;
                    jp.close().map_err(|e| internal(e.to_string()))?;
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
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.body_rejected || !self.content_ok {
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
        let handler = self.service.start_call(&self.path, channel.clone());
        self.channel = Some(channel);
        let Some(handler) = handler else {
            self.reject_grpc(response, GRPC_STATUS_UNIMPLEMENTED, "Unimplemented");
            return;
        };
        let request_type = self.request_type_name.clone().unwrap();
        let mut decoder = match self.codec {
            GrpcCodec::Proto => MessageDecoder::Proto(ProtoModelAdapter::new((*self.proto_file).clone(), handler)),
            GrpcCodec::Json => MessageDecoder::Json(JsonModelAdapter::new((*self.proto_file).clone(), handler)),
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
        if self.body_rejected || !self.body_started || data.is_empty() {
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
        if !self.body_started {
            self.reject_grpc(response, GRPC_STATUS_INTERNAL, "Missing request body");
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
}
