// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC client helpers (pre-framed request body + response decode).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::TimerHandle;
use hopf_http::{ClientHandler, ClientHandlerFactory, ClientWriter, ContentCoding, Headers};
use rjsonparser::Parser as JsonParser;
use rprotobuf::Parser as ProtoParser;

use crate::codec::{parse_grpc_content_type, GrpcCodec};
use crate::call_options::GrpcCallOptions;
use crate::compression::{
    accept_encoding_header, compress, MessageAccum, MessageCoding, DEFAULT_ENCODINGS,
    GRPC_STATUS_DEADLINE_EXCEEDED, GRPC_STATUS_INTERNAL,
};
use crate::metadata::GrpcMetadata;
use crate::timeout::format as format_grpc_timeout;
use crate::framing::{frame, frame_compressed, GrpcFrameParser};
use crate::proto::{
    JsonModelAdapter, ProtoFile, ProtoMessageHandler, ProtoModelAdapter,
};

/// Callback for a unary response message.
pub trait GrpcResponseHandler: Send {
    /// Provide a handler for the response message type (may be `None` if unknown).
    fn start_message(&mut self, type_name: Option<&str>) -> Option<Box<dyn ProtoMessageHandler>>;
    /// Transport or framing error.
    fn on_error(&mut self, error: &str);
    /// Optional: `grpc-status` from trailers / headers.
    fn on_grpc_status(&mut self, _status: i32, _message: &str) {}

    /// The call has ended, one way or another: the status from the
    /// trailers (or a trailers-only response), or the status this side
    /// gave it when the request failed (`UNAVAILABLE`), a message could
    /// not be decoded (`INTERNAL`) or was too large (`RESOURCE_EXHAUSTED`).
    /// Fires exactly once per call. Default: ignore.
    fn on_complete(&mut self, _status: i32, _message: &str) {}

    /// Initial response metadata (before the body). Default: ignore.
    fn on_initial_metadata(&mut self, _metadata: &GrpcMetadata) {}

    /// Trailing metadata (with the final status). Default: ignore.
    fn on_trailing_metadata(&mut self, _metadata: &GrpcMetadata) {}
}

/// Handle to the request side of a streaming call: messages are sent as
/// they are given, from any thread, before or after the request starts.
#[derive(Clone)]
pub struct GrpcClientCall {
    inner: Arc<Mutex<ClientCallInner>>,
}

struct ClientCallInner {
    compression: Option<ContentCoding>,
    /// Framed messages queued before the request started.
    queued: Vec<Vec<u8>>,
    half_closed: bool,
    cancelled: bool,
    handle: Option<hopf_http::ClientRequestHandle>,
}

impl GrpcClientCall {
    fn new(compression: Option<ContentCoding>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ClientCallInner {
                compression,
                queued: Vec::new(),
                half_closed: false,
                cancelled: false,
                handle: None,
            })),
        }
    }

    /// The request started: what was queued before is written now, and
    /// writes from now on go through `handle`. Returns whether the call
    /// was already half-closed.
    fn started(&self, request: &mut dyn ClientWriter, handle: hopf_http::ClientRequestHandle) -> bool {
        let mut g = self.inner.lock().unwrap();
        for framed in g.queued.drain(..) {
            request.request_body_content(&framed);
        }
        g.handle = Some(handle);
        g.half_closed
    }

    /// Send one request message (unframed, serialised for the call's
    /// codec). Ignored after [`half_close`](Self::half_close) or
    /// [`cancel`](Self::cancel).
    pub fn send(&self, message: &[u8]) {
        let mut g = self.inner.lock().unwrap();
        if g.half_closed || g.cancelled {
            return;
        }
        let framed = frame_request(g.compression, message);
        match g.handle.clone() {
            Some(handle) => {
                drop(g);
                handle.execute(move |w| w.request_body_content(&framed));
            }
            None => g.queued.push(framed),
        }
    }

    /// No more request messages: end the request body (the server sees
    /// the half-close).
    pub fn half_close(&self) {
        let mut g = self.inner.lock().unwrap();
        if g.half_closed || g.cancelled {
            return;
        }
        g.half_closed = true;
        if let Some(handle) = g.handle.clone() {
            drop(g);
            handle.execute(|w| {
                w.end_request_body();
                w.complete_request();
            });
        }
    }

    /// Abandon the call: the stream is reset and no further response
    /// callbacks arrive.
    pub fn cancel(&self) {
        let mut g = self.inner.lock().unwrap();
        if g.cancelled {
            return;
        }
        g.cancelled = true;
        g.queued.clear();
        if let Some(handle) = g.handle.clone() {
            drop(g);
            handle.execute(|w| w.cancel());
        }
    }
}

/// Builds a [`ClientHandler`] that performs one unary gRPC call.
pub struct GrpcUnaryCall {
    path: String,
    request_message: Vec<u8>,
    proto_file: Arc<ProtoFile>,
    response_type_name: Option<String>,
    codec: GrpcCodec,
    encodings: Vec<ContentCoding>,
    compression: Option<ContentCoding>,
    authority: Option<String>,
    handler: Arc<Mutex<Box<dyn GrpcResponseHandler>>>,
    options: GrpcCallOptions,
}

impl GrpcUnaryCall {
    /// Create a unary call with a pre-serialized request body (unframed).
    ///
    /// The body encoding must match [`GrpcCodec::Proto`] (protobuf wire) unless
    /// [`Self::with_codec`] selects JSON.
    pub fn new(
        proto_file: Arc<ProtoFile>,
        path: impl Into<String>,
        request_message: Vec<u8>,
        handler: Box<dyn GrpcResponseHandler>,
    ) -> Self {
        let path = path.into();
        let response_type_name = proto_file
            .get_rpc_by_path(&path)
            .map(|r| r.output_type_name.clone());
        Self {
            path,
            request_message,
            proto_file,
            response_type_name,
            codec: GrpcCodec::Proto,
            encodings: DEFAULT_ENCODINGS.to_vec(),
            compression: None,
            authority: None,
            handler: Arc::new(Mutex::new(handler)),
            options: GrpcCallOptions::new(),
        }
    }

    /// The `:authority` of the request, the host (and port) the call is
    /// for; see [`GrpcClient::authority`].
    pub fn with_authority(mut self, authority: Option<String>) -> Self {
        self.authority = authority.filter(|a| !a.is_empty());
        self
    }

    /// Per-call metadata and deadline.
    pub fn with_options(mut self, options: GrpcCallOptions) -> Self {
        self.options = options;
        self
    }

    /// Compress the request message with this algorithm; see
    /// [`GrpcClient::compression`].
    pub fn with_compression(mut self, coding: Option<ContentCoding>) -> Self {
        self.compression = coding.filter(|c| *c != ContentCoding::Identity);
        self
    }

    /// Select request/response payload codec (`Proto` default, or `Json`).
    pub fn with_codec(mut self, codec: GrpcCodec) -> Self {
        self.codec = codec;
        self
    }

    /// The compression algorithms this call decodes in the response and
    /// offers in `grpc-accept-encoding`; see [`GrpcClient::encodings`].
    pub fn with_encodings(mut self, encodings: &[ContentCoding]) -> Self {
        self.encodings = encodings
            .iter()
            .copied()
            .filter(|c| *c != ContentCoding::Identity)
            .collect();
        self
    }

    /// Frame the request for HTTP body use, compressed when
    /// [`with_compression`](Self::with_compression) says so and it shrinks.
    pub fn framed_request(&self) -> Vec<u8> {
        frame_request(self.compression, &self.request_message)
    }
}

/// Frames a request message, compressed and flagged when `compression`
/// is set and the message is smaller that way.
fn frame_request(compression: Option<ContentCoding>, message: &[u8]) -> Vec<u8> {
    if let Some(coding) = compression {
        if let Ok(Some(packed)) = compress(coding, message) {
            return frame_compressed(&packed);
        }
    }
    frame(message)
}

impl GrpcUnaryCall {
    fn handler_for(&self, call: Option<GrpcClientCall>) -> Box<dyn ClientHandler> {
        Box::new(GrpcClientHandler {
            path: self.path.clone(),
            framed: self.framed_request(),
            proto_file: Arc::clone(&self.proto_file),
            response_type_name: self.response_type_name.clone(),
            codec: self.codec,
            encodings: self.encodings.clone(),
            compression: self.compression,
            authority: self.authority.clone(),
            handler: Arc::clone(&self.handler),
            call,
            request: None,
            frame_parser: None,
            response_coding: MessageCoding::Identity,
            failed: false,
            completed: false,
            grpc_status: None,
            options: self.options.clone(),
            header_metadata: GrpcMetadata::new(),
            trailer_metadata: GrpcMetadata::new(),
            initial_delivered: false,
            response_body_started: false,
            deadline_timer: None,
            finished: Arc::new(AtomicBool::new(false)),
        })
    }
}

impl ClientHandlerFactory for GrpcUnaryCall {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        self.handler_for(None)
    }
}

/// gRPC status codes this side assigns.
const GRPC_STATUS_UNKNOWN: i32 = 2;
const GRPC_STATUS_UNAVAILABLE: i32 = 14;

struct GrpcClientHandler {
    path: String,
    framed: Vec<u8>,
    proto_file: Arc<ProtoFile>,
    response_type_name: Option<String>,
    codec: GrpcCodec,
    encodings: Vec<ContentCoding>,
    compression: Option<ContentCoding>,
    authority: Option<String>,
    handler: Arc<Mutex<Box<dyn GrpcResponseHandler>>>,
    /// The request side of a streaming call; `None` for a unary call,
    /// whose one message goes out in `start`.
    call: Option<GrpcClientCall>,
    /// To cancel the stream from a response callback.
    request: Option<hopf_http::ClientRequestHandle>,
    frame_parser: Option<GrpcFrameParser<MessageAccum>>,
    response_coding: MessageCoding,
    failed: bool,
    completed: bool,
    grpc_status: Option<(i32, String)>,
    options: GrpcCallOptions,
    header_metadata: GrpcMetadata,
    trailer_metadata: GrpcMetadata,
    initial_delivered: bool,
    response_body_started: bool,
    deadline_timer: Option<TimerHandle>,
    finished: Arc<AtomicBool>,
}

impl GrpcClientHandler {
    /// The call is over: tell the handler, once.
    fn complete(&mut self, status: i32, message: &str) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.stop_deadline();
        self.completed = true;
        self.handler.lock().unwrap().on_complete(status, message);
    }

    fn stop_deadline(&mut self) {
        if let Some(timer) = self.deadline_timer.take() {
            timer.cancel();
        }
    }

    fn deliver_initial_metadata(&mut self) {
        if self.initial_delivered || self.failed {
            return;
        }
        self.initial_delivered = true;
        let md = self.header_metadata.clone();
        self.handler.lock().unwrap().on_initial_metadata(&md);
    }

    fn deliver_trailing_metadata(&mut self) {
        if self.failed {
            return;
        }
        let md = if self.initial_delivered {
            self.trailer_metadata.clone()
        } else {
            self.header_metadata.clone()
        };
        self.handler.lock().unwrap().on_trailing_metadata(&md);
    }

    fn ingest_response_header(&mut self, name: &str, value: &str, trailers: bool) {
        let key = name.to_ascii_lowercase();
        if GrpcMetadata::is_reserved(&key) || key == "grpc-status" || key == "grpc-message" {
            return;
        }
        let target = if trailers || self.response_body_started {
            &mut self.trailer_metadata
        } else {
            &mut self.header_metadata
        };
        target.add_received(&key, value);
    }

    /// Fails the call from this side with `status`: `on_error`, then
    /// `on_complete`, and the stream is cancelled so the server stops
    /// sending.
    fn fail_with(&mut self, status: i32, msg: &str) {
        if self.failed || self.finished.load(Ordering::Acquire) {
            return;
        }
        self.failed = true;
        self.handler.lock().unwrap().on_error(msg);
        self.complete(status, msg);
        if let Some(request) = &self.request {
            request.execute(|w| w.cancel());
        }
    }

    fn fail(&mut self, msg: &str) {
        self.fail_with(GRPC_STATUS_INTERNAL, msg);
    }

    /// Fails the call with a gRPC status this side determined (a framing or
    /// decompression failure), named in the error text.
    fn fail_status(&mut self, status: i32, msg: &str) {
        self.fail_with(status, &format!("{msg} (grpc-status {status})"));
    }

    fn new_frame_parser(&self) -> GrpcFrameParser<MessageAccum> {
        GrpcFrameParser::new(MessageAccum::new(
            self.response_coding.clone(),
            crate::framing::DEFAULT_MAX_MESSAGE_SIZE,
        ))
    }

    /// Decodes one complete response frame into a fresh message handler
    /// from [`GrpcResponseHandler::start_message`].
    fn decode_frame(&mut self, accum: MessageAccum) {
        if let Some((status, err)) = accum.error {
            self.fail_status(status, &err);
            return;
        }
        let type_name = self.response_type_name.clone();
        let msg_handler = {
            let mut h = self.handler.lock().unwrap();
            h.start_message(type_name.as_deref())
        };
        let Some(msg_handler) = msg_handler else {
            self.fail("no response handler");
            return;
        };
        let mut slice = accum.buf.as_slice();
        let result: Result<(), String> = match self.codec {
            GrpcCodec::Proto => {
                let mut adapter = ProtoModelAdapter::new((*self.proto_file).clone(), msg_handler);
                (|| {
                    if let Some(ref ty) = type_name {
                        adapter.start_root_message(ty).map_err(|e| e.to_string())?;
                    }
                    {
                        let mut pb = ProtoParser::new(&mut adapter);
                        pb.receive(&mut slice).map_err(|e| e.to_string())?;
                        pb.close().map_err(|e| e.to_string())?;
                    }
                    adapter.end_root_message().map_err(|e| e.to_string())
                })()
            }
            GrpcCodec::Json => {
                let mut adapter = JsonModelAdapter::new((*self.proto_file).clone(), msg_handler);
                (|| {
                    if let Some(ref ty) = type_name {
                        adapter.start_root_message(ty).map_err(|e| e.to_string())?;
                    }
                    {
                        let mut jp = JsonParser::new(&mut adapter);
                        jp.receive(&mut slice).map_err(|e| e.to_string())?;
                        jp.close().map_err(|e| e.to_string())?;
                    }
                    adapter.end_root_message().map_err(|e| e.to_string())
                })()
            }
        };
        if let Err(e) = result {
            self.fail(&e);
        }
    }
}

impl ClientHandler for GrpcClientHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", &self.path);
        h.set(":scheme", "https");
        if let Some(authority) = &self.authority {
            h.set(":authority", authority);
        }
        h.set("content-type", self.codec.content_type());
        h.set("te", "trailers");
        h.set("grpc-accept-encoding", accept_encoding_header(&self.encodings));
        if let Some(coding) = self.compression {
            h.set("grpc-encoding", coding.token());
        }
        self.options.metadata().apply_to(&mut h);
        if let Some(nanos) = self.options.remaining_nanos() {
            h.set("grpc-timeout", format_grpc_timeout(nanos));
            let mut millis = nanos / 1_000_000;
            if nanos % 1_000_000 != 0 {
                millis += 1;
            }
            let conn = request.conn_handle();
            let handle = request.request_handle();
            self.request = Some(handle.clone());
            let finished = Arc::clone(&self.finished);
            self.deadline_timer = Some(conn.schedule_timer(
                Duration::from_millis(millis),
                {
                    let req = handle.clone();
                    let handler = Arc::clone(&self.handler);
                    Box::new(move || {
                        if finished.swap(true, Ordering::AcqRel) {
                            return;
                        }
                        req.execute(|w| w.cancel());
                        let mut h = handler.lock().unwrap();
                        h.on_error("Deadline exceeded");
                        h.on_grpc_status(GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
                        h.on_complete(GRPC_STATUS_DEADLINE_EXCEEDED, "Deadline exceeded");
                    })
                },
            ));
        } else {
            let handle = request.request_handle();
            self.request = Some(handle.clone());
        }
        request.headers(h);
        request.start_request_body();
        let handle = self.request.as_ref().unwrap().clone();
        match &self.call {
            None => {
                request.request_body_content(&self.framed);
                request.end_request_body();
                request.complete_request();
            }
            Some(call) => {
                // Messages sent before the request started go out now;
                // later ones reach the stream through the handle.
                if call.started(request, handle) {
                    request.end_request_body();
                    request.complete_request();
                }
            }
        }
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        for field in headers.iter() {
            self.ingest_response_header(&field.name, &field.value, false);
        }
        if let Some(status) = headers.get("grpc-status") {
            let code = status.parse().unwrap_or(GRPC_STATUS_UNKNOWN);
            let msg = headers.get("grpc-message").unwrap_or("").to_string();
            self.grpc_status = Some((code, msg.clone()));
            self.handler.lock().unwrap().on_grpc_status(code, &msg);
        } else {
            self.deliver_initial_metadata();
        }
        // Prefer response Content-Type when present; otherwise use the request codec.
        self.codec = headers
            .get("content-type")
            .and_then(parse_grpc_content_type)
            .unwrap_or(self.codec);
        // a flagged message is decoded with the response's grpc-encoding,
        // bounded by the message limit so it cannot expand without end
        self.response_coding =
            MessageCoding::resolve(headers.get("grpc-encoding"), &self.encodings);
        self.frame_parser = Some(self.new_frame_parser());
    }

    fn response_body_content(&mut self, _request: &mut dyn ClientWriter, mut data: &[u8]) {
        if self.failed || data.is_empty() {
            return;
        }
        if !self.response_body_started {
            self.deliver_initial_metadata();
            self.response_body_started = true;
        }
        // One frame at a time, each decoded into its own message handler.
        while !data.is_empty() {
            let ended = {
                let Some(parser) = self.frame_parser.as_mut() else {
                    return;
                };
                let consumed = parser.receive_until_frame(data);
                data = &data[consumed..];
                if let Some((status, err)) = parser.handler_mut().error.take() {
                    self.fail_status(status, &err);
                    return;
                }
                parser.handler_mut().ended
            };
            if !ended {
                return;
            }
            let next = self.new_frame_parser();
            let Some(parser) = self.frame_parser.replace(next) else {
                return;
            };
            self.decode_frame(parser.into_handler());
            if self.failed {
                return;
            }
        }
    }

    fn response_trailers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        if self.failed {
            // the call has already been reported as failed; the status the
            // server sends after a message this side could not decode must
            // not be reported as its outcome
            return;
        }
        for field in headers.iter() {
            self.ingest_response_header(&field.name, &field.value, true);
        }
        self.deliver_trailing_metadata();
        if let Some(status) = headers.get("grpc-status") {
            let code = status.parse().unwrap_or(GRPC_STATUS_UNKNOWN);
            let msg = headers.get("grpc-message").unwrap_or("").to_string();
            self.grpc_status = Some((code, msg.clone()));
            self.handler.lock().unwrap().on_grpc_status(code, &msg);
            self.complete(code, &msg);
        }
    }

    fn end_response_body(&mut self, _request: &mut dyn ClientWriter) {
        if self.failed {
            return;
        }
        if let Some(parser) = &self.frame_parser {
            if parser.has_partial_frame() {
                self.fail("incomplete gRPC response frame");
            }
        }
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
        if self.failed || self.completed {
            return;
        }
        self.deliver_trailing_metadata();
        // A trailers-only response carried the status in its headers; a
        // response with neither is not a gRPC outcome at all.
        match self.grpc_status.clone() {
            Some((code, msg)) => self.complete(code, &msg),
            None => self.complete(GRPC_STATUS_UNKNOWN, "missing grpc-status"),
        }
    }

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &std::io::Error) {
        if self.failed {
            return;
        }
        self.failed = true;
        let msg = err.to_string();
        self.handler.lock().unwrap().on_error(&msg);
        self.complete(GRPC_STATUS_UNAVAILABLE, &msg);
    }
}

/// Builds the [`ClientHandler`] for one streaming call; see
/// [`GrpcClient::streaming_call`].
pub struct GrpcStreamingCall {
    unary: GrpcUnaryCall,
    call: GrpcClientCall,
}

impl GrpcStreamingCall {
    /// Select request/response payload codec (`Proto` default, or `Json`).
    pub fn with_codec(mut self, codec: GrpcCodec) -> Self {
        self.unary = self.unary.with_codec(codec);
        self
    }
}

impl ClientHandlerFactory for GrpcStreamingCall {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        self.unary.handler_for(Some(self.call.clone()))
    }
}

/// Thin holder around a [`ProtoFile`] for constructing calls.
pub struct GrpcClient {
    proto_file: Arc<ProtoFile>,
    encodings: Vec<ContentCoding>,
    compression: Option<ContentCoding>,
    authority: Option<String>,
}

impl GrpcClient {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file: Arc::new(proto_file),
            encodings: DEFAULT_ENCODINGS.to_vec(),
            compression: None,
            authority: None,
        }
    }

    /// The `:authority` to send with every call: the host, and port if it
    /// is not the default, of the server dialled (`example.com:50051`).
    /// Servers built on gRPC core refuse a call without one. Default: none.
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = Some(authority.into()).filter(|a| !a.is_empty());
        self
    }

    /// The algorithm to compress request messages with, named in
    /// `grpc-encoding` (default none). A message that would not be smaller
    /// compressed is sent as it is. The server must decode it: use one of
    /// the gRPC specification's, `gzip` or `deflate`, unless the server is
    /// known to have `br`.
    pub fn compression(mut self, coding: ContentCoding) -> Self {
        self.compression = Some(coding).filter(|c| *c != ContentCoding::Identity);
        self
    }

    pub fn proto_file(&self) -> &ProtoFile {
        &self.proto_file
    }

    /// The compression algorithms this client decodes in responses and
    /// offers in `grpc-accept-encoding`, besides `identity`, which is
    /// always allowed. The default is `gzip` and `deflate`, the algorithms
    /// of the gRPC specification; add [`ContentCoding::Brotli`] to allow
    /// `br`, an extension that only works with a server that has it too.
    pub fn encodings(mut self, encodings: &[ContentCoding]) -> Self {
        self.encodings = encodings
            .iter()
            .copied()
            .filter(|c| *c != ContentCoding::Identity)
            .collect();
        self
    }

    /// Build a [`ClientHandlerFactory`] for one unary RPC (protobuf by default).
    pub fn unary_call(
        &self,
        path: impl Into<String>,
        request_message: Vec<u8>,
        handler: Box<dyn GrpcResponseHandler>,
    ) -> GrpcUnaryCall {
        self.unary_call_with_options(path, request_message, handler, GrpcCallOptions::new())
    }

    /// Like [`Self::unary_call`] with metadata and an optional deadline.
    pub fn unary_call_with_options(
        &self,
        path: impl Into<String>,
        request_message: Vec<u8>,
        handler: Box<dyn GrpcResponseHandler>,
        options: GrpcCallOptions,
    ) -> GrpcUnaryCall {
        GrpcUnaryCall::new(Arc::clone(&self.proto_file), path, request_message, handler)
            .with_encodings(&self.encodings)
            .with_compression(self.compression)
            .with_authority(self.authority.clone())
            .with_options(options)
    }

    /// Build a [`ClientHandlerFactory`] for a streaming RPC (any
    /// combination of client and server streaming) and the handle to send
    /// its request messages with.
    pub fn streaming_call(
        &self,
        path: impl Into<String>,
        handler: Box<dyn GrpcResponseHandler>,
    ) -> (GrpcStreamingCall, GrpcClientCall) {
        let call = GrpcClientCall::new(self.compression);
        let factory = GrpcStreamingCall {
            unary: GrpcUnaryCall::new(Arc::clone(&self.proto_file), path, Vec::new(), handler)
                .with_encodings(&self.encodings)
                .with_compression(self.compression)
                .with_authority(self.authority.clone()),
            call: call.clone(),
        };
        (factory, call)
    }

    /// Build a unary RPC that sends/accepts `application/grpc+json`.
    pub fn unary_call_json(
        &self,
        path: impl Into<String>,
        request_message: Vec<u8>,
        handler: Box<dyn GrpcResponseHandler>,
    ) -> GrpcUnaryCall {
        self.unary_call(path, request_message, handler)
            .with_codec(GrpcCodec::Json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{ProtoFileParser, ProtoParseError, ScalarValue};
    use hopf_core::{ConnHandle, ConnHandleBackend, TimerHandle};
    use hopf_http::HttpVersion;
    use std::time::Duration;

    const TEST_PROTO: &str = r#"
        syntax = "proto3";
        package test;
        message Msg { string text = 1; }
        service TestSvc {
          rpc Call (Msg) returns (Msg);
        }
    "#;

    /// What the request handler was told, in order.
    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<String>>>);

    impl Events {
        fn take(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    struct FieldRecorder(Events);

    impl ProtoMessageHandler for FieldRecorder {
        fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
            self.0 .0.lock().unwrap().push(format!("field {name}={value:?}"));
            Ok(())
        }
        fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
    }

    struct RecordingHandler(Events);

    impl GrpcResponseHandler for RecordingHandler {
        fn start_message(&mut self, _type_name: Option<&str>) -> Option<Box<dyn ProtoMessageHandler>> {
            Some(Box::new(FieldRecorder(self.0.clone())))
        }
        fn on_error(&mut self, error: &str) {
            self.0 .0.lock().unwrap().push(format!("error {error}"));
        }
        fn on_grpc_status(&mut self, status: i32, message: &str) {
            self.0 .0.lock().unwrap().push(format!("status {status} {message:?}"));
        }
        fn on_complete(&mut self, status: i32, message: &str) {
            self.0 .0.lock().unwrap().push(format!("complete {status} {message:?}"));
        }
    }

    /// What was written to the request, by the handler in `start` and by
    /// deferred tasks through the request handle alike.
    #[derive(Default)]
    struct Sent {
        headers: Option<Headers>,
        body: Vec<u8>,
        ended: bool,
        cancelled: bool,
    }

    struct SyncTimerBackend;

    impl ConnHandleBackend for SyncTimerBackend {
        fn with_endpoint(&self, _task: hopf_core::EndpointTask) {}
        fn execute(&self, task: hopf_core::Task) {
            task();
        }
        fn is_probably_open(&self) -> bool {
            true
        }
        fn schedule_timer(&self, delay: Duration, callback: hopf_core::Task) -> TimerHandle {
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                callback();
            });
            TimerHandle::from_cancel(|| {})
        }
    }

    /// Records what the client handler sent.
    struct MockRequest {
        sent: Arc<Mutex<Sent>>,
        conn: ConnHandle,
    }

    impl Default for MockRequest {
        fn default() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Sent::default())),
                conn: ConnHandle::from_execute(Arc::new(|task| task())),
            }
        }
    }

    impl MockRequest {
        fn with_sent(sent: Arc<Mutex<Sent>>) -> Self {
            Self {
                sent,
                conn: ConnHandle::from_execute(Arc::new(|task| task())),
            }
        }

        fn headers(&self) -> Option<Headers> {
            self.sent.lock().unwrap().headers.clone()
        }
        fn body(&self) -> Vec<u8> {
            self.sent.lock().unwrap().body.clone()
        }
    }

    impl ClientWriter for MockRequest {
        fn headers(&mut self, headers: Headers) {
            self.sent.lock().unwrap().headers = Some(headers);
        }
        fn start_request_body(&mut self) {}
        fn request_body_content(&mut self, data: &[u8]) {
            self.sent.lock().unwrap().body.extend_from_slice(data);
        }
        fn end_request_body(&mut self) {
            self.sent.lock().unwrap().ended = true;
        }
        fn complete_request(&mut self) {
            self.sent.lock().unwrap().ended = true;
        }
        fn cancel(&mut self) {
            self.sent.lock().unwrap().cancelled = true;
        }
        fn version(&self) -> HttpVersion {
            HttpVersion::Http2
        }
        fn conn_handle(&self) -> ConnHandle {
            self.conn.clone()
        }
        fn request_handle(&self) -> hopf_http::ClientRequestHandle {
            let sent = Arc::clone(&self.sent);
            hopf_http::ClientRequestHandle::from_runner(
                self.conn_handle(),
                Arc::new(move |task: hopf_http::ClientWriterTask| {
                    let mut w = MockRequest::with_sent(Arc::clone(&sent));
                    task(&mut w);
                }),
            )
        }
    }

    fn client() -> GrpcClient {
        GrpcClient::new(ProtoFileParser::parse(TEST_PROTO).unwrap())
    }

    /// Delivers a response of `headers`, `body` and `trailers` to `handler`.
    fn deliver(
        handler: &mut dyn ClientHandler,
        headers: &[(&str, &str)],
        body: &[u8],
        trailers: &[(&str, &str)],
    ) -> MockRequest {
        let mut req = MockRequest::default();
        handler.start(&mut req);
        let mut h = Headers::new();
        h.status(200);
        h.set("content-type", "application/grpc");
        for (k, v) in headers {
            h.set(*k, *v);
        }
        handler.response_headers(&mut req, &h);
        handler.start_response_body(&mut req);
        handler.response_body_content(&mut req, body);
        handler.end_response_body(&mut req);
        let mut t = Headers::new();
        for (k, v) in trailers {
            t.set(*k, *v);
        }
        handler.response_trailers(&mut req, &t);
        handler.response_complete(&mut req);
        req
    }

    /// A response message that fails to decode fails the call once, with
    /// `on_error`; the OK trailers that follow must not then be reported
    /// as a success with `on_grpc_status`.
    #[test]
    fn no_grpc_status_after_error() {
        let events = Events::default();
        let call = client().unary_call(
            "/test.TestSvc/Call",
            vec![],
            Box::new(RecordingHandler(events.clone())),
        );
        let mut handler = call.create_handler();
        // field 1 with wire type 7, which does not exist
        deliver(&mut *handler, &[], &frame(&[0x0F, 0x00]), &[("grpc-status", "0")]);
        let got = events.take();
        let errors: Vec<&String> = got.iter().filter(|e| e.starts_with("error ")).collect();
        assert_eq!(errors.len(), 1, "expected exactly one on_error: {got:?}");
        assert!(!got.iter().any(|e| e.starts_with("status ")), "no on_grpc_status after the failure: {got:?}");
    }

    /// A call names the server it is for in `:authority` when the client
    /// was told it, whether unary or streaming, and leaves it out
    /// otherwise.
    #[test]
    fn request_carries_the_configured_authority() {
        let mut handler = client()
            .authority("example.test:50051")
            .unary_call("/test.TestSvc/Call", vec![], Box::new(RecordingHandler(Events::default())))
            .create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        assert_eq!(req.headers().unwrap().get(":authority"), Some("example.test:50051"));

        let (factory, _call) = streaming_client().authority("example.test:50051").streaming_call(
            "/test.TestSvc/ServerStream",
            Box::new(RecordingHandler(Events::default())),
        );
        let mut handler = factory.create_handler();
        let req = deliver(&mut *handler, &[], &[], &[("grpc-status", "0")]);
        assert_eq!(req.headers().unwrap().get(":authority"), Some("example.test:50051"));

        let mut handler = client()
            .unary_call("/test.TestSvc/Call", vec![], Box::new(RecordingHandler(Events::default())))
            .create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        assert_eq!(req.headers().unwrap().get(":authority"), None);
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = hopf_http::Encoder::new(ContentCoding::Gzip).unwrap();
        let mut out = Vec::new();
        e.push(data, &mut |o| out.extend_from_slice(o)).unwrap();
        e.finish(&mut |o| out.extend_from_slice(o)).unwrap();
        out
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

    #[test]
    fn client_compresses_request_when_configured() {
        let events = Events::default();
        let text = "a".repeat(600);
        let call = client().compression(ContentCoding::Gzip).unary_call(
            "/test.TestSvc/Call",
            msg(&text),
            Box::new(RecordingHandler(events.clone())),
        );
        let mut handler = call.create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        let headers = req.headers().unwrap();
        let body = req.body();
        assert_eq!(headers.get("grpc-encoding"), Some("gzip"));
        assert_eq!(body[0], 1, "compressed flag");
        let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
        assert_eq!(len, body.len() - 5);
        assert!(len < 600, "not smaller: {len}");
        let mut d = hopf_http::Decoder::new(ContentCoding::Gzip, 1 << 20).unwrap();
        let mut out = Vec::new();
        d.push(&body[5..], &mut |o| out.extend_from_slice(o)).unwrap();
        d.finish().unwrap();
        assert_eq!(out, msg(&text));
        assert_eq!(
            events.take(),
            vec!["field text=String(\"ok\")", "status 0 \"\"", "complete 0 \"\""]
        );

        // a message that would not shrink goes as it is, and by default
        // nothing is compressed at all
        let call = client().compression(ContentCoding::Gzip).unary_call(
            "/test.TestSvc/Call",
            msg("x"),
            Box::new(RecordingHandler(Events::default())),
        );
        let mut handler = call.create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        assert_eq!(req.body(), frame(&msg("x")));

        let call = client().unary_call(
            "/test.TestSvc/Call",
            msg(&text),
            Box::new(RecordingHandler(Events::default())),
        );
        let mut handler = call.create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        assert_eq!(req.headers().unwrap().get("grpc-encoding"), None);
        assert_eq!(req.body(), frame(&msg(&text)));
    }

    #[test]
    fn client_decodes_gzip_response() {
        let events = Events::default();
        let call = client().unary_call(
            "/test.TestSvc/Call",
            vec![],
            Box::new(RecordingHandler(events.clone())),
        );
        let mut handler = call.create_handler();
        let req = deliver(
            &mut *handler,
            &[("grpc-encoding", "gzip")],
            &frame_compressed(&gzip(&msg("hello"))),
            &[("grpc-status", "0")],
        );
        assert_eq!(
            req.headers().and_then(|h| h.get("grpc-accept-encoding").map(str::to_string)),
            Some("identity,gzip,deflate".to_string())
        );
        let got = events.take();
        assert_eq!(
            got,
            vec!["field text=String(\"hello\")", "status 0 \"\"", "complete 0 \"\""]
        );
    }

    #[test]
    fn client_deadline_cancels_when_server_is_silent() {
        let events = Events::default();
        let opts = GrpcCallOptions::new().timeout(Duration::from_millis(5));
        let call = client()
            .unary_call(
                "/test.TestSvc/Call",
                vec![],
                Box::new(RecordingHandler(events.clone())),
            )
            .with_options(opts);
        let mut handler = call.create_handler();
        let mut req = MockRequest {
            sent: Arc::new(Mutex::new(Sent::default())),
            conn: ConnHandle::from_backend(Arc::new(SyncTimerBackend)),
        };
        handler.start(&mut req);
        assert!(req.headers().unwrap().get("grpc-timeout").is_some());
        std::thread::sleep(Duration::from_millis(40));
        assert!(req.sent.lock().unwrap().cancelled);
        let got = events.take();
        assert!(
            got.iter().any(|e| e.starts_with("complete 4 ")),
            "{got:?}"
        );
    }

    /// A compressed response that cannot be decoded fails the call with
    /// the gRPC status the failure maps to, and nothing after it.
    #[test]
    fn client_reports_undecodable_compressed_response() {
        let cases: [(&[(&str, &str)], Vec<u8>, i32); 3] = [
            (&[("grpc-encoding", "gzip")], frame_compressed(b"not gzip"), 13),
            (&[], frame_compressed(&gzip(&msg("x"))), 13),
            (&[("grpc-encoding", "snappy")], frame_compressed(b"??"), 12),
        ];
        for (headers, body, status) in cases {
            let events = Events::default();
            let call = client().unary_call(
                "/test.TestSvc/Call",
                vec![],
                Box::new(RecordingHandler(events.clone())),
            );
            let mut handler = call.create_handler();
            deliver(&mut *handler, headers, &body, &[("grpc-status", "0")]);
            let got = events.take();
            assert_eq!(got.len(), 2, "{headers:?}: {got:?}");
            assert!(got[0].starts_with("error ") && got[0].contains(&format!("grpc-status {status}")), "{got:?}");
            assert!(got[1].starts_with(&format!("complete {status} ")), "{got:?}");
        }
    }

    const STREAM_PROTO: &str = r#"
        syntax = "proto3";
        package test;
        message Msg { string text = 1; }
        service TestSvc {
          rpc Call (Msg) returns (Msg);
          rpc ServerStream (Msg) returns (stream Msg);
          rpc ClientStream (stream Msg) returns (Msg);
        }
    "#;

    fn streaming_client() -> GrpcClient {
        GrpcClient::new(ProtoFileParser::parse(STREAM_PROTO).unwrap())
    }

    /// The gRPC frames in a request body.
    fn frames_in(body: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = body;
        while rest.len() >= 5 {
            let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
            out.push(rest[5..5 + len].to_vec());
            rest = &rest[5 + len..];
        }
        out
    }

    /// Server streaming: three response messages, each decoded into its
    /// own message handler, then `on_complete(0)` from the trailers.
    #[test]
    fn server_streaming_delivers_each_message_then_completes() {
        let events = Events::default();
        let (factory, _call) = streaming_client().streaming_call(
            "/test.TestSvc/ServerStream",
            Box::new(RecordingHandler(events.clone())),
        );
        let mut handler = factory.create_handler();
        let mut body = Vec::new();
        for t in ["a", "b", "c"] {
            body.extend_from_slice(&frame(&msg(t)));
        }
        deliver(&mut *handler, &[], &body, &[("grpc-status", "0")]);
        let got = events.take();
        let fields: Vec<&String> = got.iter().filter(|e| e.starts_with("field ")).collect();
        assert_eq!(fields.len(), 3, "three messages: {got:?}");
        assert_eq!(got.last().map(String::as_str), Some("complete 0 \"\""), "{got:?}");
        assert_eq!(got.iter().filter(|e| e.starts_with("complete ")).count(), 1);
    }

    /// Client streaming: messages sent through the call handle after the
    /// request started reach the request body as frames, and the half-close
    /// ends the body.
    #[test]
    fn client_streaming_sends_after_start_and_half_closes() {
        let events = Events::default();
        let (factory, call) = streaming_client().streaming_call(
            "/test.TestSvc/ClientStream",
            Box::new(RecordingHandler(events.clone())),
        );
        let mut handler = factory.create_handler();
        let req = MockRequest::default();
        let mut start_view = MockRequest::with_sent(Arc::clone(&req.sent));
        handler.start(&mut start_view);
        assert!(!req.sent.lock().unwrap().ended, "a streaming request is not ended at start");
        for t in ["a", "b", "c"] {
            call.send(&msg(t));
        }
        call.half_close();
        let sent = req.sent.lock().unwrap();
        assert_eq!(frames_in(&sent.body), vec![msg("a"), msg("b"), msg("c")]);
        assert!(sent.ended, "half-close must end the request body");
        assert!(!sent.cancelled);
    }

    /// A response message that cannot be decoded ends the call from this
    /// side: `on_error`, `on_complete(INTERNAL)`, the stream cancelled, and
    /// no `on_grpc_status` from the trailers that follow.
    #[test]
    fn decode_failure_completes_with_internal_and_cancels() {
        let events = Events::default();
        let (factory, _call) = streaming_client().streaming_call(
            "/test.TestSvc/ServerStream",
            Box::new(RecordingHandler(events.clone())),
        );
        let mut handler = factory.create_handler();
        let req = MockRequest::default();
        let mut view = MockRequest::with_sent(Arc::clone(&req.sent));
        handler.start(&mut view);
        let mut h = Headers::new();
        h.status(200);
        h.set("content-type", "application/grpc");
        handler.response_headers(&mut view, &h);
        handler.response_body_content(&mut view, &frame(&[0x0F, 0x00]));
        let mut t = Headers::new();
        t.set("grpc-status", "0");
        handler.response_trailers(&mut view, &t);
        handler.response_complete(&mut view);
        let got = events.take();
        assert!(got.iter().any(|e| e.starts_with("error ")), "{got:?}");
        assert_eq!(got.iter().filter(|e| e.starts_with("complete ")).count(), 1, "{got:?}");
        assert!(got.iter().any(|e| e.starts_with("complete 13 ")), "INTERNAL: {got:?}");
        assert!(!got.iter().any(|e| e.starts_with("status ")), "{got:?}");
        assert!(req.sent.lock().unwrap().cancelled, "the stream must be cancelled");
    }

    /// A trailers-only response completes the call with its status, and a
    /// failed request completes it with UNAVAILABLE; either exactly once.
    #[test]
    fn trailers_only_and_request_failure_complete_once() {
        let events = Events::default();
        let call = client().unary_call("/test.TestSvc/Call", vec![], Box::new(RecordingHandler(events.clone())));
        let mut handler = call.create_handler();
        let mut req = MockRequest::default();
        handler.start(&mut req);
        let mut h = Headers::new();
        h.status(200);
        h.set("content-type", "application/grpc");
        h.set("grpc-status", "12");
        h.set("grpc-message", "nope");
        handler.response_headers(&mut req, &h);
        handler.response_complete(&mut req);
        let got = events.take();
        assert_eq!(got.iter().filter(|e| e.starts_with("complete ")).count(), 1, "{got:?}");
        assert!(got.iter().any(|e| e == "complete 12 \"nope\""), "{got:?}");

        let events = Events::default();
        let call = client().unary_call("/test.TestSvc/Call", vec![], Box::new(RecordingHandler(events.clone())));
        let mut handler = call.create_handler();
        let mut req = MockRequest::default();
        handler.start(&mut req);
        handler.request_failed(&mut req, &std::io::Error::new(std::io::ErrorKind::ConnectionReset, "gone"));
        let got = events.take();
        assert!(got.iter().any(|e| e.starts_with("complete 14 ")), "UNAVAILABLE: {got:?}");
        assert_eq!(got.iter().filter(|e| e.starts_with("complete ")).count(), 1);
    }
}
