// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC server binding to Hopf [`ServerHandler`].

use std::sync::{Arc, Mutex};

use hopf_http::{Headers, ServerHandler, ServerHandlerFactory, ServerWriter};
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

/// Application SPI for unary RPC handling.
pub trait GrpcService: Send + Sync {
    /// Begin a unary call; return a request event handler, or `None` if unimplemented.
    fn start_unary_call(
        &self,
        path: &str,
        response: GrpcResponseChannel,
    ) -> Option<Box<dyn ProtoMessageHandler>>;
}

/// Cloneable channel for sending the unary response (Gumdrop `GrpcResponseSender`).
#[derive(Clone)]
pub struct GrpcResponseChannel {
    inner: Arc<Mutex<ChannelInner>>,
}

struct ChannelInner {
    proto_file: Arc<ProtoFile>,
    response_type_name: Option<String>,
    codec: GrpcCodec,
    pending: Option<PendingResponse>,
    sent: bool,
}

enum PendingResponse {
    Error { status: i32, message: String },
    /// A serialised response message, framed (and compressed) when sent.
    Message(Vec<u8>),
}

impl GrpcResponseChannel {
    fn new(
        proto_file: Arc<ProtoFile>,
        response_type_name: Option<String>,
        codec: GrpcCodec,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ChannelInner {
                proto_file,
                response_type_name,
                codec,
                pending: None,
                sent: false,
            })),
        }
    }

    fn take_pending(&self) -> Option<PendingResponse> {
        self.inner.lock().unwrap().pending.take()
    }

    /// Negotiated response codec (`Proto` or `Json`).
    pub fn codec(&self) -> GrpcCodec {
        self.inner.lock().unwrap().codec
    }
}

impl GrpcResponseChannel {
    /// Open an event-driven response encoder.
    pub fn open_message(
        &self,
        message_type_name: Option<&str>,
    ) -> Result<GrpcResponseMessage, String> {
        let g = self.inner.lock().unwrap();
        if g.sent {
            return Err("response already sent".into());
        }
        let type_name = message_type_name
            .map(str::to_string)
            .or_else(|| g.response_type_name.clone())
            .ok_or_else(|| "unknown response message type".to_string())?;
        let proto_file = Arc::clone(&g.proto_file);
        let codec = g.codec;
        let inner = Arc::clone(&self.inner);
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
            inner,
        })
    }

    /// Send a gRPC error (HTTP 200 + `grpc-status` in headers, no body).
    pub fn send_error(&self, status: i32, message: &str) {
        let mut g = self.inner.lock().unwrap();
        if g.sent {
            return;
        }
        g.sent = true;
        g.pending = Some(PendingResponse::Error {
            status,
            message: message.to_string(),
        });
    }

    /// Internal error → status 13.
    pub fn send_error_cause(&self, _cause: &dyn std::error::Error) {
        self.send_error(13, "Internal error");
    }
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
    inner: Arc<Mutex<ChannelInner>>,
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
        let mut g = self.inner.lock().unwrap();
        if g.sent {
            return Err("response already sent".into());
        }
        g.sent = true;
        g.pending = Some(PendingResponse::Message(bytes));
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
    Proto(ProtoModelAdapter<Box<dyn ProtoMessageHandler>>),
    Json(JsonModelAdapter<Box<dyn ProtoMessageHandler>>),
}

struct DecodeState {
    decoder: MessageDecoder,
    frame_parser: Option<GrpcFrameParser<MessageAccum>>,
    message_done: bool,
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
    codec: GrpcCodec,
    content_ok: bool,
    body_started: bool,
    body_rejected: bool,
    channel: Option<GrpcResponseChannel>,
    decode: Option<DecodeState>,
}

impl GrpcHandler {
    fn flush_pending(&mut self, response: &mut dyn ServerWriter) {
        let Some(channel) = &self.channel else {
            return;
        };
        let Some(pending) = channel.take_pending() else {
            return;
        };
        let ct = self.codec.content_type();
        let accept = accept_encoding_header(&self.encodings);
        match pending {
            PendingResponse::Error { status, message } => {
                write_trailers_only(response, ct, &accept, status, &message);
            }
            PendingResponse::Message(message) => {
                let mut h = Headers::new();
                h.status(200);
                h.set("content-type", ct);
                h.set("grpc-accept-encoding", accept);
                if let Some(coding) = self.response_coding {
                    // messages that are big enough are compressed with it,
                    // each flagged on its own
                    h.set("grpc-encoding", coding.token());
                }
                let body = self.frame_response(&message);
                response.headers(h);
                response.start_response_body();
                response.response_body_content(&body);
                response.end_response_body();
                let mut t = Headers::new();
                t.set("grpc-status", "0");
                response.trailers(t);
                response.complete();
            }
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

    /// Fails the call with a gRPC status, as a trailers-only response. Once
    /// the service has been invoked this goes through its channel, so that
    /// a response it has already sent is not followed by a second one.
    fn reject_grpc(&mut self, response: &mut dyn ServerWriter, status: i32, message: &str) {
        if self.body_rejected {
            return;
        }
        self.body_rejected = true;
        match &self.channel {
            Some(channel) => {
                channel.send_error(status, message);
                self.flush_pending(response);
            }
            None => {
                let accept = accept_encoding_header(&self.encodings);
                write_trailers_only(response, self.codec.content_type(), &accept, status, message)
            }
        }
    }

    /// Frames a response message, compressed when the call has a response
    /// coding, the message is at least the threshold, and it shrinks.
    fn frame_response(&self, message: &[u8]) -> Vec<u8> {
        if let Some(coding) = self.response_coding {
            if message.len() >= self.compression_threshold {
                if let Ok(Some(packed)) = compress(coding, message) {
                    return frame_compressed(&packed);
                }
            }
        }
        frame(message)
    }

    fn new_frame_parser(&self) -> GrpcFrameParser<MessageAccum> {
        let mut parser = GrpcFrameParser::new(MessageAccum::new(
            self.request_coding.clone(),
            self.max_message_size,
        ));
        parser.set_max_message_size(self.max_message_size);
        parser
    }

    /// Decodes the gathered request message into the service's handler.
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

        let channel = GrpcResponseChannel::new(
            Arc::clone(&self.proto_file),
            self.response_type_name.clone(),
            self.codec,
        );
        let handler = self.service.start_unary_call(&self.path, channel.clone());
        self.channel = Some(channel);
        if handler.is_none() {
            self.channel
                .as_ref()
                .unwrap()
                .send_error(GRPC_STATUS_UNIMPLEMENTED, "Unimplemented");
            self.body_rejected = true;
            self.flush_pending(response);
            return;
        }
        let handler = handler.unwrap();
        let request_type = self.request_type_name.clone().unwrap();
        let decoder = match self.codec {
            GrpcCodec::Proto => {
                let mut adapter =
                    ProtoModelAdapter::new((*self.proto_file).clone(), handler);
                if let Err(e) = adapter.start_root_message(&request_type) {
                    self.reject_grpc(response, GRPC_STATUS_INTERNAL, &format!("Invalid request type: {e}"));
                    return;
                }
                MessageDecoder::Proto(adapter)
            }
            GrpcCodec::Json => {
                let mut adapter =
                    JsonModelAdapter::new((*self.proto_file).clone(), handler);
                if let Err(e) = adapter.start_root_message(&request_type) {
                    self.reject_grpc(response, GRPC_STATUS_INTERNAL, &format!("Invalid request type: {e}"));
                    return;
                }
                MessageDecoder::Json(adapter)
            }
        };
        self.decode = Some(DecodeState {
            decoder,
            frame_parser: Some(self.new_frame_parser()),
            message_done: false,
        });
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.body_rejected || !self.body_started || data.is_empty() {
            return;
        }
        // A unary RPC carries exactly one gRPC message frame - this
        // handler has no streaming variant (`GrpcService` only offers
        // `start_unary_call`), so any bytes arriving after the first
        // frame already completed are a genuine protocol violation, not
        // a second legitimate message to silently drop (issue #197).
        let already_done = self.decode.as_ref().map(|d| d.message_done).unwrap_or(false);
        if already_done {
            self.reject_grpc(response, GRPC_STATUS_INTERNAL, "Too many request messages");
            return;
        }
        {
            let Some(decode) = self.decode.as_mut() else {
                return;
            };
            let Some(parser) = decode.frame_parser.as_mut() else {
                return;
            };
            parser.receive(data);
            if let Some((status, err)) = parser.handler_mut().error.take() {
                self.reject_grpc(response, status, &err);
                return;
            }
            if !parser.handler_mut().ended {
                self.flush_pending(response);
                return;
            }
        }
        if let Err((status, e)) = self.finish_frame_message() {
            self.reject_grpc(response, status, &e);
            return;
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
        let ok = self
            .decode
            .as_ref()
            .map(|d| {
                d.message_done
                    && d.frame_parser
                        .as_ref()
                        .map(|p| !p.has_partial_frame())
                        .unwrap_or(true)
            })
            .unwrap_or(false);
        if !ok {
            self.reject_grpc(response, GRPC_STATUS_INTERNAL, "Incomplete gRPC frame");
            return;
        }
        self.flush_pending(response);
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        self.flush_pending(response);
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
            unimplemented!("not exercised by this test — GrpcHandler's request_body_content never calls it")
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
}
