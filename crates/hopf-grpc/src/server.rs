// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC server binding to Hopf [`ServerHandler`].

use std::sync::{Arc, Mutex};

use hopf_http::{Headers, ServerHandler, ServerHandlerFactory, ServerWriter};
use rjsonparser::Parser as JsonParser;
use rprotobuf::{Buffer, Parser as ProtoParser, Writer as ProtoWriter};

use crate::codec::{parse_grpc_content_type, GrpcCodec};
use crate::framing::{frame, GrpcEventHandler, GrpcFrameParser, DEFAULT_MAX_MESSAGE_SIZE};
use crate::proto::{
    JsonModelAdapter, JsonModelSerializer, ProtoFile, ProtoMessageHandler, ProtoModelAdapter,
    ProtoModelSerializer, ProtoParseError, ScalarValue,
};

const GRPC_STATUS_UNIMPLEMENTED: i32 = 12;

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
    Framed(Vec<u8>),
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
        g.pending = Some(PendingResponse::Framed(frame(&bytes)));
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
}

impl GrpcHandlerFactory {
    pub fn new(proto_file: ProtoFile, service: Arc<dyn GrpcService>) -> Self {
        Self {
            proto_file: Arc::new(proto_file),
            service,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }

    pub fn set_max_message_size(&mut self, max_message_size: u64) {
        self.max_message_size = crate::framing::effective_max_message_size(max_message_size);
    }
}

impl ServerHandlerFactory for GrpcHandlerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(GrpcHandler {
            proto_file: Arc::clone(&self.proto_file),
            service: Arc::clone(&self.service),
            max_message_size: self.max_message_size,
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
    frame_parser: Option<GrpcFrameParser<FrameAccum>>,
    message_done: bool,
}

struct FrameAccum {
    buf: Vec<u8>,
    error: Option<String>,
    ended: bool,
}

impl GrpcEventHandler for FrameAccum {
    fn start_message(&mut self, _compression_flag: u8, length: u32) {
        self.buf.clear();
        self.buf.reserve(length as usize);
        self.ended = false;
    }
    fn message_data(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }
    fn end_message(&mut self) {
        self.ended = true;
    }
    fn parse_error(&mut self, message: &str) {
        self.error = Some(message.to_string());
    }
}

struct GrpcHandler {
    proto_file: Arc<ProtoFile>,
    service: Arc<dyn GrpcService>,
    max_message_size: u64,
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
        match pending {
            PendingResponse::Error { status, message } => {
                let mut h = Headers::new();
                h.status(200);
                h.set("content-type", ct);
                h.set("grpc-status", status.to_string());
                h.set("grpc-message", message);
                response.headers(h);
                response.complete();
            }
            PendingResponse::Framed(body) => {
                let mut h = Headers::new();
                h.status(200);
                h.set("content-type", ct);
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

    fn finish_frame_message(&mut self) -> Result<(), String> {
        let decode = self.decode.as_mut().ok_or("no decode state")?;
        let parser = decode.frame_parser.take().ok_or("no frame parser")?;
        let accum = parser.into_handler();
        if let Some(err) = accum.error {
            return Err(err);
        }
        let mut slice = accum.buf.as_slice();
        match &mut decode.decoder {
            MessageDecoder::Proto(adapter) => {
                {
                    let mut pb = ProtoParser::new(adapter);
                    pb.receive(&mut slice).map_err(|e| e.to_string())?;
                    pb.close().map_err(|e| e.to_string())?;
                }
                adapter
                    .end_root_message()
                    .map_err(|e: ProtoParseError| e.to_string())?;
            }
            MessageDecoder::Json(adapter) => {
                {
                    let mut jp = JsonParser::new(adapter);
                    jp.receive(&mut slice).map_err(|e| e.to_string())?;
                    jp.close().map_err(|e| e.to_string())?;
                }
                adapter
                    .end_root_message()
                    .map_err(|e: ProtoParseError| e.to_string())?;
            }
        }
        decode.message_done = true;
        let mut frame_parser = GrpcFrameParser::new(FrameAccum {
            buf: Vec::new(),
            error: None,
            ended: false,
        });
        frame_parser.set_max_message_size(self.max_message_size);
        decode.frame_parser = Some(frame_parser);
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
                    self.reject_http(response, 400, &format!("Invalid request type: {e}"));
                    return;
                }
                MessageDecoder::Proto(adapter)
            }
            GrpcCodec::Json => {
                let mut adapter =
                    JsonModelAdapter::new((*self.proto_file).clone(), handler);
                if let Err(e) = adapter.start_root_message(&request_type) {
                    self.reject_http(response, 400, &format!("Invalid request type: {e}"));
                    return;
                }
                MessageDecoder::Json(adapter)
            }
        };
        let mut frame_parser = GrpcFrameParser::new(FrameAccum {
            buf: Vec::new(),
            error: None,
            ended: false,
        });
        frame_parser.set_max_message_size(self.max_message_size);
        self.decode = Some(DecodeState {
            decoder,
            frame_parser: Some(frame_parser),
            message_done: false,
        });
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.body_rejected || !self.body_started || data.is_empty() {
            return;
        }
        // A unary RPC carries exactly one gRPC message frame — this
        // handler has no streaming variant (`GrpcService` only offers
        // `start_unary_call`), so any bytes arriving after the first
        // frame already completed are a genuine protocol violation, not
        // a second legitimate message to silently drop (issue #197).
        let already_done = self.decode.as_ref().map(|d| d.message_done).unwrap_or(false);
        if already_done {
            self.reject_http(response, 400, "unary request carried more than one gRPC message frame");
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
            if parser.handler_mut().error.is_some() {
                let err = parser.handler_mut().error.take().unwrap();
                self.reject_http(response, 400, &err);
                return;
            }
            if !parser.handler_mut().ended {
                self.flush_pending(response);
                return;
            }
        }
        if let Err(e) = self.finish_frame_message() {
            self.reject_http(response, 400, &e);
            return;
        }
        self.flush_pending(response);
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.body_rejected {
            return;
        }
        if !self.body_started {
            self.reject_http(response, 400, "Missing request body");
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
            self.reject_http(response, 400, "Invalid gRPC frame");
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

    /// Wire-encoded `Msg { text: "x" }` — a real (non-empty) payload, so
    /// the frame's header doesn't exactly fill a single `receive()` call
    /// (`GrpcFrameParser::receive` only fires `end_message` once it sees
    /// at least one more byte after a frame's header — an empty-payload
    /// frame needs a following byte to complete within the same call).
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
        status: Option<u16>,
        body: Vec<u8>,
    }

    impl ServerWriter for MockWriter {
        fn headers(&mut self, headers: Headers) {
            self.status = Some(headers.status_code());
        }
        fn start_response_body(&mut self) {}
        fn response_body_content(&mut self, data: &[u8]) {
            self.body.extend_from_slice(data);
        }
        fn end_response_body(&mut self) {}
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
    /// message frame must be rejected (400), not silently discarded —
    /// `GrpcService` has no streaming variant, so any bytes after the
    /// first frame completes are a genuine protocol violation.
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
        assert_eq!(w.status, None, "no response expected yet");

        let msg = grpc_frame(&test_message_payload());
        handler.request_body_content(&mut w, &msg);
        assert_eq!(w.status, None, "first frame alone must not reject the request");

        // A second complete frame — the actual bug: this used to be
        // silently discarded instead of rejected.
        handler.request_body_content(&mut w, &msg);
        assert_eq!(w.status, Some(400), "a second frame in a unary request must be rejected: {:?}", w.status);
        assert!(
            !w.body.is_empty(),
            "a rejection should carry an explanatory body"
        );
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

        assert_ne!(w.status, Some(400), "a single well-formed frame must not be rejected: {:?} body={:?}", w.status, String::from_utf8_lossy(&w.body));
    }
}
