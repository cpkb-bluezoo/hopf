// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC client helpers (pre-framed request body + response decode).

use std::sync::{Arc, Mutex};

use hopf_http::{ClientHandler, ClientHandlerFactory, ClientWriter, Headers};
use rjsonparser::Parser as JsonParser;
use rprotobuf::Parser as ProtoParser;

use crate::codec::{parse_grpc_content_type, GrpcCodec};
use crate::framing::{frame, GrpcEventHandler, GrpcFrameParser};
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
}

/// Builds a [`ClientHandler`] that performs one unary gRPC call.
pub struct GrpcUnaryCall {
    path: String,
    request_message: Vec<u8>,
    proto_file: Arc<ProtoFile>,
    response_type_name: Option<String>,
    codec: GrpcCodec,
    handler: Arc<Mutex<Box<dyn GrpcResponseHandler>>>,
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
            handler: Arc::new(Mutex::new(handler)),
        }
    }

    /// Select request/response payload codec (`Proto` default, or `Json`).
    pub fn with_codec(mut self, codec: GrpcCodec) -> Self {
        self.codec = codec;
        self
    }

    /// Frame the request for HTTP body use.
    pub fn framed_request(&self) -> Vec<u8> {
        frame(&self.request_message)
    }
}

impl ClientHandlerFactory for GrpcUnaryCall {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(GrpcClientHandler {
            path: self.path.clone(),
            framed: frame(&self.request_message),
            proto_file: Arc::clone(&self.proto_file),
            response_type_name: self.response_type_name.clone(),
            codec: self.codec,
            handler: Arc::clone(&self.handler),
            frame_parser: None,
            decoder: None,
            message_done: false,
            failed: false,
            grpc_status: None,
        })
    }
}

struct FrameAccum {
    buf: Vec<u8>,
    error: Option<String>,
    ended: bool,
}

impl GrpcEventHandler for FrameAccum {
    fn start_message(&mut self, _: u8, length: u32) {
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

enum ResponseDecoder {
    Proto(ProtoModelAdapter<Box<dyn ProtoMessageHandler>>),
    Json(JsonModelAdapter<Box<dyn ProtoMessageHandler>>),
}

struct GrpcClientHandler {
    path: String,
    framed: Vec<u8>,
    proto_file: Arc<ProtoFile>,
    response_type_name: Option<String>,
    codec: GrpcCodec,
    handler: Arc<Mutex<Box<dyn GrpcResponseHandler>>>,
    frame_parser: Option<GrpcFrameParser<FrameAccum>>,
    decoder: Option<ResponseDecoder>,
    message_done: bool,
    failed: bool,
    grpc_status: Option<(i32, String)>,
}

impl GrpcClientHandler {
    fn fail(&mut self, msg: &str) {
        if self.failed {
            return;
        }
        self.failed = true;
        self.handler.lock().unwrap().on_error(msg);
    }

    fn decode_frame(&mut self) {
        let Some(parser) = self.frame_parser.take() else {
            return;
        };
        let accum = parser.into_handler();
        if let Some(err) = accum.error {
            self.fail(&err);
            return;
        }
        let Some(decoder) = self.decoder.as_mut() else {
            self.fail("no adapter");
            return;
        };
        let mut slice = accum.buf.as_slice();
        match decoder {
            ResponseDecoder::Proto(adapter) => {
                {
                    let mut pb = ProtoParser::new(adapter);
                    if let Err(e) = pb.receive(&mut slice) {
                        self.fail(&e.to_string());
                        return;
                    }
                    if let Err(e) = pb.close() {
                        self.fail(&e.to_string());
                        return;
                    }
                }
                if let Err(e) = adapter.end_root_message() {
                    self.fail(&e.to_string());
                    return;
                }
            }
            ResponseDecoder::Json(adapter) => {
                {
                    let mut jp = JsonParser::new(adapter);
                    if let Err(e) = jp.receive(&mut slice) {
                        self.fail(&e.to_string());
                        return;
                    }
                    if let Err(e) = jp.close() {
                        self.fail(&e.to_string());
                        return;
                    }
                }
                if let Err(e) = adapter.end_root_message() {
                    self.fail(&e.to_string());
                    return;
                }
            }
        }
        self.message_done = true;
    }
}

impl ClientHandler for GrpcClientHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let mut h = Headers::new();
        h.set(":method", "POST");
        h.set(":path", &self.path);
        h.set(":scheme", "https");
        h.set("content-type", self.codec.content_type());
        h.set("te", "trailers");
        request.headers(h);
        request.start_request_body();
        request.request_body_content(&self.framed);
        request.end_request_body();
        request.complete_request();
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        if let Some(status) = headers.get("grpc-status") {
            let code = status.parse().unwrap_or(2);
            let msg = headers.get("grpc-message").unwrap_or("").to_string();
            self.grpc_status = Some((code, msg.clone()));
            self.handler.lock().unwrap().on_grpc_status(code, &msg);
        }
        // Prefer response Content-Type when present; otherwise use the request codec.
        let codec = headers
            .get("content-type")
            .and_then(parse_grpc_content_type)
            .unwrap_or(self.codec);
        let type_name = self.response_type_name.clone();
        let msg_handler = {
            let mut h = self.handler.lock().unwrap();
            h.start_message(type_name.as_deref())
        };
        let Some(msg_handler) = msg_handler else {
            self.fail("no response handler");
            return;
        };
        let decoder = match codec {
            GrpcCodec::Proto => {
                let mut adapter =
                    ProtoModelAdapter::new((*self.proto_file).clone(), msg_handler);
                if let Some(ref ty) = type_name {
                    if let Err(e) = adapter.start_root_message(ty) {
                        self.fail(&e.to_string());
                        return;
                    }
                }
                ResponseDecoder::Proto(adapter)
            }
            GrpcCodec::Json => {
                let mut adapter =
                    JsonModelAdapter::new((*self.proto_file).clone(), msg_handler);
                if let Some(ref ty) = type_name {
                    if let Err(e) = adapter.start_root_message(ty) {
                        self.fail(&e.to_string());
                        return;
                    }
                }
                ResponseDecoder::Json(adapter)
            }
        };
        self.decoder = Some(decoder);
        self.frame_parser = Some(GrpcFrameParser::new(FrameAccum {
            buf: Vec::new(),
            error: None,
            ended: false,
        }));
    }

    fn response_body_content(&mut self, _request: &mut dyn ClientWriter, data: &[u8]) {
        if self.failed || data.is_empty() {
            return;
        }
        let ended = {
            let Some(parser) = self.frame_parser.as_mut() else {
                return;
            };
            parser.receive(data);
            if let Some(err) = parser.handler_mut().error.take() {
                self.fail(&err);
                return;
            }
            parser.handler_mut().ended && !self.message_done
        };
        if ended {
            self.decode_frame();
        }
    }

    fn response_trailers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        if let Some(status) = headers.get("grpc-status") {
            let code = status.parse().unwrap_or(2);
            let msg = headers.get("grpc-message").unwrap_or("").to_string();
            self.grpc_status = Some((code, msg.clone()));
            self.handler.lock().unwrap().on_grpc_status(code, &msg);
        }
    }

    fn end_response_body(&mut self, _request: &mut dyn ClientWriter) {
        if self.failed {
            return;
        }
        if !self.message_done {
            if let Some(parser) = &self.frame_parser {
                if parser.has_partial_frame() || !parser.is_message_completed() {
                    self.fail("incomplete gRPC response frame");
                }
            }
        }
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
        let _ = &self.grpc_status;
    }
}

/// Thin holder around a [`ProtoFile`] for constructing unary calls.
pub struct GrpcClient {
    proto_file: Arc<ProtoFile>,
}

impl GrpcClient {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file: Arc::new(proto_file),
        }
    }

    pub fn proto_file(&self) -> &ProtoFile {
        &self.proto_file
    }

    /// Build a [`ClientHandlerFactory`] for one unary RPC (protobuf by default).
    pub fn unary_call(
        &self,
        path: impl Into<String>,
        request_message: Vec<u8>,
        handler: Box<dyn GrpcResponseHandler>,
    ) -> GrpcUnaryCall {
        GrpcUnaryCall::new(Arc::clone(&self.proto_file), path, request_message, handler)
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
