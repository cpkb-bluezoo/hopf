// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC client helpers (pre-framed request body + response decode).

use std::sync::{Arc, Mutex};

use hopf_http::{ClientHandler, ClientHandlerFactory, ClientWriter, ContentCoding, Headers};
use rjsonparser::Parser as JsonParser;
use rprotobuf::Parser as ProtoParser;

use crate::codec::{parse_grpc_content_type, GrpcCodec};
use crate::compression::{
    accept_encoding_header, compress, MessageAccum, MessageCoding, DEFAULT_ENCODINGS,
};
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
            encodings: DEFAULT_ENCODINGS.to_vec(),
            compression: None,
            handler: Arc::new(Mutex::new(handler)),
        }
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

impl ClientHandlerFactory for GrpcUnaryCall {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(GrpcClientHandler {
            path: self.path.clone(),
            framed: self.framed_request(),
            proto_file: Arc::clone(&self.proto_file),
            response_type_name: self.response_type_name.clone(),
            codec: self.codec,
            encodings: self.encodings.clone(),
            compression: self.compression,
            handler: Arc::clone(&self.handler),
            frame_parser: None,
            decoder: None,
            message_done: false,
            failed: false,
            grpc_status: None,
        })
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
    encodings: Vec<ContentCoding>,
    compression: Option<ContentCoding>,
    handler: Arc<Mutex<Box<dyn GrpcResponseHandler>>>,
    frame_parser: Option<GrpcFrameParser<MessageAccum>>,
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

    /// Fails the call with a gRPC status this side determined (a framing or
    /// decompression failure), named in the error text.
    fn fail_status(&mut self, status: i32, msg: &str) {
        self.fail(&format!("{msg} (grpc-status {status})"));
    }

    fn decode_frame(&mut self) {
        let Some(parser) = self.frame_parser.take() else {
            return;
        };
        let accum = parser.into_handler();
        if let Some((status, err)) = accum.error {
            self.fail_status(status, &err);
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
        h.set("grpc-accept-encoding", accept_encoding_header(&self.encodings));
        if let Some(coding) = self.compression {
            h.set("grpc-encoding", coding.token());
        }
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
        // a flagged message is decoded with the response's grpc-encoding,
        // bounded by the message limit so it cannot expand without end
        let coding = MessageCoding::resolve(headers.get("grpc-encoding"), &self.encodings);
        self.frame_parser = Some(GrpcFrameParser::new(MessageAccum::new(
            coding,
            crate::framing::DEFAULT_MAX_MESSAGE_SIZE,
        )));
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
            if let Some((status, err)) = parser.handler_mut().error.take() {
                self.fail_status(status, &err);
                return;
            }
            parser.handler_mut().ended && !self.message_done
        };
        if ended {
            self.decode_frame();
        }
    }

    fn response_trailers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        if self.failed {
            // the call has already been reported as failed; the status the
            // server sends after a message this side could not decode must
            // not be reported as its outcome
            return;
        }
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
    encodings: Vec<ContentCoding>,
    compression: Option<ContentCoding>,
}

impl GrpcClient {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file: Arc::new(proto_file),
            encodings: DEFAULT_ENCODINGS.to_vec(),
            compression: None,
        }
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
        GrpcUnaryCall::new(Arc::clone(&self.proto_file), path, request_message, handler)
            .with_encodings(&self.encodings)
            .with_compression(self.compression)
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
    use hopf_core::ConnHandle;
    use hopf_http::HttpVersion;

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
    }

    /// Records what the client handler sent.
    #[derive(Default)]
    struct MockRequest {
        headers: Option<Headers>,
        body: Vec<u8>,
    }

    impl ClientWriter for MockRequest {
        fn headers(&mut self, headers: Headers) {
            self.headers = Some(headers);
        }
        fn start_request_body(&mut self) {}
        fn request_body_content(&mut self, data: &[u8]) {
            self.body.extend_from_slice(data);
        }
        fn end_request_body(&mut self) {}
        fn complete_request(&mut self) {}
        fn version(&self) -> HttpVersion {
            HttpVersion::Http2
        }
        fn conn_handle(&self) -> ConnHandle {
            ConnHandle::from_execute(Arc::new(|task| task()))
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
        assert_eq!(got.len(), 1, "expected exactly one on_error: {got:?}");
        assert!(got[0].starts_with("error "), "{got:?}");
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
        let headers = req.headers.unwrap();
        assert_eq!(headers.get("grpc-encoding"), Some("gzip"));
        assert_eq!(req.body[0], 1, "compressed flag");
        let len = u32::from_be_bytes(req.body[1..5].try_into().unwrap()) as usize;
        assert_eq!(len, req.body.len() - 5);
        assert!(len < 600, "not smaller: {len}");
        let mut d = hopf_http::Decoder::new(ContentCoding::Gzip, 1 << 20).unwrap();
        let mut out = Vec::new();
        d.push(&req.body[5..], &mut |o| out.extend_from_slice(o)).unwrap();
        d.finish().unwrap();
        assert_eq!(out, msg(&text));
        assert_eq!(events.take(), vec!["field text=String(\"ok\")", "status 0 \"\""]);

        // a message that would not shrink goes as it is, and by default
        // nothing is compressed at all
        let call = client().compression(ContentCoding::Gzip).unary_call(
            "/test.TestSvc/Call",
            msg("x"),
            Box::new(RecordingHandler(Events::default())),
        );
        let mut handler = call.create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        assert_eq!(req.body, frame(&msg("x")));

        let call = client().unary_call(
            "/test.TestSvc/Call",
            msg(&text),
            Box::new(RecordingHandler(Events::default())),
        );
        let mut handler = call.create_handler();
        let req = deliver(&mut *handler, &[], &frame(&msg("ok")), &[("grpc-status", "0")]);
        assert_eq!(req.headers.unwrap().get("grpc-encoding"), None);
        assert_eq!(req.body, frame(&msg(&text)));
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
            req.headers.as_ref().and_then(|h| h.get("grpc-accept-encoding")),
            Some("identity,gzip,deflate")
        );
        let got = events.take();
        assert_eq!(got, vec!["field text=String(\"hello\")", "status 0 \"\""]);
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
            assert_eq!(got.len(), 1, "{headers:?}: {got:?}");
            assert!(got[0].starts_with("error ") && got[0].contains(&format!("grpc-status {status}")), "{got:?}");
        }
    }
}
