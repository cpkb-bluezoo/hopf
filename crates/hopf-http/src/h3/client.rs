// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 client connection and request-stream adapters.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler};
use hopf_quic::{
    connect_quic_hooks, QuicClientConfig, QuicConnApi, QuicConnection, QuicDriverHandle,
};

use crate::{
    ClientHandler, ClientHandlerFactory, ClientWriter, Headers, HttpLimits,
};

use super::endpoint::{H3PeerState, H3UniStream};
use super::{frame, qpack, H3FrameHandler, H3Parser};

/// HTTP/3 client connection installed in the QUIC hooks driver.
pub struct H3ClientConnection {
    factory: Arc<dyn ClientHandlerFactory>,
    limits: HttpLimits,
    peer_state: Arc<Mutex<H3PeerState>>,
}

impl H3ClientConnection {
    /// Create an HTTP/3 client connection (one request Stream after handshake).
    pub fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            peer_state: Arc::new(Mutex::new(H3PeerState::default())),
        }
    }
}

impl QuicConnection for H3ClientConnection {
    fn connected(&mut self, api: &mut dyn QuicConnApi) {
        if let Some(stream) = api.open_uni() {
            let mut bytes = vec![0x00];
            frame::write_settings(&mut bytes);
            api.write(stream, &bytes);
        }
        for ty in [0x02u8, 0x03] {
            if let Some(stream) = api.open_uni() {
                api.write(stream, &[ty]);
            }
        }
        // Request stream — [`H3ClientStream`] starts the app request in `connected`.
        let _ = api.open_bi();
    }

    fn accept_bi(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3ClientStream::new(Arc::clone(&self.factory), self.limits))
    }

    fn accept_uni(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3UniStream::new(Arc::clone(&self.peer_state)))
    }
}

/// Dial an HTTP/3 peer (ALPN `h3`).
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

/// Buffered outbound request during [`ClientHandler::start`].
struct H3ClientWriter {
    request_headers: Option<Headers>,
    body: Vec<u8>,
    done: bool,
}

impl H3ClientWriter {
    fn new() -> Self {
        Self {
            request_headers: None,
            body: Vec::new(),
            done: false,
        }
    }
}

impl ClientWriter for H3ClientWriter {
    fn headers(&mut self, mut headers: Headers) {
        if !headers.contains(":scheme") {
            headers.add(":scheme", "https");
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

struct NullClientWriter;

impl ClientWriter for NullClientWriter {
    fn headers(&mut self, _: Headers) {}
    fn start_request_body(&mut self) {}
    fn request_body_content(&mut self, _: &[u8]) {}
    fn end_request_body(&mut self) {}
    fn complete_request(&mut self) {}
}

/// One outbound H3 request / inbound response on a bidirectional QUIC stream.
struct H3ClientStream {
    factory: Arc<dyn ClientHandlerFactory>,
    #[allow(dead_code)]
    limits: HttpLimits,
    parser: H3Parser,
    handler: Option<Box<dyn ClientHandler>>,
    response_headers_received: bool,
    response_body_started: bool,
    started: bool,
}

impl H3ClientStream {
    fn new(factory: Arc<dyn ClientHandlerFactory>, limits: HttpLimits) -> Self {
        Self {
            factory,
            limits,
            parser: H3Parser::new(),
            handler: None,
            response_headers_received: false,
            response_body_started: false,
            started: false,
        }
    }

    fn start_request(&mut self, endpoint: &mut dyn Endpoint) {
        if self.started {
            return;
        }
        self.started = true;

        let mut handler = self.factory.create_handler();
        let mut writer = H3ClientWriter::new();
        handler.start(&mut writer);

        let headers = writer.request_headers.take().unwrap_or_default();
        let body = writer.body;
        let done = writer.done;

        let mut out = Vec::new();
        let block = qpack::encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
        frame::write_headers(&mut out, &block);
        if !body.is_empty() {
            frame::write_data(&mut out, &body);
        }
        endpoint.send(&out);
        if done {
            endpoint.close();
        }

        self.handler = Some(handler);
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
        let Ok(pairs) = qpack::decode(payload) else {
            return;
        };
        if pairs.len() > self.limits.max_header_count {
            return;
        }
        let mut headers = Headers::new();
        for (name, value) in pairs {
            headers.add(name, value);
        }
        let mut w = NullClientWriter;
        if let Some(handler) = &mut self.handler {
            if self.response_headers_received {
                if self.response_body_started {
                    handler.end_response_body(&mut w);
                    self.response_body_started = false;
                }
                handler.response_trailers(&mut w, &headers);
            } else {
                self.response_headers_received = true;
                handler.response_headers(&mut w, &headers);
            }
        }
    }

    fn settings_frame(&mut self, _: &[u8]) {}
    fn goaway_frame(&mut self, _: &[u8]) {}
    fn frame_error(&mut self, _: &str) {}
}

impl ProtocolHandler for H3ClientStream {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.start_request(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        let mut parser = std::mem::take(&mut self.parser);
        parser.push(data, self);
        self.parser = parser;
        *data = &[];
        let _ = endpoint;
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.finish_response();
    }

    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}
