// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 server connection and request-stream adapters.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler};
use hopf_quic::{
    listen_quic_hooks, QuicConnApi, QuicConnection, QuicDriverHandle, QuicListenHooksConfig,
    QuicServerConfig,
};

use crate::stream::{
    ProtocolUpgradeHandler, ServerHandler, ServerHandlerFactory, ServerResponseHandle, ServerWriter,
};
use crate::{Headers, HttpLimits};

use super::response::{ArcH3ResponseControl, H3ResponseControl, H3SessionWriter};
use super::{frame, qpack, H3FrameHandler, H3Parser};

/// HTTP/3 connection state installed in the QUIC hooks driver.
pub struct H3ServerConnection {
    factory: Arc<dyn ServerHandlerFactory>,
    limits: HttpLimits,
}

impl H3ServerConnection {
    /// Create an HTTP/3 server connection.
    pub fn new(factory: Arc<dyn ServerHandlerFactory>, limits: HttpLimits) -> Self {
        Self { factory, limits }
    }
}

impl QuicConnection for H3ServerConnection {
    fn connected(&mut self, api: &mut dyn QuicConnApi) {
        if let Some(stream) = api.open_uni() {
            let mut bytes = vec![0x00]; // control stream type
            frame::write_settings(&mut bytes);
            api.write(stream, &bytes);
        }
        // RFC 9204 requires both critical QPACK streams even with dynamic QPACK disabled.
        for ty in [0x02, 0x03] {
            if let Some(stream) = api.open_uni() {
                api.write(stream, &[ty]);
            }
        }
    }

    fn accept_bi(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3RequestStream::new(Arc::clone(&self.factory), self.limits))
    }

    fn accept_uni(&mut self) -> Box<dyn ProtocolHandler> {
        Box::new(H3UniStream::default())
    }
}

/// Listen for HTTP/3 connections using QUIC hooks.
pub fn listen_h3(
    addr: SocketAddr,
    server_config: Arc<QuicServerConfig>,
    factory: Arc<dyn ServerHandlerFactory>,
    limits: HttpLimits,
) -> io::Result<QuicDriverHandle> {
    let connection_factory = Arc::new(move || {
        Box::new(H3ServerConnection::new(Arc::clone(&factory), limits)) as Box<dyn QuicConnection>
    });
    listen_quic_hooks(QuicListenHooksConfig::new(
        addr,
        server_config,
        connection_factory,
    ))
}

/// Per-request buffered response.
struct H3Writer {
    control: Arc<H3ResponseControl>,
}

impl H3Writer {
    fn new() -> Self {
        Self {
            control: H3ResponseControl::new(),
        }
    }

    fn session_writer(&mut self) -> H3SessionWriter {
        self.control.writer()
    }

    fn flush(&mut self, endpoint: &mut dyn Endpoint) {
        let upgraded = self.control.shared.lock().unwrap().upgraded;
        let headers = {
            let mut shared = self.control.shared.lock().unwrap();
            shared.needs_flush = false;
            shared.headers.take()
        };
        let body = {
            let mut shared = self.control.shared.lock().unwrap();
            std::mem::take(&mut shared.body)
        };
        let trailers = {
            let mut shared = self.control.shared.lock().unwrap();
            if shared.complete && !upgraded {
                shared.trailers.take()
            } else {
                None
            }
        };
        let complete = {
            let shared = self.control.shared.lock().unwrap();
            shared.complete && !upgraded
        };
        let headers_sent = self.control.shared.lock().unwrap().headers_sent;

        let mut out = Vec::new();
        if let Some(mut headers) = headers {
            if !headers.contains(":status") {
                headers.status(200);
            }
            if !headers.contains("date") {
                headers.set("Date", crate::utils::http_date_now());
            }
            let block = qpack::encode(headers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
            frame::write_headers(&mut out, &block);
            self.control.shared.lock().unwrap().headers_sent = true;
        } else if !headers_sent && body.is_empty() && trailers.is_none() {
            return;
        }
        if !body.is_empty() {
            frame::write_data(&mut out, &body);
        }
        if let Some(trailers) = trailers {
            let block =
                qpack::encode(trailers.iter().map(|h| (h.name.as_str(), h.value.as_str())));
            frame::write_headers(&mut out, &block);
        }
        if !out.is_empty() {
            endpoint.send(&out);
        }
        if complete {
            endpoint.close();
        }
    }

    fn flush_if_ready(&mut self, endpoint: &mut dyn Endpoint) {
        let ready = {
            let shared = self.control.shared.lock().unwrap();
            shared.headers.is_some()
                || shared.trailers.is_some()
                || shared.needs_flush
                || (shared.headers_sent && !shared.body.is_empty())
        };
        if ready {
            self.flush(endpoint);
        }
    }
}

impl ServerWriter for H3Writer {
    fn headers(&mut self, headers: Headers) {
        self.session_writer().headers(headers);
    }
    fn start_response_body(&mut self) {}
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

    fn response_handle(&self) -> crate::stream::ServerResponseHandle {
        ServerResponseHandle::new(ArcH3ResponseControl::new(Arc::clone(&self.control)))
    }

    fn pause_request_body(&mut self) {
        self.session_writer().pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.session_writer().resume_request_body();
    }
}

/// A peer-initiated HTTP/3 request stream.
struct H3RequestStream {
    factory: Arc<dyn ServerHandlerFactory>,
    #[allow(dead_code)]
    limits: HttpLimits,
    parser: H3Parser,
    handler: Option<Box<dyn ServerHandler>>,
    writer: H3Writer,
    body_started: bool,
    paused_body: Vec<u8>,
    needs_protocol_flush: Arc<Mutex<bool>>,
    upgraded: Option<Box<dyn ProtocolUpgradeHandler>>,
}

impl H3RequestStream {
    fn new(factory: Arc<dyn ServerHandlerFactory>, limits: HttpLimits) -> Self {
        let needs_protocol_flush = Arc::new(Mutex::new(false));
        let stream = Self {
            factory,
            limits,
            parser: H3Parser::new(),
            handler: None,
            writer: H3Writer::new(),
            body_started: false,
            paused_body: Vec::new(),
            needs_protocol_flush: Arc::clone(&needs_protocol_flush),
            upgraded: None,
        };
        let flag = Arc::clone(&needs_protocol_flush);
        stream.writer.control.set_flush(Some(Arc::new(move || {
            *flag.lock().unwrap() = true;
        })));
        stream
    }

    fn bind_execute_conn(&mut self) {
        let flag = Arc::clone(&self.needs_protocol_flush);
        self.writer.control.bind_conn(ConnHandle::from_execute(Arc::new(
            move |task| {
                task();
                *flag.lock().unwrap() = true;
            },
        )));
    }

    fn maybe_flush_after_deferred(&mut self, endpoint: &mut dyn Endpoint) {
        self.deliver_paused_body();
        if let Some(up) = self.upgraded.as_mut() {
            let out = up.take_outbound();
            if !out.is_empty() {
                self.writer
                    .control
                    .shared
                    .lock()
                    .unwrap()
                    .body
                    .extend_from_slice(&out);
            }
        }
        self.writer.flush_if_ready(endpoint);
    }

    fn deliver_request_body(&mut self, payload: &[u8]) {
        if let Some(up) = self.upgraded.as_mut() {
            if !payload.is_empty() {
                up.receive(payload);
            }
            let out = up.take_outbound();
            if !out.is_empty() {
                self.writer
                    .control
                    .shared
                    .lock()
                    .unwrap()
                    .body
                    .extend_from_slice(&out);
            }
            return;
        }
        if self.writer.control.body_paused() {
            if !payload.is_empty() {
                self.paused_body.extend_from_slice(payload);
            }
            return;
        }
        if let Some(handler) = &mut self.handler {
            if !self.body_started {
                handler.start_request_body(&mut self.writer);
                self.body_started = true;
            }
            handler.request_body_content(&mut self.writer, payload);
        }
    }

    fn deliver_paused_body(&mut self) {
        if self.writer.control.body_paused() {
            return;
        }
        let body = std::mem::take(&mut self.paused_body);
        if !body.is_empty() {
            self.deliver_request_body(&body);
        }
    }

    fn finish_request(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(up) = self.upgraded.as_mut() {
            up.closed();
            let out = up.take_outbound();
            if !out.is_empty() {
                self.writer
                    .control
                    .shared
                    .lock()
                    .unwrap()
                    .body
                    .extend_from_slice(&out);
            }
            self.writer.flush(endpoint);
            return;
        }
        if let Some(handler) = &mut self.handler {
            if self.body_started {
                handler.end_request_body(&mut self.writer);
            }
            handler.request_complete(&mut self.writer);
            if let Some(up) = self.writer.control.take_upgrade() {
                self.upgraded = Some(up);
            }
        }
        self.writer.flush(endpoint);
    }
}

impl H3FrameHandler for H3RequestStream {
    fn data_frame(&mut self, payload: &[u8]) {
        self.deliver_request_body(payload);
    }

    fn headers_frame(&mut self, payload: &[u8]) {
        // Second HEADERS after the request handler exists = request trailers;
        // ignore for now (gRPC does not use request trailers).
        if self.handler.is_some() {
            return;
        }
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
        let mut handler = self.factory.create_handler();
        handler.headers(&mut self.writer, &headers);
        if let Some(up) = self.writer.control.take_upgrade() {
            self.upgraded = Some(up);
        }
        self.handler = Some(handler);
    }

    fn settings_frame(&mut self, _: &[u8]) {}
    fn goaway_frame(&mut self, _: &[u8]) {}
    fn frame_error(&mut self, _: &str) {}
}

impl ProtocolHandler for H3RequestStream {
    fn connected(&mut self, _: &mut dyn Endpoint) {
        self.bind_execute_conn();
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.bind_execute_conn();
        let mut parser = std::mem::take(&mut self.parser);
        parser.push(data, self);
        self.parser = parser;
        *data = &[];
        self.maybe_flush_after_deferred(endpoint);
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        self.bind_execute_conn();
        self.finish_request(endpoint);
    }

    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

/// Consumes the type byte and ignores peer control/QPACK unidirectional streams.
#[derive(Default)]
pub(crate) struct H3UniStream {
    type_seen: bool,
}

impl ProtocolHandler for H3UniStream {
    fn connected(&mut self, _: &mut dyn Endpoint) {}
    fn receive(&mut self, _: &mut dyn Endpoint, data: &mut &[u8]) {
        if !self.type_seen && !data.is_empty() {
            // Stream types used by H3 are single-byte QUIC varints.
            self.type_seen = true;
        }
        *data = &[];
    }
    fn disconnected(&mut self, _: &mut dyn Endpoint) {}
    fn error(&mut self, _: &mut dyn Endpoint, _: &io::Error) {}
}

#[cfg(all(test, feature = "integration"))]
mod smoke {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use hopf_quic::{
        client_config_for_pem_bytes, server_config_self_signed, ALPN_H3,
    };

    use crate::h3::connect_h3;
    use crate::{
        ClientHandler, ClientHandlerFactory, ClientWriter, Headers, HttpLimits, ServerHandler,
        ServerHandlerFactory, ServerWriter,
    };

    struct Hello;
    impl ServerHandler for Hello {
        fn headers(&mut self, response: &mut dyn ServerWriter, _: &Headers) {
            let body = b"Hello, world\n";
            let mut h = Headers::new();
            h.status(200);
            h.set("content-type", "text/plain");
            h.set("content-length", body.len().to_string());
            response.headers(h);
            response.start_response_body();
            response.response_body_content(body);
            response.end_response_body();
            response.complete();
        }
        fn request_complete(&mut self, _: &mut dyn ServerWriter) {}
    }

    #[derive(Default)]
    struct Outcome {
        status: u16,
        body: Vec<u8>,
        done: bool,
        date: Option<String>,
    }

    struct GetOnce {
        out: Arc<Mutex<Outcome>>,
    }

    impl ClientHandler for GetOnce {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "GET");
            h.set(":path", "/");
            h.set("host", "localhost");
            request.headers(h);
            request.complete_request();
        }
        fn response_headers(&mut self, _: &mut dyn ClientWriter, headers: &Headers) {
            let mut out = self.out.lock().unwrap();
            out.status = headers.status_code();
            out.date = headers.get("date").map(str::to_string);
        }
        fn response_body_content(&mut self, _: &mut dyn ClientWriter, data: &[u8]) {
            self.out.lock().unwrap().body.extend_from_slice(data);
        }
        fn response_complete(&mut self, _: &mut dyn ClientWriter) {
            self.out.lock().unwrap().done = true;
        }
    }

    struct GetFactory {
        out: Arc<Mutex<Outcome>>,
    }

    impl ClientHandlerFactory for GetFactory {
        fn create_handler(&self) -> Box<dyn ClientHandler> {
            Box::new(GetOnce {
                out: Arc::clone(&self.out),
            })
        }
    }

    #[test]
    fn h3_get_hello_over_quic() {
        let (server_cfg, pem) = server_config_self_signed(&["localhost"], &[ALPN_H3]).unwrap();
        let client_cfg = client_config_for_pem_bytes(&pem, &[ALPN_H3]).unwrap();

        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits2 = Arc::clone(&hits);
        struct CountingFactory(Arc<std::sync::atomic::AtomicUsize>);
        impl ServerHandlerFactory for CountingFactory {
            fn create_handler(&self) -> Box<dyn ServerHandler> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::new(Hello)
            }
        }
        let server = listen_h3(
            "127.0.0.1:0".parse().unwrap(),
            server_cfg,
            Arc::new(CountingFactory(hits2)),
            HttpLimits::default(),
        )
        .unwrap();

        let out = Arc::new(Mutex::new(Outcome::default()));
        let _client = connect_h3(
            server.local_addr,
            client_cfg,
            "localhost",
            Arc::new(GetFactory {
                out: Arc::clone(&out),
            }),
            HttpLimits::default(),
        )
        .unwrap();

        for _ in 0..200 {
            if out.lock().unwrap().done {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "server never saw a request"
        );
        let g = out.lock().unwrap();
        assert!(g.done, "client never completed");
        assert_eq!(g.status, 200);
        assert_eq!(g.body.as_slice(), b"Hello, world\n");
        assert!(
            g.date.as_deref().is_some_and(|d| d.ends_with(" GMT")),
            "response missing Date header: {:?}",
            g.date
        );
        server.shutdown();
    }
}
