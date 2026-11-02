// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! H1 [`ProtocolHandler`](hopf_core::ProtocolHandler) on one TCP/TLS Endpoint.

use std::sync::Arc;

use hopf_core::{Endpoint, LoopBuf, ProtocolHandler};

use crate::limits::HttpLimits;
use crate::stream::{
    ClientHandler, ClientHandlerFactory, HttpRole, ServerHandler, ServerHandlerFactory,
};

use super::client_codec::H1ClientCodec;
use super::over_ring;
use super::server_codec::H1ServerCodec;
use super::session_client_codec::H1SessionClientCodec;

/// HTTP/1.x engine for one transport Endpoint (listen or dial).
///
/// Serializes [`crate::stream::HttpStream`]s on the pipe. Role selects which
/// codec face is active. Server and client are peers — neither is the product centre.
pub struct H1Endpoint {
    role: HttpRole,
    server: Option<H1ServerCodec<Box<dyn ServerHandler>>>,
    client: Option<H1ClientCodec<Box<dyn ClientHandler>>>,
    session: Option<H1SessionClientCodec>,
    #[allow(dead_code)] // keep-alive / next Stream (H2-shaped) later
    server_factory: Option<Arc<dyn ServerHandlerFactory>>,
    #[allow(dead_code)]
    client_factory: Option<Arc<dyn ClientHandlerFactory>>,
    #[allow(dead_code)]
    limits: HttpLimits,
    secure: bool,
    /// Next stream id (odd for client-initiated, matching H2/H3 habit).
    #[allow(dead_code)]
    next_stream_id: u64,
}

impl H1Endpoint {
    /// Server role on a bound (or dialed) Endpoint — receives requests.
    pub fn server(
        factory: Arc<dyn ServerHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        let handler = factory.create_handler();
        Self {
            role: HttpRole::Server,
            server: Some(H1ServerCodec::new(handler, limits, secure)),
            client: None,
            session: None,
            server_factory: Some(factory),
            client_factory: None,
            limits,
            secure,
            next_stream_id: 1,
        }
    }

    /// Client role on a dialed (or bound) Endpoint — sends requests.
    pub fn client(
        factory: Arc<dyn ClientHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        let handler = factory.create_handler();
        let mut codec = H1ClientCodec::new(handler, limits, secure);
        codec.set_stream_id(1);
        Self {
            role: HttpRole::Client,
            server: None,
            client: Some(codec),
            session: None,
            server_factory: None,
            client_factory: Some(factory),
            limits,
            secure,
            next_stream_id: 1,
        }
    }

    fn bind_server_handle(&mut self, endpoint: &dyn Endpoint) {
        if let Some(codec) = self.server.as_mut() {
            codec.bind_conn_handle(endpoint.handle());
            codec.bind_connection_info(endpoint);
        }
    }

    fn bind_client_handle(&mut self, endpoint: &dyn Endpoint) {
        if let Some(codec) = self.client.as_mut() {
            codec.bind_conn_handle(endpoint.handle());
        }
    }

    fn flush_server(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(codec) = self.server.as_mut() {
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
            if codec.pause_request_body() {
                endpoint.pause_read();
            } else {
                endpoint.resume_read();
            }
            if codec.wants_close() {
                endpoint.close();
            }
        }
    }

    /// Client role using the Gumdrop-shaped [`HttpRequest`](crate::HttpRequest) session API.
    pub(crate) fn client_session(codec: H1SessionClientCodec, limits: HttpLimits, secure: bool) -> Self {
        Self {
            role: HttpRole::Client,
            server: None,
            client: None,
            session: Some(codec),
            server_factory: None,
            client_factory: None,
            limits,
            secure,
            next_stream_id: 1,
        }
    }

    fn flush_client(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(codec) = self.client.as_mut() {
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
            if codec.wants_close() {
                endpoint.close();
            }
        }
        if let Some(codec) = self.session.as_mut() {
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
            // Renew on outbound progress (request bytes just went out) and
            // on inbound progress (this flush follows a `receive()` that
            // fed the parser) alike — `touch_stage_timer` itself is a no-op
            // when no request is in flight.
            codec.arm_writable(endpoint);
            codec.touch_stage_timer(endpoint);
            if codec.wants_close() {
                endpoint.close();
            }
        }
    }

    fn kickoff_client(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(codec) = self.client.as_mut() {
            codec.on_connected();
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
        }
        if let Some(codec) = self.session.as_mut() {
            codec.on_connected(endpoint.handle());
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
            codec.arm_writable(endpoint);
            codec.touch_stage_timer(endpoint);
        }
    }
}

impl ProtocolHandler for H1Endpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.bind_server_handle(endpoint);
        self.bind_client_handle(endpoint);
        // Plaintext dial: send the request now. TLS dial waits for
        // `security_established` so application data is not queued mid-handshake.
        if self.role == HttpRole::Client && !self.secure {
            self.kickoff_client(endpoint);
        }
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        info: &hopf_core::SecurityInfo,
    ) {
        self.bind_server_handle(endpoint);
        self.bind_client_handle(endpoint);
        if self.role == HttpRole::Client && self.secure {
            if let Some(codec) = self.session.as_mut() {
                codec.notify_security_established(info);
            }
            self.kickoff_client(endpoint);
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut LoopBuf) {
        self.bind_server_handle(endpoint);
        match self.role {
            HttpRole::Server => {
                if let Some(codec) = self.server.as_mut() {
                    let _ = over_ring(buf, |data| codec.receive_bytes(data));
                }
                self.flush_server(endpoint);
            }
            HttpRole::Client => {
                if let Some(codec) = self.client.as_mut() {
                    let _ = over_ring(buf, |data| codec.receive_bytes(data));
                }
                if let Some(codec) = self.session.as_mut() {
                    let _ = over_ring(buf, |data| codec.receive_bytes(data));
                }
                self.flush_client(endpoint);
            }
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        match self.role {
            HttpRole::Server => {
                if let Some(codec) = self.server.as_mut() {
                    let _ = codec.close();
                }
                self.flush_server(endpoint);
            }
            HttpRole::Client => {
                if let Some(codec) = self.client.as_mut() {
                    let _ = codec.close();
                }
                if let Some(codec) = self.session.as_mut() {
                    let _ = codec.close();
                }
                self.flush_client(endpoint);
            }
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        if let Some(codec) = self.session.as_mut() {
            codec.fail_transport(std::io::Error::new(err.kind(), err.to_string()));
        }
        endpoint.close();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use hopf_core::testing::Peer;

    use super::*;
    use crate::client::api::{
        HttpClientSessionHandle, HttpConnectionHandler, HttpRequest, HttpResponseHandler,
    };
    use crate::h1::session_client_codec::H1SessionConfig;

    struct Ignore;

    impl HttpResponseHandler for Ignore {
        fn ok(&mut self, _status: u16) {}
        fn error(&mut self, _status: u16) {}
        fn header(&mut self, _name: &str, _value: &str) {}
        fn response_body_content(&mut self, _data: &[u8]) {}
        fn close(&mut self) {}
        fn failed(&mut self, _err: std::io::Error) {}
    }

    /// Opens an upload and keeps hold of the request and the connection handle.
    struct Upload(Arc<Mutex<Option<(HttpRequest, hopf_core::ConnHandle)>>>);

    impl HttpConnectionHandler for Upload {
        fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
            let mut req = session.post("/upload");
            req.start_request_body(Box::new(Ignore)).unwrap();
            *self.0.lock().unwrap() = Some((req, session.conn_handle().unwrap()));
        }
    }

    /// A body writer that is told to carry on has to be told when the
    /// connection has taken what it wrote, not when the bytes are merely
    /// handed to the connection's buffer. Otherwise a writer that goes again
    /// on every callback outruns a slow peer and overflows that buffer.
    #[test]
    fn body_writable_fires_when_the_output_is_drained_not_when_it_is_handed_over() {
        let slot = Arc::new(Mutex::new(None));
        let config = Arc::new(H1SessionConfig {
            host: "ex.com".into(),
            port: 80,
            limits: HttpLimits::default(),
            secure: false,
            handler: Mutex::new(Some(Box::new(Upload(Arc::clone(&slot))))),
            stage: Duration::ZERO,
        });
        let codec = H1SessionClientCodec::new(config);
        let mut peer = Peer::connect(H1Endpoint::client_session(codec, HttpLimits::default(), false), |_| false);
        let (mut req, handle) = slot.lock().unwrap().take().expect("connected");

        let body = vec![b'x'; 300 * 1024];
        let accepted = req.request_body_content(&body).unwrap();
        assert!(accepted > 0 && accepted < body.len(), "a short write, got {accepted}");
        let writable = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&writable);
        req.on_body_writable(Box::new(move || flag.store(true, Ordering::SeqCst))).unwrap();

        handle.poke();
        let sent = peer.run("");
        assert!(sent.len() >= accepted, "the body went out");
        assert!(!writable.load(Ordering::SeqCst), "handed over, not yet drained");

        peer.drain();
        assert!(writable.load(Ordering::SeqCst), "told once the output drained");
        assert_eq!(req.request_body_content(&body[accepted..]).unwrap().min(1), 1, "room again");
    }
}
