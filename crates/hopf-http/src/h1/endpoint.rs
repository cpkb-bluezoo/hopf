// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! H1 [`ProtocolHandler`](hopf_core::ProtocolHandler) on one TCP/TLS Endpoint.

use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler};

use crate::limits::HttpLimits;
use crate::stream::{
    ClientHandler, ClientHandlerFactory, HttpRole, ServerHandler, ServerHandlerFactory,
};

use super::client_codec::H1ClientCodec;
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
            codec.on_connected();
            let out = codec.take_outbound();
            if !out.is_empty() {
                endpoint.send(&out);
            }
        }
    }
}

impl ProtocolHandler for H1Endpoint {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.bind_server_handle(endpoint);
        // Plaintext dial: send the request now. TLS dial waits for
        // `security_established` so application data is not queued mid-handshake.
        if self.role == HttpRole::Client && !self.secure {
            self.kickoff_client(endpoint);
        }
    }

    fn security_established(
        &mut self,
        endpoint: &mut dyn Endpoint,
        _info: &hopf_core::SecurityInfo,
    ) {
        self.bind_server_handle(endpoint);
        if self.role == HttpRole::Client && self.secure {
            self.kickoff_client(endpoint);
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.bind_server_handle(endpoint);
        match self.role {
            HttpRole::Server => {
                if let Some(codec) = self.server.as_mut() {
                    let _ = codec.receive(data);
                }
                self.flush_server(endpoint);
            }
            HttpRole::Client => {
                if let Some(codec) = self.client.as_mut() {
                    let _ = codec.receive(data);
                }
                if let Some(codec) = self.session.as_mut() {
                    let _ = codec.receive(data);
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

    fn error(&mut self, endpoint: &mut dyn Endpoint, _err: &std::io::Error) {
        endpoint.close();
    }
}

/// Deprecated alias — use [`H1Endpoint::server`].
#[deprecated(note = "renamed to H1Endpoint::server")]
pub type HttpConnection = H1Endpoint;

impl H1Endpoint {
    /// Deprecated constructor — use [`H1Endpoint::server`].
    #[deprecated(note = "use H1Endpoint::server")]
    pub fn new(
        factory: Arc<dyn ServerHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        Self::server(factory, limits, secure)
    }

    /// Deprecated — use [`H1Endpoint::server`].
    #[deprecated(note = "renamed to H1Endpoint::server")]
    pub fn origin(
        factory: Arc<dyn ServerHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        Self::server(factory, limits, secure)
    }

    /// Deprecated — use [`H1Endpoint::client`].
    #[deprecated(note = "renamed to H1Endpoint::client")]
    pub fn user_agent(
        factory: Arc<dyn ClientHandlerFactory>,
        limits: HttpLimits,
        secure: bool,
    ) -> Self {
        Self::client(factory, limits, secure)
    }
}
