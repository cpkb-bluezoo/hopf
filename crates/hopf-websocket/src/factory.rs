// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`ServerHandlerFactory`] that accepts WebSocket handshakes on H1/H2/H3.

use std::sync::Arc;

use hopf_http::{
    Headers, ServerHandler, ServerHandlerFactory, ServerWriter,
};

use crate::handshake::{
    is_extended_connect_websocket, validate_h1_upgrade, websocket_accept_headers,
    websocket_connect_response_headers,
};
use crate::session::WsSession;
use crate::upgrade::{WsEventHandler, WsUpgradeHandler};

/// Configuration for [`WebSocketFactory`].
#[derive(Clone, Debug)]
pub struct WebSocketConfig {
    /// Maximum data-frame payload bytes.
    pub max_payload: usize,
    /// Optional subprotocol to select when the client offers it.
    pub subprotocol: Option<String>,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_payload: 16 * 1024 * 1024,
            subprotocol: None,
        }
    }
}

/// Builds per-connection [`WsEventHandler`] instances.
pub trait WsEventHandlerFactory: Send + Sync {
    /// Create a handler for a new WebSocket (path from `:path`).
    fn create(&self, path: &str, request_headers: &Headers) -> Box<dyn WsEventHandler>;
}

/// HTTP factory that upgrades valid WebSocket requests and rejects others with 400.
pub struct WebSocketFactory<F: WsEventHandlerFactory> {
    events: Arc<F>,
    config: WebSocketConfig,
}

impl<F: WsEventHandlerFactory> WebSocketFactory<F> {
    /// Create a factory.
    pub fn new(events: F, config: WebSocketConfig) -> Self {
        Self {
            events: Arc::new(events),
            config,
        }
    }
}

impl<F: WsEventHandlerFactory + 'static> ServerHandlerFactory for WebSocketFactory<F> {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(WsHttpHandler {
            events: Arc::clone(&self.events),
            config: self.config.clone(),
            request: Headers::new(),
        })
    }
}

struct WsHttpHandler<F: WsEventHandlerFactory> {
    events: Arc<F>,
    config: WebSocketConfig,
    request: Headers,
}

impl<F: WsEventHandlerFactory> ServerHandler for WsHttpHandler<F> {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        self.request = headers.clone();
        let path = headers.get(":path").unwrap_or("/");
        let event = self.events.create(path, headers);
        let max = self.config.max_payload;
        let sub = self.config.subprotocol.as_deref();

        if let Ok(key) = validate_h1_upgrade(headers) {
            let resp = websocket_accept_headers(key, sub);
            let handler = Box::new(WsUpgradeHandler::server(event, max));
            if !response.upgrade(resp, handler) {
                let mut h = Headers::new();
                h.status(500);
                response.headers(h);
                response.complete();
            }
            return;
        }

        if is_extended_connect_websocket(headers) {
            let resp = websocket_connect_response_headers(sub);
            let handler = Box::new(WsUpgradeHandler::server(event, max));
            if !response.upgrade(resp, handler) {
                let mut h = Headers::new();
                h.status(500);
                response.headers(h);
                response.complete();
            }
            return;
        }

        let mut h = Headers::new();
        h.status(400);
        h.set("Content-Type", "text/plain");
        response.headers(h);
        response.start_response_body();
        response.response_body_content(b"WebSocket upgrade required");
        response.end_response_body();
        response.complete();
    }

    fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
}

/// Echo handler for examples and integration tests.
pub struct EchoWsHandler;

impl WsEventHandler for EchoWsHandler {
    fn opened(&mut self, _session: &mut WsSession<'_>) {}

    fn text_message(&mut self, session: &mut WsSession<'_>, text: &str) {
        session.send_text(text);
    }

    fn binary_message(&mut self, session: &mut WsSession<'_>, data: &[u8]) {
        session.send_binary(data);
    }
}

/// Factory that always returns [`EchoWsHandler`].
pub struct EchoFactory;

impl WsEventHandlerFactory for EchoFactory {
    fn create(&self, _path: &str, _request_headers: &Headers) -> Box<dyn WsEventHandler> {
        Box::new(EchoWsHandler)
    }
}
