// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Transport-negotiating HTTP client connection ([`HttpClientConnection`]).
//!
//! Mirrors server-side [`crate::dispatch::AlpnHttpEndpoint`] and
//! [`crate::h2::CleartextHttpEndpoint`]: ALPN, cleartext H2 prior-knowledge, or
//! HTTP/1.1 — then the same [`HttpRequest`](crate::HttpRequest) session API.

use std::sync::Arc;

use hopf_core::{Endpoint, ProtocolHandler, SecurityInfo};

use crate::h1::{H1Endpoint, H1SessionClientCodec};
use crate::limits::HttpLimits;

use super::h2_session::H2HttpClientSession;
use super::session_config::HttpClientSessionConfig;

fn h1_session_handler(
    config: Arc<HttpClientSessionConfig>,
    limits: HttpLimits,
    secure: bool,
) -> Box<dyn ProtocolHandler> {
    let codec = H1SessionClientCodec::new(config);
    Box::new(H1Endpoint::client_session(codec, limits, secure))
}

fn h2_session_handler(
    config: Arc<HttpClientSessionConfig>,
    limits: HttpLimits,
    secure: bool,
) -> Box<dyn ProtocolHandler> {
    Box::new(H2HttpClientSession::new(config, limits, secure))
}

/// Negotiates HTTP version on the wire, then runs the Gumdrop session API.
///
/// Public so callers that need to dial through their own lower transport
/// layer first (a SOCKS5 proxy, an HTTP CONNECT tunnel, …) instead of this
/// crate's own DNS-resolve-then-dial (`connect_http`/`connect_https`) can
/// still get the Gumdrop-shaped session API
/// ([`HttpConnectionHandler`](super::api::HttpConnectionHandler),
/// [`HttpRequest`](super::api::HttpRequest)) on top of it: wrap the
/// already-established transport's innermost [`ProtocolHandler`] with one of
/// these instead of reimplementing H1/H2 version negotiation.
///
/// For a `secure` connection, the caller is responsible for actually
/// arranging the TLS handshake (e.g. [`Endpoint::start_client_tls`] once its
/// own lower layer reports `connected`) — this only reacts to the resulting
/// [`ProtocolHandler::security_established`] callback to pick H1 vs H2 by
/// ALPN, exactly like [`connect_https`](super::connect_https)'s own
/// `TlsAlpnClientEndpoint` does; it does not configure TLS on any dial
/// itself. For a cleartext connection, `connected` dispatches immediately
/// using `h2_prior_knowledge`, matching [`connect_http`](super::connect_http).
pub struct HttpClientConnection {
    config: Arc<HttpClientSessionConfig>,
    limits: HttpLimits,
    secure: bool,
    h2_prior_knowledge: bool,
    inner: Option<Box<dyn ProtocolHandler>>,
    pending_receive: Vec<u8>,
}

impl HttpClientConnection {
    /// `config.secure` and `secure` must agree (the config decides what
    /// [`HttpConnectionHandler::on_security_established`] expects); `secure`
    /// is accepted separately only because the surrounding dial helpers in
    /// this module already had it to hand.
    pub fn new(
        config: Arc<HttpClientSessionConfig>,
        limits: HttpLimits,
        secure: bool,
        h2_prior_knowledge: bool,
    ) -> Self {
        Self {
            config,
            limits,
            secure,
            h2_prior_knowledge,
            inner: None,
            pending_receive: Vec::new(),
        }
    }

    fn install_h1(&mut self) {
        self.inner = Some(h1_session_handler(
            Arc::clone(&self.config),
            self.limits,
            self.secure,
        ));
    }

    fn install_h2(&mut self) {
        self.inner = Some(h2_session_handler(
            Arc::clone(&self.config),
            self.limits,
            self.secure,
        ));
    }

    fn start_cleartext(&mut self, endpoint: &mut dyn Endpoint) {
        if self.h2_prior_knowledge {
            self.install_h2();
        } else {
            self.install_h1();
        }
        if let Some(inner) = self.inner.as_mut() {
            inner.connected(endpoint);
        }
    }

    fn start_tls(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        let is_h2 = info.alpn().map(|a| a == b"h2").unwrap_or(false);
        if is_h2 {
            self.install_h2();
        } else {
            self.install_h1();
        }
        if let Some(inner) = self.inner.as_mut() {
            inner.connected(endpoint);
            inner.security_established(endpoint, info);
        }
        if !self.pending_receive.is_empty() {
            let buf = std::mem::take(&mut self.pending_receive);
            let mut slice: &[u8] = &buf;
            if let Some(inner) = self.inner.as_mut() {
                inner.receive(endpoint, &mut slice);
            }
        }
    }
}

impl ProtocolHandler for HttpClientConnection {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.secure {
            return;
        }
        if self.h2_prior_knowledge {
            self.start_cleartext(endpoint);
            return;
        }
        // Cleartext H2 prior-knowledge without the builder flag: sniff first bytes
        // from the peer (unusual on dial; client normally sends first).
        self.install_h1();
        if let Some(inner) = self.inner.as_mut() {
            inner.connected(endpoint);
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        if !self.secure {
            return;
        }
        self.start_tls(endpoint, info);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if let Some(inner) = self.inner.as_mut() {
            inner.receive(endpoint, data);
        } else {
            self.pending_receive.extend_from_slice(data);
            *data = &[];
        }
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Some(inner) = self.inner.as_mut() {
            inner.disconnected(endpoint);
        } else if let Some(mut h) = self.config.handler.lock().unwrap().take() {
            // Peer closed before negotiation ever got an H1/H2 session
            // installed — `on_connected` can never fire now.
            h.on_error(&std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before negotiation completed",
            ));
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        if let Some(inner) = self.inner.as_mut() {
            inner.error(endpoint, err);
        } else {
            // Failed before an H1/H2 session was even installed (e.g. TLS
            // handshake failure, or connect-refused/reset delivered before
            // `connected`/`security_established`) — `on_connected` can
            // never have fired, so the stashed `HttpConnectionHandler` is
            // still sitting in `config.handler` and would otherwise just be
            // dropped with zero notification (issue #88).
            if let Some(mut h) = self.config.handler.lock().unwrap().take() {
                h.on_error(err);
            }
            endpoint.close();
        }
    }
}
