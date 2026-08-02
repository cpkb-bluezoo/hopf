// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server (receive-request / send-response) face of an [`super::HttpStream`].
//!
//! Peer of [`super::client`] — not a privileged product centre.

use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ConnHandle, SecurityInfo};

use crate::headers::Headers;

/// Transport metadata for the current connection (Gumdrop
/// `HTTPResponseState.getRemoteAddress`/`getLocalAddress`/`getSecurityInfo`).
///
/// Captured once when the transport binds and constant for the connection's
/// lifetime — cheap to read on every [`ServerWriter`] call.
#[derive(Clone, Debug, Default)]
pub struct ConnectionInfo {
    pub(crate) remote_addr: Option<SocketAddr>,
    pub(crate) local_addr: Option<SocketAddr>,
    pub(crate) security_info: SecurityInfo,
}

impl ConnectionInfo {
    pub(crate) fn new(
        remote_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        security_info: SecurityInfo,
    ) -> Self {
        Self {
            remote_addr,
            local_addr,
            security_info,
        }
    }

    /// Peer address, when the transport is a socket (`None` for in-process tests).
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Local bound address, when the transport is a socket.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Whether a TLS layer is active on this connection.
    pub fn is_secure(&self) -> bool {
        self.security_info.is_secure()
    }

    /// Negotiated TLS parameters (ALPN, protocol, cipher, SNI, mTLS
    /// fingerprint). Plaintext connections get [`SecurityInfo::plaintext`].
    pub fn security_info(&self) -> &SecurityInfo {
        &self.security_info
    }
}

/// Factory that creates a server handler per HTTP Stream.
///
/// Unlike Gumdrop's `HTTPRequestHandlerFactory.createHandler(state, headers)`,
/// this factory does not see the request — it cannot route by path or
/// short-circuit with an early 401/404 before a handler exists. Routing and
/// auth-gating are instead composed by *decoration*: wrap an inner
/// `ServerHandlerFactory`/`ServerHandler` in one that inspects headers in
/// [`ServerHandler::headers`] and either forwards to the inner handler or
/// answers directly (see [`crate::auth::BasicAuthFactory`] for the pattern).
/// This is a deliberate departure from Gumdrop, not a gap: composition over
/// a request-aware factory keeps handler construction side-effect-free and
/// lets multiple concerns (auth, routing, logging) stack independently.
pub trait ServerHandlerFactory: Send + Sync {
    /// Create a handler for the next inbound request Stream.
    fn create_handler(&self) -> Box<dyn ServerHandler>;
}

/// Receives one inbound HTTP request as incremental push events.
///
/// Sequence with a body: [`headers`] → [`start_request_body`] →
/// [`request_body_content`]* → [`end_request_body`] → [`request_complete`].
/// Without a body: [`headers`] → [`request_complete`].
pub trait ServerHandler: Send {
    /// Request headers are complete (pseudo-headers included).
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers);

    /// First body byte is about to arrive.
    fn start_request_body(&mut self, _response: &mut dyn ServerWriter) {}

    /// Body chunk (zero-copy for the duration of the call).
    fn request_body_content(&mut self, _response: &mut dyn ServerWriter, _data: &[u8]) {}

    /// Request body finished.
    fn end_request_body(&mut self, _response: &mut dyn ServerWriter) {}

    /// Trailer headers after the request body (a second HEADERS frame on
    /// H2/H3). Default: ignore — most applications (e.g. gRPC) don't send
    /// or need request trailers.
    fn request_trailers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}

    /// Request fully received; response may already be in progress.
    fn request_complete(&mut self, response: &mut dyn ServerWriter);
}

/// Transport-internal control plane for deferred response writes.
///
/// H1/H2/H3 each provide an implementation; application code uses only
/// [`ServerResponseHandle`].
pub(crate) trait ResponseControl: Send + Sync {
    fn conn_handle(&self) -> ConnHandle;
    fn execute(&self, f: Box<dyn FnOnce(&mut dyn ServerWriter) + Send>);
    fn pause_request_body(&self);
    fn resume_request_body(&self);
}

/// Cloneable handle to finish this Stream's response after offload.
///
/// Obtain via [`ServerWriter::response_handle`]. Framing and flush stay inside
/// the transport's [`ResponseControl`] implementation.
#[derive(Clone)]
pub struct ServerResponseHandle {
    conn: ConnHandle,
    control: Arc<dyn ResponseControl>,
}

impl ServerResponseHandle {
    pub(crate) fn new(control: Arc<dyn ResponseControl>) -> Self {
        let conn = control.conn_handle();
        Self { conn, control }
    }

    /// Connection handle for [`hopf_core::StorageExecutor`] / reactor hops.
    pub fn conn_handle(&self) -> &ConnHandle {
        &self.conn
    }

    /// Run `f` on the owning reactor with a live [`ServerWriter`] for this Stream.
    pub fn execute(&self, f: impl FnOnce(&mut dyn ServerWriter) + Send + 'static) {
        self.control.execute(Box::new(f));
    }

    /// Stop delivering request-body events for this Stream.
    pub fn pause_request_body(&self) {
        self.control.pause_request_body();
    }

    /// Resume after [`pause_request_body`](Self::pause_request_body).
    pub fn resume_request_body(&self) {
        self.control.resume_request_body();
    }
}

/// Handler that takes over a connection (H1) or stream (H2/H3) after a
/// successful protocol upgrade / Extended CONNECT.
///
/// HTTP framing stops delivering request/response events for the upgraded
/// resource; subsequent bytes (raw on H1, DATA payloads on H2/H3) are passed
/// to [`receive`](Self::receive). Outbound bytes from [`take_outbound`](Self::take_outbound)
/// are written by the transport.
pub trait ProtocolUpgradeHandler: Send {
    /// Inbound application bytes after the upgrade.
    fn receive(&mut self, data: &[u8]);

    /// Drain bytes queued for the peer since the last flush.
    fn take_outbound(&mut self) -> Vec<u8>;

    /// Peer closed the transport / stream.
    fn closed(&mut self) {}

    /// When `true`, the HTTP transport should tear down after flushing any
    /// remaining [`take_outbound`](Self::take_outbound) bytes (H1: close the
    /// connection; H2/H3: end the stream). Default: keep the transport open.
    fn wants_close(&self) -> bool {
        false
    }
}

/// Outbound response writer for the current server Stream.
pub trait ServerWriter {
    /// Send a 1xx informational response.
    fn send_informational(&mut self, _code: u16, _headers: &Headers) {}

    /// Buffer response headers (flushed on [`start_response_body`] or [`complete`]).
    fn headers(&mut self, headers: Headers);

    /// Flush response headers and begin the body.
    fn start_response_body(&mut self);

    /// Write response body bytes (auto-chunked when applicable).
    fn response_body_content(&mut self, data: &[u8]);

    /// Finish the response body (sends final chunk if chunked).
    fn end_response_body(&mut self);

    /// Buffer trailer headers sent after the response body (H2/H3).
    ///
    /// On HTTP/2 this becomes a second HEADERS frame with `END_STREAM`.
    /// On HTTP/3 this is a second HEADERS frame before stream FIN.
    /// HTTP/1.1 ignores trailers (same gap as Gumdrop). Call after body
    /// bytes and before or with [`complete`](Self::complete).
    fn trailers(&mut self, _headers: Headers) {}

    /// Complete the response (flushes headers if body was never started).
    fn complete(&mut self);

    /// Switch this connection (H1) or stream (H2/H3) to an upgraded byte protocol.
    ///
    /// For HTTP/1.1 WebSocket this typically sends a **101** response then hands
    /// subsequent connection bytes to `handler`. For HTTP/2 and HTTP/3 Extended
    /// CONNECT it sends **200** and routes stream DATA payloads to `handler`.
    ///
    /// Returns `false` if the transport cannot upgrade (already responded, wrong
    /// version, etc.).
    fn upgrade(&mut self, _headers: Headers, _handler: Box<dyn ProtocolUpgradeHandler>) -> bool {
        false
    }

    /// W3C `traceparent` for the active request span, when tracing is enabled.
    ///
    /// Pass to an outbound HTTP client (for example
    /// `hopf_otel::with_traceparent`) so the distributed trace continues.
    /// Default: none.
    fn traceparent(&self) -> Option<&str> {
        None
    }

    /// Connection handle for storage / reactor hops (never transport-typed).
    fn conn_handle(&self) -> ConnHandle;

    /// Remote/local addresses and TLS metadata for the current connection
    /// (Gumdrop `getRemoteAddress`/`getLocalAddress`/`isSecure`/`getSecurityInfo`).
    /// Default: unknown/plaintext — transports that don't track this yet fall
    /// back rather than panic.
    fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo::default()
    }

    /// Cloneable handle to finish this Stream's response after offload.
    fn response_handle(&self) -> ServerResponseHandle;

    /// Stop delivering request-body events for this Stream.
    fn pause_request_body(&mut self);

    /// Resume after [`pause_request_body`](Self::pause_request_body).
    fn resume_request_body(&mut self);
}

impl ServerHandler for Box<dyn ServerHandler> {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        (**self).headers(response, headers);
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        (**self).start_request_body(response);
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        (**self).request_body_content(response, data);
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        (**self).end_request_body(response);
    }

    fn request_trailers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        (**self).request_trailers(response, headers);
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        (**self).request_complete(response);
    }
}
