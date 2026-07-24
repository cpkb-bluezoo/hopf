// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server (receive-request / send-response) face of an [`super::HttpStream`].
//!
//! Peer of [`super::client`] — not a privileged product centre.

use std::sync::Arc;

use hopf_core::ConnHandle;

use crate::headers::Headers;

/// Factory that creates a server handler per HTTP Stream.
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

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        (**self).request_complete(response);
    }
}
