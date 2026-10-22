// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client (send-request / receive-response) face of an [`super::HttpStream`].
//!
//! Peer of [`super::server`] — not a delayed add-on.

use std::sync::Arc;

use hopf_core::ConnHandle;

use crate::headers::Headers;
use crate::version::HttpVersion;
use super::server::ProtocolUpgradeHandler;

/// Factory that creates a client handler per outbound Stream.
pub trait ClientHandlerFactory: Send + Sync {
    /// Create a handler for the next outbound request Stream.
    fn create_handler(&self) -> Box<dyn ClientHandler>;
}

/// Drives one outbound HTTP request and receives the response.
///
/// Typical sequence: write request via [`ClientWriter`] in [`start`], then
/// [`response_headers`] → body* → [`response_complete`].
pub trait ClientHandler: Send {
    /// Stream is ready; send the request (headers ± body) via `request`.
    fn start(&mut self, request: &mut dyn ClientWriter);

    /// An interim 1xx response arrived (e.g. `100 Continue`, `103 Early
    /// Hints`). Never terminal — the real final response still follows on
    /// the same request via [`response_headers`](Self::response_headers).
    /// Default: ignore.
    fn informational_response(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {}

    /// `101 Switching Protocols` arrived (e.g. h2c Upgrade, RFC 7540 §3.2).
    /// Unlike other 1xx statuses this ends HTTP/1.1 framing on the
    /// connection — bytes after this point belong to the new protocol, not
    /// another HTTP response. Neither [`Self::response_headers`] nor
    /// [`Self::response_complete`] fires afterward for this request.
    /// Default: ignore.
    fn switching_protocols(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {}

    /// Response headers are complete (including `:status`).
    fn response_headers(&mut self, request: &mut dyn ClientWriter, headers: &Headers);

    /// First response body byte.
    fn start_response_body(&mut self, _request: &mut dyn ClientWriter) {}

    /// Response body chunk.
    fn response_body_content(&mut self, _request: &mut dyn ClientWriter, _data: &[u8]) {}

    /// Response body finished.
    fn end_response_body(&mut self, _request: &mut dyn ClientWriter) {}

    /// Trailer headers after the response body (H2/H3 second HEADERS).
    ///
    /// Default: ignore. gRPC clients use this for `grpc-status` /
    /// `grpc-message`.
    fn response_trailers(&mut self, _request: &mut dyn ClientWriter, _headers: &Headers) {}

    /// Response fully received.
    fn response_complete(&mut self, request: &mut dyn ClientWriter);

    /// The connection failed or was closed before the response completed
    /// (e.g. a peer GOAWAY that never reached this stream, or a transport
    /// error). Mutually exclusive with [`Self::response_complete`] — at
    /// most one of the two fires per request. Default: ignore.
    fn request_failed(&mut self, _request: &mut dyn ClientWriter, _err: &std::io::Error) {}

    /// Whether this request accepts HTTP Datagrams (RFC 9297). Default: no.
    fn wants_datagrams(&self) -> bool {
        false
    }

    /// An HTTP Datagram associated with this request (H3 demux or DATAGRAM
    /// capsule). Only called when [`wants_datagrams`](Self::wants_datagrams)
    /// is true.
    fn datagram_received(&mut self, _data: &[u8]) {}
}

/// Outbound request writer / in-flight control for a client Stream.
pub trait ClientWriter {
    /// Buffer request headers (pseudo-headers `:method`, `:path`, …).
    fn headers(&mut self, headers: Headers);

    /// Flush request headers and begin the body (or end if no body).
    fn start_request_body(&mut self);

    /// Write request body bytes.
    fn request_body_content(&mut self, data: &[u8]);

    /// Finish the request body.
    fn end_request_body(&mut self);

    /// Buffer trailer headers sent after the request body (H3; H2 when wired).
    ///
    /// On HTTP/3 this becomes a second HEADERS frame before stream FIN
    /// (RFC 9114 §4.1). HTTP/1.1 ignores outbound trailers (same gap as
    /// inbound H1 trailers). Call after body bytes (if any) and before or
    /// with [`complete_request`](Self::complete_request).
    ///
    /// Default: ignore.
    fn trailers(&mut self, _headers: Headers) {}

    /// Finish the request (flushes headers if body was never started).
    fn complete_request(&mut self);

    /// Switch this connection (H1) or stream (H2/H3) to an upgraded byte
    /// protocol, once the server has accepted — a `101` on H1, or a `2xx`
    /// Extended-CONNECT response on H2/H3. Call from within
    /// [`ClientHandler::switching_protocols`], the same place
    /// [`ServerWriter::upgrade`](super::ServerWriter::upgrade) is called
    /// from on the server side.
    ///
    /// Every upgrade-seeking client (WebSocket, and protocols layered on
    /// HTTP Datagrams/Capsules) should install its handler here rather than
    /// negotiating its own transport — this is the one mechanism shared
    /// across HTTP versions, so the caller never has to know or care which
    /// of h1/h2/h3 the connection ended up using.
    ///
    /// Returns `false` if an upgrade handler was already installed for this
    /// request, or the transport doesn't support installing one at this
    /// point (e.g. called outside `switching_protocols`).
    fn upgrade(&mut self, _handler: Box<dyn ProtocolUpgradeHandler>) -> bool {
        false
    }

    /// The negotiated transport this stream is actually running on.
    ///
    /// Most requests don't need this — the point of [`ClientHandler`] is
    /// that a plain request looks the same regardless of h1/h2/h3. A
    /// protocol upgrade can genuinely need it, though: unlike a plain
    /// request, the *shape* of an upgrade request differs by transport
    /// (an HTTP/1.1 `Upgrade:` header vs. an HTTP/2 or HTTP/3 Extended
    /// CONNECT's `:protocol` pseudo-header, RFC 9220), so
    /// [`ClientHandler::start`] needs to know which one it's building —
    /// checked once, from [`Self::headers`] before anything is sent, not
    /// something that changes mid-stream.
    fn version(&self) -> HttpVersion;

    /// A handle to this request's underlying connection, usable from any
    /// thread — the client-side counterpart of
    /// [`ServerWriter::conn_handle`](super::ServerWriter::conn_handle).
    ///
    /// Wakes the connection from off-thread work: an upgrade handler that
    /// queues outbound datagrams (call from [`ClientHandler::switching_protocols`]),
    /// or a layered client such as gRPC that schedules a local call deadline
    /// when the request starts. Plain requests that finish entirely inside
    /// [`ClientHandler`] callbacks do not need it.
    fn conn_handle(&self) -> ConnHandle;

    /// A handle to write more of this request later, from any thread: the
    /// client-side counterpart of
    /// [`ServerWriter::response_handle`](super::ServerWriter::response_handle).
    /// Call it from [`ClientHandler::start`] and keep the result; a task
    /// given to [`ClientRequestHandle::execute`] runs on the connection's
    /// thread with a writer for this request. HTTP/2 and HTTP/3 support
    /// writing the body in pieces this way (a client-streaming gRPC call,
    /// say); on HTTP/1.1 the handle discards what is written.
    fn request_handle(&self) -> ClientRequestHandle {
        ClientRequestHandle::detached(self.conn_handle(), self.version())
    }

    /// Abandon the request: on HTTP/2 a `RST_STREAM(CANCEL)`, on HTTP/3 a
    /// stream reset. No further callbacks reach the [`ClientHandler`].
    /// Default: no effect.
    fn cancel(&mut self) {}
}

/// A deferred write to a request: what [`ClientRequestHandle::execute`]
/// runs, with a writer for the request.
pub type ClientWriterTask = Box<dyn FnOnce(&mut dyn ClientWriter) + Send>;

/// Cloneable handle to write more of a request after
/// [`ClientHandler::start`], from any thread; see
/// [`ClientWriter::request_handle`].
#[derive(Clone)]
pub struct ClientRequestHandle {
    conn: ConnHandle,
    run: Arc<dyn Fn(ClientWriterTask) + Send + Sync>,
}

impl ClientRequestHandle {
    /// A handle whose tasks `run` carries out; transports build theirs
    /// this way, and so can a test that wants to see what is written.
    pub fn from_runner(conn: ConnHandle, run: Arc<dyn Fn(ClientWriterTask) + Send + Sync>) -> Self {
        Self { conn, run }
    }

    /// A handle bound to no request: tasks run on `conn` against a writer
    /// that discards everything.
    pub fn detached(conn: ConnHandle, version: HttpVersion) -> Self {
        let runner_conn = conn.clone();
        Self::from_runner(
            conn,
            Arc::new(move |task: ClientWriterTask| {
                let conn = runner_conn.clone();
                runner_conn.execute(Box::new(move || {
                    let mut writer = DiscardingClientWriter { conn, version };
                    task(&mut writer);
                }));
            }),
        )
    }

    /// Connection handle for reactor hops.
    pub fn conn_handle(&self) -> &ConnHandle {
        &self.conn
    }

    /// Run `f` on the connection's thread with a writer for the request.
    pub fn execute(&self, f: impl FnOnce(&mut dyn ClientWriter) + Send + 'static) {
        (self.run)(Box::new(f));
    }
}

/// A [`ClientWriter`] that accepts and discards everything.
pub struct DiscardingClientWriter {
    conn: ConnHandle,
    version: HttpVersion,
}

impl ClientWriter for DiscardingClientWriter {
    fn headers(&mut self, _headers: Headers) {}
    fn start_request_body(&mut self) {}
    fn request_body_content(&mut self, _data: &[u8]) {}
    fn end_request_body(&mut self) {}
    fn complete_request(&mut self) {}
    fn version(&self) -> HttpVersion {
        self.version
    }
    fn conn_handle(&self) -> ConnHandle {
        self.conn.clone()
    }
}

impl ClientHandler for Box<dyn ClientHandler> {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        (**self).start(request);
    }

    fn informational_response(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        (**self).informational_response(request, headers);
    }

    fn switching_protocols(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        (**self).switching_protocols(request, headers);
    }

    fn response_headers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        (**self).response_headers(request, headers);
    }

    fn start_response_body(&mut self, request: &mut dyn ClientWriter) {
        (**self).start_response_body(request);
    }

    fn response_body_content(&mut self, request: &mut dyn ClientWriter, data: &[u8]) {
        (**self).response_body_content(request, data);
    }

    fn end_response_body(&mut self, request: &mut dyn ClientWriter) {
        (**self).end_response_body(request);
    }

    fn response_trailers(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        (**self).response_trailers(request, headers);
    }

    fn response_complete(&mut self, request: &mut dyn ClientWriter) {
        (**self).response_complete(request);
    }

    fn request_failed(&mut self, request: &mut dyn ClientWriter, err: &std::io::Error) {
        (**self).request_failed(request, err);
    }

    fn wants_datagrams(&self) -> bool {
        (**self).wants_datagrams()
    }

    fn datagram_received(&mut self, data: &[u8]) {
        (**self).datagram_received(data);
    }
}
