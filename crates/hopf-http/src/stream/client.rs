// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Client (send-request / receive-response) face of an [`super::HttpStream`].
//!
//! Peer of [`super::server`] — not a delayed add-on.

use crate::headers::Headers;

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
