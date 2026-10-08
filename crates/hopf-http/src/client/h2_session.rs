// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 [`HttpRequest`] session adapter.
//!
//! Several bodyless requests may be in flight at once (each on its own
//! stream, opened in the order they were accepted, as the peer's
//! `SETTINGS_MAX_CONCURRENT_STREAMS` allows); a request *body* is streamed
//! for one request at a time, since [`HttpRequest::request_body_content`]
//! carries no request id.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler, TimerHandle};

use crate::client::api::{
    HttpClientError, HttpClientSessionHandle, HttpResponseHandler,
    SessionRequestOps,
};
use crate::h2::H2Endpoint;
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{ClientHandler, ClientHandlerFactory, ClientWriter};
use crate::version::HttpVersion;

use super::session_config::HttpClientSessionConfig;

/// Soft cap on bytes buffered in a job's `pending_body` between flushes —
/// mirrors `h1::session_client_codec::MAX_UNFLUSHED_BODY`'s rationale, just
/// split across two smaller caps here (see [`MAX_STREAM_BACKLOG`] for the
/// other half): `request_body_content` short-writes once this is reached
/// instead of growing unboundedly while the producer outruns the reactor's
/// chance to actually drain it (e.g. a cross-connection producer that never
/// gives this connection an I/O event of its own — see
/// [`hopf_core::ConnHandle::poke`]).
const MAX_PENDING_JOB_BODY: usize = 128 * 1024;

/// Soft cap on bytes queued in the underlying [`H2Endpoint`] client
/// stream's flow-control backlog (`H2ClientStream::pending_body`) before
/// [`H2HttpClientSession::flush_session`] stops handing it more bytes from
/// the open body job. Bounds memory when the peer's flow-control window
/// stays closed for a while, independent of [`MAX_PENDING_JOB_BODY`].
const MAX_STREAM_BACKLOG: usize = 128 * 1024;

/// A request accepted by `send`/`start_request_body` whose stream has not
/// opened yet.
struct OutboundJob {
    method: String,
    path: String,
    headers: Headers,
    /// Taken by [`H2HttpClientSession::flush_session`] the moment the
    /// stream opens — ownership then moves to the [`H2StreamHandler`]
    /// stored inside [`H2Endpoint`]'s client-stream table.
    handler: Option<Box<dyn HttpResponseHandler>>,
    /// `true` for a `start_request_body` request: its bytes arrive through
    /// `body_content` until `end_body`.
    has_body: bool,
    /// Body bytes accepted by `request_body_content` while the stream was
    /// still unopened.
    pending_body: Vec<u8>,
    body_complete: bool,
}

/// The body-streaming request once its stream is open: bytes still arrive
/// through `body_content` and drain into the stream as flow control allows.
struct OpenBody {
    stream_id: u32,
    pending_body: Vec<u8>,
    body_complete: bool,
    /// Whether end-of-stream has already been handed to the H2 stream —
    /// set at most once.
    end_sent: bool,
}

struct H2SessionShared {
    config: Arc<HttpClientSessionConfig>,
    /// Requests accepted but not yet opened as streams, oldest first.
    queue: VecDeque<OutboundJob>,
    /// The body-streaming request whose stream is open (see [`OpenBody`]).
    open_body: Option<OpenBody>,
    /// Streams opened and not yet complete (or failed).
    open_streams: usize,
    /// Set by `enqueue`/`body_content`/`end_body` whenever there's new work
    /// for [`H2HttpClientSession::flush_session`] to do.
    dirty: bool,
    /// One-shot resume signal for a short write from `body_content` — see
    /// [`H2HttpClientSession::maybe_fire_writable_callback`].
    writable_callback: Option<Box<dyn FnOnce() + Send>>,
    /// Bumped by `enqueue` on every new request — lets a stage-timer fire
    /// captured for an *earlier* request recognize it's stale instead of
    /// mistakenly timing out whatever request is in flight now. See
    /// [`H2HttpClientSession::arm_stage_timer_if_in_flight`].
    generation: u64,
}

impl H2SessionShared {
    fn new(config: Arc<HttpClientSessionConfig>) -> Self {
        Self {
            config,
            queue: VecDeque::new(),
            open_body: None,
            open_streams: 0,
            dirty: false,
            writable_callback: None,
            generation: 0,
        }
    }

    fn authority(&self) -> String {
        let default_port = if self.config.secure { 443 } else { 80 };
        if self.config.port == default_port {
            self.config.host.clone()
        } else {
            format!("{}:{}", self.config.host, self.config.port)
        }
    }

    /// Any request accepted and not yet answered.
    fn in_flight(&self) -> bool {
        self.open_streams > 0 || !self.queue.is_empty()
    }

    /// The still-unopened request whose body is being streamed, if any.
    fn queued_body_job(&mut self) -> Option<&mut OutboundJob> {
        self.queue.iter_mut().find(|j| j.has_body && !j.body_complete)
    }

    /// Whether a request body is still being streamed (its `end_body` has
    /// not been called yet), queued or open.
    fn body_streaming(&self) -> bool {
        self.queue.iter().any(|j| j.has_body && !j.body_complete)
            || self.open_body.as_ref().map(|b| !b.body_complete).unwrap_or(false)
    }
}

struct H2SessionFactory {
    shared: Arc<Mutex<H2SessionShared>>,
}

impl ClientHandlerFactory for H2SessionFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(H2StreamHandler {
            shared: Arc::clone(&self.shared),
            response: None,
        })
    }
}

struct H2StreamHandler {
    shared: Arc<Mutex<H2SessionShared>>,
    response: Option<Box<dyn HttpResponseHandler>>,
}

impl H2StreamHandler {
    fn with_response<R>(&mut self, f: impl FnOnce(&mut dyn HttpResponseHandler) -> R) -> R {
        let mut h = self.response.take().expect("response handler");
        let r = f(&mut *h);
        self.response = Some(h);
        r
    }

    fn stream_finished(&self) {
        let mut g = self.shared.lock().unwrap();
        g.open_streams = g.open_streams.saturating_sub(1);
    }
}

impl ClientHandler for H2StreamHandler {
    fn start(&mut self, _request: &mut dyn ClientWriter) {
        // The Gumdrop session API never reaches this: it opens streams via
        // `H2Endpoint::open_client_stream` directly (see
        // `H2HttpClientSession::flush_session`), constructing this handler
        // with `response` already populated. `factory.create_handler()` +
        // `ClientHandler::start` is only reached via
        // `H2Endpoint::start_client_request`, used by the lower-level
        // auto-kickoff `ClientHandler` SPI, not this session adapter.
        unreachable!(
            "H2StreamHandler is only ever constructed pre-started by the Gumdrop H2 session path"
        );
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        let status = headers.status_code();
        self.with_response(|h| {
            if (200..300).contains(&status) {
                h.ok(status);
            } else {
                h.error(status);
            }
            for field in headers.iter() {
                if field.name.starts_with(':') {
                    continue;
                }
                h.header(&field.name, &field.value);
            }
        });
    }

    fn start_response_body(&mut self, _request: &mut dyn ClientWriter) {
        self.with_response(|h| h.start_response_body());
    }

    fn response_body_content(&mut self, _request: &mut dyn ClientWriter, data: &[u8]) {
        self.with_response(|h| h.response_body_content(data));
    }

    fn end_response_body(&mut self, _request: &mut dyn ClientWriter) {
        self.with_response(|h| h.end_response_body());
    }

    fn response_trailers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        self.with_response(|h| h.response_trailers(headers));
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
        // Count the stream as finished *before* calling out to the app's
        // `close()` -- a caller chaining a follow-up request from inside
        // `close()` (an ordinary pattern for sequential session use) must
        // see the session as idle by then, not still busy with the very
        // request that just finished.
        self.stream_finished();
        self.with_response(|h| h.close());
    }

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &io::Error) {
        self.stream_finished();
        if let Some(mut h) = self.response.take() {
            h.failed(io::Error::new(err.kind(), err.to_string()));
        }
    }
}

struct OpsBridge(Arc<Mutex<H2SessionShared>>);

impl SessionRequestOps for OpsBridge {
    fn is_open(&self) -> bool {
        true
    }

    fn send_no_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        self.enqueue(method, path, headers, handler, false)
    }

    fn start_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        self.enqueue(method, path, headers, handler, true)
    }

    fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
        let mut g = self.0.lock().unwrap();
        let pending: &mut Vec<u8> = if let Some(job) = g.queued_body_job() {
            &mut job.pending_body
        } else {
            match g.open_body.as_mut() {
                Some(b) if !b.body_complete => &mut b.pending_body,
                Some(_) => return Err(HttpClientError::new("request body already ended")),
                None => return Err(HttpClientError::new("must call start_request_body first")),
            }
        };
        let available = MAX_PENDING_JOB_BODY.saturating_sub(pending.len());
        let accept = data.len().min(available);
        pending.extend_from_slice(&data[..accept]);
        g.dirty = true;
        Ok(accept)
    }

    fn end_body(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if let Some(job) = g.queued_body_job() {
            job.body_complete = true;
        } else {
            match g.open_body.as_mut() {
                Some(b) if !b.body_complete => b.body_complete = true,
                Some(_) => return Err(HttpClientError::new("request body already ended")),
                None => return Err(HttpClientError::new("must call start_request_body first")),
            }
        }
        g.dirty = true;
        Ok(())
    }

    fn cancel_request(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        // The most recently accepted request that hasn't opened yet is the
        // one a caller can still take back. Once open, the handler has
        // moved into the `H2Endpoint`'s client-stream table and this is
        // best-effort bookkeeping only: it can't reach in to abort the
        // peer-visible stream (no RST_STREAM support here — matches this
        // framework's stated scope).
        if let Some(job) = g.queue.pop_back() {
            if let Some(mut h) = job.handler {
                h.failed(io::Error::new(io::ErrorKind::Interrupted, "request cancelled"));
            }
        } else {
            g.open_body = None;
        }
        Ok(())
    }

    fn on_body_writable(&mut self, cb: Box<dyn FnOnce() + Send>) {
        let mut g = self.0.lock().unwrap();
        g.writable_callback = Some(cb);
        // The queue may already have drained between the short write and
        // this registration; marking the session dirty makes the next
        // `receive()`/poke re-check for room instead of waiting for I/O
        // that an idle connection never gets.
        g.dirty = true;
    }
}

impl OpsBridge {
    fn enqueue(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
        has_body: bool,
    ) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if has_body && g.body_streaming() {
            return Err(HttpClientError::new("request body already in flight"));
        }
        g.generation = g.generation.wrapping_add(1);
        g.queue.push_back(OutboundJob {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            handler: Some(handler),
            has_body,
            pending_body: Vec::new(),
            body_complete: !has_body,
        });
        g.dirty = true;
        Ok(())
    }
}

/// H2 client connection exposing the Gumdrop session API.
pub(crate) struct H2HttpClientSession {
    inner: H2Endpoint,
    shared: Arc<Mutex<H2SessionShared>>,
    connected_notified: bool,
    stage_timer: Option<TimerHandle>,
}

impl H2HttpClientSession {
    pub fn new(config: Arc<HttpClientSessionConfig>, limits: HttpLimits, secure: bool) -> Self {
        let shared = Arc::new(Mutex::new(H2SessionShared::new(Arc::clone(&config))));
        let factory = Arc::new(H2SessionFactory {
            shared: Arc::clone(&shared),
        });
        Self {
            inner: H2Endpoint::client_session(factory, limits, secure),
            shared,
            connected_notified: false,
            stage_timer: None,
        }
    }

    fn cancel_stage_timer(&mut self) {
        if let Some(t) = self.stage_timer.take() {
            t.cancel();
        }
    }

    /// (Re)arm the [`crate::HttpClientTimeouts::stage`] timer if a request
    /// is in flight — call on every outbound or inbound sign of life so a
    /// still-progressing request doesn't spuriously time out. The fire
    /// callback double-checks `in_flight`/`generation` before failing the
    /// connection, since (unlike the H1 session) there's no single point
    /// that always sees "this request is now fully done" to cancel from —
    /// see [`H2SessionShared::generation`].
    fn arm_stage_timer_if_in_flight(&mut self, endpoint: &mut dyn Endpoint) {
        self.cancel_stage_timer();
        let (stage, generation, in_flight) = {
            let g = self.shared.lock().unwrap();
            (g.config.stage, g.generation, g.in_flight())
        };
        if !in_flight || stage.is_zero() {
            return;
        }
        let handle = endpoint.handle();
        let shared = Arc::clone(&self.shared);
        let timer = endpoint.schedule_timer(
            stage,
            Box::new(move || {
                let still_current = {
                    let g = shared.lock().unwrap();
                    g.in_flight() && g.generation == generation
                };
                if still_current {
                    handle.with_endpoint(|ep2| {
                        ep2.fail(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP client stage timed out",
                        ));
                    });
                }
            }),
        );
        self.stage_timer = Some(timer);
    }

    fn request_ops(&self) -> Arc<Mutex<dyn SessionRequestOps + Send>> {
        Arc::new(Mutex::new(OpsBridge(Arc::clone(&self.shared))))
    }

    fn maybe_notify_connected(&mut self, endpoint: &mut dyn Endpoint) {
        if self.connected_notified || !self.inner.client_connection_ready() {
            return;
        }
        self.connected_notified = true;
        let handler = self
            .shared
            .lock()
            .unwrap()
            .config
            .handler
            .lock()
            .unwrap()
            .take();
        if let Some(mut h) = handler {
            let mut session = HttpClientSessionHandle::new(
                self.request_ops(),
                HttpVersion::Http2,
                Some(endpoint.handle()),
            );
            h.on_connected(&mut session);
        }
        self.flush_session(endpoint);
        self.arm_stage_timer_if_in_flight(endpoint);
    }

    /// Open a stream for every queued request the connection can take right
    /// now, oldest first, then hand off whatever body bytes are queued for
    /// the open body request (and end-of-stream, once there are none left
    /// to send) — the Gumdrop-session counterpart to
    /// `H2Endpoint::start_client_request`'s one-shot "whole body now" path
    /// used by the lower-level `ClientHandler` SPI.
    ///
    /// Runs on every `receive()`/`connected`/`security_established`/`poke()`
    /// so a producer anywhere (including a stashed
    /// [`hopf_core::ConnHandle`] on another connection) can call
    /// `request_body_content` then poke to get bytes moving without
    /// blocking or busy-polling.
    fn flush_session(&mut self, endpoint: &mut dyn Endpoint) {
        {
            let mut g = self.shared.lock().unwrap();
            if !g.dirty {
                return;
            }
            g.dirty = false;
        }
        if !self.inner.client_connection_ready() {
            self.shared.lock().unwrap().dirty = true;
            return;
        }

        // 1. Open queued streams in order.
        loop {
            let (headers, handler, bodyless, has_body) = {
                let mut g = self.shared.lock().unwrap();
                let Some(job) = g.queue.front() else { break };
                // A second body request waits until the first body has
                // been handed over entirely: body bytes target one open
                // stream at a time.
                if job.has_body && g.open_body.is_some() {
                    g.dirty = true;
                    break;
                }
                if !self.inner.can_open_client_stream() {
                    // Peer's MAX_CONCURRENT_STREAMS exhausted (or not ready
                    // yet) — retry on a later receive()/poke.
                    g.dirty = true;
                    break;
                }
                let scheme = if g.config.secure { "https" } else { "http" };
                let authority = g.authority();
                let job = g.queue.front_mut().expect("checked above");
                let mut h = Headers::new();
                h.set(":method", &job.method);
                h.set(":path", &job.path);
                h.set(":scheme", scheme);
                h.set(":authority", &authority);
                for field in job.headers.iter() {
                    if field.name.starts_with(':') {
                        continue;
                    }
                    h.add(field.name.clone(), field.value.clone());
                }
                let handler = job.handler.take().expect("handler present until stream opens");
                let bodyless = job.body_complete && job.pending_body.is_empty();
                (h, handler, bodyless, job.has_body)
            };
            let stream_handler: Box<dyn ClientHandler> = Box::new(H2StreamHandler {
                shared: Arc::clone(&self.shared),
                response: Some(handler),
            });
            let Some(stream_id) =
                self.inner.open_client_stream(headers, stream_handler, bodyless, endpoint)
            else {
                // `can_open_client_stream` said yes a moment ago; nothing
                // else runs between on this thread, so this is unreachable
                // in practice — but never lose the request silently.
                let mut g = self.shared.lock().unwrap();
                let job = g.queue.pop_front().expect("front job still queued");
                drop(g);
                let _ = job;
                break;
            };
            let mut g = self.shared.lock().unwrap();
            let job = g.queue.pop_front().expect("front job still queued");
            g.open_streams += 1;
            if has_body && !bodyless {
                g.open_body = Some(OpenBody {
                    stream_id,
                    pending_body: job.pending_body,
                    body_complete: job.body_complete,
                    end_sent: false,
                });
            }
        }

        // 2. Drain the open body request into its stream.
        let open = self.shared.lock().unwrap().open_body.as_ref().map(|b| b.stream_id);
        if let Some(stream_id) = open {
            if self.inner.client_stream_pending_len(stream_id) >= MAX_STREAM_BACKLOG {
                // Still catching up on flow control; `receive()` already
                // retries `flush_client_streams()` on every call (e.g. once
                // a WINDOW_UPDATE arrives), and this flag brings us back
                // here too once more of `pending_body` might fit.
                self.shared.lock().unwrap().dirty = true;
            } else {
                let (bytes, end_now, fully_done) = {
                    let mut g = self.shared.lock().unwrap();
                    let b = g.open_body.as_mut().expect("checked above");
                    let bytes = std::mem::take(&mut b.pending_body);
                    let end_now = b.body_complete && !b.end_sent;
                    if end_now {
                        b.end_sent = true;
                    }
                    (bytes, end_now, b.end_sent)
                };
                if !bytes.is_empty() || end_now {
                    self.inner.feed_client_stream_body(stream_id, &bytes, end_now, endpoint);
                }
                if fully_done {
                    let mut g = self.shared.lock().unwrap();
                    g.open_body = None;
                    // A body request queued behind this one may open now.
                    if g.queue.iter().any(|j| j.has_body) {
                        g.dirty = true;
                    }
                }
            }
        }
        self.maybe_fire_writable_callback();
    }

    /// Fire the one-shot `on_body_writable` callback, if any, once there's
    /// room again in both the pre-stream job queue and (if the stream is
    /// already open) the `H2Endpoint`-level flow-control backlog.
    fn maybe_fire_writable_callback(&mut self) {
        let cb = {
            let mut g = self.shared.lock().unwrap();
            if g.writable_callback.is_none() {
                return;
            }
            let job_has_room = match g.queued_body_job() {
                Some(j) => j.pending_body.len() < MAX_PENDING_JOB_BODY,
                None => g
                    .open_body
                    .as_ref()
                    .map(|b| b.pending_body.len() < MAX_PENDING_JOB_BODY)
                    .unwrap_or(true),
            };
            let stream_has_room = match g.open_body.as_ref().map(|b| b.stream_id) {
                Some(id) => self.inner.client_stream_pending_len(id) < MAX_STREAM_BACKLOG,
                None => true,
            };
            if job_has_room && stream_has_room {
                g.writable_callback.take()
            } else {
                None
            }
        };
        if let Some(cb) = cb {
            cb();
        }
    }

    /// A transport-level failure reached this connection — notify whoever
    /// can still hear about it, mirroring
    /// `h1::session_client_codec::H1SessionInner::fail_transport`: if
    /// `on_connected` hasn't fired yet, the stashed
    /// [`crate::HttpConnectionHandler`] gets `on_error`; otherwise, every
    /// queued request whose stream hasn't opened yet (still holding its
    /// response handler directly) gets `failed()`. Requests whose streams
    /// *have* opened are handled separately by
    /// `H2Endpoint::fail_client_streams`, called from
    /// `self.inner.error`/`disconnected` right after this.
    fn fail_transport(&mut self, err: io::Error) {
        if !self.connected_notified {
            let taken = self.shared.lock().unwrap().config.handler.lock().unwrap().take();
            if let Some(mut h) = taken {
                h.on_error(&err);
            }
            return;
        }
        let queued: Vec<Box<dyn HttpResponseHandler>> = {
            let mut g = self.shared.lock().unwrap();
            g.queue.drain(..).filter_map(|j| j.handler).collect()
        };
        for mut h in queued {
            h.failed(io::Error::new(err.kind(), err.to_string()));
        }
    }

    fn forward_outbound(&mut self, endpoint: &mut dyn Endpoint) {
        let out = self.inner.take_outbound();
        if !out.is_empty() {
            endpoint.send(&out);
        }
    }
}

impl ProtocolHandler for H2HttpClientSession {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        self.inner.connected(endpoint);
        self.forward_outbound(endpoint);
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &hopf_core::SecurityInfo) {
        // Forward to the stashed HttpConnectionHandler without consuming it —
        // `maybe_notify_connected` below still needs to `take()` it.
        {
            let g = self.shared.lock().unwrap();
            let mut handler = g.config.handler.lock().unwrap();
            if let Some(h) = handler.as_mut() {
                h.on_security_established(info);
            }
        }
        self.inner.security_established(endpoint, info);
        self.forward_outbound(endpoint);
        self.maybe_notify_connected(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.inner.receive(endpoint, data);
        self.maybe_notify_connected(endpoint);
        self.flush_session(endpoint);
        // Inbound frames (a WINDOW_UPDATE above all) can free room in the
        // stream backlog without this session having any new work of its
        // own, so the short-write resume signal is checked on every
        // receive, not only when `flush_session` had something to do.
        self.maybe_fire_writable_callback();
        self.arm_stage_timer_if_in_flight(endpoint);
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        self.cancel_stage_timer();
        self.fail_transport(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
        self.inner.disconnected(endpoint);
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.cancel_stage_timer();
        self.fail_transport(io::Error::new(err.kind(), err.to_string()));
        self.inner.error(endpoint, err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct NullHandler;
    impl HttpResponseHandler for NullHandler {
        fn ok(&mut self, _status: u16) {}
        fn error(&mut self, _status: u16) {}
        fn header(&mut self, _name: &str, _value: &str) {}
        fn response_body_content(&mut self, _data: &[u8]) {}
        fn close(&mut self) {}
        fn failed(&mut self, _err: io::Error) {}
    }

    fn session() -> H2HttpClientSession {
        let config = Arc::new(HttpClientSessionConfig {
            host: "ex.com".into(),
            port: 80,
            limits: HttpLimits::default(),
            secure: false,
            handler: Mutex::new(None),
            stage: std::time::Duration::ZERO,
        });
        H2HttpClientSession::new(config, HttpLimits::default(), false)
    }

    /// `request_body_content` short-writes rather than growing
    /// `OutboundJob::pending_body` past its cap — issue #85's "does not
    /// silently accept unbounded bytes" acceptance criterion.
    #[test]
    fn body_content_short_writes_past_the_pending_job_cap() {
        let session = session();
        let ops = session.request_ops();
        ops.lock()
            .unwrap()
            .start_body("PUT", "/upload", Headers::new(), Box::new(NullHandler))
            .unwrap();

        let big = vec![b'x'; MAX_PENDING_JOB_BODY + 1000];
        let accepted = ops.lock().unwrap().body_content(&big).unwrap();
        assert!(
            accepted < big.len() && accepted > 0,
            "expected a short write, got {accepted} of {}",
            big.len()
        );
        assert_eq!(
            session.shared.lock().unwrap().queue.front().unwrap().pending_body.len(),
            accepted
        );

        // Full: a further call short-writes to zero.
        let accepted2 = ops.lock().unwrap().body_content(b"more").unwrap();
        assert_eq!(accepted2, 0);
    }

    /// Once room opens up in the pending-job queue (simulating what
    /// `flush_session` does when it drains it into the H2 stream), a
    /// registered `on_body_writable` callback fires — issue #85's "resume
    /// path works" criterion, tested independent of a real H2 connection.
    #[test]
    fn writable_callback_fires_once_pending_job_queue_has_room_again() {
        let mut session = session();
        let ops = session.request_ops();
        ops.lock()
            .unwrap()
            .start_body("PUT", "/upload", Headers::new(), Box::new(NullHandler))
            .unwrap();
        let big = vec![b'x'; MAX_PENDING_JOB_BODY];
        ops.lock().unwrap().body_content(&big).unwrap();

        let resumed = Arc::new(AtomicBool::new(false));
        let resumed2 = Arc::clone(&resumed);
        ops.lock()
            .unwrap()
            .on_body_writable(Box::new(move || resumed2.store(true, Ordering::SeqCst)));

        // Still full: no callback yet.
        session.maybe_fire_writable_callback();
        assert!(!resumed.load(Ordering::SeqCst));

        // Simulate `flush_session` having drained the queue into the H2
        // stream (no real connection needed: no stream is open, so
        // `maybe_fire_writable_callback` only weighs job-queue room).
        session
            .shared
            .lock()
            .unwrap()
            .queue
            .front_mut()
            .unwrap()
            .pending_body
            .clear();

        session.maybe_fire_writable_callback();
        assert!(
            resumed.load(Ordering::SeqCst),
            "writable callback should fire once the pending-job queue has room again"
        );
    }

    /// On HTTP/2 several bodyless requests may be in flight at once: a
    /// second `send` while the first is unanswered is queued, not refused.
    #[test]
    fn bodyless_requests_queue_while_another_is_in_flight() {
        let session = session();
        let ops = session.request_ops();
        ops.lock()
            .unwrap()
            .send_no_body("GET", "/one", Headers::new(), Box::new(NullHandler))
            .unwrap();
        ops.lock()
            .unwrap()
            .send_no_body("GET", "/two", Headers::new(), Box::new(NullHandler))
            .expect("a second bodyless request is queued on an H2 session");
        ops.lock()
            .unwrap()
            .send_no_body("GET", "/three", Headers::new(), Box::new(NullHandler))
            .expect("a third bodyless request is queued on an H2 session");
        assert_eq!(session.shared.lock().unwrap().queue.len(), 3);
    }

    /// Only one request body streams at a time: body bytes have no request
    /// id, so a second body request is refused until the first has ended.
    #[test]
    fn a_second_body_request_is_refused_while_one_streams() {
        let session = session();
        let ops = session.request_ops();
        ops.lock()
            .unwrap()
            .start_body("PUT", "/upload", Headers::new(), Box::new(NullHandler))
            .unwrap();
        let err = ops
            .lock()
            .unwrap()
            .start_body("PUT", "/upload2", Headers::new(), Box::new(NullHandler))
            .unwrap_err();
        assert_eq!(err.to_string(), "request body already in flight");
        // A bodyless request may still join the queue behind it.
        ops.lock()
            .unwrap()
            .send_no_body("GET", "/meanwhile", Headers::new(), Box::new(NullHandler))
            .unwrap();
        // Once the body has ended, another body request is accepted.
        ops.lock().unwrap().end_body().unwrap();
        ops.lock()
            .unwrap()
            .start_body("PUT", "/upload2", Headers::new(), Box::new(NullHandler))
            .unwrap();
    }

    /// Registering the writable callback marks the session dirty, so a poke
    /// after a short write re-checks for room even if the queue drained in
    /// between — otherwise an idle connection would never fire it.
    #[test]
    fn on_body_writable_marks_the_session_dirty() {
        let session = session();
        let ops = session.request_ops();
        ops.lock()
            .unwrap()
            .start_body("PUT", "/upload", Headers::new(), Box::new(NullHandler))
            .unwrap();
        session.shared.lock().unwrap().dirty = false;
        ops.lock().unwrap().on_body_writable(Box::new(|| {}));
        assert!(session.shared.lock().unwrap().dirty);
    }
}
