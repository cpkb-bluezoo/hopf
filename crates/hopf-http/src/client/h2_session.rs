// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 [`HttpRequest`] session adapter (multiplexing-ready; one in-flight for now).

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

/// Soft cap on bytes buffered in [`OutboundJob::pending_body`] between
/// flushes — mirrors `h1::session_client_codec::MAX_UNFLUSHED_BODY`'s
/// rationale, just split across two smaller caps here (see
/// [`MAX_STREAM_BACKLOG`] for the other half): `request_body_content`
/// short-writes once this is reached instead of growing unboundedly while
/// the producer outruns the reactor's chance to actually drain it (e.g. a
/// cross-connection producer that never gives this connection an I/O event
/// of its own — see [`hopf_core::ConnHandle::poke`]).
const MAX_PENDING_JOB_BODY: usize = 128 * 1024;

/// Soft cap on bytes queued in the underlying [`H2Endpoint`] client
/// stream's flow-control backlog (`H2ClientStream::pending_body`) before
/// [`H2HttpClientSession::flush_session`] stops handing it more bytes from
/// [`OutboundJob::pending_body`]. Bounds memory when the peer's flow-control
/// window stays closed for a while, independent of [`MAX_PENDING_JOB_BODY`].
const MAX_STREAM_BACKLOG: usize = 128 * 1024;

struct OutboundJob {
    method: String,
    path: String,
    headers: Headers,
    /// Taken by [`H2HttpClientSession::flush_session`] the moment the
    /// stream opens — ownership then moves to the [`H2StreamHandler`]
    /// stored inside [`H2Endpoint`]'s client-stream table.
    handler: Option<Box<dyn HttpResponseHandler>>,
    /// Body bytes accepted by `request_body_content` but not yet handed to
    /// the (possibly not-yet-open) H2 stream.
    pending_body: Vec<u8>,
    body_complete: bool,
    /// Whether end-of-stream has already been handed to the H2 stream
    /// (either on the opening HEADERS frame for a bodyless request, or via
    /// `feed_client_stream_body`) — set at most once per job.
    end_sent: bool,
}

struct H2SessionShared {
    config: Arc<HttpClientSessionConfig>,
    job: Option<OutboundJob>,
    in_flight: bool,
    /// `Some` once HEADERS have been sent for `job` (see
    /// [`H2Endpoint::open_client_stream`]).
    stream_id: Option<u32>,
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
            job: None,
            in_flight: false,
            stream_id: None,
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
        self.with_response(|h| h.close());
        self.shared.lock().unwrap().in_flight = false;
    }

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &io::Error) {
        if let Some(mut h) = self.response.take() {
            h.failed(io::Error::new(err.kind(), err.to_string()));
        }
        self.shared.lock().unwrap().in_flight = false;
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
        self.enqueue(method, path, headers, handler, true)
    }

    fn start_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        self.enqueue(method, path, headers, handler, false)
    }

    fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
        let mut g = self.0.lock().unwrap();
        let Some(job) = g.job.as_mut() else {
            return Err(HttpClientError::new("must call start_request_body first"));
        };
        if job.body_complete {
            return Err(HttpClientError::new("request body already ended"));
        }
        let available = MAX_PENDING_JOB_BODY.saturating_sub(job.pending_body.len());
        let accept = data.len().min(available);
        job.pending_body.extend_from_slice(&data[..accept]);
        g.dirty = true;
        Ok(accept)
    }

    fn end_body(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        let Some(job) = g.job.as_mut() else {
            return Err(HttpClientError::new("must call start_request_body first"));
        };
        job.body_complete = true;
        g.dirty = true;
        Ok(())
    }

    fn cancel_request(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if let Some(job) = g.job.take() {
            // Only reachable before the stream opens (`handler` still
            // `Some`) — once open, the handler has moved into the
            // `H2Endpoint`'s client-stream table and this is best-effort
            // bookkeeping only: it lets a *new* request start, but can't
            // reach in to abort the peer-visible stream (no RST_STREAM
            // support here — matches this framework's stated scope).
            if let Some(mut h) = job.handler {
                h.failed(io::Error::new(io::ErrorKind::Interrupted, "request cancelled"));
            }
        }
        g.in_flight = false;
        g.job = None;
        g.stream_id = None;
        Ok(())
    }

    fn on_body_writable(&mut self, cb: Box<dyn FnOnce() + Send>) {
        self.0.lock().unwrap().writable_callback = Some(cb);
    }
}

impl OpsBridge {
    fn enqueue(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
        body_complete: bool,
    ) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if g.in_flight {
            return Err(HttpClientError::new("request already in flight"));
        }
        g.in_flight = true;
        g.generation = g.generation.wrapping_add(1);
        g.job = Some(OutboundJob {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            handler: Some(handler),
            pending_body: Vec::new(),
            body_complete,
            end_sent: false,
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
            (g.config.stage, g.generation, g.in_flight)
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
                    g.in_flight && g.generation == generation
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

    /// Open the current job's stream if it hasn't been opened yet, then
    /// hand off whatever body bytes are queued (and end-of-stream, once
    /// there are none left to send) — the Gumdrop-session counterpart to
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
            if !g.dirty || g.job.is_none() {
                return;
            }
            g.dirty = false;
        }

        if self.shared.lock().unwrap().stream_id.is_none() {
            if !self.inner.client_connection_ready() {
                self.shared.lock().unwrap().dirty = true;
                return;
            }
            let (headers, handler, bodyless) = {
                let mut g = self.shared.lock().unwrap();
                let scheme = if g.config.secure { "https" } else { "http" };
                let authority = g.authority();
                let job = g.job.as_mut().unwrap();
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
                (h, handler, bodyless)
            };
            let stream_handler: Box<dyn ClientHandler> = Box::new(H2StreamHandler {
                shared: Arc::clone(&self.shared),
                response: Some(handler),
            });
            let Some(stream_id) =
                self.inner.open_client_stream(headers, stream_handler, bodyless, endpoint)
            else {
                // Not ready yet (e.g. peer's MAX_CONCURRENT_STREAMS
                // exhausted) — retry on a later receive()/poke.
                self.shared.lock().unwrap().dirty = true;
                return;
            };
            let mut g = self.shared.lock().unwrap();
            g.stream_id = Some(stream_id);
            if bodyless {
                g.job.as_mut().unwrap().end_sent = true;
            }
        }

        let stream_id = self.shared.lock().unwrap().stream_id.unwrap();
        if self.inner.client_stream_pending_len(stream_id) >= MAX_STREAM_BACKLOG {
            // Still catching up on flow control; `receive()` already retries
            // `flush_client_streams()` on every call (e.g. once a
            // WINDOW_UPDATE arrives), and this flag brings us back here too
            // once more of `pending_body` might fit.
            self.shared.lock().unwrap().dirty = true;
            return;
        }

        let (bytes, end_now, fully_done) = {
            let mut g = self.shared.lock().unwrap();
            let job = g.job.as_mut().unwrap();
            let bytes = std::mem::take(&mut job.pending_body);
            let end_now = job.body_complete && !job.end_sent;
            if end_now {
                job.end_sent = true;
            }
            (bytes, end_now, job.end_sent)
        };
        if !bytes.is_empty() || end_now {
            self.inner.feed_client_stream_body(stream_id, &bytes, end_now, endpoint);
        }
        if fully_done {
            let mut g = self.shared.lock().unwrap();
            g.job = None;
            g.stream_id = None;
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
            let job_has_room = g
                .job
                .as_ref()
                .map(|j| j.pending_body.len() < MAX_PENDING_JOB_BODY)
                .unwrap_or(true);
            let stream_has_room = match g.stream_id {
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
    /// [`crate::HttpConnectionHandler`] gets `on_error`; otherwise, a job
    /// whose stream hasn't opened yet (still holding its response handler
    /// directly) gets `failed()`. A job whose stream *has* opened is
    /// handled separately by `H2Endpoint::fail_client_streams`, called from
    /// `self.inner.error`/`disconnected` right after this.
    fn fail_transport(&mut self, err: io::Error) {
        if !self.connected_notified {
            let taken = self.shared.lock().unwrap().config.handler.lock().unwrap().take();
            if let Some(mut h) = taken {
                h.on_error(&err);
            }
            return;
        }
        let taken = {
            let mut g = self.shared.lock().unwrap();
            g.job.as_mut().and_then(|j| j.handler.take())
        };
        if let Some(mut h) = taken {
            h.failed(err);
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
            session.shared.lock().unwrap().job.as_ref().unwrap().pending_body.len(),
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
        // stream (no real connection needed: `stream_id` stays `None`, so
        // `maybe_fire_writable_callback` only weighs job-queue room).
        session
            .shared
            .lock()
            .unwrap()
            .job
            .as_mut()
            .unwrap()
            .pending_body
            .clear();

        session.maybe_fire_writable_callback();
        assert!(
            resumed.load(Ordering::SeqCst),
            "writable callback should fire once the pending-job queue has room again"
        );
    }
}
