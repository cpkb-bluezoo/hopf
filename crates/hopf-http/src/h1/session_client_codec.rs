// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.1 client codec driven by [`HttpRequest`] (Gumdrop session API).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ConnHandle, Endpoint, TimerHandle};

use crate::client::api::{
    HttpClientError, HttpClientSessionHandle, HttpConnectionHandler, HttpResponseHandler,
    SessionRequestOps,
};
use crate::error::{HttpError, HttpResult};
use crate::h1::encode_request::write_request_headers;
use crate::h1::parse::{parse_version, FirstLineKind, H1Events, H1Scanner, Next};
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::utils::{is_chunked_te, is_invalid_te, parse_content_length};
use crate::version::HttpVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Idle,
    StatusLine,
    Header,
    Body,
    BodyChunkedSize,
    BodyChunkedTrailer,
    BodyUntilClose,
    Done,
}

/// Configuration for [`H1SessionClientCodec`].
pub(crate) use crate::client::session_config::HttpClientSessionConfig as H1SessionConfig;

/// Soft cap on bytes buffered in [`H1SessionInner::out`] between flushes.
///
/// `request_body_content` short-writes once this is reached instead of
/// growing `out` unboundedly while the producer outruns the reactor's
/// chance to actually flush to the socket (e.g. a cross-connection
/// producer that never gives this connection an I/O event of its own —
/// see [`hopf_core::ConnHandle::poke`]).
const MAX_UNFLUSHED_BODY: usize = 256 * 1024;

pub(crate) struct H1SessionClientCodec {
    scanner: H1Scanner,
    inner: Arc<Mutex<H1SessionInner>>,
}

impl H1SessionClientCodec {
    pub fn new(config: Arc<H1SessionConfig>) -> Self {
        let max_line = config.limits.max_line_length;
        Self {
            scanner: H1Scanner::new(FirstLineKind::Status, max_line),
            inner: Arc::new(Mutex::new(H1SessionInner::new(config))),
        }
    }

    pub fn request_ops(&self) -> Arc<Mutex<dyn SessionRequestOps + Send>> {
        Arc::new(Mutex::new(OpsBridge(Arc::clone(&self.inner))))
    }

    pub fn on_connected(&mut self, conn_handle: ConnHandle) {
        let ops = self.request_ops();
        let handler = {
            let mut inner = self.inner.lock().unwrap();
            inner.open = true;
            if inner.connected_notified {
                return;
            }
            inner.connected_notified = true;
            let h = inner.config.handler.lock().unwrap().take();
            h
        };
        if let Some(mut h) = handler {
            let mut session =
                HttpClientSessionHandle::new(ops, HttpVersion::Http11, Some(conn_handle));
            h.on_connected(&mut session);
        }
    }

    pub fn receive(&mut self, data: &mut &[u8]) -> HttpResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(err) = inner.fatal.clone() {
            *data = &[];
            return Err(err);
        }
        if matches!(inner.state, ParseState::Idle | ParseState::Done) {
            *data = &[];
            return Ok(());
        }
        let consumed = self.scanner.push(data, &mut *inner);
        *data = &data[consumed..];
        if inner.fatal.is_some() || inner.state == ParseState::Done {
            *data = &[];
        }
        inner.take_error()
    }

    /// A transport-level failure (connect refused/reset, TLS handshake
    /// failure, …) reached this connection — see
    /// [`H1SessionInner::fail_transport`].
    pub fn fail_transport(&mut self, err: io::Error) {
        self.inner.lock().unwrap().fail_transport(err);
    }

    /// (Re)arm the [`crate::HttpClientTimeouts::stage`] timer if a request
    /// is in flight — see [`H1SessionInner::arm_stage_timer`]. A no-op
    /// otherwise (nothing to time out).
    pub fn touch_stage_timer(&mut self, ep: &mut dyn Endpoint) {
        let mut inner = self.inner.lock().unwrap();
        if inner.in_flight {
            inner.arm_stage_timer(ep);
        }
    }

    pub fn close(&mut self) -> HttpResult<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.close()
    }

    pub fn take_outbound(&mut self) -> Vec<u8> {
        // `out` is always empty afterward, so any registered short-write
        // backpressure callback can now safely accept more body bytes. Fire
        // it only after releasing the lock — it commonly calls straight
        // back into `request_body_content`, which would deadlock on a
        // still-held `std::sync::Mutex`.
        let (out, cb) = {
            let mut inner = self.inner.lock().unwrap();
            (inner.take_outbound(), inner.take_writable_callback())
        };
        if let Some(cb) = cb {
            cb();
        }
        out
    }

    pub fn wants_close(&self) -> bool {
        self.inner.lock().unwrap().wants_close()
    }
}

struct H1SessionInner {
    config: Arc<H1SessionConfig>,
    state: ParseState,
    version: HttpVersion,
    open: bool,
    connected_notified: bool,
    close_connection: bool,
    out: Vec<u8>,
    response_headers: Headers,
    pending_name: Option<String>,
    content_length: Option<u64>,
    body_received: u64,
    chunked: bool,
    body_started: bool,
    req_method: String,
    response_handler: Option<Box<dyn HttpResponseHandler>>,
    in_flight: bool,
    req_chunked: bool,
    body_complete: bool,
    fatal: Option<HttpError>,
    writable_callback: Option<Box<dyn FnOnce() + Send>>,
    /// [`crate::HttpClientTimeouts::stage`] budget for the current request —
    /// armed once its bytes hit the wire, renewed on every byte of response
    /// progress, cancelled once the response completes. See
    /// [`Self::arm_stage_timer`].
    stage_timer: Option<TimerHandle>,
}

impl H1SessionInner {
    fn new(config: Arc<H1SessionConfig>) -> Self {
        Self {
            config,
            state: ParseState::Idle,
            version: HttpVersion::Http11,
            open: false,
            connected_notified: false,
            close_connection: false,
            out: Vec::new(),
            response_headers: Headers::new(),
            pending_name: None,
            content_length: None,
            body_received: 0,
            chunked: false,
            body_started: false,
            req_method: String::new(),
            response_handler: None,
            in_flight: false,
            req_chunked: false,
            body_complete: false,
            fatal: None,
            writable_callback: None,
            stage_timer: None,
        }
    }

    fn host_header_value(&self) -> String {
        let default_port = if self.config.secure { 443 } else { 80 };
        if self.config.port == default_port {
            self.config.host.clone()
        } else {
            format!("{}:{}", self.config.host, self.config.port)
        }
    }

    fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Take any registered short-write resume callback (see
    /// [`MAX_UNFLUSHED_BODY`]) without invoking it — the caller must run it
    /// only after releasing the lock on this struct, since the callback
    /// commonly calls straight back into `request_body_content`.
    fn take_writable_callback(&mut self) -> Option<Box<dyn FnOnce() + Send>> {
        self.writable_callback.take()
    }

    fn wants_close(&self) -> bool {
        self.close_connection || self.fatal.is_some() || self.state == ParseState::Done
    }

    /// A transport-level failure (DNS, connect, TLS handshake, or a later
    /// reset) reached this connection — notify whoever can still hear about
    /// it and nobody else, matching how [`crate::HttpConnectionHandler`] and
    /// [`crate::HttpResponseHandler`] are each scoped: the connection
    /// handler only ever runs once, at `on_connected`, so if that hasn't
    /// happened yet it's still sitting in `config.handler` and gets
    /// `on_error`; otherwise, whatever request is currently in flight gets
    /// `failed()` — there's nothing to notify if neither applies (an idle
    /// connection between requests has no active listener for this).
    fn fail_transport(&mut self, err: io::Error) {
        if !self.connected_notified {
            if let Some(mut h) = self.config.handler.lock().unwrap().take() {
                h.on_error(&err);
            }
            return;
        }
        if let Some(mut h) = self.response_handler.take() {
            h.failed(err);
        }
    }

    fn take_error(&mut self) -> HttpResult<()> {
        match self.fatal.clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn fail(&mut self, err: HttpError) {
        if self.fatal.is_some() {
            return;
        }
        self.close_connection = true;
        self.fatal = Some(err);
        self.cancel_stage_timer();
        if let Some(mut h) = self.response_handler.take() {
            h.failed(io::Error::new(io::ErrorKind::Other, "HTTP protocol error"));
        }
    }

    fn cancel_stage_timer(&mut self) {
        if let Some(t) = self.stage_timer.take() {
            t.cancel();
        }
    }

    /// (Re)arm the stage timer, canceling any previous one. Call whenever
    /// there's fresh activity for the in-flight request — bytes just sent,
    /// or a byte of response just parsed — so a still-progressing request
    /// doesn't spuriously time out; a genuinely stalled peer still does.
    fn arm_stage_timer(&mut self, ep: &mut dyn Endpoint) {
        self.cancel_stage_timer();
        if self.config.stage.is_zero() {
            return;
        }
        let handle = ep.handle();
        let timer = ep.schedule_timer(
            self.config.stage,
            Box::new(move || {
                handle.with_endpoint(|ep2| {
                    ep2.fail(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HTTP client stage timed out",
                    ));
                });
            }),
        );
        self.stage_timer = Some(timer);
    }

    fn fail_stop(&mut self, err: HttpError) -> Next {
        self.fail(err);
        Next::Stop
    }

    fn begin_request(
        &mut self,
        method: String,
        path: String,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
        has_body: bool,
    ) -> Result<(), HttpClientError> {
        if !self.open {
            return Err(HttpClientError::new("connection not open"));
        }
        if self.in_flight {
            return Err(HttpClientError::new("request already in flight"));
        }
        self.in_flight = true;
        self.req_method = method.clone();
        self.response_handler = Some(handler);
        self.body_complete = !has_body;
        self.req_chunked = headers
            .get("transfer-encoding")
            .map(is_chunked_te)
            .unwrap_or(false);
        if !self.req_chunked && has_body && !headers.contains("content-length") {
            self.req_chunked = true;
        }

        let host = self.host_header_value();
        write_request_headers(
            &mut self.out,
            &method,
            &path,
            &host,
            &headers,
            has_body,
            self.version,
        );

        if !has_body {
            self.state = ParseState::StatusLine;
        }
        Ok(())
    }

    fn write_body_chunk(&mut self, data: &[u8]) -> usize {
        if self.body_complete {
            return 0;
        }
        let available = MAX_UNFLUSHED_BODY.saturating_sub(self.out.len());
        if available == 0 {
            return 0;
        }
        let data = &data[..data.len().min(available)];
        if self.req_chunked {
            let hdr = format!("{:x}\r\n", data.len());
            self.out.extend_from_slice(hdr.as_bytes());
            self.out.extend_from_slice(data);
            self.out.extend_from_slice(b"\r\n");
        } else {
            self.out.extend_from_slice(data);
        }
        data.len()
    }

    fn finish_request_body(&mut self) {
        if self.body_complete {
            return;
        }
        if self.req_chunked {
            self.out.extend_from_slice(b"0\r\n\r\n");
            self.req_chunked = false;
        }
        self.body_complete = true;
        self.state = ParseState::StatusLine;
    }

    fn deliver_status(&mut self) {
        let status = self.response_headers.status_code();
        if let Some(h) = self.response_handler.as_mut() {
            if (200..300).contains(&status) {
                h.ok(status);
            } else {
                h.error(status);
            }
            for field in self.response_headers.iter() {
                if field.name.starts_with(':') {
                    continue;
                }
                h.header(&field.name, &field.value);
            }
        }
    }

    fn ensure_body_started(&mut self) {
        if !self.body_started {
            self.body_started = true;
            if let Some(h) = self.response_handler.as_mut() {
                h.start_response_body();
            }
        }
    }

    fn finish_response(&mut self) {
        self.cancel_stage_timer();
        if let Some(mut h) = self.response_handler.take() {
            if self.body_started {
                h.end_response_body();
            }
            h.close();
        }
        self.body_started = false;
        self.in_flight = false;
        self.req_method.clear();
        self.response_headers = Headers::new();
        self.pending_name = None;
        self.content_length = None;
        self.body_received = 0;
        self.chunked = false;

        if self.close_connection {
            self.state = ParseState::Done;
            self.open = false;
        } else {
            self.state = ParseState::Idle;
        }
    }

    fn end_response_headers(&mut self) -> Next {
        if let Some(conn) = self.response_headers.get("connection") {
            if conn
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("close"))
            {
                self.close_connection = true;
            }
        }

        let status = self.response_headers.status_code();
        if (100..200).contains(&status) {
            if let Some(h) = self.response_handler.as_mut() {
                for field in self.response_headers.iter() {
                    if field.name.starts_with(':') {
                        continue;
                    }
                    h.header(&field.name, &field.value);
                }
            }
            self.response_headers = Headers::new();
            self.state = ParseState::StatusLine;
            return Next::FirstLine;
        }

        self.chunked = false;
        self.content_length = None;
        if let Some(te) = self.response_headers.get("transfer-encoding") {
            if is_invalid_te(te) {
                return self.fail_stop(HttpError::new(0, "invalid Transfer-Encoding"));
            }
            if is_chunked_te(te) {
                self.chunked = true;
            }
        } else {
            let cl_parsed: Vec<Option<u64>> = self
                .response_headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
                .map(|h| parse_content_length(&h.value))
                .collect();
            if let Some(&first) = cl_parsed.first() {
                let Some(n) = first else {
                    return self.fail_stop(HttpError::new(0, "invalid Content-Length"));
                };
                if cl_parsed.iter().any(|&v| v != Some(n)) {
                    return self.fail_stop(HttpError::new(0, "conflicting Content-Length"));
                }
                self.content_length = Some(n);
            }
        }

        if status == 204 || status == 304 {
            self.content_length = Some(0);
            self.chunked = false;
        } else if self.req_method.eq_ignore_ascii_case("HEAD") {
            self.content_length = Some(0);
            self.chunked = false;
        }

        self.deliver_status();

        if self.chunked {
            self.state = ParseState::BodyChunkedSize;
            return Next::ChunkSize;
        }
        match self.content_length {
            Some(0) => {
                self.finish_response();
                Next::Stop
            }
            Some(n) => {
                self.state = ParseState::Body;
                self.body_received = 0;
                Next::Body(n)
            }
            None => {
                self.state = ParseState::BodyUntilClose;
                Next::UntilClose
            }
        }
    }

    fn close(&mut self) -> HttpResult<()> {
        if self.state == ParseState::BodyUntilClose {
            self.finish_response();
        } else if !matches!(self.state, ParseState::Idle | ParseState::Done) {
            if let Some(mut h) = self.response_handler.take() {
                h.failed(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete HTTP response",
                ));
            }
            self.fail(HttpError::new(0, "incomplete HTTP response"));
        }
        self.open = false;
        self.take_error()
    }
}

struct OpsBridge(Arc<Mutex<H1SessionInner>>);

impl SessionRequestOps for OpsBridge {
    fn is_open(&self) -> bool {
        self.0.lock().unwrap().open && self.0.lock().unwrap().state != ParseState::Done
    }

    fn send_no_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        self.0.lock().unwrap().begin_request(
            method.to_string(),
            path.to_string(),
            headers,
            handler,
            false,
        )
    }

    fn start_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        self.0.lock().unwrap().begin_request(
            method.to_string(),
            path.to_string(),
            headers,
            handler,
            true,
        )
    }

    fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
        if !self.0.lock().unwrap().in_flight || self.0.lock().unwrap().body_complete {
            return Err(HttpClientError::new("must call start_request_body first"));
        }
        Ok(self.0.lock().unwrap().write_body_chunk(data))
    }

    fn end_body(&mut self) -> Result<(), HttpClientError> {
        if !self.0.lock().unwrap().in_flight || self.0.lock().unwrap().body_complete {
            return Err(HttpClientError::new("must call start_request_body first"));
        }
        self.0.lock().unwrap().finish_request_body();
        Ok(())
    }

    fn cancel_request(&mut self) -> Result<(), HttpClientError> {
        let mut inner = self.0.lock().unwrap();
        if let Some(mut h) = inner.response_handler.take() {
            h.failed(io::Error::new(io::ErrorKind::Interrupted, "request cancelled"));
        }
        inner.in_flight = false;
        inner.body_complete = true;
        inner.state = ParseState::Idle;
        Ok(())
    }

    fn on_body_writable(&mut self, cb: Box<dyn FnOnce() + Send>) {
        self.0.lock().unwrap().writable_callback = Some(cb);
    }
}

impl H1Events for H1SessionInner {
    fn method(&mut self, _value: &[u8]) -> Next {
        self.fail_stop(HttpError::new(0, "request-line on a client"))
    }

    fn request_target(&mut self, _value: &[u8]) -> Next {
        self.fail_stop(HttpError::new(0, "request-line on a client"))
    }

    fn http_version(&mut self, value: &[u8]) -> Next {
        let Some(v) = parse_version(value) else {
            return self.fail_stop(HttpError::new(0, "bad response version"));
        };
        self.version = v;
        Next::Continue
    }

    fn status_code(&mut self, value: &[u8]) -> Next {
        let s = std::str::from_utf8(value).unwrap_or("");
        let Ok(code) = s.parse::<u16>() else {
            return self.fail_stop(HttpError::new(0, "bad status code"));
        };
        self.response_headers.status(code);
        Next::Continue
    }

    fn reason_phrase(&mut self, _value: &[u8]) -> Next {
        Next::Continue
    }

    fn first_line_end(&mut self) -> Next {
        self.state = ParseState::Header;
        Next::Fields
    }

    fn header_name(&mut self, value: &[u8]) -> Next {
        let name: String = value.iter().map(|&b| b as char).collect();
        self.pending_name = Some(name);
        Next::Continue
    }

    fn header_value(&mut self, value: &[u8]) -> Next {
        let Some(name) = self.pending_name.take() else {
            return self.fail_stop(HttpError::new(0, "value without field name"));
        };
        if self.state == ParseState::BodyChunkedTrailer {
            return Next::Continue;
        }
        let v: String = value.iter().map(|&b| b as char).collect();
        self.response_headers.add(name, v);
        Next::Continue
    }

    fn headers_end(&mut self) -> Next {
        if self.state == ParseState::BodyChunkedTrailer {
            self.finish_response();
            return Next::Stop;
        }
        self.end_response_headers()
    }

    fn chunk_size_line(&mut self, value: &[u8]) -> Next {
        let line: String = value.iter().map(|&b| b as char).collect();
        let semi = line.find(';');
        let size_str = semi.map(|i| &line[..i]).unwrap_or(&line).trim();
        let Ok(chunk_size) = usize::from_str_radix(size_str, 16) else {
            return self.fail_stop(HttpError::new(0, "bad chunk size"));
        };
        if chunk_size == 0 {
            self.state = ParseState::BodyChunkedTrailer;
            self.pending_name = None;
            return Next::Fields;
        }
        Next::ChunkBody(chunk_size as u64)
    }

    fn body_data(&mut self, value: &[u8]) -> Next {
        self.ensure_body_started();
        if let Some(h) = self.response_handler.as_mut() {
            h.response_body_content(value);
        }
        self.body_received += value.len() as u64;
        Next::Continue
    }

    fn body_end(&mut self) -> Next {
        self.finish_response();
        Next::Stop
    }

    fn chunk_end(&mut self) -> Next {
        self.state = ParseState::BodyChunkedSize;
        Next::ChunkSize
    }

    fn too_long(&mut self) -> Next {
        self.fail_stop(HttpError::new(0, "response token too long"))
    }

    fn bad_syntax(&mut self, _what: &'static str) -> Next {
        self.fail_stop(HttpError::new(0, "malformed HTTP response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Rec {
        status: u16,
        body: Vec<u8>,
        done: bool,
    }

    struct Handler {
        rec: Arc<Mutex<Rec>>,
    }

    impl HttpResponseHandler for Handler {
        fn ok(&mut self, status: u16) {
            self.rec.lock().unwrap().status = status;
        }
        fn error(&mut self, status: u16) {
            self.rec.lock().unwrap().status = status;
        }
        fn header(&mut self, _: &str, _: &str) {}
        fn response_body_content(&mut self, data: &[u8]) {
            self.rec.lock().unwrap().body.extend_from_slice(data);
        }
        fn close(&mut self) {
            self.rec.lock().unwrap().done = true;
        }
        fn failed(&mut self, _: io::Error) {}
    }

    struct Conn {
        rec: Arc<Mutex<Rec>>,
    }

    impl HttpConnectionHandler for Conn {
        fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
            let mut req = session.post("/");
            req.header("content-type", "application/json").unwrap();
            req.start_request_body(Box::new(Handler {
                rec: Arc::clone(&self.rec),
            }))
            .unwrap();
            req.request_body_content(b"{\"a\":1}").unwrap();
            req.end_request_body().unwrap();
        }
    }

    #[test]
    fn session_post_json_round_trip() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let config = Arc::new(H1SessionConfig {
            host: "ex.com".into(),
            port: 80,
            limits: HttpLimits::default(),
            secure: false,
            handler: Mutex::new(Some(Box::new(Conn {
                rec: Arc::clone(&rec),
            }))),
            stage: Duration::ZERO,
        });
        let mut codec = H1SessionClientCodec::new(config);
        codec.on_connected(ConnHandle::from_execute(Arc::new(|task| task())));
        let req = String::from_utf8(codec.take_outbound()).unwrap();
        assert!(req.starts_with("POST / HTTP/1.1\r\n"));
        assert!(req.to_ascii_lowercase().contains("content-type: application/json"));
        assert!(req.contains("{\"a\":1}"));

        let mut data: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        codec.receive(&mut data).unwrap();
        let g = rec.lock().unwrap();
        assert_eq!(g.status, 200);
        assert_eq!(g.body, b"hello");
        assert!(g.done);
    }

    struct NullHandler;

    impl HttpResponseHandler for NullHandler {
        fn ok(&mut self, _status: u16) {}
        fn error(&mut self, _status: u16) {}
        fn header(&mut self, _name: &str, _value: &str) {}
        fn response_body_content(&mut self, _data: &[u8]) {}
        fn close(&mut self) {}
        fn failed(&mut self, _err: io::Error) {}
    }

    struct BodyConn {
        req_slot: Arc<Mutex<Option<crate::client::api::HttpRequest>>>,
    }

    impl HttpConnectionHandler for BodyConn {
        fn on_connected(&mut self, session: &mut HttpClientSessionHandle) {
            let mut req = session.post("/upload");
            req.start_request_body(Box::new(NullHandler)).unwrap();
            *self.req_slot.lock().unwrap() = Some(req);
        }
    }

    #[test]
    fn request_body_content_short_writes_past_cap_then_resumes_after_flush() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let req_slot = Arc::new(Mutex::new(None));
        let config = Arc::new(H1SessionConfig {
            host: "ex.com".into(),
            port: 80,
            limits: HttpLimits::default(),
            secure: false,
            handler: Mutex::new(Some(Box::new(BodyConn {
                req_slot: Arc::clone(&req_slot),
            }))),
            stage: Duration::ZERO,
        });
        let mut codec = H1SessionClientCodec::new(config);
        codec.on_connected(ConnHandle::from_execute(Arc::new(|task| task())));
        // Drop the request-line bytes `start_request_body` already queued.
        codec.take_outbound();

        let mut req = req_slot.lock().unwrap().take().unwrap();
        let big = vec![b'x'; MAX_UNFLUSHED_BODY + 1000];
        let accepted = req.request_body_content(&big).unwrap();
        assert!(
            accepted < big.len() && accepted > 0,
            "expected a short write, got {accepted} of {}",
            big.len()
        );

        let resumed = Arc::new(AtomicBool::new(false));
        let resumed2 = Arc::clone(&resumed);
        req.on_body_writable(Box::new(move || resumed2.store(true, Ordering::SeqCst)))
            .unwrap();

        // A flush drains `out` back to empty, so the callback should fire.
        let flushed = codec.take_outbound();
        assert!(!flushed.is_empty());
        assert!(
            resumed.load(Ordering::SeqCst),
            "writable callback should fire once buffered bytes are flushed"
        );

        // The remainder is now accepted in full.
        let remainder = &big[accepted..];
        let accepted2 = req.request_body_content(remainder).unwrap();
        assert_eq!(accepted2, remainder.len());
    }
}
