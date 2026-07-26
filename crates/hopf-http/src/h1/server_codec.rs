// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.x server codec (inbound request / outbound response).
//!
//! Parsing is driven by [`super::parse::H1Scanner`], which emits HTTP's own
//! token vocabulary (method, request-target, header name/value, chunk-size
//! line, body bytes) as each production completes. The scanner consumes every
//! byte it is handed and keeps any partial token in its own bounded state, so
//! neither this module nor the transport below it ever holds a line buffer.

use std::sync::Arc;

use hopf_core::ConnHandle;

use crate::error::{HttpError, HttpResult};
use crate::h1::parse::{parse_version, FirstLineKind, H1Events, H1Scanner, Next};
use crate::h1::response::H1ResponseControl;
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{ProtocolUpgradeHandler, ServerHandler, ServerWriter};
use crate::utils::{
    is_chunked_te, is_default_method, is_invalid_te, is_token, is_valid_header_name,
    is_valid_host, is_valid_request_target, method_implies_no_body, parse_content_length,
};
use crate::version::HttpVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    RequestLine,
    Header,
    Body,
    BodyChunkedSize,
    BodyChunkedTrailer,
    BodyUntilClose,
    /// Connection has switched protocols (WebSocket, etc.).
    Upgraded,
}

/// Incremental HTTP/1.x request parser + response framer for one connection.
pub struct H1ServerCodec<H: ServerHandler> {
    scanner: H1Scanner,
    driver: Driver<H>,
}

impl<H: ServerHandler> H1ServerCodec<H> {
    /// Create a parser. `secure` sets `:scheme` to `https` vs `http`.
    pub fn new(handler: H, limits: HttpLimits, secure: bool) -> Self {
        let max_line = limits.max_line_length;
        Self {
            scanner: H1Scanner::new(FirstLineKind::Request, max_line),
            driver: Driver::new(handler, limits, secure),
        }
    }

    /// Feed inbound bytes. Advances `data` past consumed input.
    ///
    /// Everything is consumed unless the connection has switched protocols,
    /// in which case the remainder belongs to the upgrade handler.
    pub fn receive(&mut self, data: &mut &[u8]) -> HttpResult<()> {
        if let Some(err) = self.driver.fatal.clone() {
            *data = &[];
            return Err(err);
        }

        if self.driver.state == ParseState::Upgraded {
            self.feed_upgraded(data);
            return Ok(());
        }

        // Activate an upgrade installed while the last response was written.
        if self.take_upgrade() {
            self.feed_upgraded(data);
            return Ok(());
        }

        let consumed = self.scanner.push(data, &mut self.driver);
        *data = &data[consumed..];

        if self.take_upgrade() {
            self.feed_upgraded(data);
            return self.driver.take_error();
        }
        if self.driver.fatal.is_some() {
            *data = &[];
        }
        self.driver.take_error()
    }

    /// Install a pending upgrade handler, if the response layer created one.
    fn take_upgrade(&mut self) -> bool {
        if let Some(up) = self.driver.response.take_upgrade() {
            self.driver.upgraded = Some(up);
            self.driver.state = ParseState::Upgraded;
            true
        } else {
            false
        }
    }

    fn feed_upgraded(&mut self, data: &mut &[u8]) {
        if data.is_empty() {
            return;
        }
        if let Some(up) = self.driver.upgraded.as_mut() {
            up.receive(data);
        }
        *data = &[];
    }

    /// Connection EOF — completes until-close bodies.
    pub fn close(&mut self) -> HttpResult<()> {
        if let Some(up) = self.driver.upgraded.as_mut() {
            up.closed();
            return Ok(());
        }
        if self.driver.state == ParseState::BodyUntilClose {
            self.driver.finish_until_close();
        } else if !self.scanner.at_message_start() || self.driver.state != ParseState::RequestLine {
            self.driver
                .fail(HttpError::new(400, "incomplete HTTP message"));
        }
        self.driver.take_error()
    }

    /// Bytes queued for the peer (100-continue, responses, errors, upgrade).
    pub fn take_outbound(&mut self) -> Vec<u8> {
        let mut out = self.driver.response.take_outbound();
        if let Some(up) = self.driver.upgraded.as_mut() {
            out.extend(up.take_outbound());
        }
        out
    }

    /// Whether the peer should be closed after flushing outbound data.
    pub fn wants_close(&self) -> bool {
        self.driver.response.wants_close() || self.driver.fatal.is_some()
    }

    /// Bind the transport [`ConnHandle`] (call from `H1Endpoint` on connect/receive).
    pub fn bind_conn_handle(&mut self, conn: ConnHandle) {
        self.driver.response.bind_conn(conn);
    }

    /// Whether deferred execute left bytes that still need an endpoint flush.
    pub fn needs_flush(&self) -> bool {
        self.driver.response.needs_flush()
    }

    /// Whether request-body delivery is paused for this connection.
    pub fn pause_request_body(&self) -> bool {
        self.driver.response.pause_request_body_flag()
    }

    /// Replace the application handler (e.g. after factory creates a new one).
    pub fn set_handler(&mut self, handler: H) {
        self.driver.app = Some(handler);
    }

    /// Method captured so far on the in-progress request-line (tests / debugging).
    pub fn partial_method(&self) -> Option<&str> {
        self.driver.partial_method.as_deref()
    }

    /// Request-target captured so far on the in-progress request-line.
    pub fn partial_target(&self) -> Option<&str> {
        self.driver.partial_target.as_deref()
    }
}

struct Driver<H: ServerHandler> {
    app: Option<H>,
    limits: HttpLimits,
    secure: bool,
    state: ParseState,
    /// Filled as request-line tokens arrive (before app callbacks).
    partial_method: Option<String>,
    partial_target: Option<String>,
    version: HttpVersion,
    /// True once the HTTP-version token has been accepted.
    version_ready: bool,
    headers: Headers,
    /// Field name awaiting its value.
    pending_name: Option<String>,
    content_length: Option<u64>,
    body_received: u64,
    chunked: bool,
    body_started: bool,
    request_count: u32,
    max_requests: u32,
    response: Arc<H1ResponseControl>,
    fatal: Option<HttpError>,
    line_too_long_status: u16,
    /// Active protocol upgrade (WebSocket, …).
    upgraded: Option<Box<dyn ProtocolUpgradeHandler>>,
}

impl<H: ServerHandler> Driver<H> {
    fn new(handler: H, limits: HttpLimits, secure: bool) -> Self {
        Self {
            app: Some(handler),
            limits,
            secure,
            state: ParseState::RequestLine,
            partial_method: None,
            partial_target: None,
            version: HttpVersion::Http11,
            version_ready: false,
            headers: Headers::new(),
            pending_name: None,
            content_length: None,
            body_received: 0,
            chunked: false,
            body_started: false,
            request_count: 0,
            max_requests: 0,
            response: H1ResponseControl::new(),
            fatal: None,
            line_too_long_status: 414,
            upgraded: None,
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
        self.response.write_error_response(err.status);
        self.response.set_close_connection(true);
        self.fatal = Some(err);
    }

    /// Record a fatal error and stop the scanner.
    fn fail_stop(&mut self, err: HttpError) -> Next {
        self.fail(err);
        Next::Stop
    }

    fn with_app_response<R>(&mut self, f: impl FnOnce(&mut H, &mut dyn ServerWriter) -> R) -> R {
        let mut app = self.app.take().expect("handler missing");
        self.response.set_version(self.version);
        self.response
            .set_method(self.headers.method().unwrap_or("GET"));
        let mut view = self.response.writer();
        let r = f(&mut app, &mut view);
        self.app = Some(app);
        r
    }

    fn as_str<'a>(&self, v: &'a [u8]) -> Result<&'a str, HttpError> {
        std::str::from_utf8(v).map_err(|_| HttpError::new(400, "invalid UTF-8/ASCII"))
    }

    fn finish_request_no_body(&mut self) {
        self.with_app_response(|app, resp| app.request_complete(resp));
        self.reset_message_fields();
    }

    fn finish_request_with_body(&mut self) {
        if self.body_started {
            self.with_app_response(|app, resp| {
                app.end_request_body(resp);
                app.request_complete(resp);
            });
        } else {
            self.with_app_response(|app, resp| app.request_complete(resp));
        }
        self.reset_message_fields();
    }

    fn reset_message_fields(&mut self) {
        self.state = ParseState::RequestLine;
        self.headers = Headers::new();
        self.pending_name = None;
        self.content_length = None;
        self.body_received = 0;
        self.chunked = false;
        self.body_started = false;
        self.response.reset_message_fields();
        self.partial_method = None;
        self.partial_target = None;
        self.version_ready = false;
        self.line_too_long_status = 414;
    }

    fn ensure_body_started(&mut self) {
        if !self.body_started {
            self.body_started = true;
            self.with_app_response(|app, resp| app.start_request_body(resp));
        }
    }

    fn finish_until_close(&mut self) {
        self.finish_request_with_body();
    }

    /// Validate the completed header block and decide what follows it.
    fn end_headers(&mut self) -> Next {
        if self.version == HttpVersion::Http11 {
            let host_count = self
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("host") || h.name == ":authority")
                .count();
            if host_count != 1 {
                return self.fail_stop(HttpError::new(400, "Host required"));
            }
            let host = self
                .headers
                .get("host")
                .or_else(|| self.headers.get(":authority"))
                .unwrap_or("");
            if !is_valid_host(host) {
                return self.fail_stop(HttpError::new(400, "invalid Host"));
            }
        }

        if let Some(conn) = self.headers.get("connection") {
            if conn
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("close"))
            {
                self.response.set_close_connection(true);
            }
        }

        self.chunked = false;
        self.content_length = None;
        if let Some(te) = self.headers.get("transfer-encoding") {
            if is_invalid_te(te) {
                return self.fail_stop(HttpError::new(400, "invalid Transfer-Encoding"));
            }
            if is_chunked_te(te) {
                self.chunked = true;
                self.headers.remove("content-length");
            }
        } else if let Some(cl) = self.headers.get("content-length") {
            match parse_content_length(cl) {
                Some(n) => self.content_length = Some(n),
                None => return self.fail_stop(HttpError::new(400, "invalid Content-Length")),
            }
        }

        let method = self.headers.method().unwrap_or("");
        if method_implies_no_body(method) && !self.chunked {
            self.content_length = Some(0);
        }

        self.request_count = self.request_count.saturating_add(1);
        if self.max_requests > 0 && self.request_count >= self.max_requests {
            self.response.set_close_connection(true);
        }

        let expect_continue = self.version != HttpVersion::Http10
            && self
                .headers
                .get("expect")
                .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
            && (self.chunked || self.content_length.unwrap_or(0) > 0);
        if expect_continue {
            self.response.extend_out(b"HTTP/1.1 100 Continue\r\n\r\n");
        }

        let hdrs = self.headers.clone();
        self.with_app_response(|app, resp| app.headers(resp, &hdrs));

        if self.fatal.is_some() {
            return Next::Stop;
        }

        if self.chunked {
            self.state = ParseState::BodyChunkedSize;
            self.line_too_long_status = 400;
            return Next::ChunkSize;
        }
        match self.content_length {
            Some(0) => {
                self.finish_request_no_body();
                Next::FirstLine
            }
            Some(n) => {
                self.state = ParseState::Body;
                self.body_received = 0;
                Next::Body(n)
            }
            None if self.version == HttpVersion::Http10 => {
                self.state = ParseState::BodyUntilClose;
                Next::UntilClose
            }
            None => self.fail_stop(HttpError::new(411, "Length Required")),
        }
    }
}

impl<H: ServerHandler> H1Events for Driver<H> {
    fn method(&mut self, value: &[u8]) -> Next {
        self.line_too_long_status = 414;
        let s = match self.as_str(value) {
            Ok(s) => s,
            Err(e) => return self.fail_stop(e),
        };
        if s.bytes().any(|b| b < 0x20 && b != b'\t') {
            return self.fail_stop(HttpError::new(400, "CTL in method"));
        }
        if s.is_empty() {
            return self.fail_stop(HttpError::new(400, "empty method"));
        }
        if !is_token(s) {
            return self.fail_stop(HttpError::new(400, "invalid method"));
        }
        if !is_default_method(s) {
            return self.fail_stop(HttpError::new(501, "method not implemented"));
        }
        self.partial_method = Some(s.to_string());
        Next::Continue
    }

    fn request_target(&mut self, value: &[u8]) -> Next {
        let s = match self.as_str(value) {
            Ok(s) => s,
            Err(e) => return self.fail_stop(e),
        };
        if !is_valid_request_target(s) {
            return self.fail_stop(HttpError::new(400, "invalid request-target"));
        }
        self.partial_target = Some(s.to_string());
        Next::Continue
    }

    fn http_version(&mut self, value: &[u8]) -> Next {
        let s = match self.as_str(value) {
            Ok(s) => s,
            Err(e) => return self.fail_stop(e),
        };
        let method = self.partial_method.as_deref().unwrap_or("");
        let target = self.partial_target.as_deref().unwrap_or("");
        let Some(version) = parse_version(value) else {
            if s == "HTTP/2.0" && method == "PRI" && target == "*" {
                return self.fail_stop(HttpError::new(505, "HTTP/2 preface not supported yet"));
            }
            return self.fail_stop(HttpError::new(505, "HTTP version not supported"));
        };
        self.version = version;
        if version == HttpVersion::Http10 {
            self.response.set_close_connection(true);
        }
        self.version_ready = true;
        Next::Continue
    }

    fn status_code(&mut self, _value: &[u8]) -> Next {
        self.fail_stop(HttpError::new(400, "status-line on a server"))
    }

    fn reason_phrase(&mut self, _value: &[u8]) -> Next {
        self.fail_stop(HttpError::new(400, "status-line on a server"))
    }

    fn first_line_end(&mut self) -> Next {
        if !self.version_ready || self.partial_method.is_none() || self.partial_target.is_none() {
            return self.fail_stop(HttpError::new(400, "malformed request-line"));
        }
        let method = self.partial_method.clone().unwrap();
        let target = self.partial_target.clone().unwrap();
        self.headers = Headers::new();
        self.headers.add(":method", method);
        self.headers.add(":path", target);
        self.headers
            .add(":scheme", if self.secure { "https" } else { "http" });
        self.state = ParseState::Header;
        self.line_too_long_status = 431;
        Next::Fields
    }

    fn header_name(&mut self, value: &[u8]) -> Next {
        self.line_too_long_status = if self.state == ParseState::BodyChunkedTrailer {
            400
        } else {
            431
        };
        if self.state != ParseState::BodyChunkedTrailer
            && self.headers.len() >= self.limits.max_header_count
        {
            return self.fail_stop(HttpError::new(431, "too many headers"));
        }
        let name: String = value.iter().map(|&b| b as char).collect();
        if !is_valid_header_name(&name) {
            return self.fail_stop(HttpError::new(400, "invalid header name"));
        }
        self.pending_name = Some(name);
        Next::Continue
    }

    fn header_value(&mut self, value: &[u8]) -> Next {
        let Some(name) = self.pending_name.take() else {
            return self.fail_stop(HttpError::new(400, "value without field name"));
        };
        // Trailers are accepted but not merged into the header set.
        if self.state == ParseState::BodyChunkedTrailer {
            return Next::Continue;
        }
        let v: String = value.iter().map(|&b| b as char).collect();
        self.headers.add(name, v);
        Next::Continue
    }

    fn headers_end(&mut self) -> Next {
        if self.state == ParseState::BodyChunkedTrailer {
            self.finish_request_with_body();
            return Next::FirstLine;
        }
        self.end_headers()
    }

    fn chunk_size_line(&mut self, value: &[u8]) -> Next {
        self.line_too_long_status = 400;
        let line: String = value.iter().map(|&b| b as char).collect();
        let semi = line.find(';');
        if semi.is_some_and(|i| line[i..].contains('"')) {
            return self.fail_stop(HttpError::new(400, "quoted chunk-ext"));
        }
        let size_str = semi.map(|i| &line[..i]).unwrap_or(&line).trim();
        let Ok(chunk_size) = usize::from_str_radix(size_str, 16) else {
            return self.fail_stop(HttpError::new(400, "bad chunk size"));
        };
        if chunk_size > self.limits.max_chunk_size {
            return self.fail_stop(HttpError::new(400, "chunk too large"));
        }
        if self.body_received.saturating_add(chunk_size as u64)
            > self.limits.max_request_body as u64
        {
            return self.fail_stop(HttpError::new(413, "request body too large"));
        }
        if chunk_size == 0 {
            self.state = ParseState::BodyChunkedTrailer;
            self.pending_name = None;
            return Next::Fields;
        }
        Next::ChunkBody(chunk_size as u64)
    }

    fn body_data(&mut self, value: &[u8]) -> Next {
        if self.limits.max_request_body > 0
            && self
                .body_received
                .saturating_add(value.len() as u64)
                > self.limits.max_request_body as u64
        {
            return self.fail_stop(HttpError::new(413, "request body too large"));
        }
        self.ensure_body_started();
        self.with_app_response(|app, resp| app.request_body_content(resp, value));
        self.body_received += value.len() as u64;
        Next::Continue
    }

    fn body_end(&mut self) -> Next {
        self.finish_request_with_body();
        Next::FirstLine
    }

    fn chunk_end(&mut self) -> Next {
        self.state = ParseState::BodyChunkedSize;
        Next::ChunkSize
    }

    fn too_long(&mut self) -> Next {
        let status = self.line_too_long_status;
        let msg = match status {
            414 => "request-line too long",
            431 => "header line too long",
            _ => "token too long",
        };
        self.fail_stop(HttpError::new(status, msg))
    }

    fn bad_syntax(&mut self, what: &'static str) -> Next {
        let status = match self.state {
            ParseState::RequestLine => 400,
            _ => 400,
        };
        let _ = what;
        self.fail_stop(HttpError::new(status, "malformed HTTP message"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::ServerHandler;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Rec {
        events: Vec<String>,
        body: Vec<u8>,
    }

    impl ServerHandler for Arc<Mutex<Rec>> {
        fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
            self.lock().unwrap().events.push(format!(
                "headers {} {}",
                headers.method().unwrap_or("?"),
                headers.path().unwrap_or("?")
            ));
            let mut h = Headers::new();
            h.status(200);
            h.set("Content-Type", "text/plain");
            response.headers(h);
            response.start_response_body();
            response.response_body_content(b"ok");
            response.end_response_body();
            response.complete();
        }

        fn start_request_body(&mut self, _response: &mut dyn ServerWriter) {
            self.lock().unwrap().events.push("start_body".into());
        }

        fn request_body_content(&mut self, _response: &mut dyn ServerWriter, data: &[u8]) {
            self.lock().unwrap().body.extend_from_slice(data);
        }

        fn end_request_body(&mut self, _response: &mut dyn ServerWriter) {
            self.lock().unwrap().events.push("end_body".into());
        }

        fn request_complete(&mut self, _response: &mut dyn ServerWriter) {
            self.lock().unwrap().events.push("complete".into());
        }
    }

    /// Feed chunk by chunk, asserting the codec retains *nothing* — the
    /// scanner owns any partial token, so the transport buffer always drains
    /// completely (see `h1::parse` module docs).
    fn feed_all(p: &mut H1ServerCodec<Arc<Mutex<Rec>>>, chunks: &[&[u8]]) {
        for c in chunks {
            let mut slice: &[u8] = c;
            p.receive(&mut slice).unwrap();
            assert!(
                slice.is_empty(),
                "codec left {} byte(s) unconsumed from {:?}",
                slice.len(),
                String::from_utf8_lossy(c)
            );
        }
    }

    /// The design property: a request split at *every* byte boundary parses
    /// identically and never asks the caller to retain anything.
    #[test]
    fn every_split_point_consumes_everything() {
        let msg: &[u8] = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello";
        for split in 1..msg.len() {
            let rec = Arc::new(Mutex::new(Rec::default()));
            let mut p = H1ServerCodec::new(Arc::clone(&rec), HttpLimits::default(), false);
            for part in [&msg[..split], &msg[split..]] {
                let mut slice: &[u8] = part;
                p.receive(&mut slice).unwrap();
                assert!(slice.is_empty(), "split {split} retained bytes");
            }
            let g = rec.lock().unwrap();
            assert_eq!(g.body, b"hello", "split {split}");
            assert!(g.events.iter().any(|e| e == "complete"), "split {split}");
        }
    }

    #[test]
    fn get_split_buffers() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut p = H1ServerCodec::new(Arc::clone(&rec), HttpLimits::default(), false);
        feed_all(
            &mut p,
            &[
                b"GET /hel",
                b"lo HTTP/1.1\r",
                b"\nHost: ex.com\r\n",
                b"\r\n",
            ],
        );
        let g = rec.lock().unwrap();
        assert_eq!(g.events[0], "headers GET /hello");
        assert!(g.events.contains(&"complete".into()));
        let out = String::from_utf8(p.take_outbound()).unwrap();
        assert!(out.contains("HTTP/1.1 200"));
        assert!(out.contains("ok"));
    }

    #[test]
    fn mid_line_parse_state_advances() {
        // Issue #3: after "GET /myresource H" we already know method + target.
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut p = H1ServerCodec::new(Arc::clone(&rec), HttpLimits::default(), false);
        let mut pending = Vec::new();
        pending.extend_from_slice(b"GET /myresource H");
        let mut slice = pending.as_slice();
        let before = slice.len();
        p.receive(&mut slice).unwrap();
        let consumed = before - slice.len();
        pending.drain(..consumed);

        assert_eq!(p.partial_method(), Some("GET"));
        assert_eq!(p.partial_target(), Some("/myresource"));
        assert!(rec.lock().unwrap().events.is_empty(), "no app callbacks yet");

        pending.extend_from_slice(b"TTP/1.1\r\nHost: x\r\n\r\n");
        let mut slice = pending.as_slice();
        let before = slice.len();
        p.receive(&mut slice).unwrap();
        let consumed = before - slice.len();
        pending.drain(..consumed);
        assert!(pending.is_empty());
        assert_eq!(
            rec.lock().unwrap().events[0],
            "headers GET /myresource"
        );
    }

    #[test]
    fn content_length_body_split() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut p = H1ServerCodec::new(Arc::clone(&rec), HttpLimits::default(), false);
        feed_all(
            &mut p,
            &[
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhe",
                b"llo",
            ],
        );
        let g = rec.lock().unwrap();
        assert_eq!(g.body, b"hello");
        assert!(g.events.iter().any(|e| e == "start_body"));
        assert!(g.events.iter().any(|e| e == "end_body"));
    }

    #[test]
    fn chunked_body() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut p = H1ServerCodec::new(Arc::clone(&rec), HttpLimits::default(), false);
        feed_all(
            &mut p,
            &[b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"],
        );
        feed_all(&mut p, &[b"5\r\nhello\r\n0\r\n\r\n"]);
        let g = rec.lock().unwrap();
        assert_eq!(g.body, b"hello");
    }

    #[test]
    fn host_required_http11() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut p = H1ServerCodec::new(Arc::clone(&rec), HttpLimits::default(), false);
        let mut data: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        let err = p.receive(&mut data).unwrap_err();
        assert_eq!(err.status, 400);
    }

    /// Handler that schedules the response via [`ServerResponseHandle::execute`].
    struct DeferredHandler {
        from_thread: bool,
    }

    impl ServerHandler for DeferredHandler {
        fn headers(&mut self, response: &mut dyn ServerWriter, _headers: &Headers) {
            response.pause_request_body();
            let handle = response.response_handle();
            let write = move |w: &mut dyn ServerWriter| {
                let mut h = Headers::new();
                h.status(200);
                h.set("Content-Type", "text/plain");
                h.set("Content-Length", "8");
                w.headers(h);
                w.start_response_body();
                w.response_body_content(b"deferred");
                w.end_response_body();
                w.complete();
            };
            if self.from_thread {
                let handle2 = handle.clone();
                let t = std::thread::spawn(move || {
                    handle2.execute(write);
                });
                t.join().unwrap();
            } else {
                handle.execute(write);
            }
            response.resume_request_body();
        }

        fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
    }

    #[test]
    fn deferred_execute_inline_from_headers() {
        // Default codec ConnHandle is from_execute(inline).
        let mut p = H1ServerCodec::new(
            DeferredHandler { from_thread: false },
            HttpLimits::default(),
            false,
        );
        let mut data: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        p.receive(&mut data).unwrap();
        // from_execute path: bytes land in the shared session; take_outbound sees them.
        let out = String::from_utf8(p.take_outbound()).unwrap();
        assert!(out.contains("HTTP/1.1 200"), "{out}");
        assert!(out.contains("deferred"), "{out}");
        assert!(!p.pause_request_body());
    }

    #[test]
    fn deferred_execute_from_thread_with_from_execute() {
        let mut p = H1ServerCodec::new(
            DeferredHandler { from_thread: true },
            HttpLimits::default(),
            false,
        );
        // Explicit from_execute (same as default, documents the contract).
        p.bind_conn_handle(ConnHandle::from_execute(Arc::new(|task| task())));
        let mut data: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        p.receive(&mut data).unwrap();
        let out = String::from_utf8(p.take_outbound()).unwrap();
        assert!(out.contains("deferred"), "{out}");
    }

    #[test]
    fn deferred_execute_in_request_complete() {
        struct CompleteDeferred;
        impl ServerHandler for CompleteDeferred {
            fn headers(&mut self, _response: &mut dyn ServerWriter, _headers: &Headers) {}
            fn request_complete(&mut self, response: &mut dyn ServerWriter) {
                let handle = response.response_handle();
                handle.execute(|w| {
                    let mut h = Headers::new();
                    h.status(201);
                    h.set("Content-Length", "0");
                    w.headers(h);
                    w.complete();
                });
            }
        }
        let mut p = H1ServerCodec::new(CompleteDeferred, HttpLimits::default(), false);
        let mut data: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        p.receive(&mut data).unwrap();
        let out = String::from_utf8(p.take_outbound()).unwrap();
        assert!(out.contains("HTTP/1.1 201"), "{out}");
    }
}
