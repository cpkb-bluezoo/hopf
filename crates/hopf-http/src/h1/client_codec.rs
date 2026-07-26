// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.x client codec (outbound request / inbound response).
//!
//! Response parsing is driven by [`super::parse::H1Scanner`] in
//! [`FirstLineKind::Status`] mode; see `h1::parse` for the streaming
//! contract (every byte consumed, partial tokens owned by the scanner).

use crate::error::{HttpError, HttpResult};
use crate::h1::parse::{parse_version, FirstLineKind, H1Events, H1Scanner, Next};
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{ClientHandler, ClientWriter};
use crate::utils::{is_chunked_te, is_invalid_te, method_implies_no_body, parse_content_length};
use crate::version::HttpVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Waiting to send the request (after `on_connected`).
    Idle,
    StatusLine,
    Header,
    Body,
    BodyChunkedSize,
    BodyChunkedTrailer,
    BodyUntilClose,
    Done,
}

/// Incremental HTTP/1.x client codec for one Stream on an H1 Endpoint.
pub struct H1ClientCodec<H: ClientHandler> {
    scanner: H1Scanner,
    driver: Driver<H>,
}

impl<H: ClientHandler> H1ClientCodec<H> {
    /// Create a codec. `secure` sets `:scheme` default when the handler omits it.
    pub fn new(handler: H, limits: HttpLimits, secure: bool) -> Self {
        let max_line = limits.max_line_length;
        Self {
            scanner: H1Scanner::new(FirstLineKind::Status, max_line),
            driver: Driver::new(handler, limits, secure),
        }
    }

    /// Assign stream id (for logging / future multiplex).
    pub fn set_stream_id(&mut self, id: u64) {
        self.driver.stream_id = id;
    }

    /// Endpoint connected — start the outbound request.
    pub fn on_connected(&mut self) {
        self.driver.kickoff();
    }

    /// Feed inbound response bytes. Consumes everything given.
    pub fn receive(&mut self, data: &mut &[u8]) -> HttpResult<()> {
        if let Some(err) = self.driver.fatal.clone() {
            *data = &[];
            return Err(err);
        }
        if matches!(self.driver.state, ParseState::Idle | ParseState::Done) {
            *data = &[];
            return Ok(());
        }
        let consumed = self.scanner.push(data, &mut self.driver);
        *data = &data[consumed..];
        if self.driver.fatal.is_some() || self.driver.state == ParseState::Done {
            *data = &[];
        }
        self.driver.take_error()
    }

    /// Connection EOF.
    pub fn close(&mut self) -> HttpResult<()> {
        if self.driver.state == ParseState::BodyUntilClose {
            self.driver.finish_response();
        } else if !matches!(self.driver.state, ParseState::Idle | ParseState::Done) {
            self.driver.fail(HttpError::new(0, "incomplete HTTP response"));
        }
        self.driver.take_error()
    }

    /// Bytes queued for the peer.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.driver.out)
    }

    /// Whether the peer should be closed after flush.
    pub fn wants_close(&self) -> bool {
        self.driver.close_connection || self.driver.fatal.is_some()
    }
}

struct Driver<H: ClientHandler> {
    app: Option<H>,
    #[allow(dead_code)]
    limits: HttpLimits,
    secure: bool,
    state: ParseState,
    #[allow(dead_code)]
    stream_id: u64,
    version: HttpVersion,
    response_headers: Headers,
    /// Field name awaiting its value.
    pending_name: Option<String>,
    content_length: Option<u64>,
    body_received: u64,
    chunked: bool,
    body_started: bool,
    close_connection: bool,
    out: Vec<u8>,
    req_headers: Option<Headers>,
    req_headers_sent: bool,
    req_chunked: bool,
    req_method: String,
    fatal: Option<HttpError>,
}

impl<H: ClientHandler> Driver<H> {
    fn new(handler: H, limits: HttpLimits, secure: bool) -> Self {
        Self {
            app: Some(handler),
            limits,
            secure,
            state: ParseState::Idle,
            stream_id: 1,
            version: HttpVersion::Http11,
            response_headers: Headers::new(),
            pending_name: None,
            content_length: None,
            body_received: 0,
            chunked: false,
            body_started: false,
            close_connection: false,
            out: Vec::new(),
            req_headers: None,
            req_headers_sent: false,
            req_chunked: false,
            req_method: String::new(),
            fatal: None,
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
    }

    fn fail_stop(&mut self, err: HttpError) -> Next {
        self.fail(err);
        Next::Stop
    }

    fn kickoff(&mut self) {
        if self.state != ParseState::Idle {
            return;
        }
        let mut app = self.app.take().expect("handler");
        {
            let mut view = UaView {
                out: &mut self.out,
                secure: self.secure,
                req_headers: &mut self.req_headers,
                req_headers_sent: &mut self.req_headers_sent,
                req_chunked: &mut self.req_chunked,
                req_method: &mut self.req_method,
                version: self.version,
            };
            app.start(&mut view);
        }
        self.app = Some(app);
        self.state = ParseState::StatusLine;
    }

    fn with_app<R>(&mut self, f: impl FnOnce(&mut H, &mut UaView<'_>) -> R) -> R {
        let mut app = self.app.take().expect("handler");
        let mut view = UaView {
            out: &mut self.out,
            secure: self.secure,
            req_headers: &mut self.req_headers,
            req_headers_sent: &mut self.req_headers_sent,
            req_chunked: &mut self.req_chunked,
            req_method: &mut self.req_method,
            version: self.version,
        };
        let r = f(&mut app, &mut view);
        self.app = Some(app);
        r
    }

    fn ensure_body_started(&mut self) {
        if !self.body_started {
            self.body_started = true;
            self.with_app(|app, req| app.start_response_body(req));
        }
    }

    fn finish_response(&mut self) {
        if self.state == ParseState::Done {
            return;
        }
        if self.body_started {
            self.with_app(|app, req| {
                app.end_response_body(req);
                app.response_complete(req);
            });
        } else {
            self.with_app(|app, req| app.response_complete(req));
        }
        self.state = ParseState::Done;
    }

    /// Validate the completed response header block and decide what follows.
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
            // Informational — never terminal. Surface it, discard it, and
            // keep reading on this same connection for the real final
            // status line (RFC 9110 §15.2: a 1xx MUST be followed by a
            // final response to the same request).
            let hdrs = self.response_headers.clone();
            self.with_app(|app, req| app.informational_response(req, &hdrs));
            if self.fatal.is_some() {
                return Next::Stop;
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
            // Same duplicate-Content-Length handling as the server side
            // (RFC 9112 §6.3): differing values are a framing error.
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
            // Only HEAD suppresses a *response* body; `method_implies_no_body`
            // concerns request bodies and must not be used here.
            self.content_length = Some(0);
            self.chunked = false;
        }

        let hdrs = self.response_headers.clone();
        self.with_app(|app, req| app.response_headers(req, &hdrs));

        if self.fatal.is_some() {
            return Next::Stop;
        }

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
}

impl<H: ClientHandler> H1Events for Driver<H> {
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
        // Trailers are accepted but not merged into the response header set.
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
        self.with_app(|app, req| app.response_body_content(req, value));
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

struct UaView<'a> {
    out: &'a mut Vec<u8>,
    secure: bool,
    req_headers: &'a mut Option<Headers>,
    req_headers_sent: &'a mut bool,
    req_chunked: &'a mut bool,
    req_method: &'a mut String,
    version: HttpVersion,
}

impl ClientWriter for UaView<'_> {
    fn headers(&mut self, mut headers: Headers) {
        if *self.req_headers_sent {
            return;
        }
        if let Some(m) = headers.method() {
            *self.req_method = m.to_string();
        }
        if !headers.contains(":scheme") {
            headers.add(":scheme", if self.secure { "https" } else { "http" });
        }
        *self.req_chunked = headers
            .get("transfer-encoding")
            .map(is_chunked_te)
            .unwrap_or(false);
        *self.req_headers = Some(headers);
    }

    fn start_request_body(&mut self) {
        self.flush_request_headers();
    }

    fn request_body_content(&mut self, data: &[u8]) {
        if !*self.req_headers_sent {
            self.flush_request_headers();
        }
        if *self.req_chunked {
            let hdr = format!("{:x}\r\n", data.len());
            self.out.extend_from_slice(hdr.as_bytes());
            self.out.extend_from_slice(data);
            self.out.extend_from_slice(b"\r\n");
        } else {
            self.out.extend_from_slice(data);
        }
    }

    fn end_request_body(&mut self) {
        if !*self.req_headers_sent {
            self.flush_request_headers();
        }
        if *self.req_chunked {
            self.out.extend_from_slice(b"0\r\n\r\n");
            *self.req_chunked = false;
        }
    }

    fn complete_request(&mut self) {
        if !*self.req_headers_sent {
            self.flush_request_headers();
        }
        if *self.req_chunked {
            self.out.extend_from_slice(b"0\r\n\r\n");
            *self.req_chunked = false;
        }
    }
}

impl UaView<'_> {
    fn flush_request_headers(&mut self) {
        if *self.req_headers_sent {
            return;
        }
        let headers = self.req_headers.take().unwrap_or_default();
        let method = headers.method().unwrap_or("GET");
        *self.req_method = method.to_string();
        let path = headers.path().unwrap_or("/");
        let ver = self.version.as_str();
        let mut msg = format!("{method} {path} {ver}\r\n");

        let host = headers
            .get("host")
            .or_else(|| headers.get(":authority"))
            .unwrap_or("localhost");
        if !headers.contains("host") {
            msg.push_str(&format!("Host: {host}\r\n"));
        }
        for h in headers.iter() {
            if h.name.starts_with(':') {
                continue;
            }
            msg.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
        let has_cl = headers.contains("content-length");
        let has_te = headers.contains("transfer-encoding");
        if !has_cl && !has_te && !method_implies_no_body(method) {
            if matches!(method, "POST" | "PUT" | "PATCH") {
                msg.push_str("Content-Length: 0\r\n");
            }
        }
        msg.push_str("\r\n");
        self.out.extend_from_slice(msg.as_bytes());
        *self.req_headers_sent = true;
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
        informational: Vec<u16>,
    }

    struct GetHello {
        host: String,
        rec: Arc<Mutex<Rec>>,
    }

    impl ClientHandler for GetHello {
        fn start(&mut self, request: &mut dyn ClientWriter) {
            let mut h = Headers::new();
            h.set(":method", "GET");
            h.set(":path", "/");
            h.set("host", &self.host);
            request.headers(h);
            request.complete_request();
        }

        fn informational_response(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec
                .lock()
                .unwrap()
                .informational
                .push(headers.status_code());
        }

        fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
            self.rec.lock().unwrap().status = headers.status_code();
        }

        fn response_body_content(&mut self, _request: &mut dyn ClientWriter, data: &[u8]) {
            self.rec.lock().unwrap().body.extend_from_slice(data);
        }

        fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
            self.rec.lock().unwrap().done = true;
        }
    }

    #[test]
    fn get_response_with_content_length() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut c = H1ClientCodec::new(
            GetHello {
                host: "ex.com".into(),
                rec: Arc::clone(&rec),
            },
            HttpLimits::default(),
            false,
        );
        c.on_connected();
        let req = String::from_utf8(c.take_outbound()).unwrap();
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
        assert!(
            req.to_ascii_lowercase().contains("host: ex.com\r\n"),
            "request was {req:?}"
        );

        let mut data: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        c.receive(&mut data).unwrap();
        assert!(data.is_empty());
        let g = rec.lock().unwrap();
        assert_eq!(g.status, 200);
        assert_eq!(g.body, b"hello");
        assert!(g.done);
    }

    #[test]
    fn duplicate_conflicting_content_length_in_response_rejected() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut c = H1ClientCodec::new(
            GetHello {
                host: "ex.com".into(),
                rec: Arc::clone(&rec),
            },
            HttpLimits::default(),
            false,
        );
        c.on_connected();
        let _ = c.take_outbound();

        let mut data: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
        assert!(c.receive(&mut data).is_err());
    }

    /// A `100 Continue` sent before the real response must not be delivered
    /// as the terminal response — the client keeps reading on the same
    /// connection for the actual final status line (RFC 9110 §15.2).
    #[test]
    fn informational_1xx_response_is_not_terminal() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut c = H1ClientCodec::new(
            GetHello {
                host: "ex.com".into(),
                rec: Arc::clone(&rec),
            },
            HttpLimits::default(),
            false,
        );
        c.on_connected();
        let _ = c.take_outbound();

        let mut data: &[u8] =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        c.receive(&mut data).unwrap();
        assert!(data.is_empty());

        let g = rec.lock().unwrap();
        assert_eq!(g.informational, vec![100]);
        assert_eq!(g.status, 200);
        assert_eq!(g.body, b"hello");
        assert!(g.done);
    }

    /// Same, but the 1xx and the real response arrive in separate `receive`
    /// calls — the discard-and-keep-reading state must survive that split.
    #[test]
    fn informational_1xx_split_across_receive_calls() {
        let rec = Arc::new(Mutex::new(Rec::default()));
        let mut c = H1ClientCodec::new(
            GetHello {
                host: "ex.com".into(),
                rec: Arc::clone(&rec),
            },
            HttpLimits::default(),
            false,
        );
        c.on_connected();
        let _ = c.take_outbound();

        let mut first: &[u8] = b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n";
        c.receive(&mut first).unwrap();
        assert!(first.is_empty());
        assert_eq!(rec.lock().unwrap().informational, vec![103]);
        assert_eq!(rec.lock().unwrap().status, 0, "no terminal response yet");

        let mut second: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        c.receive(&mut second).unwrap();
        assert!(second.is_empty());

        let g = rec.lock().unwrap();
        assert_eq!(g.status, 200);
        assert_eq!(g.body, b"ok");
        assert!(g.done);
    }
}
