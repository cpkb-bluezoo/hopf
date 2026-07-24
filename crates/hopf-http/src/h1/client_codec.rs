// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.x client codec (outbound request / inbound response).

use hopf_core::{ByteStreamHandler, ByteStreamLexer, HandlerControl};

use crate::error::{HttpError, HttpResult};
use crate::h1::scan::{HttpScanPhase, HttpScanPhaseGate, HttpScanner, HttpToken};
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{ClientHandler, ClientWriter};
use crate::utils::{
    is_chunked_te, is_invalid_te, method_implies_no_body, parse_content_length,
};
use crate::version::HttpVersion;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Waiting to send the request (after `on_connected`).
    Idle,
    StatusLine,
    Header,
    Body,
    BodyChunkedSize,
    BodyChunkedData,
    BodyChunkedTrailer,
    BodyUntilClose,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusStep {
    Version,
    Code,
    Reason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderStep {
    Name,
    Colon,
    Value,
}

/// Incremental HTTP/1.x client codec for one Stream on an H1 Endpoint.
pub struct H1ClientCodec<H: ClientHandler> {
    lexer: ByteStreamLexer<HttpScanner, Driver<H>>,
}

impl<H: ClientHandler> H1ClientCodec<H> {
    /// Create a codec. `secure` sets `:scheme` default when the handler omits it.
    pub fn new(handler: H, limits: HttpLimits, secure: bool) -> Self {
        let max_line = limits.max_line_length;
        let phase = HttpScanPhaseGate::new();
        let driver = Driver::new(handler, limits, secure, phase.clone());
        Self {
            lexer: ByteStreamLexer::new(
                HttpScanner::new(phase),
                driver,
                max_line,
                HttpToken::Crlf,
                HttpToken::Text,
            ),
        }
    }

    /// Assign stream id (for logging / future multiplex).
    pub fn set_stream_id(&mut self, id: u64) {
        self.lexer.handler_mut().stream_id = id;
    }

    /// Endpoint connected — start the outbound request.
    pub fn on_connected(&mut self) {
        self.lexer.handler_mut().kickoff();
    }

    /// Feed inbound response bytes.
    pub fn receive(&mut self, data: &mut &[u8]) -> HttpResult<()> {
        let driver = self.lexer.handler_mut();
        if driver.fatal.is_some() {
            *data = &[];
            return Err(driver.fatal.clone().unwrap());
        }
        if driver.state == ParseState::BodyUntilClose {
            if !data.is_empty() {
                driver.deliver_until_close(data);
            }
            return driver.take_error();
        }
        if matches!(driver.state, ParseState::Idle | ParseState::Done) {
            return Ok(());
        }
        self.lexer.feed(data);
        let driver = self.lexer.handler_mut();
        if driver.state == ParseState::BodyUntilClose && !data.is_empty() {
            driver.deliver_until_close(data);
        }
        driver.take_error()
    }

    /// Connection EOF.
    pub fn close(&mut self) -> HttpResult<()> {
        let driver = self.lexer.handler_mut();
        if driver.state == ParseState::BodyUntilClose {
            driver.finish_until_close();
        } else if !matches!(driver.state, ParseState::Idle | ParseState::Done) {
            driver.fail(HttpError::new(0, "incomplete HTTP response"));
        }
        driver.take_error()
    }

    /// Bytes queued for the peer.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.lexer.handler_mut().out)
    }

    /// Whether the peer should be closed after flush.
    pub fn wants_close(&self) -> bool {
        let d = self.lexer.handler();
        d.close_connection || d.fatal.is_some()
    }
}

struct Driver<H: ClientHandler> {
    app: Option<H>,
    limits: HttpLimits,
    secure: bool,
    phase: HttpScanPhaseGate,
    state: ParseState,
    status_step: StatusStep,
    header_step: HeaderStep,
    #[allow(dead_code)]
    stream_id: u64,
    version: HttpVersion,
    response_headers: Headers,
    pending_name: Option<String>,
    pending_value: String,
    content_length: Option<u64>,
    body_received: u64,
    chunked: bool,
    chunk_data_left: usize,
    chunk_crlf_got: usize,
    chunk_crlf_buf: [u8; 2],
    chunk_size_word: String,
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
    fn new(handler: H, limits: HttpLimits, secure: bool, phase: HttpScanPhaseGate) -> Self {
        Self {
            app: Some(handler),
            limits,
            secure,
            phase,
            state: ParseState::Idle,
            status_step: StatusStep::Version,
            header_step: HeaderStep::Name,
            stream_id: 1,
            version: HttpVersion::Http11,
            response_headers: Headers::new(),
            pending_name: None,
            pending_value: String::new(),
            content_length: None,
            body_received: 0,
            chunked: false,
            chunk_data_left: 0,
            chunk_crlf_got: 0,
            chunk_crlf_buf: [0; 2],
            chunk_size_word: String::new(),
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
        self.status_step = StatusStep::Version;
        self.phase.set(HttpScanPhase::RequestLine);
        let _ = self.limits;
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

    fn process_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        if self.fatal.is_some() {
            return HandlerControl::Stop;
        }
        match self.state {
            ParseState::StatusLine => self.on_status_token(ty, window),
            ParseState::Header | ParseState::BodyChunkedTrailer => self.on_header_token(ty, window),
            ParseState::BodyChunkedSize => self.on_chunk_size_token(ty, window),
            _ => HandlerControl::Continue,
        }
    }

    fn on_status_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        match (self.status_step, ty) {
            (StatusStep::Version, HttpToken::Word) => {
                let s = std::str::from_utf8(window).unwrap_or("");
                let Some(v) = HttpVersion::parse(s) else {
                    self.fail(HttpError::new(0, "bad response version"));
                    return HandlerControl::Stop;
                };
                self.version = v;
                self.status_step = StatusStep::Code;
                HandlerControl::Continue
            }
            (StatusStep::Version, HttpToken::Sp) => HandlerControl::Continue,
            (StatusStep::Code, HttpToken::Sp) => HandlerControl::Continue,
            (StatusStep::Code, HttpToken::Word) => {
                let s = std::str::from_utf8(window).unwrap_or("");
                let Ok(code) = s.parse::<u16>() else {
                    self.fail(HttpError::new(0, "bad status code"));
                    return HandlerControl::Stop;
                };
                self.response_headers.status(code);
                self.status_step = StatusStep::Reason;
                HandlerControl::Continue
            }
            (StatusStep::Reason, HttpToken::Sp) => HandlerControl::LatchText,
            (StatusStep::Reason, HttpToken::Text) => HandlerControl::Continue,
            (StatusStep::Reason, HttpToken::Crlf) | (StatusStep::Code, HttpToken::Crlf) => {
                self.state = ParseState::Header;
                self.header_step = HeaderStep::Name;
                self.phase.set(HttpScanPhase::Header);
                HandlerControl::Continue
            }
            _ => {
                self.fail(HttpError::new(0, "malformed status line"));
                HandlerControl::Stop
            }
        }
    }

    fn on_header_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        match (self.header_step, ty) {
            (HeaderStep::Name, HttpToken::Crlf) => {
                if self.state == ParseState::BodyChunkedTrailer {
                    self.finish_response();
                    return HandlerControl::Continue;
                }
                self.end_response_headers()
            }
            (HeaderStep::Name, HttpToken::Sp) => {
                if self.pending_name.is_none() {
                    self.fail(HttpError::new(0, "obs-fold without field"));
                    return HandlerControl::Stop;
                }
                self.pending_value.push(' ');
                self.header_step = HeaderStep::Value;
                HandlerControl::LatchText
            }
            (HeaderStep::Name, HttpToken::Word) => {
                if self.pending_name.is_some() {
                    self.commit_pending_header();
                }
                let name: String = window.iter().map(|&b| b as char).collect();
                self.pending_name = Some(name);
                self.pending_value.clear();
                self.header_step = HeaderStep::Colon;
                HandlerControl::Continue
            }
            (HeaderStep::Colon, HttpToken::Colon) => {
                self.header_step = HeaderStep::Value;
                HandlerControl::LatchText
            }
            (HeaderStep::Value, HttpToken::Text) => {
                let s: String = window.iter().map(|&b| b as char).collect();
                self.pending_value.push_str(&s);
                HandlerControl::Continue
            }
            (HeaderStep::Value, HttpToken::Crlf) => {
                self.header_step = HeaderStep::Name;
                HandlerControl::Continue
            }
            _ => {
                self.fail(HttpError::new(0, "malformed response header"));
                HandlerControl::Stop
            }
        }
    }

    fn commit_pending_header(&mut self) {
        if let Some(name) = self.pending_name.take() {
            let value = self.pending_value.trim().to_string();
            self.pending_value.clear();
            self.response_headers.add(name, value);
        }
    }

    fn end_response_headers(&mut self) -> HandlerControl {
        self.commit_pending_header();

        if let Some(conn) = self.response_headers.get("connection") {
            if conn
                .split(',')
                .any(|p| p.trim().eq_ignore_ascii_case("close"))
            {
                self.close_connection = true;
            }
        }

        self.chunked = false;
        self.content_length = None;
        if let Some(te) = self.response_headers.get("transfer-encoding") {
            if is_invalid_te(te) {
                self.fail(HttpError::new(0, "invalid Transfer-Encoding"));
                return HandlerControl::Stop;
            }
            if is_chunked_te(te) {
                self.chunked = true;
            }
        } else if let Some(cl) = self.response_headers.get("content-length") {
            match parse_content_length(cl) {
                Some(n) => self.content_length = Some(n),
                None => {
                    self.fail(HttpError::new(0, "invalid Content-Length"));
                    return HandlerControl::Stop;
                }
            }
        }

        let status = self.response_headers.status_code();
        if (100..200).contains(&status) || status == 204 || status == 304 {
            self.content_length = Some(0);
            self.chunked = false;
        } else if self.req_method.eq_ignore_ascii_case("HEAD") {
            self.content_length = Some(0);
            self.chunked = false;
        }

        let hdrs = self.response_headers.clone();
        self.with_app(|app, req| app.response_headers(req, &hdrs));

        if self.chunked {
            self.state = ParseState::BodyChunkedSize;
            self.chunk_size_word.clear();
            self.phase.set(HttpScanPhase::ChunkSize);
            return HandlerControl::Continue;
        }
        match self.content_length {
            Some(0) => {
                self.finish_response();
                HandlerControl::Continue
            }
            Some(n) => {
                self.state = ParseState::Body;
                self.body_received = 0;
                HandlerControl::EnterRaw(n)
            }
            None => {
                self.state = ParseState::BodyUntilClose;
                HandlerControl::Stop
            }
        }
    }

    fn on_chunk_size_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        match ty {
            HttpToken::Word => {
                let s: String = window.iter().map(|&b| b as char).collect();
                self.chunk_size_word.push_str(&s);
                HandlerControl::Continue
            }
            HttpToken::Crlf => {
                let line = std::mem::take(&mut self.chunk_size_word);
                let semi = line.find(';');
                let size_str = semi.map(|i| &line[..i]).unwrap_or(&line).trim();
                let Ok(chunk_size) = usize::from_str_radix(size_str, 16) else {
                    self.fail(HttpError::new(0, "bad chunk size"));
                    return HandlerControl::Stop;
                };
                if chunk_size == 0 {
                    self.state = ParseState::BodyChunkedTrailer;
                    self.header_step = HeaderStep::Name;
                    self.phase.set(HttpScanPhase::Header);
                    return HandlerControl::Continue;
                }
                self.chunk_data_left = chunk_size;
                self.chunk_crlf_got = 0;
                self.state = ParseState::BodyChunkedData;
                HandlerControl::EnterRaw((chunk_size + 2) as u64)
            }
            _ => {
                self.fail(HttpError::new(0, "bad chunk size line"));
                HandlerControl::Stop
            }
        }
    }

    fn finish_response(&mut self) {
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

    fn deliver_body_cl(&mut self, slice: &[u8]) -> HandlerControl {
        self.ensure_body_started();
        self.with_app(|app, req| app.response_body_content(req, slice));
        self.body_received += slice.len() as u64;
        if self.body_received >= self.content_length.unwrap_or(0) {
            self.finish_response();
        }
        HandlerControl::Continue
    }

    fn deliver_chunk_data(&mut self, mut slice: &[u8]) -> HandlerControl {
        while !slice.is_empty() {
            if self.chunk_data_left > 0 {
                let n = slice.len().min(self.chunk_data_left);
                let (data, rest) = slice.split_at(n);
                self.ensure_body_started();
                self.with_app(|app, req| app.response_body_content(req, data));
                self.body_received += n as u64;
                self.chunk_data_left -= n;
                slice = rest;
                continue;
            }
            let need = 2 - self.chunk_crlf_got;
            let n = slice.len().min(need);
            self.chunk_crlf_buf[self.chunk_crlf_got..self.chunk_crlf_got + n]
                .copy_from_slice(&slice[..n]);
            self.chunk_crlf_got += n;
            slice = &slice[n..];
            if self.chunk_crlf_got == 2 {
                if self.chunk_crlf_buf != [b'\r', b'\n'] {
                    self.fail(HttpError::new(0, "bad chunk CRLF"));
                    return HandlerControl::Stop;
                }
                self.state = ParseState::BodyChunkedSize;
                self.chunk_size_word.clear();
                self.chunk_crlf_got = 0;
                self.phase.set(HttpScanPhase::ChunkSize);
            }
        }
        HandlerControl::Continue
    }

    fn ensure_body_started(&mut self) {
        if !self.body_started {
            self.body_started = true;
            self.with_app(|app, req| app.start_response_body(req));
        }
    }

    fn deliver_until_close(&mut self, data: &mut &[u8]) {
        if data.is_empty() {
            return;
        }
        self.ensure_body_started();
        let chunk = *data;
        self.with_app(|app, req| app.response_body_content(req, chunk));
        *data = &[];
    }

    fn finish_until_close(&mut self) {
        self.finish_response();
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

impl<H: ClientHandler> ByteStreamHandler for Driver<H> {
    type Token = HttpToken;

    fn token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        self.process_token(ty, window)
    }

    fn raw_bytes(&mut self, slice: &[u8]) -> HandlerControl {
        if self.fatal.is_some() {
            return HandlerControl::Stop;
        }
        match self.state {
            ParseState::Body => self.deliver_body_cl(slice),
            ParseState::BodyChunkedData => self.deliver_chunk_data(slice),
            _ => HandlerControl::Continue,
        }
    }

    fn token_too_long(&mut self) {
        self.fail(HttpError::new(0, "response token too long"));
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
}
