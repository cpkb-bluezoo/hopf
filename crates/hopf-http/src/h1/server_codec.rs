// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.x server codec (inbound request / outbound response).
//!
//! Grammar-driven tokens from [`super::scan::HttpScanner`] advance the parse
//! FSM as each production completes (issue #3). Incomplete tokens stay in the
//! caller's slice — this module does **not** own a line buffer.

use std::sync::Arc;

use hopf_core::{ByteStreamHandler, ByteStreamLexer, ConnHandle, HandlerControl};

use crate::error::{HttpError, HttpResult};
use crate::stream::{ProtocolUpgradeHandler, ServerHandler, ServerWriter};
use crate::headers::Headers;
use crate::h1::response::H1ResponseControl;
use crate::h1::scan::{HttpScanPhase, HttpScanPhaseGate, HttpScanner, HttpToken};
use crate::limits::HttpLimits;
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
    BodyChunkedData,
    BodyChunkedTrailer,
    BodyUntilClose,
    /// Connection has switched protocols (WebSocket, etc.).
    Upgraded,
}

/// Where we are inside the request-line grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqLineStep {
    Method,
    Target,
    Version,
}

/// Where we are inside a header field-line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderStep {
    /// Expect field-name `Word`, obs-fold `Sp`, or empty `Crlf`.
    Name,
    /// Saw name; expect `Colon`.
    Colon,
    /// Collecting value (`Text` / fold); `Crlf` ends this line of the value.
    Value,
}

/// Incremental HTTP/1.x request parser + response framer for one connection.
pub struct H1ServerCodec<H: ServerHandler> {
    lexer: ByteStreamLexer<HttpScanner, Driver<H>>,
}

impl<H: ServerHandler> H1ServerCodec<H> {
    /// Create a parser. `secure` sets `:scheme` to `https` vs `http`.
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

    /// Feed inbound bytes. Advances `data` past consumed input.
    pub fn receive(&mut self, data: &mut &[u8]) -> HttpResult<()> {
        let driver = self.lexer.handler_mut();
        if driver.fatal.is_some() {
            *data = &[];
            return Err(driver.fatal.clone().unwrap());
        }

        if driver.state == ParseState::Upgraded {
            if let Some(up) = driver.upgraded.as_mut() {
                if !data.is_empty() {
                    up.receive(data);
                    *data = &[];
                }
            }
            return Ok(());
        }

        // Activate upgrade installed during the last response write.
        if let Some(up) = driver.response.take_upgrade() {
            driver.upgraded = Some(up);
            driver.state = ParseState::Upgraded;
            if !data.is_empty() {
                if let Some(up) = driver.upgraded.as_mut() {
                    up.receive(data);
                }
                *data = &[];
            }
            return Ok(());
        }

        if driver.state == ParseState::BodyUntilClose {
            if !data.is_empty() {
                driver.deliver_until_close(data);
            }
            return driver.take_error();
        }

        self.lexer.feed(data);

        let driver = self.lexer.handler_mut();
        if let Some(up) = driver.response.take_upgrade() {
            driver.upgraded = Some(up);
            driver.state = ParseState::Upgraded;
            if !data.is_empty() {
                if let Some(up) = driver.upgraded.as_mut() {
                    up.receive(data);
                }
                *data = &[];
            }
            return driver.take_error();
        }

        if driver.state == ParseState::BodyUntilClose && !data.is_empty() {
            driver.deliver_until_close(data);
        }
        driver.take_error()
    }

    /// Connection EOF — completes until-close bodies.
    pub fn close(&mut self) -> HttpResult<()> {
        let driver = self.lexer.handler_mut();
        if let Some(up) = driver.upgraded.as_mut() {
            up.closed();
            return Ok(());
        }
        if driver.state == ParseState::BodyUntilClose {
            driver.finish_until_close();
        } else if driver.state != ParseState::RequestLine {
            driver.fail(HttpError::new(400, "incomplete HTTP message"));
        }
        driver.take_error()
    }

    /// Bytes queued for the peer (100-continue, responses, errors, upgrade).
    pub fn take_outbound(&mut self) -> Vec<u8> {
        let driver = self.lexer.handler_mut();
        let mut out = driver.response.take_outbound();
        if let Some(up) = driver.upgraded.as_mut() {
            out.extend(up.take_outbound());
        }
        out
    }

    /// Whether the peer should be closed after flushing outbound data.
    pub fn wants_close(&self) -> bool {
        let d = self.lexer.handler();
        d.response.wants_close() || d.fatal.is_some()
    }

    /// Bind the transport [`ConnHandle`] (call from `H1Endpoint` on connect/receive).
    pub fn bind_conn_handle(&mut self, conn: ConnHandle) {
        self.lexer.handler_mut().response.bind_conn(conn);
    }

    /// Whether deferred execute left bytes that still need an endpoint flush.
    pub fn needs_flush(&self) -> bool {
        self.lexer.handler().response.needs_flush()
    }

    /// Whether request-body delivery is paused for this connection.
    pub fn pause_request_body(&self) -> bool {
        self.lexer.handler().response.pause_request_body_flag()
    }

    /// Replace the application handler (e.g. after factory creates a new one).
    pub fn set_handler(&mut self, handler: H) {
        self.lexer.handler_mut().app = Some(handler);
    }

    /// Method captured so far on the in-progress request-line (tests / debugging).
    pub fn partial_method(&self) -> Option<&str> {
        self.lexer.handler().partial_method.as_deref()
    }

    /// Request-target captured so far on the in-progress request-line.
    pub fn partial_target(&self) -> Option<&str> {
        self.lexer.handler().partial_target.as_deref()
    }
}

struct Driver<H: ServerHandler> {
    app: Option<H>,
    limits: HttpLimits,
    secure: bool,
    phase: HttpScanPhaseGate,
    state: ParseState,
    req_step: ReqLineStep,
    header_step: HeaderStep,
    /// Filled as request-line tokens arrive (before app callbacks).
    partial_method: Option<String>,
    partial_target: Option<String>,
    /// True once the HTTP-version `Word` has been accepted.
    request_line_version_ready: bool,
    version: HttpVersion,
    headers: Headers,
    pending_name: Option<String>,
    pending_value: String,
    content_length: Option<u64>,
    body_received: u64,
    chunked: bool,
    chunk_data_left: usize,
    chunk_crlf_got: usize,
    chunk_crlf_buf: [u8; 2],
    /// Accumulates chunk-size `Word` (may include `;ext`).
    chunk_size_word: String,
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
    fn new(handler: H, limits: HttpLimits, secure: bool, phase: HttpScanPhaseGate) -> Self {
        Self {
            app: Some(handler),
            limits,
            secure,
            phase,
            state: ParseState::RequestLine,
            req_step: ReqLineStep::Method,
            header_step: HeaderStep::Name,
            partial_method: None,
            partial_target: None,
            request_line_version_ready: false,
            version: HttpVersion::Http11,
            headers: Headers::new(),
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

    fn set_phase(&self, phase: HttpScanPhase) {
        self.phase.set(phase);
    }

    fn window_str<'a>(&self, window: &'a [u8]) -> HttpResult<&'a str> {
        std::str::from_utf8(window).map_err(|_| HttpError::new(400, "invalid UTF-8/ASCII"))
    }

    fn process_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        if self.fatal.is_some() {
            return HandlerControl::Stop;
        }
        match self.state {
            ParseState::RequestLine => self.on_request_line_token(ty, window),
            ParseState::Header | ParseState::BodyChunkedTrailer => {
                self.on_header_token(ty, window)
            }
            ParseState::BodyChunkedSize => self.on_chunk_size_token(ty, window),
            ParseState::Body | ParseState::BodyChunkedData | ParseState::BodyUntilClose => {
                HandlerControl::Continue
            }
            ParseState::Upgraded => HandlerControl::Stop,
        }
    }

    fn on_request_line_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        self.line_too_long_status = 414;
        match (self.req_step, ty) {
            (ReqLineStep::Method, HttpToken::Word) => {
                let s = match self.window_str(window) {
                    Ok(s) => s,
                    Err(e) => {
                        self.fail(e);
                        return HandlerControl::Stop;
                    }
                };
                if s.bytes().any(|b| b < 0x20 && b != b'\t') {
                    self.fail(HttpError::new(400, "CTL in method"));
                    return HandlerControl::Stop;
                }
                if !is_token(s) {
                    self.fail(HttpError::new(400, "invalid method"));
                    return HandlerControl::Stop;
                }
                if !is_default_method(s) {
                    self.fail(HttpError::new(501, "method not implemented"));
                    return HandlerControl::Stop;
                }
                self.partial_method = Some(s.to_string());
                self.req_step = ReqLineStep::Target;
                HandlerControl::Continue
            }
            (ReqLineStep::Method, HttpToken::Sp) => {
                self.fail(HttpError::new(400, "empty method"));
                HandlerControl::Stop
            }
            (ReqLineStep::Target, HttpToken::Sp) => HandlerControl::Continue,
            (ReqLineStep::Target, HttpToken::Word) => {
                let s = match self.window_str(window) {
                    Ok(s) => s,
                    Err(e) => {
                        self.fail(e);
                        return HandlerControl::Stop;
                    }
                };
                if !is_valid_request_target(s) {
                    self.fail(HttpError::new(400, "invalid request-target"));
                    return HandlerControl::Stop;
                }
                self.partial_target = Some(s.to_string());
                self.req_step = ReqLineStep::Version;
                HandlerControl::Continue
            }
            (ReqLineStep::Version, HttpToken::Sp) => HandlerControl::Continue,
            (ReqLineStep::Version, HttpToken::Word) => {
                let s = match self.window_str(window) {
                    Ok(s) => s,
                    Err(e) => {
                        self.fail(e);
                        return HandlerControl::Stop;
                    }
                };
                let method = self.partial_method.as_deref().unwrap_or("");
                let target = self.partial_target.as_deref().unwrap_or("");
                let Some(version) = HttpVersion::parse(s) else {
                    if s == "HTTP/2.0" && method == "PRI" && target == "*" {
                        self.fail(HttpError::new(505, "HTTP/2 preface not supported yet"));
                    } else {
                        self.fail(HttpError::new(505, "HTTP version not supported"));
                    }
                    return HandlerControl::Stop;
                };
                self.version = version;
                if version == HttpVersion::Http10 {
                    self.response.set_close_connection(true);
                }
                self.request_line_version_ready = true;
                HandlerControl::Continue
            }
            (_, HttpToken::Crlf) => {
                if !self.request_line_version_ready
                    || self.partial_method.is_none()
                    || self.partial_target.is_none()
                {
                    self.fail(HttpError::new(400, "malformed request-line"));
                    return HandlerControl::Stop;
                }
                let method = self.partial_method.clone().unwrap();
                let target = self.partial_target.clone().unwrap();
                self.headers = Headers::new();
                self.headers.add(":method", method);
                self.headers.add(":path", target);
                self.headers
                    .add(":scheme", if self.secure { "https" } else { "http" });
                self.state = ParseState::Header;
                self.header_step = HeaderStep::Name;
                self.line_too_long_status = 431;
                self.set_phase(HttpScanPhase::Header);
                HandlerControl::Continue
            }
            _ => {
                self.fail(HttpError::new(400, "malformed request-line"));
                HandlerControl::Stop
            }
        }
    }

    fn on_header_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        self.line_too_long_status = if self.state == ParseState::BodyChunkedSize {
            400
        } else {
            431
        };
        if self.headers.len() >= self.limits.max_header_count
            && matches!(self.header_step, HeaderStep::Name)
            && ty == HttpToken::Word
        {
            self.fail(HttpError::new(431, "too many headers"));
            return HandlerControl::Stop;
        }

        match (self.header_step, ty) {
            (HeaderStep::Name, HttpToken::Crlf) => {
                // Empty line — end of header/trailer section.
                if self.state == ParseState::BodyChunkedTrailer {
                    self.finish_request_with_body();
                    self.enter_request_line();
                    return HandlerControl::Continue;
                }
                self.end_headers()
            }
            (HeaderStep::Name, HttpToken::Sp) => {
                // Obs-fold continuation of previous field value.
                if self.pending_name.is_none() {
                    self.fail(HttpError::new(400, "obs-fold without field"));
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
                if !is_valid_header_name(&name) {
                    self.fail(HttpError::new(400, "invalid header name"));
                    return HandlerControl::Stop;
                }
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
            // Non-empty trailers: accept then ignore values (Gumdrop H1 gap).
            (HeaderStep::Name | HeaderStep::Colon | HeaderStep::Value, _)
                if self.state == ParseState::BodyChunkedTrailer =>
            {
                if ty == HttpToken::Colon {
                    self.header_step = HeaderStep::Value;
                    return HandlerControl::LatchText;
                }
                if ty == HttpToken::Crlf {
                    self.header_step = HeaderStep::Name;
                }
                HandlerControl::Continue
            }
            _ => {
                self.fail(HttpError::new(400, "malformed header"));
                HandlerControl::Stop
            }
        }
    }

    fn on_chunk_size_token(&mut self, ty: HttpToken, window: &[u8]) -> HandlerControl {
        self.line_too_long_status = 400;
        match ty {
            HttpToken::Word => {
                let s: String = window.iter().map(|&b| b as char).collect();
                self.chunk_size_word.push_str(&s);
                HandlerControl::Continue
            }
            HttpToken::Crlf => {
                let line = std::mem::take(&mut self.chunk_size_word);
                let semi = line.find(';');
                if semi.is_some_and(|i| line[i..].contains('"')) {
                    self.fail(HttpError::new(400, "quoted chunk-ext"));
                    return HandlerControl::Stop;
                }
                let size_str = semi.map(|i| &line[..i]).unwrap_or(&line).trim();
                let Ok(chunk_size) = usize::from_str_radix(size_str, 16) else {
                    self.fail(HttpError::new(400, "bad chunk size"));
                    return HandlerControl::Stop;
                };
                if chunk_size > self.limits.max_chunk_size {
                    self.fail(HttpError::new(400, "chunk too large"));
                    return HandlerControl::Stop;
                }
                if self.body_received.saturating_add(chunk_size as u64)
                    > self.limits.max_request_body as u64
                {
                    self.fail(HttpError::new(413, "request body too large"));
                    return HandlerControl::Stop;
                }
                if chunk_size == 0 {
                    self.state = ParseState::BodyChunkedTrailer;
                    self.header_step = HeaderStep::Name;
                    self.set_phase(HttpScanPhase::Header);
                    return HandlerControl::Continue;
                }
                self.chunk_data_left = chunk_size;
                self.chunk_crlf_got = 0;
                self.state = ParseState::BodyChunkedData;
                HandlerControl::EnterRaw((chunk_size + 2) as u64)
            }
            _ => {
                self.fail(HttpError::new(400, "bad chunk size line"));
                HandlerControl::Stop
            }
        }
    }

    fn commit_pending_header(&mut self) {
        if let Some(name) = self.pending_name.take() {
            let value = self.pending_value.trim().to_string();
            self.pending_value.clear();
            self.headers.add(name, value);
        }
    }

    fn end_headers(&mut self) -> HandlerControl {
        self.commit_pending_header();

        if self.version == HttpVersion::Http11 {
            let host_count = self
                .headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("host") || h.name == ":authority")
                .count();
            if host_count != 1 {
                self.fail(HttpError::new(400, "Host required"));
                return HandlerControl::Stop;
            }
            let host = self
                .headers
                .get("host")
                .or_else(|| self.headers.get(":authority"))
                .unwrap_or("");
            if !is_valid_host(host) {
                self.fail(HttpError::new(400, "invalid Host"));
                return HandlerControl::Stop;
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
                self.fail(HttpError::new(400, "invalid Transfer-Encoding"));
                return HandlerControl::Stop;
            }
            if is_chunked_te(te) {
                self.chunked = true;
                self.headers.remove("content-length");
            }
        } else if let Some(cl) = self.headers.get("content-length") {
            match parse_content_length(cl) {
                Some(n) => self.content_length = Some(n),
                None => {
                    self.fail(HttpError::new(400, "invalid Content-Length"));
                    return HandlerControl::Stop;
                }
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
            self.response
                .extend_out(b"HTTP/1.1 100 Continue\r\n\r\n");
        }

        let hdrs = self.headers.clone();
        self.with_app_response(|app, resp| app.headers(resp, &hdrs));

        if self.fatal.is_some() {
            return HandlerControl::Stop;
        }

        if self.chunked {
            self.state = ParseState::BodyChunkedSize;
            self.chunk_size_word.clear();
            self.set_phase(HttpScanPhase::ChunkSize);
            return HandlerControl::Continue;
        }
        match self.content_length {
            Some(0) => {
                self.finish_request_no_body();
                self.enter_request_line();
                HandlerControl::Continue
            }
            Some(n) => {
                self.state = ParseState::Body;
                self.body_received = 0;
                HandlerControl::EnterRaw(n)
            }
            None if self.version == HttpVersion::Http10 => {
                self.state = ParseState::BodyUntilClose;
                HandlerControl::Stop
            }
            None => {
                self.fail(HttpError::new(411, "Length Required"));
                HandlerControl::Stop
            }
        }
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

    fn enter_request_line(&mut self) {
        self.state = ParseState::RequestLine;
        self.req_step = ReqLineStep::Method;
        self.header_step = HeaderStep::Name;
        self.partial_method = None;
        self.partial_target = None;
        self.request_line_version_ready = false;
        self.set_phase(HttpScanPhase::RequestLine);
        self.line_too_long_status = 414;
    }

    fn reset_message_fields(&mut self) {
        self.headers = Headers::new();
        self.pending_name = None;
        self.pending_value.clear();
        self.content_length = None;
        self.body_received = 0;
        self.chunked = false;
        self.chunk_data_left = 0;
        self.chunk_crlf_got = 0;
        self.chunk_size_word.clear();
        self.body_started = false;
        self.response.reset_message_fields();
        self.partial_method = None;
        self.partial_target = None;
        self.request_line_version_ready = false;
        self.req_step = ReqLineStep::Method;
        self.header_step = HeaderStep::Name;
    }

    fn deliver_body_cl(&mut self, slice: &[u8]) -> HandlerControl {
        if self.limits.max_request_body > 0
            && self.body_received.saturating_add(slice.len() as u64)
                > self.limits.max_request_body as u64
        {
            self.fail(HttpError::new(413, "request body too large"));
            return HandlerControl::Stop;
        }
        self.ensure_body_started();
        self.with_app_response(|app, resp| app.request_body_content(resp, slice));
        self.body_received += slice.len() as u64;
        if self.body_received >= self.content_length.unwrap_or(0) {
            self.finish_request_with_body();
            self.enter_request_line();
        }
        HandlerControl::Continue
    }

    fn deliver_chunk_data(&mut self, mut slice: &[u8]) -> HandlerControl {
        while !slice.is_empty() {
            if self.chunk_data_left > 0 {
                let n = slice.len().min(self.chunk_data_left);
                let (data, rest) = slice.split_at(n);
                self.ensure_body_started();
                self.with_app_response(|app, resp| app.request_body_content(resp, data));
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
                    self.fail(HttpError::new(400, "bad chunk CRLF"));
                    return HandlerControl::Stop;
                }
                self.state = ParseState::BodyChunkedSize;
                self.chunk_size_word.clear();
                self.chunk_crlf_got = 0;
                self.set_phase(HttpScanPhase::ChunkSize);
            }
        }
        HandlerControl::Continue
    }

    fn ensure_body_started(&mut self) {
        if !self.body_started {
            self.body_started = true;
            self.with_app_response(|app, resp| app.start_request_body(resp));
        }
    }

    fn deliver_until_close(&mut self, data: &mut &[u8]) {
        if data.is_empty() {
            return;
        }
        self.ensure_body_started();
        let chunk = *data;
        self.with_app_response(|app, resp| app.request_body_content(resp, chunk));
        self.body_received += chunk.len() as u64;
        *data = &[];
    }

    fn finish_until_close(&mut self) {
        self.finish_request_with_body();
        self.enter_request_line();
    }
}

impl<H: ServerHandler> ByteStreamHandler for Driver<H> {
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
        let status = self.line_too_long_status;
        let msg = match status {
            414 => "request-line too long",
            431 => "header line too long",
            _ => "token too long",
        };
        self.fail(HttpError::new(status, msg));
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

    fn feed_all(p: &mut H1ServerCodec<Arc<Mutex<Rec>>>, chunks: &[&[u8]]) {
        let mut pending = Vec::new();
        for c in chunks {
            pending.extend_from_slice(c);
            let mut slice = pending.as_slice();
            let before = slice.len();
            p.receive(&mut slice).unwrap();
            let consumed = before - slice.len();
            pending.drain(..consumed);
        }
        assert!(pending.is_empty(), "leftover {pending:?}");
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
