// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Gumdrop-shaped HTTP client request API ([`HttpRequest`], [`HttpResponseHandler`]).
//!
//! After [`HttpConnectionHandler::on_connected`], use [`HttpClientSessionHandle`]
//! (`get`, `post`, `method`, …), set headers on [`HttpRequest`], then either
//! [`HttpRequest::send`] (no body) or [`HttpRequest::start_request_body`] followed by
//! [`HttpRequest::request_body_content`] / [`HttpRequest::end_request_body`].

use std::io;
use std::sync::{Arc, Mutex};

use crate::headers::Headers;
use crate::version::HttpVersion;

/// Client-side error from [`HttpRequest`] or session operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpClientError {
    message: &'static str,
}

impl HttpClientError {
    pub(crate) fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for HttpClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for HttpClientError {}

/// Connection lifecycle for an outbound HTTP client (Gumdrop `HTTPClientHandler`).
pub trait HttpConnectionHandler: Send + Sync {
    /// Transport is ready; create and send requests via `session`.
    fn on_connected(&mut self, session: &mut HttpClientSessionHandle);

    /// Connection closed before or after requests completed.
    fn on_disconnected(&mut self) {}

    /// Transport or protocol failure on the connection.
    fn on_error(&mut self, _err: &io::Error) {}
}

/// Event-driven response callbacks (Gumdrop `HTTPResponseHandler`).
pub trait HttpResponseHandler: Send {
    /// 2xx status line received (before individual header callbacks).
    fn ok(&mut self, status: u16);

    /// 4xx/5xx (or other non-success) status received.
    fn error(&mut self, status: u16);

    /// One response or trailer header field.
    fn header(&mut self, name: &str, value: &str);

    /// Response body is starting.
    fn start_response_body(&mut self) {}

    /// Response body chunk.
    fn response_body_content(&mut self, data: &[u8]);

    /// Response body finished.
    fn end_response_body(&mut self) {}

    /// Trailer block after the body (H2/H3; HTTP/1.1 chunked trailers).
    fn response_trailers(&mut self, _headers: &Headers) {}

    /// Response fully received (after body and trailers).
    fn close(&mut self);

    /// Connection or stream failed before a complete response.
    fn failed(&mut self, err: io::Error);
}

/// Live client connection — request factory (Gumdrop `HTTPClient` methods).
pub struct HttpClientSessionHandle {
    pub(crate) ops: Arc<Mutex<dyn SessionRequestOps + Send>>,
    version: HttpVersion,
}

impl HttpClientSessionHandle {
    pub(crate) fn new(ops: Arc<Mutex<dyn SessionRequestOps + Send>>, version: HttpVersion) -> Self {
        Self { ops, version }
    }

    /// Negotiated protocol version.
    pub fn version(&self) -> HttpVersion {
        self.version
    }

    /// Whether multiple requests may be in flight (HTTP/2+).
    pub fn supports_multiplexing(&self) -> bool {
        self.version.supports_multiplexing()
    }

    /// `GET` request.
    pub fn get(&mut self, path: &str) -> HttpRequest {
        self.method("GET", path)
    }

    /// `POST` request.
    pub fn post(&mut self, path: &str) -> HttpRequest {
        self.method("POST", path)
    }

    /// `PUT` request.
    pub fn put(&mut self, path: &str) -> HttpRequest {
        self.method("PUT", path)
    }

    /// `DELETE` request.
    pub fn delete(&mut self, path: &str) -> HttpRequest {
        self.method("DELETE", path)
    }

    /// `HEAD` request.
    pub fn head(&mut self, path: &str) -> HttpRequest {
        self.method("HEAD", path)
    }

    /// `OPTIONS` request.
    pub fn options(&mut self, path: &str) -> HttpRequest {
        self.method("OPTIONS", path)
    }

    /// `PATCH` request.
    pub fn patch(&mut self, path: &str) -> HttpRequest {
        self.method("PATCH", path)
    }

    /// Request with a custom HTTP method.
    pub fn method(&mut self, method: &str, path: &str) -> HttpRequest {
        HttpRequest::new(Arc::clone(&self.ops), method.to_string(), path.to_string())
    }
}

/// Outbound HTTP request (Gumdrop `HTTPRequest`).
pub struct HttpRequest {
    session: Arc<Mutex<dyn SessionRequestOps + Send>>,
    method: String,
    path: String,
    headers: Headers,
    phase: RequestPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestPhase {
    Building,
    BodyStreaming,
    Complete,
    Cancelled,
}

/// Session-specific send/cancel operations (implemented by H1/H2/H3 adapters).
pub(crate) trait SessionRequestOps: Send {
    fn is_open(&self) -> bool;
    fn send_no_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError>;
    fn start_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError>;
    fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError>;
    fn end_body(&mut self) -> Result<(), HttpClientError>;
    fn cancel_request(&mut self) -> Result<(), HttpClientError>;
}

impl HttpRequest {
    /// Add a request header (before send / start_request_body).
    pub fn header(
        &mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<(), HttpClientError> {
        if self.phase != RequestPhase::Building {
            return Err(HttpClientError::new("headers already sent"));
        }
        self.headers.add(name.as_ref(), value.as_ref());
        Ok(())
    }

    /// Send a bodyless request (`GET`, `HEAD`, …).
    pub fn send(&mut self, handler: Box<dyn HttpResponseHandler>) -> Result<(), HttpClientError> {
        if self.phase == RequestPhase::Cancelled {
            return Err(HttpClientError::new("request cancelled"));
        }
        if self.phase != RequestPhase::Building {
            return Err(HttpClientError::new("request already sent"));
        }
        if !self.session.lock().unwrap().is_open() {
            return Err(HttpClientError::new("connection not open"));
        }
        let method = self.method.clone();
        let path = self.path.clone();
        let headers = std::mem::take(&mut self.headers);
        self.session
            .lock()
            .unwrap()
            .send_no_body(&method, &path, headers, handler)?;
        self.phase = RequestPhase::Complete;
        Ok(())
    }

    /// Begin a request with a body; follow with [`Self::request_body_content`] and
    /// [`Self::end_request_body`].
    pub fn start_request_body(
        &mut self,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        if self.phase == RequestPhase::Cancelled {
            return Err(HttpClientError::new("request cancelled"));
        }
        if self.phase != RequestPhase::Building {
            return Err(HttpClientError::new("request already sent"));
        }
        if !self.session.lock().unwrap().is_open() {
            return Err(HttpClientError::new("connection not open"));
        }
        let method = self.method.clone();
        let path = self.path.clone();
        let headers = std::mem::take(&mut self.headers);
        self.session
            .lock()
            .unwrap()
            .start_body(&method, &path, headers, handler)?;
        self.phase = RequestPhase::BodyStreaming;
        Ok(())
    }

    /// Stream request body bytes (after [`Self::start_request_body`]).
    pub fn request_body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
        if self.phase != RequestPhase::BodyStreaming {
            return Err(HttpClientError::new("must call start_request_body first"));
        }
        self.session.lock().unwrap().body_content(data)
    }

    /// Finish the request body.
    pub fn end_request_body(&mut self) -> Result<(), HttpClientError> {
        if self.phase != RequestPhase::BodyStreaming {
            return Err(HttpClientError::new("must call start_request_body first"));
        }
        self.session.lock().unwrap().end_body()?;
        self.phase = RequestPhase::Complete;
        Ok(())
    }

    /// Cancel this request.
    pub fn cancel(&mut self) -> Result<(), HttpClientError> {
        if self.phase == RequestPhase::Complete || self.phase == RequestPhase::Cancelled {
            return Ok(());
        }
        self.phase = RequestPhase::Cancelled;
        self.session.lock().unwrap().cancel_request()
    }

    pub(crate) fn new(
        session: Arc<Mutex<dyn SessionRequestOps + Send>>,
        method: String,
        path: String,
    ) -> Self {
        Self {
            session,
            method,
            path,
            headers: Headers::new(),
            phase: RequestPhase::Building,
        }
    }
}
