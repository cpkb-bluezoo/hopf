// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 [`HttpRequest`] session adapter — the QUIC-backed counterpart to
//! `h2_session.rs`'s [`super::h2_session::H2HttpClientSession`], letting one
//! `HttpClient` connection issue many sequential Gumdrop-style requests over
//! HTTP/3, not just the one eager stream [`crate::h3::connect_h3`] opens.
//!
//! Unlike H2 (and H1), a request's body is buffered here in full before the
//! stream opens, rather than streamed incrementally: `H3ClientWriter`
//! (`crate::h3::client`) hands the whole request — headers, body, trailers
//! — to the wire in one shot from inside [`crate::ClientHandler::start`],
//! with no later opportunity to feed it more bytes. Genuine incremental/
//! backpressured H3 request bodies would need changes to that writer's
//! model; out of scope here. [`SessionRequestOps::on_body_writable`] is
//! therefore never actually needed (`body_content` never short-writes), so
//! it's left at the trait's default no-op.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use hopf_quic::QuicClientConfig;

use crate::client::api::{
    HttpClientError, HttpClientSessionHandle, HttpConnectionHandler, HttpResponseHandler,
    SessionRequestOps,
};
use crate::h3::client::PendingOpens;
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{ClientHandler, ClientHandlerFactory, ClientWriter};
use crate::version::HttpVersion;

struct H3Job {
    method: String,
    path: String,
    headers: Headers,
    handler: Option<Box<dyn HttpResponseHandler>>,
    pending_body: Vec<u8>,
    body_complete: bool,
}

struct H3SessionShared {
    driver: Arc<hopf_quic::QuicDriverHandle>,
    pending_opens: PendingOpens,
    authority: String,
    job: Option<H3Job>,
    in_flight: bool,
}

/// Everything one queued stream needs, handed from [`OpsBridge`] to the
/// [`ClientHandlerFactory`] pushed onto [`H3SessionShared::pending_opens`].
/// Wrapped in a `Mutex<Option<_>>` so [`ClientHandlerFactory::create_handler`]
/// (`&self`, possibly-multi-call by signature) can move it out the one time
/// it's actually invoked.
struct H3JobData {
    method: String,
    path: String,
    authority: String,
    headers: Headers,
    body: Vec<u8>,
    handler: Box<dyn HttpResponseHandler>,
    shared: Arc<Mutex<H3SessionShared>>,
}

struct H3JobFactory {
    data: Mutex<Option<H3JobData>>,
}

impl ClientHandlerFactory for H3JobFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        let data = self
            .data
            .lock()
            .unwrap()
            .take()
            .expect("H3JobFactory::create_handler called more than once");
        Box::new(H3StreamHandler {
            method: data.method,
            path: data.path,
            authority: data.authority,
            headers: Some(data.headers),
            body: data.body,
            response: Some(data.handler),
            shared: data.shared,
        })
    }
}

struct H3StreamHandler {
    method: String,
    path: String,
    authority: String,
    headers: Option<Headers>,
    body: Vec<u8>,
    response: Option<Box<dyn HttpResponseHandler>>,
    shared: Arc<Mutex<H3SessionShared>>,
}

impl H3StreamHandler {
    fn with_response<R>(&mut self, f: impl FnOnce(&mut dyn HttpResponseHandler) -> R) -> R {
        let mut h = self.response.take().expect("response handler");
        let r = f(&mut *h);
        self.response = Some(h);
        r
    }
}

impl ClientHandler for H3StreamHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let mut h = Headers::new();
        h.set(":method", &self.method);
        h.set(":path", &self.path);
        h.set(":scheme", "https");
        h.set(":authority", &self.authority);
        for field in self.headers.take().unwrap_or_default().iter() {
            if field.name.starts_with(':') {
                continue;
            }
            h.add(field.name.clone(), field.value.clone());
        }
        request.headers(h);
        if !self.body.is_empty() {
            request.start_request_body();
            request.request_body_content(&self.body);
        }
        request.complete_request();
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
        // Clear `in_flight` *before* calling out to the app's `close()` --
        // a Gumdrop-style caller chaining a follow-up request from inside
        // `close()` (a completely ordinary pattern for sequential session
        // use) must see the session as already idle by then, not still
        // "in flight" against the very request that just finished.
        self.shared.lock().unwrap().in_flight = false;
        self.with_response(|h| h.close());
    }

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &io::Error) {
        self.shared.lock().unwrap().in_flight = false;
        if let Some(mut h) = self.response.take() {
            h.failed(io::Error::new(err.kind(), err.to_string()));
        }
    }
}

struct OpsBridge(Arc<Mutex<H3SessionShared>>);

impl SessionRequestOps for OpsBridge {
    fn is_open(&self) -> bool {
        self.0.lock().unwrap().driver.is_active()
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
        job.pending_body.extend_from_slice(data);
        Ok(data.len())
    }

    fn end_body(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        {
            let Some(job) = g.job.as_mut() else {
                return Err(HttpClientError::new("must call start_request_body first"));
            };
            job.body_complete = true;
        }
        self.open_queued_stream(&mut g);
        Ok(())
    }

    fn cancel_request(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if let Some(job) = g.job.take() {
            if let Some(mut h) = job.handler {
                h.failed(io::Error::new(io::ErrorKind::Interrupted, "request cancelled"));
            }
        }
        g.in_flight = false;
        Ok(())
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
        g.job = Some(H3Job {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            handler: Some(handler),
            pending_body: Vec::new(),
            body_complete,
        });
        if body_complete {
            self.open_queued_stream(&mut g);
        }
        Ok(())
    }

    /// Move the current job into a fresh [`H3JobFactory`], push it onto the
    /// connection's pending-opens queue, and wake the driver — the H3
    /// counterpart of H2's `flush_session` opening a stream, just without
    /// the incremental-body/flow-control bookkeeping that needs (see this
    /// module's doc comment).
    fn open_queued_stream(&self, g: &mut H3SessionShared) {
        let Some(job) = g.job.take() else { return };
        let factory: Arc<dyn ClientHandlerFactory> = Arc::new(H3JobFactory {
            data: Mutex::new(Some(H3JobData {
                method: job.method,
                path: job.path,
                authority: g.authority.clone(),
                headers: job.headers,
                body: job.pending_body,
                handler: job.handler.expect("job always carries a handler until opened"),
                shared: Arc::clone(&self.0),
            })),
        });
        g.pending_opens.lock().unwrap().push_back(factory);
        let _ = g.driver.poke_hooks();
    }
}

/// Dial an HTTP/3 origin for Gumdrop-session use: `handler.on_connected` is
/// called once the QUIC/TLS handshake completes, with a
/// [`HttpClientSessionHandle`] that can issue any number of sequential
/// requests (one in flight at a time — matching
/// [`super::h2_session::H2HttpClientSession`]'s current scope, not full
/// concurrent multiplexing).
///
/// `host`/`port` are the HTTP origin (used for the `:authority`
/// pseudo-header) — usually the same as `server_name`/`addr`, but distinct
/// for e.g. an Alt-Svc-advertised alternate host.
pub(crate) fn connect_h3_session(
    addr: SocketAddr,
    client_config: Arc<QuicClientConfig>,
    server_name: impl Into<String>,
    host: &str,
    port: u16,
    limits: HttpLimits,
    handler: Box<dyn HttpConnectionHandler>,
) -> io::Result<()> {
    let authority = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let handler = Arc::new(Mutex::new(Some(handler)));
    let handler_for_ready = Arc::clone(&handler);

    // `on_ready` needs `H3SessionShared`, which needs the `(driver,
    // pending_opens)` that `crate::h3::connect_h3_session` itself returns
    // -- filled in via this cell right after that call, strictly before
    // `on_ready` can possibly fire (it only runs once real network I/O
    // completes the handshake, on the driver thread, never synchronously
    // within the call below).
    let cell: Arc<Mutex<Option<Arc<Mutex<H3SessionShared>>>>> = Arc::new(Mutex::new(None));
    let cell_for_ready = Arc::clone(&cell);
    let authority_for_ready = authority.clone();

    let on_ready: Box<dyn FnOnce() + Send> = Box::new(move || {
        let Some(shared) = cell_for_ready.lock().unwrap().clone() else {
            return;
        };
        let Some(mut h) = handler_for_ready.lock().unwrap().take() else {
            return;
        };
        let _ = &authority_for_ready;
        let ops: Arc<Mutex<dyn SessionRequestOps + Send>> = Arc::new(Mutex::new(OpsBridge(shared)));
        let mut session = HttpClientSessionHandle::new(ops, HttpVersion::Http3, None);
        h.on_connected(&mut session);
    });

    let dial = crate::h3::client::connect_h3_session(addr, client_config, server_name, limits, on_ready);
    let (driver, pending_opens) = match dial {
        Ok(v) => v,
        Err(e) => {
            if let Some(mut h) = handler.lock().unwrap().take() {
                h.on_error(&e);
            }
            return Err(e);
        }
    };

    let shared = Arc::new(Mutex::new(H3SessionShared {
        driver: Arc::new(driver),
        pending_opens,
        authority,
        job: None,
        in_flight: false,
    }));
    *cell.lock().unwrap() = Some(shared);

    Ok(())
}
