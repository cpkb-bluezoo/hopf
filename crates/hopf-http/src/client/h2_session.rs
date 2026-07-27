// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 [`HttpRequest`] session adapter (multiplexing-ready; one in-flight for now).

use std::io;
use std::sync::{Arc, Mutex};

use hopf_core::{Endpoint, ProtocolHandler};

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

struct OutboundJob {
    method: String,
    path: String,
    headers: Headers,
    handler: Box<dyn HttpResponseHandler>,
    body: Vec<u8>,
    body_complete: bool,
}

struct H2SessionShared {
    config: Arc<HttpClientSessionConfig>,
    job: Option<OutboundJob>,
    in_flight: bool,
    pending_kick: bool,
}

impl H2SessionShared {
    fn new(config: Arc<HttpClientSessionConfig>) -> Self {
        Self {
            config,
            job: None,
            in_flight: false,
            pending_kick: false,
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

    fn take_pending_kick(&mut self) -> bool {
        std::mem::take(&mut self.pending_kick)
    }

    fn take_job_for_send(&mut self) -> OutboundJob {
        self.job.take().expect("no outbound job for H2 stream")
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
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let (job, scheme, authority) = {
            let mut g = self.shared.lock().unwrap();
            let job = g.take_job_for_send();
            let scheme = if g.config.secure { "https" } else { "http" };
            let authority = g.authority();
            (job, scheme, authority)
        };
        self.response = Some(job.handler);

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
        request.headers(h);
        if job.body.is_empty() && job.body_complete {
            request.complete_request();
        } else {
            request.start_request_body();
            if !job.body.is_empty() {
                request.request_body_content(&job.body);
            }
            if job.body_complete {
                request.end_request_body();
            }
        }
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
        self.enqueue(method, path, headers, handler, Vec::new(), true, true)
    }

    fn start_body(
        &mut self,
        method: &str,
        path: &str,
        headers: Headers,
        handler: Box<dyn HttpResponseHandler>,
    ) -> Result<(), HttpClientError> {
        self.enqueue(method, path, headers, handler, Vec::new(), false, false)
    }

    fn body_content(&mut self, data: &[u8]) -> Result<usize, HttpClientError> {
        let mut g = self.0.lock().unwrap();
        let Some(job) = g.job.as_mut() else {
            return Err(HttpClientError::new("must call start_request_body first"));
        };
        job.body.extend_from_slice(data);
        Ok(data.len())
    }

    fn end_body(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        let Some(job) = g.job.as_mut() else {
            return Err(HttpClientError::new("must call start_request_body first"));
        };
        job.body_complete = true;
        g.pending_kick = true;
        Ok(())
    }

    fn cancel_request(&mut self) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if let Some(mut job) = g.job.take() {
            job.handler
                .failed(io::Error::new(io::ErrorKind::Interrupted, "request cancelled"));
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
        body: Vec<u8>,
        body_complete: bool,
        kick: bool,
    ) -> Result<(), HttpClientError> {
        let mut g = self.0.lock().unwrap();
        if g.in_flight {
            return Err(HttpClientError::new("request already in flight"));
        }
        g.in_flight = true;
        g.job = Some(OutboundJob {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            handler,
            body,
            body_complete,
        });
        if kick {
            g.pending_kick = true;
        }
        Ok(())
    }
}

/// H2 client connection exposing the Gumdrop session API.
pub(crate) struct H2HttpClientSession {
    inner: H2Endpoint,
    shared: Arc<Mutex<H2SessionShared>>,
    connected_notified: bool,
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
        }
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
            let mut session =
                HttpClientSessionHandle::new(self.request_ops(), HttpVersion::Http2);
            h.on_connected(&mut session);
        }
        self.flush_pending_kick(endpoint);
    }

    fn flush_pending_kick(&mut self, endpoint: &mut dyn Endpoint) {
        let kick = self.shared.lock().unwrap().take_pending_kick();
        if kick && self.inner.client_connection_ready() {
            self.inner.kick_client_request(endpoint);
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
        self.inner.security_established(endpoint, info);
        self.forward_outbound(endpoint);
        self.maybe_notify_connected(endpoint);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        self.inner.receive(endpoint, data);
        self.maybe_notify_connected(endpoint);
        self.flush_pending_kick(endpoint);
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        self.inner.disconnected(endpoint);
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        self.inner.error(endpoint, err);
    }
}
