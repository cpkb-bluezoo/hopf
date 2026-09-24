// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Automatic conditional `GET`/`HEAD` (RFC 9110 §13) as a handler decorator.
//!
//! [`ConditionalServerFactory`] wraps any [`ServerHandlerFactory`]. When a
//! `GET` or `HEAD` carries `If-None-Match`, `If-Modified-Since`, `If-Match`
//! or `If-Unmodified-Since`, and the wrapped handler answers `200` with an
//! `ETag` and/or `Last-Modified`, the precondition is evaluated with
//! [`evaluate_preconditions`] and the response becomes `304 Not Modified` or
//! `412 Precondition Failed` as the RFC directs; the handler's body is
//! discarded. It works below the version line, so it serves HTTP/1.1,
//! HTTP/2 and HTTP/3 alike.
//!
//! It only acts on safe methods: a handler that changes state must call
//! [`evaluate_preconditions`] itself *before* acting, because by the time a
//! decorator sees the response the change has already happened.

use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;

use crate::caching::{evaluate_preconditions, EntityTag, Precondition, Validators};
use crate::headers::Headers;
use crate::stream::{
    ConnectionInfo, ProtocolUpgradeHandler, ResponseControl, ServerHandler, ServerHandlerFactory,
    ServerResponseHandle, ServerWriter,
};
use crate::utils::parse_http_date;

/// The request fields that make a response conditional.
const CONDITIONAL_FIELDS: [&str; 4] =
    ["if-match", "if-unmodified-since", "if-none-match", "if-modified-since"];

/// Fields a `304` must carry when a `200` would have (RFC 9110 §15.4.5), plus
/// `Last-Modified`, which caches use to refresh their entry.
const NOT_MODIFIED_KEEPS: [&str; 7] = [
    "cache-control",
    "content-location",
    "date",
    "etag",
    "expires",
    "vary",
    "last-modified",
];

/// [`ServerHandlerFactory`] decorator that answers conditional `GET`/`HEAD`
/// requests with `304` / `412`. See the [module docs](self).
///
/// # Response rules
///
/// - Only a `200` response is considered (preconditions are ignored for any
///   other status, RFC 9110 §13.2.1), and only its `ETag` and `Last-Modified`
///   are consulted. A response with neither has nothing to compare, so only
///   existence-based conditions such as `If-None-Match: *` can apply.
/// - `304` carries `Cache-Control`, `Content-Location`, `Date`, `ETag`,
///   `Expires`, `Vary` and `Last-Modified` from the `200` it replaces, and no
///   body. `412` has no body.
/// - Everything else, and every request without a precondition, passes
///   through untouched at no cost.
pub struct ConditionalServerFactory {
    inner: Arc<dyn ServerHandlerFactory>,
}

impl ConditionalServerFactory {
    /// Wrap `inner`.
    pub fn new(inner: Arc<dyn ServerHandlerFactory>) -> Self {
        Self { inner }
    }
}

impl ServerHandlerFactory for ConditionalServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(ConditionalHandler {
            inner: self.inner.create_handler(),
            st: Arc::new(Mutex::new(State::default())),
        })
    }
}

#[derive(Default)]
struct State {
    method: String,
    /// The request's conditional fields; empty when the request is not
    /// eligible, which makes the whole wrapper transparent.
    request: Headers,
    decided: bool,
    /// The response was replaced by a `304`/`412`: drop the handler's body.
    suppress: bool,
}

impl State {
    fn active(&self) -> bool {
        !self.request.is_empty() && !self.decided
    }

    /// Decide the fate of the response whose headers are `h`.
    fn intercept(&mut self, h: Headers) -> Headers {
        self.decided = true;
        if h.status_code() != 200 {
            return h;
        }
        let validators = Validators {
            etag: h.get("etag").and_then(EntityTag::parse),
            last_modified: h.get("last-modified").and_then(parse_http_date),
        };
        match evaluate_preconditions(&self.method, &self.request, Some(&validators)) {
            Precondition::Proceed => h,
            Precondition::NotModified => {
                self.suppress = true;
                let mut out = Headers::new();
                out.status(304);
                for f in h.iter() {
                    if NOT_MODIFIED_KEEPS.iter().any(|k| f.name.eq_ignore_ascii_case(k)) {
                        out.add(f.name.clone(), f.value.clone());
                    }
                }
                out
            }
            Precondition::PreconditionFailed => {
                self.suppress = true;
                let mut out = Headers::new();
                out.status(412);
                out.set("content-length", "0");
                out
            }
        }
    }
}

struct ConditionalWriter<'a> {
    inner: &'a mut dyn ServerWriter,
    st: Arc<Mutex<State>>,
}

impl ServerWriter for ConditionalWriter<'_> {
    fn send_informational(&mut self, code: u16, headers: &Headers) {
        self.inner.send_informational(code, headers);
    }

    fn headers(&mut self, headers: Headers) {
        let out = {
            let mut st = self.st.lock().unwrap();
            if st.active() {
                st.intercept(headers)
            } else {
                headers
            }
        };
        self.inner.headers(out);
    }

    fn start_response_body(&mut self) {
        if !self.st.lock().unwrap().suppress {
            self.inner.start_response_body();
        }
    }

    fn response_body_content(&mut self, data: &[u8]) {
        if !self.st.lock().unwrap().suppress {
            self.inner.response_body_content(data);
        }
    }

    fn end_response_body(&mut self) {
        if !self.st.lock().unwrap().suppress {
            self.inner.end_response_body();
        }
    }

    fn trailers(&mut self, headers: Headers) {
        if !self.st.lock().unwrap().suppress {
            self.inner.trailers(headers);
        }
    }

    fn complete(&mut self) {
        self.inner.complete();
    }

    fn upgrade(&mut self, headers: Headers, handler: Box<dyn ProtocolUpgradeHandler>) -> bool {
        self.st.lock().unwrap().decided = true;
        self.inner.upgrade(headers, handler)
    }

    fn traceparent(&self) -> Option<&str> {
        self.inner.traceparent()
    }

    fn conn_handle(&self) -> ConnHandle {
        self.inner.conn_handle()
    }

    fn connection_info(&self) -> ConnectionInfo {
        self.inner.connection_info()
    }

    fn response_handle(&self) -> ServerResponseHandle {
        // Writes a handler defers to another thread must still pass the
        // precondition check.
        let real = self.inner.response_handle();
        ServerResponseHandle::new(Arc::new(ConditionalControl {
            inner: Arc::clone(real.control()),
            st: Arc::clone(&self.st),
        }))
    }

    fn pause_request_body(&mut self) {
        self.inner.pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.inner.resume_request_body();
    }
}

struct ConditionalControl {
    inner: Arc<dyn ResponseControl>,
    st: Arc<Mutex<State>>,
}

impl ResponseControl for ConditionalControl {
    fn conn_handle(&self) -> ConnHandle {
        self.inner.conn_handle()
    }

    fn execute(&self, f: Box<dyn FnOnce(&mut dyn ServerWriter) + Send>) {
        let st = Arc::clone(&self.st);
        self.inner.execute(Box::new(move |w| {
            let mut cw = ConditionalWriter { inner: w, st };
            f(&mut cw);
        }));
    }

    fn pause_request_body(&self) {
        self.inner.pause_request_body();
    }

    fn resume_request_body(&self) {
        self.inner.resume_request_body();
    }
}

struct ConditionalHandler {
    inner: Box<dyn ServerHandler>,
    st: Arc<Mutex<State>>,
}

impl ConditionalHandler {
    fn writer<'a>(&self, w: &'a mut dyn ServerWriter) -> ConditionalWriter<'a> {
        ConditionalWriter {
            inner: w,
            st: Arc::clone(&self.st),
        }
    }
}

impl ServerHandler for ConditionalHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        {
            let method = headers.method().unwrap_or("");
            let mut st = self.st.lock().unwrap();
            st.method = method.to_string();
            if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
                let mut req = Headers::new();
                for f in headers.iter() {
                    if CONDITIONAL_FIELDS.iter().any(|c| f.name.eq_ignore_ascii_case(c)) {
                        req.add(f.name.to_ascii_lowercase(), f.value.clone());
                    }
                }
                st.request = req;
            }
        }
        let mut w = self.writer(response);
        self.inner.headers(&mut w, headers);
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        let mut w = self.writer(response);
        self.inner.start_request_body(&mut w);
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        let mut w = self.writer(response);
        self.inner.request_body_content(&mut w, data);
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        let mut w = self.writer(response);
        self.inner.end_request_body(&mut w);
    }

    fn request_trailers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        let mut w = self.writer(response);
        self.inner.request_trailers(&mut w, headers);
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        let mut w = self.writer(response);
        self.inner.request_complete(&mut w);
    }
}
