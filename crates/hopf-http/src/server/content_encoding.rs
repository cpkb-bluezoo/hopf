// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server-side content coding (RFC 9110 §8.4) as a handler decorator.
//!
//! [`ContentEncodingServerFactory`] wraps any [`ServerHandlerFactory`]. The
//! handlers it creates:
//!
//! - **compress responses** when the request's `Accept-Encoding` allows it,
//!   pushing the application's body chunks through an incremental
//!   [`Encoder`] - so a handler that streams its body (from a storage
//!   callback, an SPI, another connection) is compressed chunk by chunk in
//!   constant memory; and
//! - **decode request bodies** carrying `Content-Encoding`, so the wrapped
//!   handler sees plain bytes.
//!
//! It works below the version line: the same wrapper serves HTTP/1.1, HTTP/2
//! and HTTP/3, because it only speaks [`ServerHandler`] / [`ServerWriter`].

use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;

use crate::content_coding::{
    default_compressible, negotiate_accept_encoding, CodingError, CompressibleFn, ContentCoding,
    Decoder, Encoder, ALL_CODINGS,
};
use crate::headers::Headers;
use crate::limits::HttpLimits;
use crate::stream::{
    ConnectionInfo, ProtocolUpgradeHandler, ResponseControl, ServerHandler, ServerHandlerFactory,
    ServerResponseHandle, ServerWriter,
};

/// What the server compresses and decodes.
#[derive(Clone)]
pub struct ServerContentEncodingPolicy {
    preference: Vec<ContentCoding>,
    min_length: u64,
    max_decoded: u64,
    decode_requests: bool,
    compressible: Arc<CompressibleFn>,
}

impl std::fmt::Debug for ServerContentEncodingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerContentEncodingPolicy")
            .field("preference", &self.preference)
            .field("min_length", &self.min_length)
            .field("max_decoded", &self.max_decoded)
            .field("decode_requests", &self.decode_requests)
            .finish_non_exhaustive()
    }
}

impl ServerContentEncodingPolicy {
    /// Prefer `br`, then `gzip`, then `deflate`; compress text-like types
    /// whose declared length is at least 256 bytes (or unknown); decode
    /// request bodies up to [`HttpLimits::max_decoded_body`].
    pub fn new(limits: &HttpLimits) -> Self {
        Self {
            preference: vec![ContentCoding::Brotli, ContentCoding::Gzip, ContentCoding::Deflate],
            min_length: 256,
            max_decoded: limits.max_decoded_body as u64,
            decode_requests: true,
            compressible: Arc::new(default_compressible),
        }
    }

    /// Codings to offer, most preferred first (`identity` is ignored).
    /// Empty disables response compression.
    pub fn prefer(mut self, codings: &[ContentCoding]) -> Self {
        self.preference = codings
            .iter()
            .copied()
            .filter(|c| *c != ContentCoding::Identity)
            .collect();
        self
    }

    /// Skip compression when the response declares a `Content-Length` below
    /// this. Responses of unknown length are always eligible.
    pub fn min_length(mut self, bytes: u64) -> Self {
        self.min_length = bytes;
        self
    }

    /// Replace the compressible-`Content-Type` test. It receives the field
    /// value with parameters (`; charset=...`) already stripped.
    pub fn compressible(mut self, f: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.compressible = Arc::new(f);
        self
    }

    /// Whether to decode `Content-Encoding` request bodies (default on). When
    /// off, a coded request reaches the handler exactly as sent.
    pub fn decode_requests(mut self, on: bool) -> Self {
        self.decode_requests = on;
        self
    }

    /// Override the decoded request-size cap.
    pub fn max_decoded_body(mut self, max: usize) -> Self {
        self.max_decoded = max as u64;
        self
    }
}

/// [`ServerHandlerFactory`] decorator applying a [`ServerContentEncodingPolicy`].
///
/// # Response header policy
///
/// The application's headers are held until its first body byte (or
/// `start_response_body`). If the response is eligible - a 2xx-or-error
/// with a body, not `HEAD`/`204`/`304`, no `Content-Encoding` set by the handler (any value, `identity`
/// included, is an explicit instruction to leave the response alone), not
/// `Cache-Control: no-transform`, no `Content-Range`, a compressible
/// `Content-Type`, and at least the policy's minimum length - `Vary:
/// Accept-Encoding` is added. If the client also accepts one of the
/// policy's codings, the response is compressed: `Content-Encoding` is set,
/// `Content-Length` removed (the length is unknown until the end, so the
/// transport frames the body by chunking / stream end), and a strong `ETag`
/// is weakened. A response with no body is forwarded untouched. Unless
/// request decoding is turned off, every response also carries
/// `Accept-Encoding: br, gzip, deflate` (RFC 9110 §12.5.3) so clients learn
/// they may compress the bodies they send.
///
/// # Request handling
///
/// A request with `Content-Encoding` is decoded before the wrapped handler
/// sees it; `Content-Encoding` and `Content-Length` are removed from the
/// headers it is shown. An unknown coding is answered `415`, a corrupt or
/// truncated body `400`, and one that decodes past the cap `413`; the
/// wrapped handler is not called again after that.
pub struct ContentEncodingServerFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    policy: Arc<ServerContentEncodingPolicy>,
}

impl ContentEncodingServerFactory {
    /// Wrap `inner` under `policy`.
    pub fn new(inner: Arc<dyn ServerHandlerFactory>, policy: ServerContentEncodingPolicy) -> Self {
        Self {
            inner,
            policy: Arc::new(policy),
        }
    }
}

impl ServerHandlerFactory for ContentEncodingServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(ContentEncodingHandler {
            inner: self.inner.create_handler(),
            policy: Arc::clone(&self.policy),
            resp: Arc::new(Mutex::new(ResponseState::default())),
            decoder: None,
            rejected: false,
        })
    }
}

#[derive(Default)]
struct ResponseState {
    /// Coding negotiated from the request, if the client accepts one.
    negotiated: Option<ContentCoding>,
    eligible_method: bool,
    /// Advertise request-body codings on responses.
    advertise_requests: bool,
    policy: Option<Arc<ServerContentEncodingPolicy>>,
    pending: Option<Headers>,
    /// Headers have been handed to the transport (compress decision made).
    decided: bool,
    encoder: Option<Encoder>,
    finished: bool,
}

impl ResponseState {
    /// Forward held headers, compressing when eligible and accepted.
    fn release(&mut self, inner: &mut dyn ServerWriter, allow_compress: bool) {
        if self.decided {
            return;
        }
        self.decided = true;
        let Some(mut h) = self.pending.take() else {
            return;
        };
        if allow_compress {
            self.apply(&mut h);
        }
        if self.advertise_requests && !h.contains("accept-encoding") {
            // RFC 9110 §12.5.3: tell clients which codings we accept in
            // requests, so they can compress bodies they send us.
            h.set("accept-encoding", ALL_CODINGS.map(|c| c.token()).join(", "));
        }
        inner.headers(h);
    }

    fn apply(&mut self, h: &mut Headers) {
        let Some(policy) = self.policy.clone() else {
            return;
        };
        if policy.preference.is_empty() || !self.eligible_method {
            return;
        }
        let status = h.status_code();
        if status < 200 || status == 204 || status == 205 || status == 304 {
            return;
        }
        if h.contains("content-range") {
            return;
        }
        // A Content-Encoding the handler set itself - `identity` included -
        // is an explicit instruction: leave the response exactly as built.
        if h.contains("content-encoding") {
            return;
        }
        if h.get("cache-control")
            .is_some_and(|v| v.split(',').any(|d| d.trim().eq_ignore_ascii_case("no-transform")))
        {
            return;
        }
        let Some(ct) = h.get("content-type") else {
            return;
        };
        let essence = ct.split(';').next().unwrap_or("");
        if !(policy.compressible)(essence) {
            return;
        }
        if let Some(len) = h.get("content-length").and_then(|v| v.trim().parse::<u64>().ok()) {
            if len < policy.min_length {
                return;
            }
        }
        // Eligible: the representation now varies with Accept-Encoding.
        let has_vary = h
            .get("vary")
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("accept-encoding") || t.trim() == "*"));
        if !has_vary {
            match h.get("vary").map(|v| v.to_string()) {
                Some(v) if !v.trim().is_empty() => h.set("vary", format!("{v}, Accept-Encoding")),
                _ => h.set("vary", "Accept-Encoding"),
            }
        }
        let Some(coding) = self.negotiated else {
            return;
        };
        let Ok(enc) = Encoder::new(coding) else {
            return;
        };
        self.encoder = Some(enc);
        h.remove("content-length");
        h.set("content-encoding", coding.token());
        if let Some(etag) = h.get("etag").map(|v| v.to_string()) {
            if !etag.starts_with("W/") {
                h.set("etag", format!("W/{etag}"));
            }
        }
    }

    fn write(&mut self, inner: &mut dyn ServerWriter, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match self.encoder.as_mut() {
            Some(enc) => {
                let _ = enc.push(data, &mut |out| {
                    if !out.is_empty() {
                        inner.response_body_content(out);
                    }
                });
            }
            None => inner.response_body_content(data),
        }
    }

    fn finish(&mut self, inner: &mut dyn ServerWriter) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(enc) = self.encoder.as_mut() {
            let _ = enc.finish(&mut |out| {
                if !out.is_empty() {
                    inner.response_body_content(out);
                }
            });
        }
    }
}

/// [`ServerWriter`] the wrapped handler talks to.
struct CompressingWriter<'a> {
    inner: &'a mut dyn ServerWriter,
    st: Arc<Mutex<ResponseState>>,
}

impl ServerWriter for CompressingWriter<'_> {
    fn send_informational(&mut self, code: u16, headers: &Headers) {
        self.inner.send_informational(code, headers);
    }

    fn headers(&mut self, headers: Headers) {
        let mut st = self.st.lock().unwrap();
        if st.decided {
            drop(st);
            self.inner.headers(headers);
        } else {
            st.pending = Some(headers);
        }
    }

    fn start_response_body(&mut self) {
        self.st.lock().unwrap().release(self.inner, true);
        self.inner.start_response_body();
    }

    fn response_body_content(&mut self, data: &[u8]) {
        let mut st = self.st.lock().unwrap();
        st.release(self.inner, true);
        st.write(self.inner, data);
    }

    fn end_response_body(&mut self) {
        let mut st = self.st.lock().unwrap();
        // No body was ever written: forward headers untouched.
        st.release(self.inner, false);
        st.finish(self.inner);
        drop(st);
        self.inner.end_response_body();
    }

    fn trailers(&mut self, headers: Headers) {
        self.st.lock().unwrap().release(self.inner, false);
        self.inner.trailers(headers);
    }

    fn complete(&mut self) {
        let mut st = self.st.lock().unwrap();
        st.release(self.inner, false);
        st.finish(self.inner);
        drop(st);
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
        // Deferred writes must go through the same encoder state, or a body
        // written later would bypass compression after `Content-Encoding`
        // was already advertised.
        let real = self.inner.response_handle();
        ServerResponseHandle::new(Arc::new(CompressingControl {
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

struct CompressingControl {
    inner: Arc<dyn ResponseControl>,
    st: Arc<Mutex<ResponseState>>,
}

impl ResponseControl for CompressingControl {
    fn conn_handle(&self) -> ConnHandle {
        self.inner.conn_handle()
    }

    fn execute(&self, f: Box<dyn FnOnce(&mut dyn ServerWriter) + Send>) {
        let st = Arc::clone(&self.st);
        self.inner.execute(Box::new(move |w| {
            let mut cw = CompressingWriter { inner: w, st };
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

struct ContentEncodingHandler {
    inner: Box<dyn ServerHandler>,
    policy: Arc<ServerContentEncodingPolicy>,
    resp: Arc<Mutex<ResponseState>>,
    decoder: Option<Decoder>,
    /// The request was refused; the wrapped handler hears nothing further.
    rejected: bool,
}

impl ContentEncodingHandler {
    fn reject(&mut self, w: &mut dyn ServerWriter, err: CodingError) {
        if self.rejected {
            return;
        }
        self.rejected = true;
        self.decoder = None;
        let code = match err {
            CodingError::Unsupported => 415,
            CodingError::LimitExceeded => 413,
            CodingError::Corrupt | CodingError::Truncated => 400,
        };
        let mut h = Headers::new();
        h.status(code);
        h.set("content-length", "0");
        // RFC 9110 §15.5.16: a 415 for a content coding names what is accepted.
        h.set("accept-encoding", ALL_CODINGS.map(|c| c.token()).join(", "));
        // Straight to the transport: an error reply is never re-compressed.
        {
            let mut st = self.resp.lock().unwrap();
            st.decided = true;
            st.pending = None;
        }
        w.headers(h);
        w.complete();
    }

    fn writer<'a>(&self, w: &'a mut dyn ServerWriter) -> CompressingWriter<'a> {
        CompressingWriter {
            inner: w,
            st: Arc::clone(&self.resp),
        }
    }
}

impl ServerHandler for ContentEncodingHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        {
            let mut st = self.resp.lock().unwrap();
            st.policy = Some(Arc::clone(&self.policy));
            st.advertise_requests = self.policy.decode_requests;
            let method = headers.method().unwrap_or("");
            st.eligible_method = !method.eq_ignore_ascii_case("HEAD")
                && !method.eq_ignore_ascii_case("CONNECT");
            st.negotiated = headers
                .get("accept-encoding")
                .and_then(|ae| negotiate_accept_encoding(ae, &self.policy.preference));
        }

        let mut forwarded: Option<Headers> = None;
        if self.policy.decode_requests {
            if let Some(ce) = headers.get("content-encoding") {
                match Decoder::for_header(ce, self.policy.max_decoded) {
                    Ok(d) if d.is_passthrough() => {}
                    Ok(d) => {
                        self.decoder = Some(d);
                        let mut h = Headers::new();
                        for f in headers.iter() {
                            if f.name.eq_ignore_ascii_case("content-encoding")
                                || f.name.eq_ignore_ascii_case("content-length")
                            {
                                continue;
                            }
                            h.add(f.name.clone(), f.value.clone());
                        }
                        forwarded = Some(h);
                    }
                    Err(e) => return self.reject(response, e),
                }
            }
        }

        let mut w = self.writer(response);
        self.inner.headers(&mut w, forwarded.as_ref().unwrap_or(headers));
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.rejected {
            return;
        }
        let mut w = self.writer(response);
        self.inner.start_request_body(&mut w);
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.rejected {
            return;
        }
        let Some(decoder) = self.decoder.as_mut() else {
            let mut w = self.writer(response);
            self.inner.request_body_content(&mut w, data);
            return;
        };
        let inner = &mut self.inner;
        let st = Arc::clone(&self.resp);
        let result = decoder.push(data, &mut |out| {
            let mut w = CompressingWriter {
                inner: &mut *response,
                st: Arc::clone(&st),
            };
            inner.request_body_content(&mut w, out);
        });
        if let Err(e) = result {
            self.reject(response, e);
        }
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.rejected {
            return;
        }
        if let Some(decoder) = self.decoder.as_mut() {
            if let Err(e) = decoder.finish() {
                return self.reject(response, e);
            }
        }
        let mut w = self.writer(response);
        self.inner.end_request_body(&mut w);
    }

    fn request_trailers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        if self.rejected {
            return;
        }
        let mut w = self.writer(response);
        self.inner.request_trailers(&mut w, headers);
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        if self.rejected {
            return;
        }
        let mut w = self.writer(response);
        self.inner.request_complete(&mut w);
    }
}
