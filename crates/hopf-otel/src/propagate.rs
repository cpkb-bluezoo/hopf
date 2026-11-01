// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Outbound `traceparent` injection (Gumdrop `HTTPClient.setTrace` parity).

use hopf_http::{ClientWriter, Headers};

use crate::trace::Trace;

/// Insert `traceparent` unless the request already has one.
pub fn inject_traceparent(headers: &mut Headers, traceparent: &str) {
    if !headers.contains("traceparent") {
        headers.set("traceparent", traceparent);
    }
}

/// Inject from a [`Trace`]'s current span.
pub fn inject_trace(headers: &mut Headers, trace: &Trace) {
    inject_traceparent(headers, &trace.traceparent());
}

/// Wrap a [`ClientWriter`] so the next [`ClientWriter::headers`] call gets
/// `traceparent` (borrowed string; use with `ServerWriter::traceparent()`).
pub fn with_traceparent<'a>(
    request: &'a mut dyn ClientWriter,
    traceparent: Option<&'a str>,
) -> PropagatingClientWriter<'a> {
    PropagatingClientWriter {
        inner: request,
        traceparent,
    }
}

/// Wrap a [`ClientWriter`] using a live [`Trace`] (owned `traceparent` string).
pub fn with_trace<'a>(
    request: &'a mut dyn ClientWriter,
    trace: &Trace,
) -> OwnedPropagatingClientWriter<'a> {
    OwnedPropagatingClientWriter::from_trace(request, trace)
}

/// Client writer that injects a borrowed `traceparent` on [`ClientWriter::headers`].
pub struct PropagatingClientWriter<'a> {
    inner: &'a mut dyn ClientWriter,
    traceparent: Option<&'a str>,
}

impl ClientWriter for PropagatingClientWriter<'_> {
    fn headers(&mut self, mut headers: Headers) {
        if let Some(tp) = self.traceparent {
            inject_traceparent(&mut headers, tp);
        }
        self.inner.headers(headers);
    }

    fn start_request_body(&mut self) {
        self.inner.start_request_body();
    }

    fn request_body_content(&mut self, data: &[u8]) {
        self.inner.request_body_content(data);
    }

    fn end_request_body(&mut self) {
        self.inner.end_request_body();
    }

    fn trailers(&mut self, headers: Headers) {
        self.inner.trailers(headers);
    }

    fn complete_request(&mut self) {
        self.inner.complete_request();
    }

    fn version(&self) -> hopf_http::HttpVersion {
        self.inner.version()
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        self.inner.conn_handle()
    }
}

/// Owned `traceparent` wrapper for use when the string comes from `Trace::traceparent()`.
pub struct OwnedPropagatingClientWriter<'a> {
    inner: &'a mut dyn ClientWriter,
    traceparent: String,
}

impl<'a> OwnedPropagatingClientWriter<'a> {
    /// Wrap `request`, injecting `trace.traceparent()` on headers.
    pub fn from_trace(request: &'a mut dyn ClientWriter, trace: &Trace) -> Self {
        Self {
            inner: request,
            traceparent: trace.traceparent(),
        }
    }

    /// Wrap with an owned header value.
    pub fn new(request: &'a mut dyn ClientWriter, traceparent: impl Into<String>) -> Self {
        Self {
            inner: request,
            traceparent: traceparent.into(),
        }
    }
}

impl ClientWriter for OwnedPropagatingClientWriter<'_> {
    fn headers(&mut self, mut headers: Headers) {
        inject_traceparent(&mut headers, &self.traceparent);
        self.inner.headers(headers);
    }

    fn start_request_body(&mut self) {
        self.inner.start_request_body();
    }

    fn request_body_content(&mut self, data: &[u8]) {
        self.inner.request_body_content(data);
    }

    fn end_request_body(&mut self) {
        self.inner.end_request_body();
    }

    fn trailers(&mut self, headers: Headers) {
        self.inner.trailers(headers);
    }

    fn complete_request(&mut self) {
        self.inner.complete_request();
    }

    fn version(&self) -> hopf_http::HttpVersion {
        self.inner.version()
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        self.inner.conn_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{SpanKind, Trace};

    struct Capture {
        headers: Option<Headers>,
    }

    impl ClientWriter for Capture {
        fn headers(&mut self, headers: Headers) {
            self.headers = Some(headers);
        }
        fn start_request_body(&mut self) {}
        fn request_body_content(&mut self, _: &[u8]) {}
        fn end_request_body(&mut self) {}
        fn complete_request(&mut self) {}
        fn version(&self) -> hopf_http::HttpVersion {
            hopf_http::HttpVersion::Http11
        }
        fn conn_handle(&self) -> hopf_core::ConnHandle {
            hopf_core::ConnHandle::from_execute(std::sync::Arc::new(|task| task()))
        }
    }

    #[test]
    fn inject_does_not_overwrite() {
        let mut h = Headers::new();
        h.set(
            "traceparent",
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
        );
        inject_traceparent(
            &mut h,
            "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01",
        );
        assert_eq!(
            h.get("traceparent").unwrap(),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        );
        let t = Trace::new("c", SpanKind::Client);
        inject_trace(&mut h, &t);
        assert_eq!(
            h.get("traceparent").unwrap(),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        );
    }

    #[test]
    fn with_traceparent_wrapper_injects() {
        let mut cap = Capture { headers: None };
        {
            let mut w = with_traceparent(
                &mut cap,
                Some("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"),
            );
            let mut h = Headers::new();
            h.set(":method", "GET");
            w.headers(h);
        }
        assert_eq!(
            cap.headers.unwrap().get("traceparent").unwrap(),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        );
    }

    /// Records every call that reaches it.
    #[derive(Default)]
    struct Calls {
        log: Vec<String>,
        headers: Option<Headers>,
    }

    impl ClientWriter for Calls {
        fn headers(&mut self, headers: Headers) {
            self.log.push("headers".into());
            self.headers = Some(headers);
        }
        fn start_request_body(&mut self) {
            self.log.push("start".into());
        }
        fn request_body_content(&mut self, data: &[u8]) {
            self.log.push(format!("content:{}", data.len()));
        }
        fn end_request_body(&mut self) {
            self.log.push("end".into());
        }
        fn trailers(&mut self, _headers: Headers) {
            self.log.push("trailers".into());
        }
        fn complete_request(&mut self) {
            self.log.push("complete".into());
        }
        fn version(&self) -> hopf_http::HttpVersion {
            hopf_http::HttpVersion::Http2
        }
        fn conn_handle(&self) -> hopf_core::ConnHandle {
            hopf_core::ConnHandle::from_execute(std::sync::Arc::new(|task| task()))
        }
    }

    const TP: &str = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01";
    const WHOLE: [&str; 6] = ["headers", "start", "content:3", "end", "trailers", "complete"];

    fn drive(w: &mut dyn ClientWriter) -> hopf_http::HttpVersion {
        w.headers(Headers::new());
        w.start_request_body();
        w.request_body_content(b"abc");
        w.end_request_body();
        w.trailers(Headers::new());
        w.complete_request();
        let _ = w.conn_handle();
        w.version()
    }

    #[test]
    fn the_borrowed_wrapper_passes_every_call_through_and_adds_the_header() {
        let mut calls = Calls::default();
        let version = {
            let mut w = with_traceparent(&mut calls, Some(TP));
            drive(&mut w)
        };
        assert_eq!(calls.log, WHOLE);
        assert_eq!(version, hopf_http::HttpVersion::Http2);
        assert_eq!(calls.headers.unwrap().get("traceparent").unwrap(), TP);
    }

    #[test]
    fn the_borrowed_wrapper_with_nothing_to_add_leaves_the_headers_alone() {
        let mut calls = Calls::default();
        {
            let mut w = with_traceparent(&mut calls, None);
            drive(&mut w);
        }
        assert!(calls.headers.unwrap().get("traceparent").is_none());
    }

    #[test]
    fn the_owned_wrapper_passes_every_call_through_and_adds_the_header() {
        let mut calls = Calls::default();
        let version = {
            let mut w = OwnedPropagatingClientWriter::new(&mut calls, TP);
            drive(&mut w)
        };
        assert_eq!(calls.log, WHOLE);
        assert_eq!(version, hopf_http::HttpVersion::Http2);
        assert_eq!(calls.headers.unwrap().get("traceparent").unwrap(), TP);
    }

    #[test]
    fn a_wrapper_made_from_a_trace_sends_that_traces_header() {
        let trace = Trace::new("c", SpanKind::Client);
        let mut calls = Calls::default();
        {
            let mut w = with_trace(&mut calls, &trace);
            w.headers(Headers::new());
        }
        assert_eq!(calls.headers.unwrap().get("traceparent").unwrap(), trace.traceparent());
    }

    #[test]
    fn a_header_the_request_already_has_wins_over_the_wrapper() {
        let mut calls = Calls::default();
        {
            let mut w = OwnedPropagatingClientWriter::new(&mut calls, TP);
            let mut h = Headers::new();
            h.set("traceparent", "00-11111111111111111111111111111111-2222222222222222-01");
            w.headers(h);
        }
        assert!(calls.headers.unwrap().get("traceparent").unwrap().contains("1111"));
    }
}
