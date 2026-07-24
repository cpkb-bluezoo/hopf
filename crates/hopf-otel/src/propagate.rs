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

    fn complete_request(&mut self) {
        self.inner.complete_request();
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

    fn complete_request(&mut self) {
        self.inner.complete_request();
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
}
