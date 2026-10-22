// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Stream-level instrumentation (Gumdrop `Stream.initTelemetrySpan` parity).

use std::sync::Arc;

use hopf_http::{
    Headers, ServerHandler, ServerHandlerFactory, ServerWriter,
};

use crate::access_log::{build_record, client_host, AccessRecordParams};
use crate::batch::ExportHandle;
use crate::metrics::{HttpServerMetrics, RequestTimer};
use crate::pipeline::TelemetryPipeline;
use crate::trace::{SpanKind, Trace};

/// Wraps a [`ServerHandlerFactory`] so each request gets a SERVER span + metrics.
///
/// Enable by wrapping your app factory when building the HTTP endpoint — same
/// idea as attaching Gumdrop `TelemetryConfig` on a listener.
pub struct InstrumentedServerFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    export: ExportHandle,
    metrics: Option<Arc<HttpServerMetrics>>,
    traces_enabled: bool,
    access_enabled: bool,
    protocol_version: String,
}

impl InstrumentedServerFactory {
    /// Instrument `inner` using `pipeline` flags and exporters.
    pub fn new(inner: Arc<dyn ServerHandlerFactory>, pipeline: &TelemetryPipeline) -> Self {
        let metrics = if pipeline.config().metrics_enabled {
            Some(pipeline.http_metrics())
        } else {
            None
        };
        Self {
            inner,
            export: pipeline.export_handle(),
            metrics,
            traces_enabled: pipeline.config().traces_enabled,
            access_enabled: pipeline.accepts(hopf_core::LogLevel::Access),
            protocol_version: "HTTP/1.1".into(),
        }
    }

    /// Set the `network.protocol.version` attribute on access records (for example `HTTP/2.0`).
    pub fn with_protocol_version(mut self, version: impl Into<String>) -> Self {
        self.protocol_version = version.into();
        self
    }

    /// Manual construction (tests / custom wiring).
    pub fn with_parts(
        inner: Arc<dyn ServerHandlerFactory>,
        export: ExportHandle,
        metrics: Option<Arc<HttpServerMetrics>>,
        traces_enabled: bool,
        access_enabled: bool,
        protocol_version: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            export,
            metrics,
            traces_enabled,
            access_enabled,
            protocol_version: protocol_version.into(),
        }
    }
}

impl ServerHandlerFactory for InstrumentedServerFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(InstrumentedHandler {
            inner: self.inner.create_handler(),
            export: self.export.clone(),
            metrics: self.metrics.clone(),
            traces_enabled: self.traces_enabled,
            access_enabled: self.access_enabled,
            protocol_version: self.protocol_version.clone(),
            state: None,
        })
    }
}

struct RequestState {
    method: String,
    target: String,
    client_address: String,
    timer: RequestTimer,
    request_bytes: u64,
    response_bytes: u64,
    status: u16,
    trace: Option<Trace>,
    traceparent: String,
    finished: bool,
}

struct InstrumentedHandler {
    inner: Box<dyn ServerHandler>,
    export: ExportHandle,
    metrics: Option<Arc<HttpServerMetrics>>,
    traces_enabled: bool,
    access_enabled: bool,
    protocol_version: String,
    state: Option<RequestState>,
}

impl InstrumentedHandler {
    fn begin(&mut self, headers: &Headers, response: &dyn ServerWriter) {
        let method = headers.method().unwrap_or("UNKNOWN").to_string();
        let target = headers.path().unwrap_or("-").to_string();
        let client_address = client_host(response.connection_info().remote_addr());
        let timer = RequestTimer::start();
        if let Some(m) = &self.metrics {
            m.request_started(&method);
        }

        let (trace, traceparent) = if self.traces_enabled {
            let span_name = format!("HTTP {method}");
            let t = Trace::from_traceparent(headers.get("traceparent"), span_name, SpanKind::Server);
            t.set_exporter(self.export.clone());
            let root = t.root_span();
            if let Some(m) = headers.method() {
                root.set_attribute("http.method", m);
            }
            if let Some(p) = headers.path() {
                root.set_attribute("http.target", p);
            }
            if let Some(a) = headers.authority() {
                root.set_attribute("http.host", a);
            }
            if let Some(s) = headers.scheme() {
                root.set_attribute("http.scheme", s);
            }
            let tp = t.traceparent();
            drop(root); // attributes set; keep root open until finish()
            (Some(t), tp)
        } else {
            (None, String::new())
        };

        self.state = Some(RequestState {
            method,
            target,
            client_address,
            timer,
            request_bytes: 0,
            response_bytes: 0,
            status: 200,
            trace,
            traceparent,
            finished: false,
        });
    }

    fn finish(&mut self) {
        let Some(state) = self.state.as_mut() else {
            return;
        };
        if state.finished {
            return;
        }
        state.finished = true;

        let (trace_id, span_id) = state
            .trace
            .as_ref()
            .map(|trace| {
                let ctx = trace.root_span().context();
                (Some(ctx.trace_id), Some(ctx.span_id))
            })
            .unwrap_or((None, None));

        let method = state.method.clone();
        let target = state.target.clone();
        let client_address = state.client_address.clone();
        let status = state.status;
        let response_bytes = state.response_bytes;
        let request_bytes = state.request_bytes;
        let elapsed = state.timer.elapsed();

        if let Some(trace) = state.trace.take() {
            let root = trace.root_span();
            root.set_attribute("http.status_code", status.to_string());
            if status >= 500 {
                root.set_status_error(format!("HTTP {status}"));
            } else {
                root.set_status_ok();
            }
            root.end();
            trace.end();
        }

        if let Some(m) = &self.metrics {
            m.request_completed(
                &method,
                status,
                elapsed,
                request_bytes,
                response_bytes,
            );
        }

        if self.access_enabled {
            let record = build_record(AccessRecordParams {
                client_address: &client_address,
                method: Some(method.as_str()),
                target: Some(target.as_str()),
                protocol_version: Some(self.protocol_version.as_str()),
                protocol_user: None,
                application_user: None,
                status_code: status,
                response_bytes,
                trace_id,
                span_id,
            });
            self.export.try_send_log(record);
        }
    }
}

impl ServerHandler for InstrumentedHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        self.begin(headers, response);
        let done = {
            let Self { inner, state, .. } = self;
            let mut wrapped = InstrumentedWriter {
                inner: response,
                state: state.as_mut().unwrap(),
                completed: false,
            };
            inner.headers(&mut wrapped, headers);
            wrapped.completed
        };
        if done {
            self.finish();
        }
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.state.is_none() {
            return;
        }
        let done = {
            let Self { inner, state, .. } = self;
            let mut wrapped = InstrumentedWriter {
                inner: response,
                state: state.as_mut().unwrap(),
                completed: false,
            };
            inner.start_request_body(&mut wrapped);
            wrapped.completed
        };
        if done {
            self.finish();
        }
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.state.is_none() {
            return;
        }
        let done = {
            let Self { inner, state, .. } = self;
            let state = state.as_mut().unwrap();
            state.request_bytes = state.request_bytes.saturating_add(data.len() as u64);
            let mut wrapped = InstrumentedWriter {
                inner: response,
                state,
                completed: false,
            };
            inner.request_body_content(&mut wrapped, data);
            wrapped.completed
        };
        if done {
            self.finish();
        }
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.state.is_none() {
            return;
        }
        let done = {
            let Self { inner, state, .. } = self;
            let mut wrapped = InstrumentedWriter {
                inner: response,
                state: state.as_mut().unwrap(),
                completed: false,
            };
            inner.end_request_body(&mut wrapped);
            wrapped.completed
        };
        if done {
            self.finish();
        }
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        if self.state.is_none() {
            self.inner.request_complete(response);
            return;
        }
        {
            let Self { inner, state, .. } = self;
            let mut wrapped = InstrumentedWriter {
                inner: response,
                state: state.as_mut().unwrap(),
                completed: false,
            };
            inner.request_complete(&mut wrapped);
        }
        self.finish();
    }
}

struct InstrumentedWriter<'a> {
    inner: &'a mut dyn ServerWriter,
    state: &'a mut RequestState,
    completed: bool,
}

impl ServerWriter for InstrumentedWriter<'_> {
    fn send_informational(&mut self, code: u16, headers: &Headers) {
        self.inner.send_informational(code, headers);
    }

    fn headers(&mut self, mut headers: Headers) {
        if self.state.trace.is_some() && !headers.contains("traceparent") {
            headers.set("traceparent", self.state.traceparent.clone());
        }
        self.state.status = headers.status_code();
        self.inner.headers(headers);
    }

    fn start_response_body(&mut self) {
        self.inner.start_response_body();
    }

    fn response_body_content(&mut self, data: &[u8]) {
        self.state.response_bytes = self
            .state
            .response_bytes
            .saturating_add(data.len() as u64);
        self.inner.response_body_content(data);
    }

    fn end_response_body(&mut self) {
        self.inner.end_response_body();
    }

    fn complete(&mut self) {
        self.inner.complete();
        self.completed = true;
    }

    fn traceparent(&self) -> Option<&str> {
        if self.state.trace.is_some() {
            Some(self.state.traceparent.as_str())
        } else {
            None
        }
    }

    fn conn_handle(&self) -> hopf_core::ConnHandle {
        self.inner.conn_handle()
    }

    fn response_handle(&self) -> hopf_http::ServerResponseHandle {
        self.inner.response_handle()
    }

    fn pause_request_body(&mut self) {
        self.inner.pause_request_body();
    }

    fn resume_request_body(&mut self) {
        self.inner.resume_request_body();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use hopf_http::Headers;

    struct Rec {
        seen_tp: Option<String>,
        status: u16,
    }

    struct Hello;
    impl ServerHandler for Hello {
        fn headers(&mut self, response: &mut dyn ServerWriter, _: &Headers) {
            let body = b"ok";
            let mut h = Headers::new();
            h.status(200);
            h.set("content-length", body.len().to_string());
            // App can read traceparent for outbound clients.
            let _ = response.traceparent();
            response.headers(h);
            response.start_response_body();
            response.response_body_content(body);
            response.end_response_body();
            response.complete();
        }
        fn request_complete(&mut self, _: &mut dyn ServerWriter) {}
    }

    struct HelloFactory;
    impl ServerHandlerFactory for HelloFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            Box::new(Hello)
        }
    }

    struct CapturingWriter {
        headers: Option<Headers>,
        body: Vec<u8>,
        rec: Arc<Mutex<Rec>>,
    }

    impl ServerWriter for CapturingWriter {
        fn headers(&mut self, headers: Headers) {
            self.rec.lock().unwrap().status = headers.status_code();
            if let Some(tp) = headers.get("traceparent") {
                self.rec.lock().unwrap().seen_tp = Some(tp.to_string());
            }
            self.headers = Some(headers);
        }
        fn start_response_body(&mut self) {}
        fn response_body_content(&mut self, data: &[u8]) {
            self.body.extend_from_slice(data);
        }
        fn end_response_body(&mut self) {}
        fn complete(&mut self) {}

        fn conn_handle(&self) -> hopf_core::ConnHandle {
            hopf_core::ConnHandle::from_execute(std::sync::Arc::new(|task| task()))
        }

        fn response_handle(&self) -> hopf_http::ServerResponseHandle {
            // Test double: not used by instrumented path under test.
            panic!("CapturingWriter::response_handle not used in otel unit tests")
        }

        fn pause_request_body(&mut self) {}
        fn resume_request_body(&mut self) {}
    }

    #[test]
    fn instrumented_injects_response_traceparent_and_continues() {
        let traces = std::env::temp_dir().join(format!(
            "hopf-otel-traces-{}.jsonl",
            std::process::id()
        ));
        let metrics = std::env::temp_dir().join(format!(
            "hopf-otel-metrics-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&traces);
        let _ = std::fs::remove_file(&metrics);

        let pipeline = TelemetryPipeline::start(
            crate::OtelConfig::new("http-test")
                .with_jsonl_traces(&traces)
                .with_jsonl_metrics(&metrics),
        )
        .unwrap();

        let factory = InstrumentedServerFactory::new(Arc::new(HelloFactory), &pipeline);
        let mut handler = factory.create_handler();

        let parent = Trace::new("upstream", SpanKind::Client);
        let inbound = parent.traceparent();

        let mut req = Headers::new();
        req.set(":method", "GET");
        req.set(":path", "/");
        req.set("traceparent", &inbound);

        let rec = Arc::new(Mutex::new(Rec {
            seen_tp: None,
            status: 0,
        }));
        let mut writer = CapturingWriter {
            headers: None,
            body: Vec::new(),
            rec: Arc::clone(&rec),
        };

        handler.headers(&mut writer, &req);
        handler.request_complete(&mut writer);

        let seen = rec.lock().unwrap().seen_tp.clone().expect("traceparent");
        let parent_ctx = crate::SpanContext::from_traceparent(&inbound).unwrap();
        let resp_ctx = crate::SpanContext::from_traceparent(&seen).unwrap();
        assert_eq!(resp_ctx.trace_id, parent_ctx.trace_id);
        assert_ne!(resp_ctx.span_id, parent_ctx.span_id);
        assert_eq!(writer.body, b"ok");

        pipeline.flush().unwrap();
        pipeline.shutdown();

        let body = std::fs::read_to_string(&traces).unwrap();
        assert!(body.contains("HTTP GET"), "{body}");
        assert!(body.contains("resourceSpans"), "{body}");
        let _ = std::fs::remove_file(&traces);
        let _ = std::fs::remove_file(&metrics);
    }

    #[test]
    fn access_log_emits_one_clf_line_per_protocol_version() {
        for (version, path_part) in [
            ("HTTP/1.1", "v1"),
            ("HTTP/2.0", "v2"),
            ("HTTP/3", "v3"),
        ] {
            let path = std::env::temp_dir().join(format!(
                "hopf-otel-access-{path_part}-{}.log",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            let pipeline = TelemetryPipeline::start(
                crate::OtelConfig::new("access-test")
                    .with_access_log(
                        &path,
                        crate::AccessLogFormat::Clf,
                        crate::AccessLogUserSelection::ProtocolFirst,
                    )
                    .with_traces(false)
                    .with_metrics(false),
            )
            .unwrap();
            let factory = InstrumentedServerFactory::new(Arc::new(HelloFactory), &pipeline)
                .with_protocol_version(version);
            let mut handler = factory.create_handler();
            let mut req = Headers::new();
            req.set(":method", "GET");
            req.set(":path", "/access");
            let rec = Arc::new(Mutex::new(Rec {
                seen_tp: None,
                status: 0,
            }));
            let mut writer = CapturingWriter {
                headers: None,
                body: Vec::new(),
                rec: Arc::clone(&rec),
            };
            handler.headers(&mut writer, &req);
            handler.request_complete(&mut writer);
            pipeline.flush().unwrap();
            pipeline.shutdown();
            let body = std::fs::read_to_string(&path).unwrap();
            assert_eq!(body.matches("GET /access").count(), 1, "{body}");
            assert!(body.contains(version), "{body}");
            assert!(body.contains(" 200 2"), "{body}");
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn inject_traceparent_skips_existing() {
        let mut h = Headers::new();
        h.set("traceparent", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01");
        crate::inject_traceparent(&mut h, "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01");
        assert_eq!(
            h.get("traceparent").unwrap(),
            "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
        );
    }
}

