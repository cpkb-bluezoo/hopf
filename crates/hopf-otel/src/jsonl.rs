// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! OTLP JSON Lines file appender (export worker only).

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::config::OtelConfig;
use crate::crypto_ids::to_hex;
use crate::log_record::{AttrValue, LogRecord};

/// Append one JSON object per batch as a JSONL line.
pub struct JsonlAppender {
    path: PathBuf,
}

impl JsonlAppender {
    /// Open/create append path (parent dirs must exist).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Path being written.
    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Encode and append logs JSONL.
    pub fn append_logs(&self, config: &OtelConfig, records: &[LogRecord]) -> Result<(), String> {
        self.append_line(&encode_logs_json(config, records))
    }

    /// Encode and append traces JSONL.
    pub fn append_traces(
        &self,
        config: &OtelConfig,
        spans: &[crate::trace::FinishedSpan],
    ) -> Result<(), String> {
        self.append_line(&encode_traces_json(config, spans))
    }

    /// Encode and append metrics JSONL.
    pub fn append_metrics(
        &self,
        config: &OtelConfig,
        points: &[crate::metrics::MetricPoint],
    ) -> Result<(), String> {
        self.append_line(&encode_metrics_json(config, points))
    }

    fn append_line(&self, line: &str) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        file.write_all(b"\n").map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// Escape a string for JSON string context.
pub(crate) fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn kv_string(key: &str, value: &str) -> String {
    format!(
        "{{\"key\":\"{}\",\"value\":{{\"stringValue\":\"{}\"}}}}",
        escape_json(key),
        escape_json(value)
    )
}

fn kv_attr(key: &str, value: &AttrValue) -> String {
    let value_json = match value {
        AttrValue::String(s) => format!("{{\"stringValue\":\"{}\"}}", escape_json(s)),
        AttrValue::Int(v) => format!("{{\"intValue\":\"{v}\"}}"),
        AttrValue::Bool(v) => format!("{{\"boolValue\":{v}}}"),
        AttrValue::Double(v) => format!("{{\"doubleValue\":{v}}}"),
    };
    format!(
        "{{\"key\":\"{}\",\"value\":{value_json}}}",
        escape_json(key)
    )
}

/// OTLP JSON encoding of ExportLogsServiceRequest (one object).
pub fn encode_logs_json(config: &OtelConfig, records: &[LogRecord]) -> String {
    let mut resource_attrs = vec![kv_string("service.name", &config.service_name)];
    if let Some(v) = &config.service_version {
        resource_attrs.push(kv_string("service.version", v));
    }
    if let Some(ns) = &config.service_namespace {
        resource_attrs.push(kv_string("service.namespace", ns));
    }

    let mut by_scope: BTreeMap<&str, Vec<&LogRecord>> = BTreeMap::new();
    for rec in records {
        by_scope.entry(rec.scope.as_str()).or_default().push(rec);
    }

    let mut scope_logs = String::new();
    for (scope_idx, (scope_name, scoped)) in by_scope.iter().enumerate() {
        if scope_idx > 0 {
            scope_logs.push(',');
        }
        let mut records_json = String::new();
        for (i, rec) in scoped.iter().enumerate() {
            if i > 0 {
                records_json.push(',');
            }
            let mut attrs = vec![kv_string("event.name", &rec.name)];
            for (k, v) in &rec.attrs {
                attrs.push(kv_attr(k, v));
            }
            let body = rec
                .body
                .as_deref()
                .map(|b| format!("{{\"stringValue\":\"{}\"}}", escape_json(b)))
                .unwrap_or_else(|| "null".into());
            let trace = rec
                .trace_id
                .map(|t| format!(",\"traceId\":\"{}\"", to_hex(&t)))
                .unwrap_or_default();
            let span = rec
                .span_id
                .map(|s| format!(",\"spanId\":\"{}\"", to_hex(&s)))
                .unwrap_or_default();
            records_json.push_str(&format!(
                "{{\
                 \"timeUnixNano\":\"{}\",\
                 \"severityNumber\":{},\
                 \"severityText\":\"{}\",\
                 \"body\":{body},\
                 \"attributes\":[{attrs}]{trace}{span}\
                 }}",
                rec.time_unix_nano,
                rec.level.severity_number(),
                escape_json(rec.level.severity_text()),
                attrs = attrs.join(","),
            ));
        }
        scope_logs.push_str(&format!(
            "{{\
             \"scope\":{{\"name\":\"{}\",\"version\":\"{}\"}},\
             \"logRecords\":[{records_json}]\
             }}",
            escape_json(scope_name),
            env!("CARGO_PKG_VERSION"),
        ));
    }

    format!(
        "{{\
         \"resourceLogs\":[{{\
           \"resource\":{{\"attributes\":[{}]}},\
           \"scopeLogs\":[{scope_logs}]\
         }}]\
         }}",
        resource_attrs.join(","),
    )
}

fn resource_attrs_json(config: &OtelConfig) -> String {
    let mut resource_attrs = vec![kv_string("service.name", &config.service_name)];
    if let Some(v) = &config.service_version {
        resource_attrs.push(kv_string("service.version", v));
    }
    if let Some(ns) = &config.service_namespace {
        resource_attrs.push(kv_string("service.namespace", ns));
    }
    resource_attrs.join(",")
}

/// OTLP JSON ExportTraceServiceRequest.
pub fn encode_traces_json(config: &OtelConfig, spans: &[crate::trace::FinishedSpan]) -> String {
    use crate::crypto_ids::to_hex;
    let mut span_json = String::new();
    for (i, s) in spans.iter().enumerate() {
        if i > 0 {
            span_json.push(',');
        }
        let attrs: Vec<_> = s
            .attributes
            .iter()
            .map(|(k, v)| kv_string(k, v))
            .collect();
        let parent = s
            .parent_span_id
            .map(|p| format!(",\"parentSpanId\":\"{}\"", to_hex(&p)))
            .unwrap_or_default();
        span_json.push_str(&format!(
            "{{\
             \"traceId\":\"{}\",\
             \"spanId\":\"{}\"{parent},\
             \"name\":\"{}\",\
             \"kind\":{},\
             \"startTimeUnixNano\":\"{}\",\
             \"endTimeUnixNano\":\"{}\",\
             \"attributes\":[{}],\
             \"status\":{{\"code\":{}}}\
             }}",
            to_hex(&s.context.trace_id),
            to_hex(&s.context.span_id),
            escape_json(&s.name),
            s.kind as i32,
            s.start_time_unix_nano,
            s.end_time_unix_nano,
            attrs.join(","),
            s.status_code as i32,
        ));
    }
    format!(
        "{{\"resourceSpans\":[{{\"resource\":{{\"attributes\":[{}]}},\
         \"scopeSpans\":[{{\"scope\":{{\"name\":\"hopf\"}},\"spans\":[{span_json}]}}]}}]}}",
        resource_attrs_json(config),
    )
}

/// OTLP JSON ExportMetricsServiceRequest (compact).
pub fn encode_metrics_json(config: &OtelConfig, points: &[crate::metrics::MetricPoint]) -> String {
    use crate::metrics::MetricPoint;
    let mut metrics = String::new();
    for (i, p) in points.iter().enumerate() {
        if i > 0 {
            metrics.push(',');
        }
        match p {
            MetricPoint::Counter {
                name,
                attributes,
                value,
            } => {
                let attrs: Vec<_> = attributes.iter().map(|(k, v)| kv_string(k, v)).collect();
                metrics.push_str(&format!(
                    "{{\"name\":\"{name}\",\"sum\":{{\"dataPoints\":[{{\"attributes\":[{}],\"asInt\":\"{value}\"}}],\"isMonotonic\":true,\"aggregationTemporality\":2}}}}",
                    attrs.join(",")
                ));
            }
            MetricPoint::UpDown {
                name,
                attributes,
                value,
            } => {
                let attrs: Vec<_> = attributes.iter().map(|(k, v)| kv_string(k, v)).collect();
                metrics.push_str(&format!(
                    "{{\"name\":\"{name}\",\"gauge\":{{\"dataPoints\":[{{\"attributes\":[{}],\"asInt\":\"{value}\"}}]}}}}",
                    attrs.join(",")
                ));
            }
            MetricPoint::Histogram {
                name,
                unit,
                attributes,
                value,
            } => {
                let attrs: Vec<_> = attributes.iter().map(|(k, v)| kv_string(k, v)).collect();
                metrics.push_str(&format!(
                    "{{\"name\":\"{name}\",\"unit\":\"{unit}\",\"histogram\":{{\"dataPoints\":[{{\"attributes\":[{}],\"count\":\"1\",\"sum\":{value}}}],\"aggregationTemporality\":1}}}}",
                    attrs.join(",")
                ));
            }
        }
    }
    format!(
        "{{\"resourceMetrics\":[{{\"resource\":{{\"attributes\":[{}]}},\
         \"scopeMetrics\":[{{\"scope\":{{\"name\":\"org.bluezoo.hopf\"}},\"metrics\":[{metrics}]}}]}}]}}",
        resource_attrs_json(config),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_record::LogLevel;
    #[test]
    fn json_contains_service_and_event() {
        let cfg = OtelConfig::new("test-svc");
        let rec = LogRecord::new(LogLevel::Info, "connection.accept")
            .with_body("accept")
            .attr("net.peer.ip", "127.0.0.1");
        let s = encode_logs_json(&cfg, &[rec]);
        assert!(s.contains("test-svc"));
        assert!(s.contains("connection.accept"));
        assert!(s.contains("resourceLogs"));
    }

    #[test]
    fn json_roundtrips_trace_and_attrs() {
        let cfg = OtelConfig::new("trace-svc");
        let trace_id = [0x01; 16];
        let span_id = [0x02; 8];
        let rec = LogRecord::new(LogLevel::Info, "http.request")
            .with_body("done")
            .attr("http.method", "GET")
            .with_trace_ids(trace_id, span_id);
        let s = encode_logs_json(&cfg, &[rec]);
        assert!(s.contains("http.method"));
        assert!(s.contains("GET"));
        assert!(s.contains("01010101010101010101010101010101"));
        assert!(s.contains("0202020202020202"));
    }
}
