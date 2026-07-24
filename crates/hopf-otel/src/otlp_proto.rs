// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! OTLP protobuf encoding for ExportLogsServiceRequest (rprotobuf Writer).

use rprotobuf::Writer;

use crate::config::OtelConfig;
use crate::event::TelemetryEvent;
use crate::metrics::MetricPoint;
use crate::trace::FinishedSpan;

// Field numbers from opentelemetry-proto / Gumdrop OTLPFieldNumbers.
const LOGS_RESOURCE_LOGS: u32 = 1;
const RESOURCE_LOGS_RESOURCE: u32 = 1;
const RESOURCE_LOGS_SCOPE_LOGS: u32 = 2;
const RESOURCE_ATTRIBUTES: u32 = 1;
const SCOPE_LOGS_SCOPE: u32 = 1;
const SCOPE_LOGS_LOG_RECORDS: u32 = 2;
const SCOPE_NAME: u32 = 1;
const SCOPE_VERSION: u32 = 2;
const LOG_TIME: u32 = 1;
const LOG_SEVERITY_NUMBER: u32 = 2;
const LOG_SEVERITY_TEXT: u32 = 3;
const LOG_BODY: u32 = 5;
const LOG_ATTRIBUTES: u32 = 6;
const KV_KEY: u32 = 1;
const KV_VALUE: u32 = 2;
const ANY_STRING: u32 = 1;

const TRACES_RESOURCE_SPANS: u32 = 1;
const RESOURCE_SPANS_RESOURCE: u32 = 1;
const RESOURCE_SPANS_SCOPE_SPANS: u32 = 2;
const SCOPE_SPANS_SCOPE: u32 = 1;
const SCOPE_SPANS_SPANS: u32 = 2;
const SPAN_TRACE_ID: u32 = 1;
const SPAN_SPAN_ID: u32 = 2;
const SPAN_PARENT_SPAN_ID: u32 = 4;
const SPAN_NAME: u32 = 5;
const SPAN_KIND: u32 = 6;
const SPAN_START: u32 = 7;
const SPAN_END: u32 = 8;
const SPAN_ATTRIBUTES: u32 = 9;
const SPAN_STATUS: u32 = 15;
const STATUS_MESSAGE: u32 = 2;
const STATUS_CODE: u32 = 3;

const METRICS_RESOURCE_METRICS: u32 = 1;
const RESOURCE_METRICS_RESOURCE: u32 = 1;
const RESOURCE_METRICS_SCOPE_METRICS: u32 = 2;
const SCOPE_METRICS_SCOPE: u32 = 1;
const SCOPE_METRICS_METRICS: u32 = 2;
const METRIC_NAME: u32 = 1;
const METRIC_UNIT: u32 = 3;
const METRIC_GAUGE: u32 = 5;
const METRIC_SUM: u32 = 7;
const METRIC_HISTOGRAM: u32 = 9;
const SUM_DATA_POINTS: u32 = 1;
const SUM_AGG_TEMPORALITY: u32 = 2;
const SUM_IS_MONOTONIC: u32 = 3;
const GAUGE_DATA_POINTS: u32 = 1;
const HIST_DATA_POINTS: u32 = 1;
const HIST_AGG_TEMPORALITY: u32 = 2;
const NDP_ATTRIBUTES: u32 = 7;
const NDP_TIME: u32 = 3;
const NDP_AS_INT: u32 = 6;
const HDP_ATTRIBUTES: u32 = 9;
const HDP_TIME: u32 = 3;
const HDP_COUNT: u32 = 4;
const HDP_SUM: u32 = 5;

/// Encode a batch as `ExportLogsServiceRequest` protobuf bytes.
pub fn encode_logs_request(config: &OtelConfig, events: &[TelemetryEvent]) -> Vec<u8> {
    let mut w = Writer::buffer(4096 + events.len() * 256);
    let _ = w.write_message_field(LOGS_RESOURCE_LOGS, |rl| {
        rl.write_message_field(RESOURCE_LOGS_RESOURCE, |res| {
            write_resource(res, config)
        })?;
        rl.write_message_field(RESOURCE_LOGS_SCOPE_LOGS, |sl| {
            sl.write_message_field(SCOPE_LOGS_SCOPE, |scope| {
                scope.write_string_field(SCOPE_NAME, "hopf")?;
                scope.write_string_field(SCOPE_VERSION, env!("CARGO_PKG_VERSION"))?;
                Ok(())
            })?;
            for ev in events {
                sl.write_message_field(SCOPE_LOGS_LOG_RECORDS, |lr| write_log_record(lr, ev))?;
            }
            Ok(())
        })?;
        Ok(())
    });
    w.finish()
}

fn write_resource(w: &mut Writer<rprotobuf::Buffer>, config: &OtelConfig) -> Result<(), rprotobuf::WriteError> {
    write_kv(w, RESOURCE_ATTRIBUTES, "service.name", &config.service_name)?;
    if let Some(v) = &config.service_version {
        write_kv(w, RESOURCE_ATTRIBUTES, "service.version", v)?;
    }
    if let Some(ns) = &config.service_namespace {
        write_kv(w, RESOURCE_ATTRIBUTES, "service.namespace", ns)?;
    }
    Ok(())
}

fn write_log_record(
    w: &mut Writer<rprotobuf::Buffer>,
    ev: &TelemetryEvent,
) -> Result<(), rprotobuf::WriteError> {
    w.write_fixed64_field(LOG_TIME, ev.time_unix_nano)?;
    w.write_varint_field(LOG_SEVERITY_NUMBER, ev.severity_number() as u64)?;
    w.write_string_field(LOG_SEVERITY_TEXT, ev.severity_text())?;
    w.write_message_field(LOG_BODY, |any| {
        any.write_string_field(ANY_STRING, &ev.message)
    })?;
    write_kv(w, LOG_ATTRIBUTES, "event.name", ev.event_name())?;
    if let Some(peer) = ev.peer {
        write_kv(w, LOG_ATTRIBUTES, "net.peer.ip", &peer.ip().to_string())?;
        write_kv(w, LOG_ATTRIBUTES, "net.peer.port", &peer.port().to_string())?;
    }
    Ok(())
}

fn write_kv(
    w: &mut Writer<rprotobuf::Buffer>,
    field: u32,
    key: &str,
    value: &str,
) -> Result<(), rprotobuf::WriteError> {
    w.write_message_field(field, |kv| {
        kv.write_string_field(KV_KEY, key)?;
        kv.write_message_field(KV_VALUE, |any| any.write_string_field(ANY_STRING, value))?;
        Ok(())
    })
}

/// Encode `ExportTraceServiceRequest`.
pub fn encode_traces_request(config: &OtelConfig, spans: &[FinishedSpan]) -> Vec<u8> {
    let mut w = Writer::buffer(4096 + spans.len() * 512);
    let _ = w.write_message_field(TRACES_RESOURCE_SPANS, |rs| {
        rs.write_message_field(RESOURCE_SPANS_RESOURCE, |res| write_resource(res, config))?;
        rs.write_message_field(RESOURCE_SPANS_SCOPE_SPANS, |ss| {
            ss.write_message_field(SCOPE_SPANS_SCOPE, |scope| {
                scope.write_string_field(SCOPE_NAME, "hopf")?;
                scope.write_string_field(SCOPE_VERSION, env!("CARGO_PKG_VERSION"))?;
                Ok(())
            })?;
            for span in spans {
                ss.write_message_field(SCOPE_SPANS_SPANS, |sp| write_span(sp, span))?;
            }
            Ok(())
        })?;
        Ok(())
    });
    w.finish()
}

fn write_span(
    w: &mut Writer<rprotobuf::Buffer>,
    span: &FinishedSpan,
) -> Result<(), rprotobuf::WriteError> {
    w.write_bytes_field(SPAN_TRACE_ID, &span.context.trace_id)?;
    w.write_bytes_field(SPAN_SPAN_ID, &span.context.span_id)?;
    if let Some(parent) = &span.parent_span_id {
        w.write_bytes_field(SPAN_PARENT_SPAN_ID, parent)?;
    }
    w.write_string_field(SPAN_NAME, &span.name)?;
    w.write_varint_field(SPAN_KIND, span.kind as u64)?;
    w.write_fixed64_field(SPAN_START, span.start_time_unix_nano)?;
    w.write_fixed64_field(SPAN_END, span.end_time_unix_nano)?;
    for (k, v) in &span.attributes {
        write_kv(w, SPAN_ATTRIBUTES, k, v)?;
    }
    w.write_message_field(SPAN_STATUS, |st| {
        if !span.status_message.is_empty() {
            st.write_string_field(STATUS_MESSAGE, &span.status_message)?;
        }
        st.write_varint_field(STATUS_CODE, span.status_code as u64)?;
        Ok(())
    })?;
    Ok(())
}

/// Encode `ExportMetricsServiceRequest` (simplified sum/histogram/gauge).
pub fn encode_metrics_request(config: &OtelConfig, points: &[MetricPoint]) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut w = Writer::buffer(4096 + points.len() * 256);
    let _ = w.write_message_field(METRICS_RESOURCE_METRICS, |rm| {
        rm.write_message_field(RESOURCE_METRICS_RESOURCE, |res| write_resource(res, config))?;
        rm.write_message_field(RESOURCE_METRICS_SCOPE_METRICS, |sm| {
            sm.write_message_field(SCOPE_METRICS_SCOPE, |scope| {
                scope.write_string_field(SCOPE_NAME, "org.bluezoo.hopf.http")?;
                Ok(())
            })?;
            for p in points {
                sm.write_message_field(SCOPE_METRICS_METRICS, |m| write_metric(m, p, now))?;
            }
            Ok(())
        })?;
        Ok(())
    });
    w.finish()
}

fn write_metric(
    w: &mut Writer<rprotobuf::Buffer>,
    point: &MetricPoint,
    now: u64,
) -> Result<(), rprotobuf::WriteError> {
    match point {
        MetricPoint::Counter {
            name,
            attributes,
            value,
        } => {
            w.write_string_field(METRIC_NAME, name)?;
            w.write_message_field(METRIC_SUM, |sum| {
                sum.write_varint_field(SUM_AGG_TEMPORALITY, 2)?; // cumulative
                sum.write_bool_field(SUM_IS_MONOTONIC, true)?;
                sum.write_message_field(SUM_DATA_POINTS, |dp| {
                    for (k, v) in attributes {
                        write_kv(dp, NDP_ATTRIBUTES, k, v)?;
                    }
                    dp.write_fixed64_field(NDP_TIME, now)?;
                    dp.write_varint_field(NDP_AS_INT, *value)?;
                    Ok(())
                })?;
                Ok(())
            })?;
        }
        MetricPoint::UpDown {
            name,
            attributes,
            value,
        } => {
            w.write_string_field(METRIC_NAME, name)?;
            w.write_message_field(METRIC_GAUGE, |g| {
                g.write_message_field(GAUGE_DATA_POINTS, |dp| {
                    for (k, v) in attributes {
                        write_kv(dp, NDP_ATTRIBUTES, k, v)?;
                    }
                    dp.write_fixed64_field(NDP_TIME, now)?;
                    dp.write_varint_field(NDP_AS_INT, *value as u64)?;
                    Ok(())
                })?;
                Ok(())
            })?;
        }
        MetricPoint::Histogram {
            name,
            unit,
            attributes,
            value,
        } => {
            w.write_string_field(METRIC_NAME, name)?;
            w.write_string_field(METRIC_UNIT, unit)?;
            w.write_message_field(METRIC_HISTOGRAM, |h| {
                h.write_varint_field(HIST_AGG_TEMPORALITY, 1)?; // delta
                h.write_message_field(HIST_DATA_POINTS, |dp| {
                    for (k, v) in attributes {
                        write_kv(dp, HDP_ATTRIBUTES, k, v)?;
                    }
                    dp.write_fixed64_field(HDP_TIME, now)?;
                    dp.write_varint_field(HDP_COUNT, 1)?;
                    dp.write_double_field(HDP_SUM, *value)?;
                    Ok(())
                })?;
                Ok(())
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OtelConfig;
    use crate::event::{EventKind, TelemetryEvent};
    use crate::metrics::MetricPoint;
    use crate::trace::{FinishedSpan, SpanContext, SpanKind, SpanStatusCode};

    #[test]
    fn encode_logs_traces_metrics_nonempty() {
        let cfg = OtelConfig::new("cov");
        let logs = encode_logs_request(
            &cfg,
            &[TelemetryEvent::new(EventKind::Accept, None, "hi")],
        );
        assert!(!logs.is_empty());
        assert_eq!(logs[0] & 0x07, 2);

        let span = FinishedSpan {
            context: SpanContext::new_sampled(),
            parent_span_id: None,
            name: "HTTP GET".into(),
            kind: SpanKind::Server,
            start_time_unix_nano: 1,
            end_time_unix_nano: 2,
            attributes: vec![("http.method".into(), "GET".into())],
            status_code: SpanStatusCode::Ok,
            status_message: String::new(),
        };
        let traces = encode_traces_request(&cfg, &[span]);
        assert!(!traces.is_empty());

        let metrics = encode_metrics_request(
            &cfg,
            &[
                MetricPoint::Counter {
                    name: "http.server.requests",
                    attributes: vec![("http.method".into(), "GET".into())],
                    value: 1,
                },
                MetricPoint::UpDown {
                    name: "http.server.active_requests",
                    attributes: vec![],
                    value: 2,
                },
                MetricPoint::Histogram {
                    name: "http.server.request.duration",
                    unit: "ms",
                    attributes: vec![],
                    value: 12.5,
                },
            ],
        );
        assert!(!metrics.is_empty());
    }
}
