// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Background batching and export (never on accept/reactor threads).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::OtelConfig;
use crate::event::TelemetryEvent;
use crate::jsonl::JsonlAppender;
use crate::metrics::MetricPoint;
use crate::otlp_http::{post_protobuf, HttpEndpoint};
use crate::otlp_proto::{encode_logs_request, encode_metrics_request, encode_traces_request};
use crate::trace::FinishedSpan;

enum Msg {
    Log(TelemetryEvent),
    Spans(Vec<FinishedSpan>),
    Metric(MetricPoint),
    Flush,
    Shutdown,
}

/// Handle used from the hot path to enqueue telemetry.
#[derive(Clone)]
pub struct ExportHandle {
    tx: SyncSender<Msg>,
}

impl ExportHandle {
    /// Enqueue a log event (non-blocking).
    pub fn try_send_log(&self, event: TelemetryEvent) {
        let _ = self.tx.try_send(Msg::Log(event));
    }

    /// Enqueue finished spans from one trace.
    pub fn try_send_spans(&self, spans: Vec<FinishedSpan>) {
        if spans.is_empty() {
            return;
        }
        match self.tx.try_send(Msg::Spans(spans)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Enqueue a metric point.
    pub fn try_send_metric(&self, point: MetricPoint) {
        let _ = self.tx.try_send(Msg::Metric(point));
    }

    /// Request a flush (best-effort).
    pub fn flush(&self) {
        let _ = self.tx.try_send(Msg::Flush);
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
    }
}

/// Spawn the export worker.
pub fn spawn_worker(config: OtelConfig) -> (ExportHandle, JoinHandle<()>, Arc<AtomicBool>) {
    let (tx, rx) = mpsc::sync_channel(config.queue_capacity);
    let running = Arc::new(AtomicBool::new(true));
    let running2 = Arc::clone(&running);
    let handle = thread::Builder::new()
        .name("hopf-otel-export".into())
        .spawn(move || export_loop(config, rx, running2))
        .expect("spawn otel export worker");
    (ExportHandle { tx }, handle, running)
}

struct Sinks {
    logs_http: Option<HttpEndpoint>,
    traces_http: Option<HttpEndpoint>,
    metrics_http: Option<HttpEndpoint>,
    logs_jsonl: Option<JsonlAppender>,
    traces_jsonl: Option<JsonlAppender>,
    metrics_jsonl: Option<JsonlAppender>,
}

fn export_loop(config: OtelConfig, rx: Receiver<Msg>, running: Arc<AtomicBool>) {
    let sinks = Sinks {
        logs_http: config
            .otlp_logs_endpoint
            .as_ref()
            .and_then(|u| HttpEndpoint::parse(u)),
        traces_http: config
            .otlp_traces_endpoint
            .as_ref()
            .and_then(|u| HttpEndpoint::parse(u)),
        metrics_http: config
            .otlp_metrics_endpoint
            .as_ref()
            .and_then(|u| HttpEndpoint::parse(u)),
        logs_jsonl: config.jsonl_logs_path.as_ref().map(|p| JsonlAppender::new(p.clone())),
        traces_jsonl: config
            .jsonl_traces_path
            .as_ref()
            .map(|p| JsonlAppender::new(p.clone())),
        metrics_jsonl: config
            .jsonl_metrics_path
            .as_ref()
            .map(|p| JsonlAppender::new(p.clone())),
    };

    let mut logs: Vec<TelemetryEvent> = Vec::with_capacity(config.batch_size);
    let mut spans: Vec<FinishedSpan> = Vec::with_capacity(config.batch_size);
    let mut metrics: Vec<MetricPoint> = Vec::with_capacity(config.batch_size);
    let mut last_flush = Instant::now();

    while running.load(Ordering::Acquire) {
        let timeout = config
            .flush_interval
            .saturating_sub(last_flush.elapsed())
            .max(Duration::from_millis(50));

        match rx.recv_timeout(timeout) {
            Ok(Msg::Log(ev)) => {
                logs.push(ev);
                if logs.len() >= config.batch_size {
                    flush_logs(&config, &sinks, &mut logs);
                    last_flush = Instant::now();
                }
            }
            Ok(Msg::Spans(mut s)) => {
                spans.append(&mut s);
                if spans.len() >= config.batch_size {
                    flush_spans(&config, &sinks, &mut spans);
                    last_flush = Instant::now();
                }
            }
            Ok(Msg::Metric(m)) => {
                metrics.push(m);
                if metrics.len() >= config.batch_size {
                    flush_metrics(&config, &sinks, &mut metrics);
                    last_flush = Instant::now();
                }
            }
            Ok(Msg::Flush) => {
                flush_all(&config, &sinks, &mut logs, &mut spans, &mut metrics);
                last_flush = Instant::now();
            }
            Ok(Msg::Shutdown) => {
                flush_all(&config, &sinks, &mut logs, &mut spans, &mut metrics);
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                if last_flush.elapsed() >= config.flush_interval {
                    flush_all(&config, &sinks, &mut logs, &mut spans, &mut metrics);
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                flush_all(&config, &sinks, &mut logs, &mut spans, &mut metrics);
                break;
            }
        }
    }
    running.store(false, Ordering::Release);
}

fn flush_all(
    config: &OtelConfig,
    sinks: &Sinks,
    logs: &mut Vec<TelemetryEvent>,
    spans: &mut Vec<FinishedSpan>,
    metrics: &mut Vec<MetricPoint>,
) {
    flush_logs(config, sinks, logs);
    flush_spans(config, sinks, spans);
    flush_metrics(config, sinks, metrics);
}

fn flush_logs(config: &OtelConfig, sinks: &Sinks, batch: &mut Vec<TelemetryEvent>) {
    if batch.is_empty() {
        return;
    }
    if let Some(appender) = &sinks.logs_jsonl {
        if let Err(e) = appender.append_logs(config, batch) {
            eprintln!("hopf-otel: jsonl logs failed: {e}");
        }
    }
    if let Some(ep) = &sinks.logs_http {
        let body = encode_logs_request(config, batch);
        if let Err(e) = post_protobuf(ep, &body) {
            eprintln!("hopf-otel: otlp logs failed: {e}");
        }
    }
    batch.clear();
}

fn flush_spans(config: &OtelConfig, sinks: &Sinks, batch: &mut Vec<FinishedSpan>) {
    if batch.is_empty() || !config.traces_enabled {
        batch.clear();
        return;
    }
    if let Some(appender) = &sinks.traces_jsonl {
        if let Err(e) = appender.append_traces(config, batch) {
            eprintln!("hopf-otel: jsonl traces failed: {e}");
        }
    }
    if let Some(ep) = &sinks.traces_http {
        let body = encode_traces_request(config, batch);
        if let Err(e) = post_protobuf(ep, &body) {
            eprintln!("hopf-otel: otlp traces failed: {e}");
        }
    }
    batch.clear();
}

fn flush_metrics(config: &OtelConfig, sinks: &Sinks, batch: &mut Vec<MetricPoint>) {
    if batch.is_empty() || !config.metrics_enabled {
        batch.clear();
        return;
    }
    if let Some(appender) = &sinks.metrics_jsonl {
        if let Err(e) = appender.append_metrics(config, batch) {
            eprintln!("hopf-otel: jsonl metrics failed: {e}");
        }
    }
    if let Some(ep) = &sinks.metrics_http {
        let body = encode_metrics_request(config, batch);
        if let Err(e) = post_protobuf(ep, &body) {
            eprintln!("hopf-otel: otlp metrics failed: {e}");
        }
    }
    batch.clear();
}
