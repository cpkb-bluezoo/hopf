// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Background batching and export (never on accept/reactor threads).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::OtelConfig;
use crate::jsonl::JsonlAppender;
use crate::log_record::{LogLevel, LogRecord};
use crate::metrics::MetricPoint;
use crate::otlp_http::{post_protobuf, HttpEndpoint};
use crate::otlp_proto::{encode_metrics_request, encode_traces_request};
use crate::sink::{LogSink, LogSinkInstance};
use crate::trace::FinishedSpan;

const LOG_LEVELS: usize = 5;

/// Per-level log drop counters (queue full / disconnected).
#[derive(Default)]
pub struct DroppedLogCounts {
    by_level: [AtomicU64; LOG_LEVELS],
}

impl DroppedLogCounts {
    fn record(&self, level: LogLevel) {
        self.by_level[level.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of drops indexed by [`LogLevel::index`].
    pub fn snapshot(&self) -> [u64; LOG_LEVELS] {
        std::array::from_fn(|i| self.by_level[i].load(Ordering::Relaxed))
    }

    /// Total dropped log records.
    pub fn total(&self) -> u64 {
        self.snapshot().into_iter().sum()
    }
}

enum Msg {
    Log(LogRecord),
    Spans(Vec<FinishedSpan>),
    Metric(MetricPoint),
    Flush(SyncSender<()>),
    Shutdown,
}

/// Handle used from the hot path to enqueue telemetry.
#[derive(Clone)]
pub struct ExportHandle {
    tx: SyncSender<Msg>,
    dropped_logs: Arc<DroppedLogCounts>,
    flush_timeout: Duration,
}

impl ExportHandle {
    /// Enqueue a log record (non-blocking).
    pub fn try_send_log(&self, record: LogRecord) {
        match self.tx.try_send(Msg::Log(record)) {
            Ok(()) => {}
            Err(TrySendError::Full(r)) | Err(TrySendError::Disconnected(r)) => {
                if let Msg::Log(rec) = r {
                    self.dropped_logs.record(rec.level);
                }
            }
        }
    }

    /// Log records dropped because the export queue was full or disconnected.
    pub fn dropped_log_records(&self) -> u64 {
        self.dropped_logs.total()
    }

    /// Per-level drop counts (`LogLevel::index` order).
    pub fn dropped_logs_by_level(&self) -> [u64; LOG_LEVELS] {
        self.dropped_logs.snapshot()
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

    /// Block until the worker drains queued logs/spans/metrics, or timeout.
    pub fn flush(&self) -> Result<(), String> {
        let (ack_tx, ack_rx) = mpsc::sync_channel(0);
        self.tx
            .send(Msg::Flush(ack_tx))
            .map_err(|_| "hopf-otel export worker disconnected".to_string())?;
        ack_rx
            .recv_timeout(self.flush_timeout)
            .map_err(|_| format!("hopf-otel flush timed out after {:?}", self.flush_timeout))
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
    let dropped_logs = Arc::new(DroppedLogCounts::default());
    let dropped_logs2 = Arc::clone(&dropped_logs);
    let flush_timeout = config.flush_timeout;
    let handle = thread::Builder::new()
        .name("hopf-otel-export".into())
        .spawn(move || export_loop(config, rx, running2))
        .expect("spawn otel export worker");
    (
        ExportHandle {
            tx,
            dropped_logs: dropped_logs2,
            flush_timeout,
        },
        handle,
        running,
    )
}

struct TraceMetricSinks {
    traces_http: Option<HttpEndpoint>,
    metrics_http: Option<HttpEndpoint>,
    traces_jsonl: Option<JsonlAppender>,
    metrics_jsonl: Option<JsonlAppender>,
}

fn export_loop(config: OtelConfig, rx: Receiver<Msg>, running: Arc<AtomicBool>) {
    let mut log_sinks = LogSinkInstance::from_config(&config);
    let sinks = TraceMetricSinks {
        traces_http: config
            .otlp_traces_endpoint
            .as_ref()
            .and_then(|u| HttpEndpoint::parse(u)),
        metrics_http: config
            .otlp_metrics_endpoint
            .as_ref()
            .and_then(|u| HttpEndpoint::parse(u)),
        traces_jsonl: config
            .jsonl_traces_path
            .as_ref()
            .map(|p| JsonlAppender::new(p.clone())),
        metrics_jsonl: config
            .jsonl_metrics_path
            .as_ref()
            .map(|p| JsonlAppender::new(p.clone())),
    };

    let mut logs: Vec<LogRecord> = Vec::with_capacity(config.batch_size);
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
                    flush_logs(&config, &mut log_sinks, &mut logs);
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
            Ok(Msg::Flush(ack)) => {
                flush_all(&config, &mut log_sinks, &sinks, &mut logs, &mut spans, &mut metrics);
                last_flush = Instant::now();
                let _ = ack.send(());
            }
            Ok(Msg::Shutdown) => {
                flush_all(&config, &mut log_sinks, &sinks, &mut logs, &mut spans, &mut metrics);
                for sink in &mut log_sinks {
                    let _ = sink.shutdown();
                }
                break;
            }
            Err(RecvTimeoutError::Timeout) => {
                if last_flush.elapsed() >= config.flush_interval {
                    flush_all(&config, &mut log_sinks, &sinks, &mut logs, &mut spans, &mut metrics);
                    last_flush = Instant::now();
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                flush_all(&config, &mut log_sinks, &sinks, &mut logs, &mut spans, &mut metrics);
                break;
            }
        }
    }
    running.store(false, Ordering::Release);
}

fn flush_all(
    config: &OtelConfig,
    log_sinks: &mut [LogSinkInstance],
    sinks: &TraceMetricSinks,
    logs: &mut Vec<LogRecord>,
    spans: &mut Vec<FinishedSpan>,
    metrics: &mut Vec<MetricPoint>,
) {
    flush_logs(config, log_sinks, logs);
    flush_spans(config, sinks, spans);
    flush_metrics(config, sinks, metrics);
}

fn flush_logs(config: &OtelConfig, log_sinks: &mut [LogSinkInstance], batch: &mut Vec<LogRecord>) {
    if batch.is_empty() || !config.logs_enabled {
        batch.clear();
        return;
    }
    LogSinkInstance::flush_batch(log_sinks, config, batch);
}

fn flush_spans(config: &OtelConfig, sinks: &TraceMetricSinks, batch: &mut Vec<FinishedSpan>) {
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

fn flush_metrics(config: &OtelConfig, sinks: &TraceMetricSinks, batch: &mut Vec<MetricPoint>) {
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
