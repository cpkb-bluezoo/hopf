// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`TelemetryHook`] that only enqueues; export runs off-thread.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use hopf_core::{PeerAddr, TelemetryHook};

use crate::batch::{spawn_worker, ExportHandle};
use crate::config::{LogSinkConfig, OtelConfig};
use crate::event::{log_record_from_event, EventKind};
use crate::log_record::LogLevel;
use crate::metrics::{
    FtpServerMetrics, HttpServerMetrics, ImapServerMetrics, MqttServerMetrics, Pop3ServerMetrics,
    SmtpServerMetrics,
};

/// Pipeline: hot-path hook + background OTLP/JSONL exporters.
pub struct TelemetryPipeline {
    config: OtelConfig,
    sender: ExportHandle,
    metrics: Arc<HttpServerMetrics>,
    smtp_metrics: Arc<SmtpServerMetrics>,
    ftp_metrics: Arc<FtpServerMetrics>,
    pop3_metrics: Arc<Pop3ServerMetrics>,
    imap_metrics: Arc<ImapServerMetrics>,
    mqtt_metrics: Arc<MqttServerMetrics>,
    join: Option<JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl TelemetryPipeline {
    /// Start the export worker. Returns error if no sink is configured.
    pub fn start(config: OtelConfig) -> Result<Self, String> {
        if !config.has_sink() {
            return Err(
                "OtelConfig requires at least one OTLP or JSONL sink (logs/traces/metrics)".into(),
            );
        }
        for sink in &config.log_sinks {
            if let LogSinkConfig::OtlpHttp { endpoint, .. } = sink {
                if crate::otlp_http::HttpEndpoint::parse(endpoint).is_none() {
                    return Err(format!("invalid OTLP logs endpoint URL: {endpoint}"));
                }
            }
        }
        for (label, url) in [
            ("traces", config.otlp_traces_endpoint.as_deref()),
            ("metrics", config.otlp_metrics_endpoint.as_deref()),
        ] {
            if let Some(url) = url {
                if crate::otlp_http::HttpEndpoint::parse(url).is_none() {
                    return Err(format!("invalid OTLP {label} endpoint URL: {url}"));
                }
            }
        }
        let (sender, join, running) = spawn_worker(config.clone());
        let metrics = HttpServerMetrics::new(sender.clone());
        let smtp_metrics = SmtpServerMetrics::new(sender.clone());
        let ftp_metrics = FtpServerMetrics::new(sender.clone());
        let pop3_metrics = Pop3ServerMetrics::new(sender.clone());
        let imap_metrics = ImapServerMetrics::new(sender.clone());
        let mqtt_metrics = MqttServerMetrics::new(sender.clone());
        Ok(Self {
            config,
            sender,
            metrics,
            smtp_metrics,
            ftp_metrics,
            pop3_metrics,
            imap_metrics,
            mqtt_metrics,
            join: Some(join),
            running,
        })
    }

    /// Whether any configured log sink accepts `level`.
    pub fn accepts(&self, level: LogLevel) -> bool {
        self.config.accepts(level)
    }

    /// Shared hook for [`hopf_core::Runtime::start_with_telemetry`].
    pub fn hook(&self) -> Arc<dyn TelemetryHook> {
        Arc::new(Hook(self.sender.clone()))
    }

    /// Handle for enqueueing spans/metrics from HTTP instrumentation.
    pub fn export_handle(&self) -> ExportHandle {
        self.sender.clone()
    }

    /// Shared HTTP server metrics instruments.
    pub fn http_metrics(&self) -> Arc<HttpServerMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Shared SMTP server metrics instruments.
    pub fn smtp_metrics(&self) -> Arc<SmtpServerMetrics> {
        Arc::clone(&self.smtp_metrics)
    }

    /// Shared FTP server metrics instruments.
    pub fn ftp_metrics(&self) -> Arc<FtpServerMetrics> {
        Arc::clone(&self.ftp_metrics)
    }

    /// Shared POP3 server metrics instruments.
    pub fn pop3_metrics(&self) -> Arc<Pop3ServerMetrics> {
        Arc::clone(&self.pop3_metrics)
    }

    /// Shared IMAP server metrics instruments.
    pub fn imap_metrics(&self) -> Arc<ImapServerMetrics> {
        Arc::clone(&self.imap_metrics)
    }

    /// Shared MQTT server metrics instruments.
    pub fn mqtt_metrics(&self) -> Arc<MqttServerMetrics> {
        Arc::clone(&self.mqtt_metrics)
    }

    /// Snapshot of exporter configuration.
    pub fn config(&self) -> &OtelConfig {
        &self.config
    }

    /// Block until the export worker drains queued telemetry, or [`OtelConfig::flush_timeout`].
    pub fn flush(&self) -> Result<(), String> {
        self.sender.flush()
    }

    /// Log records dropped because the export queue was full.
    pub fn dropped_log_records(&self) -> u64 {
        self.sender.dropped_log_records()
    }

    /// Per-level drop counts (`LogLevel::index` order).
    pub fn dropped_logs_by_level(&self) -> [u64; 5] {
        self.sender.dropped_logs_by_level()
    }

    /// Stop the worker and flush.
    pub fn shutdown(mut self) {
        self.sender.shutdown();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for TelemetryPipeline {
    fn drop(&mut self) {
        if self.join.is_some() {
            self.sender.shutdown();
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
        let _ = self.running;
    }
}

struct Hook(ExportHandle);

impl TelemetryHook for Hook {
    fn on_accept(&self, peer: PeerAddr) {
        self.try_send(log_record_from_event(
            EventKind::Accept,
            Some(peer.clone()),
            format!("accept {peer}"),
        ));
    }

    fn on_dial(&self, peer: PeerAddr) {
        self.try_send(log_record_from_event(
            EventKind::Dial,
            Some(peer.clone()),
            format!("dial {peer}"),
        ));
    }

    fn on_close(&self, peer: PeerAddr) {
        self.try_send(log_record_from_event(
            EventKind::Close,
            Some(peer.clone()),
            format!("close {peer}"),
        ));
    }

    fn on_error(&self, peer: Option<PeerAddr>, msg: &str) {
        self.try_send(log_record_from_event(
            EventKind::Error,
            peer,
            msg.to_string(),
        ));
    }

    fn on_warn(&self, msg: &str) {
        self.try_send(log_record_from_event(EventKind::Warn, None, msg.to_string()));
    }
}

impl Hook {
    fn try_send(&self, rec: crate::log_record::LogRecord) {
        self.0.try_send_log(rec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LevelSet;
    use crate::event::log_record_from_event;
    use crate::log_record::LogRecord;
    use crate::otlp_proto::encode_logs_request;

    #[test]
    fn jsonl_appends_line() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-test-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("jsonl-test").with_jsonl_logs(&dir);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let hook = pipeline.hook();
        TelemetryHook::on_accept(hook.as_ref(), PeerAddr::Inet("127.0.0.1:1".parse().unwrap()));
        TelemetryHook::on_error(hook.as_ref(), None, "boom");
        pipeline.flush().unwrap();
        pipeline.shutdown();
        let body = std::fs::read_to_string(&dir).unwrap();
        assert!(body.contains("jsonl-test"), "{body}");
        assert!(body.contains("connection.accept"), "{body}");
        assert!(body.contains("boom"), "{body}");
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn accepts_false_when_no_sink_takes_level() {
        let cfg = OtelConfig::new("no-access").with_jsonl_logs(
            std::env::temp_dir().join(format!("hopf-otel-no-access-{}.jsonl", std::process::id())),
        );
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        assert!(pipeline.accepts(LogLevel::Info));
        assert!(!pipeline.accepts(LogLevel::Access));
        assert!(!pipeline.accepts(LogLevel::Qlog));
        pipeline.shutdown();
    }

    #[test]
    fn flush_waits_for_in_memory_log_batch() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-flush-batch-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let mut cfg = OtelConfig::new("flush-batch").with_jsonl_logs(&dir);
        cfg.batch_size = 10_000;
        cfg.flush_interval = std::time::Duration::from_secs(3600);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let hook = pipeline.hook();
        for i in 0..100 {
            TelemetryHook::on_warn(hook.as_ref(), &format!("line-{i}"));
        }
        pipeline.flush().unwrap();
        let body = std::fs::read_to_string(&dir).unwrap();
        for i in 0..100 {
            assert!(body.contains(&format!("line-{i}")), "{body}");
        }
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn flush_blocks_when_export_queue_is_full() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-flush-full-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let mut cfg = OtelConfig::new("flush-full").with_jsonl_logs(&dir);
        cfg.batch_size = 10_000;
        cfg.queue_capacity = 1;
        cfg.flush_interval = std::time::Duration::from_secs(3600);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let handle = pipeline.export_handle();
        let filler = std::thread::spawn(move || {
            for i in 0..200 {
                handle.try_send_log(
                    LogRecord::new(LogLevel::Warn, "runtime.warn")
                        .with_body(format!("queued-{i}")),
                );
            }
        });
        filler.join().unwrap();
        pipeline.flush().unwrap();
        let body = std::fs::read_to_string(&dir).unwrap();
        let exported = body.matches("queued-").count();
        let accepted = 200 - pipeline.dropped_log_records();
        assert_eq!(exported, accepted as usize, "{body}");
        assert!(accepted > 0);
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn dropped_log_records_count_queue_overflow() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-drops-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let mut cfg = OtelConfig::new("drops").with_jsonl_logs(&dir);
        cfg.batch_size = 10_000;
        cfg.queue_capacity = 2;
        cfg.flush_interval = std::time::Duration::from_secs(3600);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let handle = pipeline.export_handle();
        for i in 0..500 {
            handle.try_send_log(
                LogRecord::new(LogLevel::Warn, "runtime.warn").with_body(format!("flood-{i}")),
            );
        }
        assert!(pipeline.dropped_log_records() > 0);
        let by_level = pipeline.dropped_logs_by_level();
        assert!(by_level[LogLevel::Warn.index()] > 0);
        pipeline.flush().unwrap();
        pipeline.shutdown();
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn encode_protobuf_nonempty() {
        let cfg = OtelConfig::new("pb");
        let rec = log_record_from_event(EventKind::Dial, None, "dial");
        let bytes = encode_logs_request(&cfg, &[rec]);
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0] & 0x07, 2);
    }

    #[test]
    fn disjoint_sinks_receive_only_matching_levels() {
        let info_path = std::env::temp_dir().join(format!(
            "hopf-otel-pipe-info-{}.jsonl",
            std::process::id()
        ));
        let access_path = std::env::temp_dir().join(format!(
            "hopf-otel-pipe-access-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&info_path);
        let _ = std::fs::remove_file(&access_path);

        let cfg = OtelConfig::new("levels")
            .with_jsonl_log_sink(info_path.clone(), LevelSet::INFO)
            .with_jsonl_log_sink(access_path.clone(), LevelSet::ACCESS);
        let pipeline = TelemetryPipeline::start(cfg).unwrap();
        let handle = pipeline.export_handle();
        handle.try_send_log(LogRecord::new(LogLevel::Info, "i").with_body("info-msg"));
        handle.try_send_log(LogRecord::new(LogLevel::Access, "a").with_body("access-msg"));
        pipeline.flush().unwrap();
        pipeline.shutdown();

        let info_body = std::fs::read_to_string(&info_path).unwrap();
        assert!(info_body.contains("info-msg"));
        assert!(!info_body.contains("access-msg"));
        let access_body = std::fs::read_to_string(&access_path).unwrap();
        assert!(access_body.contains("access-msg"));
        assert!(!access_body.contains("info-msg"));

        let _ = std::fs::remove_file(&info_path);
        let _ = std::fs::remove_file(&access_path);
    }
}
