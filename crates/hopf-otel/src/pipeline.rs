// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`TelemetryHook`] that only enqueues; export runs off-thread.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

use hopf_core::TelemetryHook;

use crate::batch::{spawn_worker, ExportHandle};
use crate::config::OtelConfig;
use crate::event::{EventKind, TelemetryEvent};
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
        for (label, url) in [
            ("logs", config.otlp_logs_endpoint.as_deref()),
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

    /// Request an immediate flush of queued events.
    pub fn flush(&self) {
        self.sender.flush();
        // Give the worker a moment to drain.
        std::thread::sleep(std::time::Duration::from_millis(50));
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
    fn on_accept(&self, peer: SocketAddr) {
        self.0.try_send_log(TelemetryEvent::new(
            EventKind::Accept,
            Some(peer),
            format!("accept {peer}"),
        ));
    }

    fn on_dial(&self, peer: SocketAddr) {
        self.0.try_send_log(TelemetryEvent::new(
            EventKind::Dial,
            Some(peer),
            format!("dial {peer}"),
        ));
    }

    fn on_close(&self, peer: SocketAddr) {
        self.0.try_send_log(TelemetryEvent::new(
            EventKind::Close,
            Some(peer),
            format!("close {peer}"),
        ));
    }

    fn on_error(&self, peer: Option<SocketAddr>, msg: &str) {
        self.0.try_send_log(TelemetryEvent::new(
            EventKind::Error,
            peer,
            msg.to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;
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
        TelemetryHook::on_accept(hook.as_ref(), "127.0.0.1:1".parse().unwrap());
        TelemetryHook::on_error(hook.as_ref(), None, "boom");
        pipeline.flush();
        pipeline.shutdown();
        let body = std::fs::read_to_string(&dir).unwrap();
        assert!(body.contains("jsonl-test"), "{body}");
        assert!(body.contains("connection.accept"), "{body}");
        assert!(body.contains("boom"), "{body}");
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn encode_protobuf_nonempty() {
        let cfg = OtelConfig::new("pb");
        let ev = TelemetryEvent::new(EventKind::Dial, None, "dial");
        let bytes = encode_logs_request(&cfg, &[ev]);
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0] & 0x07, 2);
    }
}
