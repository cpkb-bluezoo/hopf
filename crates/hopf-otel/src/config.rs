// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Exporter configuration (Gumdrop `TelemetryConfig` subset).

use std::path::PathBuf;
use std::time::Duration;

/// Configuration for [`crate::TelemetryPipeline`].
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// `service.name` resource attribute.
    pub service_name: String,
    /// Optional `service.version`.
    pub service_version: Option<String>,
    /// Optional `service.namespace`.
    pub service_namespace: Option<String>,
    /// Max items per batch flush.
    pub batch_size: usize,
    /// Flush interval when the batch is not full.
    pub flush_interval: Duration,
    /// Bounded queue capacity; overflow drops events.
    pub queue_capacity: usize,
    /// Export traces (HTTP request spans).
    pub traces_enabled: bool,
    /// Export metrics.
    pub metrics_enabled: bool,
    /// Export connection logs via TelemetryHook.
    pub logs_enabled: bool,
    /// OTLP/HTTP logs endpoint.
    pub otlp_logs_endpoint: Option<String>,
    /// OTLP/HTTP traces endpoint (`/v1/traces`).
    pub otlp_traces_endpoint: Option<String>,
    /// OTLP/HTTP metrics endpoint (`/v1/metrics`).
    pub otlp_metrics_endpoint: Option<String>,
    /// JSONL logs path.
    pub jsonl_logs_path: Option<PathBuf>,
    /// JSONL traces path.
    pub jsonl_traces_path: Option<PathBuf>,
    /// JSONL metrics path.
    pub jsonl_metrics_path: Option<PathBuf>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            service_name: "hopf".into(),
            service_version: None,
            service_namespace: None,
            batch_size: 64,
            flush_interval: Duration::from_secs(5),
            queue_capacity: 4096,
            traces_enabled: true,
            metrics_enabled: true,
            logs_enabled: true,
            otlp_logs_endpoint: None,
            otlp_traces_endpoint: None,
            otlp_metrics_endpoint: None,
            jsonl_logs_path: None,
            jsonl_traces_path: None,
            jsonl_metrics_path: None,
        }
    }
}

impl OtelConfig {
    /// Builder with service name.
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            ..Default::default()
        }
    }

    /// Set OTLP base URL; derives `/v1/logs`, `/v1/traces`, `/v1/metrics`.
    pub fn with_otlp_endpoint(mut self, base: impl AsRef<str>) -> Self {
        let base = base.as_ref().trim_end_matches('/');
        self.otlp_logs_endpoint = Some(format!("{base}/v1/logs"));
        self.otlp_traces_endpoint = Some(format!("{base}/v1/traces"));
        self.otlp_metrics_endpoint = Some(format!("{base}/v1/metrics"));
        self
    }

    /// Enable OTLP/HTTP logs only.
    pub fn with_otlp_logs(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_logs_endpoint = Some(endpoint.into());
        self
    }

    /// JSONL logs path.
    pub fn with_jsonl_logs(mut self, path: impl Into<PathBuf>) -> Self {
        self.jsonl_logs_path = Some(path.into());
        self
    }

    /// JSONL traces path.
    pub fn with_jsonl_traces(mut self, path: impl Into<PathBuf>) -> Self {
        self.jsonl_traces_path = Some(path.into());
        self
    }

    /// JSONL metrics path.
    pub fn with_jsonl_metrics(mut self, path: impl Into<PathBuf>) -> Self {
        self.jsonl_metrics_path = Some(path.into());
        self
    }

    /// Whether any export sink is configured.
    pub fn has_sink(&self) -> bool {
        self.otlp_logs_endpoint.is_some()
            || self.otlp_traces_endpoint.is_some()
            || self.otlp_metrics_endpoint.is_some()
            || self.jsonl_logs_path.is_some()
            || self.jsonl_traces_path.is_some()
            || self.jsonl_metrics_path.is_some()
    }

    /// Enable or disable HTTP request traces.
    pub fn with_traces(mut self, enabled: bool) -> Self {
        self.traces_enabled = enabled;
        self
    }

    /// Enable or disable HTTP metrics.
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.metrics_enabled = enabled;
        self
    }
}
