// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Exporter configuration.

use std::path::PathBuf;
use std::time::Duration;

use crate::log_record::LogLevel;

/// Bitset of [`LogLevel`] values a sink accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LevelSet(u8);

impl LevelSet {
    /// Accept `LogLevel::Info` only.
    pub const INFO: Self = Self(1 << 0);
    /// Accept `LogLevel::Warn` only.
    pub const WARN: Self = Self(1 << 1);
    /// Accept `LogLevel::Error` only.
    pub const ERROR: Self = Self(1 << 2);
    /// Accept `LogLevel::Access` only.
    pub const ACCESS: Self = Self(1 << 3);
    /// Accept `LogLevel::Qlog` only.
    pub const QLOG: Self = Self(1 << 4);
    /// Default operational logs (`INFO`, `WARN`, `ERROR`).
    pub const OPERATIONAL: Self = Self(0b0_0000_0111);

    /// Empty set (accepts nothing).
    pub const NONE: Self = Self(0);

    /// Whether `level` is included.
    pub fn accepts(self, level: LogLevel) -> bool {
        self.0 & (1 << level.index()) != 0
    }

    /// Add `level` to the set.
    pub fn with(mut self, level: LogLevel) -> Self {
        self.0 |= 1 << level.index();
        self
    }

    /// Union of two sets.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One configured log export destination.
#[derive(Debug, Clone)]
pub enum LogSinkConfig {
    /// Append OTLP JSON log batches to a file.
    Jsonl {
        /// Output path.
        path: PathBuf,
        /// Accepted levels.
        levels: LevelSet,
    },
    /// POST protobuf `ExportLogsServiceRequest` to OTLP/HTTP.
    OtlpHttp {
        /// Full `/v1/logs` URL.
        endpoint: String,
        /// Accepted levels.
        levels: LevelSet,
    },
}

impl LogSinkConfig {
    /// Level filter for this sink.
    pub fn levels(&self) -> LevelSet {
        match self {
            Self::Jsonl { levels, .. } | Self::OtlpHttp { levels, .. } => *levels,
        }
    }
}

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
    /// Max wait for [`crate::TelemetryPipeline::flush`] to finish draining the worker.
    pub flush_timeout: Duration,
    /// Export traces (HTTP request spans).
    pub traces_enabled: bool,
    /// Export metrics.
    pub metrics_enabled: bool,
    /// Export connection logs via TelemetryHook.
    pub logs_enabled: bool,
    /// Log sinks (level-filtered).
    pub log_sinks: Vec<LogSinkConfig>,
    /// OTLP/HTTP traces endpoint (`/v1/traces`).
    pub otlp_traces_endpoint: Option<String>,
    /// OTLP/HTTP metrics endpoint (`/v1/metrics`).
    pub otlp_metrics_endpoint: Option<String>,
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
            flush_timeout: Duration::from_secs(30),
            traces_enabled: true,
            metrics_enabled: true,
            logs_enabled: true,
            log_sinks: Vec::new(),
            otlp_traces_endpoint: None,
            otlp_metrics_endpoint: None,
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
        self.log_sinks.push(LogSinkConfig::OtlpHttp {
            endpoint: format!("{base}/v1/logs"),
            levels: LevelSet::OPERATIONAL,
        });
        self.otlp_traces_endpoint = Some(format!("{base}/v1/traces"));
        self.otlp_metrics_endpoint = Some(format!("{base}/v1/metrics"));
        self
    }

    /// Enable OTLP/HTTP logs only (operational levels).
    pub fn with_otlp_logs(mut self, endpoint: impl Into<String>) -> Self {
        self.log_sinks.push(LogSinkConfig::OtlpHttp {
            endpoint: endpoint.into(),
            levels: LevelSet::OPERATIONAL,
        });
        self
    }

    /// JSONL logs path (operational levels).
    pub fn with_jsonl_logs(self, path: impl Into<PathBuf>) -> Self {
        self.with_jsonl_log_sink(path, LevelSet::OPERATIONAL)
    }

    /// JSONL log sink with an explicit level set.
    pub fn with_jsonl_log_sink(mut self, path: impl Into<PathBuf>, levels: LevelSet) -> Self {
        self.log_sinks.push(LogSinkConfig::Jsonl {
            path: path.into(),
            levels,
        });
        self
    }

    /// OTLP/HTTP log sink with an explicit level set.
    pub fn with_otlp_log_sink(mut self, endpoint: impl Into<String>, levels: LevelSet) -> Self {
        self.log_sinks.push(LogSinkConfig::OtlpHttp {
            endpoint: endpoint.into(),
            levels,
        });
        self
    }

    /// Append a pre-built log sink configuration.
    pub fn with_log_sink(mut self, sink: LogSinkConfig) -> Self {
        self.log_sinks.push(sink);
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
        !self.log_sinks.is_empty()
            || self.otlp_traces_endpoint.is_some()
            || self.otlp_metrics_endpoint.is_some()
            || self.jsonl_traces_path.is_some()
            || self.jsonl_metrics_path.is_some()
    }

    /// Whether any log sink would accept `level` (respects [`logs_enabled`](Self::logs_enabled)).
    pub fn accepts(&self, level: LogLevel) -> bool {
        if !self.logs_enabled {
            return false;
        }
        self.log_sinks
            .iter()
            .any(|s| s.levels().accepts(level))
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

    /// Enable or disable hook log export.
    pub fn with_logs(mut self, enabled: bool) -> Self {
        self.logs_enabled = enabled;
        self
    }
}
