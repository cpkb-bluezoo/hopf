// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server metrics instruments (HTTP + SMTP) for OTLP/JSONL export.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::batch::ExportHandle;

/// One metric data point for export.
#[derive(Debug, Clone)]
pub enum MetricPoint {
    /// Counter increment.
    Counter {
        /// Name.
        name: &'static str,
        /// Attributes.
        attributes: Vec<(String, String)>,
        /// Delta.
        value: u64,
    },
    /// Histogram observation.
    Histogram {
        /// Name.
        name: &'static str,
        /// Unit.
        unit: &'static str,
        /// Attributes.
        attributes: Vec<(String, String)>,
        /// Observed value.
        value: f64,
    },
    /// UpDown absolute (for gauges we export as sum non-monotonic snapshot — simplified).
    UpDown {
        /// Name.
        name: &'static str,
        /// Attributes.
        attributes: Vec<(String, String)>,
        /// Current value.
        value: i64,
    },
}

/// HTTP server metrics instruments.
pub struct HttpServerMetrics {
    export: ExportHandle,
    active_requests: AtomicI64,
    active_connections: AtomicI64,
}

impl HttpServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_requests: AtomicI64::new(0),
            active_connections: AtomicI64::new(0),
        })
    }

    /// Connection accepted (transport may also call separately).
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// Request started.
    pub fn request_started(&self, method: &str) {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
        let active = self.active_requests.load(Ordering::Relaxed);
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_requests",
            attributes: vec![("http.method".into(), method.into())],
            value: active,
        });
    }

    /// Request completed.
    pub fn request_completed(
        &self,
        method: &str,
        status: u16,
        duration: std::time::Duration,
        request_size: u64,
        response_size: u64,
    ) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
        let method_a = ("http.method".into(), method.to_string());
        let status_a = ("http.status_code".into(), status.to_string());
        self.export.try_send_metric(MetricPoint::Counter {
            name: "http.server.requests",
            attributes: vec![method_a.clone(), status_a.clone()],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "http.server.request.duration",
            unit: "ms",
            attributes: vec![method_a.clone(), status_a.clone()],
            value: duration.as_secs_f64() * 1000.0,
        });
        if request_size > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "http.server.request.size",
                unit: "By",
                attributes: vec![method_a.clone()],
                value: request_size as f64,
            });
        }
        if response_size > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "http.server.response.size",
                unit: "By",
                attributes: vec![method_a, status_a],
                value: response_size as f64,
            });
        }
        let active = self.active_requests.load(Ordering::Relaxed);
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "http.server.active_requests",
            attributes: vec![("http.method".into(), method.into())],
            value: active.max(0),
        });
    }
}

/// SMTP server metrics instruments (OTLP export).
pub struct SmtpServerMetrics {
    export: ExportHandle,
    active_connections: AtomicI64,
}

impl SmtpServerMetrics {
    /// Create with export handle.
    pub fn new(export: ExportHandle) -> Arc<Self> {
        Arc::new(Self {
            export,
            active_connections: AtomicI64::new(0),
        })
    }

    /// Control connection accepted.
    pub fn connection_opened(&self) {
        let v = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.connections",
            attributes: Vec::new(),
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "smtp.server.active_connections",
            attributes: Vec::new(),
            value: v,
        });
    }

    /// Control connection closed.
    pub fn connection_closed(&self) {
        let v = self.active_connections.fetch_sub(1, Ordering::Relaxed) - 1;
        self.export.try_send_metric(MetricPoint::UpDown {
            name: "smtp.server.active_connections",
            attributes: Vec::new(),
            value: v.max(0),
        });
    }

    /// AUTH attempt finished.
    pub fn auth(&self, ok: bool) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.auth",
            attributes: vec![(
                "result".into(),
                if ok { "ok" } else { "fail" }.into(),
            )],
            value: 1,
        });
    }

    /// STARTTLS completed.
    pub fn starttls(&self) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.starttls",
            attributes: Vec::new(),
            value: 1,
        });
    }

    /// Mail transaction finished (MAIL FROM → DATA end / RSET / disconnect).
    ///
    /// `outcome` is typically `"accepted"` or `"aborted"`.
    pub fn transaction_completed(
        &self,
        outcome: &str,
        duration: std::time::Duration,
        message_size: u64,
    ) {
        self.export.try_send_metric(MetricPoint::Counter {
            name: "smtp.server.messages",
            attributes: vec![("outcome".into(), outcome.into())],
            value: 1,
        });
        self.export.try_send_metric(MetricPoint::Histogram {
            name: "smtp.server.transaction.duration",
            unit: "ms",
            attributes: vec![("outcome".into(), outcome.into())],
            value: duration.as_secs_f64() * 1000.0,
        });
        if outcome == "accepted" && message_size > 0 {
            self.export.try_send_metric(MetricPoint::Histogram {
                name: "smtp.server.message.size",
                unit: "By",
                attributes: Vec::new(),
                value: message_size as f64,
            });
        }
    }
}

/// Timing helper for one request / transaction.
#[derive(Debug)]
pub struct RequestTimer {
    start: Instant,
}

impl RequestTimer {
    /// Start.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Elapsed.
    pub fn elapsed(&self) -> std::time::Duration {
        self.start.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::spawn_worker;
    use crate::config::OtelConfig;

    #[test]
    fn smtp_transaction_emits_duration_to_jsonl() {
        let dir = std::env::temp_dir().join(format!(
            "hopf-otel-smtp-tx-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&dir);
        let cfg = OtelConfig::new("smtp-tx-test").with_jsonl_metrics(&dir);
        let (handle, join, _running) = spawn_worker(cfg);
        let metrics = SmtpServerMetrics::new(handle.clone());
        metrics.connection_opened();
        metrics.transaction_completed(
            "accepted",
            std::time::Duration::from_millis(12),
            100,
        );
        metrics.connection_closed();
        handle.flush();
        std::thread::sleep(std::time::Duration::from_millis(80));
        handle.shutdown();
        let _ = join.join();
        let body = std::fs::read_to_string(&dir).unwrap_or_default();
        assert!(
            body.contains("smtp.server.transaction.duration"),
            "missing duration metric: {body}"
        );
        assert!(body.contains("smtp.server.messages"), "{body}");
        let _ = std::fs::remove_file(&dir);
    }
}
