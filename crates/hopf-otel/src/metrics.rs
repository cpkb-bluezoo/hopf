// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP server metrics (Gumdrop `HTTPServerMetrics` parity).

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

/// Timing helper for one request.
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
