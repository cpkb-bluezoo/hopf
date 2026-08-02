// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! OpenTelemetry exporters and protocol instrumentation for Hopf.
//!
//! Connection logs use [`TelemetryHook`] via [`TelemetryPipeline::hook`].
//! HTTP request traces/metrics use [`InstrumentedServerFactory`]. SMTP
//! metrics are available via [`TelemetryPipeline::smtp_metrics`]; protocol
//! crates wire them at control-handler call sites. Encoding and I/O run on
//! a dedicated export worker — never on accept or reactor threads.

#![warn(missing_docs)]

mod batch;
mod config;
mod crypto_ids;
mod event;
mod instrument;
mod jsonl;
mod metrics;
mod otlp_http;
mod otlp_proto;
mod pipeline;
mod propagate;
mod trace;

pub use batch::ExportHandle;
pub use config::OtelConfig;
pub use event::{EventKind, TelemetryEvent};
pub use instrument::InstrumentedServerFactory;
pub use metrics::{
    FtpServerMetrics, HttpServerMetrics, ImapServerMetrics, MetricPoint, Pop3ServerMetrics,
    RequestTimer, SmtpServerMetrics,
};
pub use pipeline::TelemetryPipeline;
pub use propagate::{
    inject_trace, inject_traceparent, with_trace, with_traceparent, OwnedPropagatingClientWriter,
    PropagatingClientWriter,
};
pub use trace::{FinishedSpan, Span, SpanContext, SpanKind, SpanStatusCode, Trace};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
