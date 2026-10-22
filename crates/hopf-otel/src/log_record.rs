// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Structured log records and severity levels for export routing.

use std::time::{SystemTime, UNIX_EPOCH};

/// Log severity / stream axis matched by exporters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogLevel {
    /// Operational information.
    Info,
    /// Non-fatal warning.
    Warn,
    /// Error or failure.
    Error,
    /// HTTP (or similar) access log line.
    Access,
    /// QUIC qlog JSON-SEQ payload.
    Qlog,
}

impl LogLevel {
    /// Index for per-level counters (`0..=4`).
    pub fn index(self) -> usize {
        match self {
            LogLevel::Info => 0,
            LogLevel::Warn => 1,
            LogLevel::Error => 2,
            LogLevel::Access => 3,
            LogLevel::Qlog => 4,
        }
    }

    /// OTLP `severityNumber` (OpenTelemetry mapping).
    pub fn severity_number(self) -> i32 {
        match self {
            LogLevel::Info | LogLevel::Access | LogLevel::Qlog => 9,
            LogLevel::Warn => 13,
            LogLevel::Error => 17,
        }
    }

    /// OTLP `severityText`.
    pub fn severity_text(self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Access => "ACCESS",
            LogLevel::Qlog => "QLOG",
        }
    }
}

/// Typed log attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    /// UTF-8 string.
    String(String),
    /// Signed integer.
    Int(i64),
    /// Boolean.
    Bool(bool),
    /// Floating point.
    Double(f64),
}

/// One exportable log record.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Event time (Unix nanoseconds).
    pub time_unix_nano: u64,
    /// Severity / stream level.
    pub level: LogLevel,
    /// Short event name (for example `connection.accept`).
    pub name: String,
    /// Ordered semantic attributes.
    pub attrs: Vec<(String, AttrValue)>,
    /// Optional human-readable body.
    pub body: Option<String>,
    /// W3C trace id (16 bytes), when correlated.
    pub trace_id: Option<[u8; 16]>,
    /// Span id (8 bytes), when correlated.
    pub span_id: Option<[u8; 8]>,
    /// Instrumentation scope name.
    pub scope: String,
}

impl LogRecord {
    /// Build with current time and default scope `hopf`.
    pub fn new(level: LogLevel, name: impl Into<String>) -> Self {
        Self {
            time_unix_nano: now_unix_nano(),
            level,
            name: name.into(),
            attrs: Vec::new(),
            body: None,
            trace_id: None,
            span_id: None,
            scope: "hopf".into(),
        }
    }

    /// Attach optional body text.
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Append one string attribute.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs
            .push((key.into(), AttrValue::String(value.into())));
        self
    }

    /// Attach trace and span ids.
    pub fn with_trace_ids(mut self, trace_id: [u8; 16], span_id: [u8; 8]) -> Self {
        self.trace_id = Some(trace_id);
        self.span_id = Some(span_id);
        self
    }
}

pub(crate) fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
