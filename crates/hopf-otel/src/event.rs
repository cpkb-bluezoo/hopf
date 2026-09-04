// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Telemetry events produced on the hot path (enqueue only).

use std::time::{SystemTime, UNIX_EPOCH};

use hopf_core::PeerAddr;

/// Kind of runtime event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Accepted connection.
    Accept,
    /// Outbound dial started.
    Dial,
    /// Connection closed.
    Close,
    /// Error (ACL, rate limit, I/O, …).
    Error,
    /// Non-fatal warning (misconfiguration, open relay without CIDRs, …).
    Warn,
}

/// One telemetry event (log-oriented).
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// Event kind.
    pub kind: EventKind,
    /// Optional peer address — TCP/IP or UNIX domain socket path.
    pub peer: Option<PeerAddr>,
    /// Human-readable body / message.
    pub message: String,
    /// Unix nanoseconds.
    pub time_unix_nano: u64,
}

impl TelemetryEvent {
    /// Build with current time.
    pub fn new(kind: EventKind, peer: Option<PeerAddr>, message: impl Into<String>) -> Self {
        Self {
            kind,
            peer,
            message: message.into(),
            time_unix_nano: now_unix_nano(),
        }
    }

    /// Severity number (OTLP): INFO=9, WARN=13, ERROR=17.
    pub fn severity_number(&self) -> i32 {
        match self.kind {
            EventKind::Error => 17,
            EventKind::Warn => 13,
            EventKind::Close => 9,
            EventKind::Accept | EventKind::Dial => 9,
        }
    }

    /// Severity text.
    pub fn severity_text(&self) -> &'static str {
        match self.kind {
            EventKind::Error => "ERROR",
            EventKind::Warn => "WARN",
            _ => "INFO",
        }
    }

    /// Short event name attribute.
    pub fn event_name(&self) -> &'static str {
        match self.kind {
            EventKind::Accept => "connection.accept",
            EventKind::Dial => "connection.dial",
            EventKind::Close => "connection.close",
            EventKind::Error => "connection.error",
            EventKind::Warn => "runtime.warn",
        }
    }
}

fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
