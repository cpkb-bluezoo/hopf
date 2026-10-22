// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime event kinds mapped to structured [`LogRecord`]s.

use hopf_core::PeerAddr;

use crate::log_record::{AttrValue, LogLevel, LogRecord};

/// Kind of runtime event (hook convenience API).
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

impl EventKind {
    /// Map to [`LogLevel`].
    pub fn log_level(self) -> LogLevel {
        match self {
            EventKind::Error => LogLevel::Error,
            EventKind::Warn => LogLevel::Warn,
            _ => LogLevel::Info,
        }
    }

    /// Short event name attribute.
    pub fn event_name(self) -> &'static str {
        match self {
            EventKind::Accept => "connection.accept",
            EventKind::Dial => "connection.dial",
            EventKind::Close => "connection.close",
            EventKind::Error => "connection.error",
            EventKind::Warn => "runtime.warn",
        }
    }
}

/// Build a [`LogRecord`] from a hook-style runtime event.
pub fn log_record_from_event(
    kind: EventKind,
    peer: Option<PeerAddr>,
    message: impl Into<String>,
) -> LogRecord {
    let message = message.into();
    let mut record = LogRecord::new(kind.log_level(), kind.event_name()).with_body(message);
    match peer {
        Some(PeerAddr::Inet(addr)) => {
            record
                .attrs
                .push(("net.peer.ip".into(), AttrValue::String(addr.ip().to_string())));
            record.attrs.push((
                "net.peer.port".into(),
                AttrValue::String(addr.port().to_string()),
            ));
        }
        Some(PeerAddr::Unix(path)) => {
            record
                .attrs
                .push(("net.sock.family".into(), AttrValue::String("unix".into())));
            if let Some(path) = path {
                record.attrs.push((
                    "net.sock.peer.name".into(),
                    AttrValue::String(path.display().to_string()),
                ));
            }
        }
        None => {}
    }
    record
}
