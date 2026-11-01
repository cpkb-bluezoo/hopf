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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn attr<'a>(r: &'a LogRecord, key: &str) -> Option<&'a AttrValue> {
        r.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    #[test]
    fn each_kind_has_a_level_and_a_name() {
        let cases = [
            (EventKind::Accept, LogLevel::Info, "connection.accept"),
            (EventKind::Dial, LogLevel::Info, "connection.dial"),
            (EventKind::Close, LogLevel::Info, "connection.close"),
            (EventKind::Error, LogLevel::Error, "connection.error"),
            (EventKind::Warn, LogLevel::Warn, "runtime.warn"),
        ];
        for (kind, level, name) in cases {
            assert_eq!(kind.log_level(), level);
            assert_eq!(kind.event_name(), name);
        }
    }

    #[test]
    fn an_inet_peer_adds_its_address_and_port() {
        let peer = PeerAddr::Inet("192.0.2.7:4433".parse().unwrap());
        let rec = log_record_from_event(EventKind::Accept, Some(peer), "hello");
        assert_eq!(rec.body.as_deref(), Some("hello"));
        assert_eq!(rec.name, "connection.accept");
        assert!(matches!(attr(&rec, "net.peer.ip"), Some(AttrValue::String(s)) if s == "192.0.2.7"));
        assert!(matches!(attr(&rec, "net.peer.port"), Some(AttrValue::String(s)) if s == "4433"));
    }

    #[test]
    fn a_unix_peer_adds_its_family_and_path_when_it_has_one() {
        let rec = log_record_from_event(EventKind::Close, Some(PeerAddr::Unix(Some(PathBuf::from("/run/x.sock")))), "m");
        assert!(matches!(attr(&rec, "net.sock.family"), Some(AttrValue::String(s)) if s == "unix"));
        assert!(matches!(attr(&rec, "net.sock.peer.name"), Some(AttrValue::String(s)) if s == "/run/x.sock"));
        let unnamed = log_record_from_event(EventKind::Close, Some(PeerAddr::Unix(None)), "m");
        assert!(attr(&unnamed, "net.sock.family").is_some());
        assert!(attr(&unnamed, "net.sock.peer.name").is_none());
    }

    #[test]
    fn no_peer_adds_nothing() {
        let rec = log_record_from_event(EventKind::Warn, None, "careful");
        assert!(rec.attrs.is_empty());
        assert_eq!(rec.level, LogLevel::Warn);
    }
}
