// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Telemetry hook seams (OTLP / JSONL exporters live in `hopf-otel`).

mod log_record;

use std::sync::{Arc, OnceLock, RwLock};

use crate::peer_addr::PeerAddr;

pub use log_record::{AttrValue, LogLevel, LogRecord};

static PROCESS_HOOK: OnceLock<RwLock<Option<Arc<dyn TelemetryHook>>>> = OnceLock::new();

fn process_hook_slot() -> &'static RwLock<Option<Arc<dyn TelemetryHook>>> {
    PROCESS_HOOK.get_or_init(|| RwLock::new(None))
}

/// Install the process-wide hook (for example [`hopf_otel::TelemetryPipeline::hook`]).
pub fn set_process_telemetry(hook: Arc<dyn TelemetryHook>) {
    *process_hook_slot().write().unwrap_or_else(|e| e.into_inner()) = Some(hook);
}

/// Clear the process-wide hook.
pub fn clear_process_telemetry() {
    *process_hook_slot().write().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Current process-wide hook, if any.
pub fn process_telemetry() -> Option<Arc<dyn TelemetryHook>> {
    process_hook_slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Emit through the process-wide hook when set.
pub fn emit_log(record: LogRecord) {
    if let Some(hook) = process_telemetry() {
        hook.on_log(&record);
    }
}

/// Emit a warning through the process-wide hook when set.
pub fn log_warn(name: &str, message: impl Into<String>) {
    emit_log(
        LogRecord::new(LogLevel::Warn, name)
            .with_body(message)
            .with_scope("hopf"),
    );
}

/// Emit an error through the process-wide hook when set.
pub fn log_error(name: &str, message: impl Into<String>) {
    emit_log(
        LogRecord::new(LogLevel::Error, name)
            .with_body(message)
            .with_scope("hopf"),
    );
}

/// Emit with an explicit instrumentation scope (crate name).
pub fn subsystem_log(
    level: LogLevel,
    scope: &str,
    name: &str,
    message: impl Into<String>,
) {
    emit_log(
        LogRecord::new(level, name)
            .with_scope(scope)
            .with_body(message),
    );
}

/// Emit on a connection hook when present, otherwise through [`emit_log`].
pub fn emit_connection_log(
    hook: Option<&Arc<dyn TelemetryHook>>,
    record: LogRecord,
) {
    if let Some(h) = hook {
        h.on_log(&record);
    } else {
        emit_log(record);
    }
}

/// Process-wide telemetry callbacks (no-op by default).
///
/// Implementations must stay **off the hot path** for I/O: enqueue only.
/// Use the `hopf-otel` crate (`TelemetryPipeline`) for batched OTLP/HTTP
/// and JSONL export.
pub trait TelemetryHook: Send + Sync {
    /// Accept succeeded (after ACL/peer-allowlist) — TCP or UNIX domain socket.
    fn on_accept(&self, _peer: PeerAddr) {}
    /// Dial started.
    fn on_dial(&self, _peer: PeerAddr) {}
    /// Connection closed.
    fn on_close(&self, _peer: PeerAddr) {}
    /// I/O or protocol error.
    fn on_error(&self, _peer: Option<PeerAddr>, _msg: &str) {}
    /// Non-fatal configuration / operational warning (e.g. open relay with
    /// no CIDR allowlist). Default: no-op.
    fn on_warn(&self, _msg: &str) {}
    /// Structured log record. Default: map ERROR/WARN to [`Self::on_error`] /
    /// [`Self::on_warn`]; other levels are ignored.
    fn on_log(&self, record: &LogRecord) {
        let body = record.body.as_deref().unwrap_or("");
        match record.level {
            LogLevel::Error => {
                let peer = peer_from_attrs(&record.attrs);
                self.on_error(peer, body);
            }
            LogLevel::Warn => self.on_warn(body),
            LogLevel::Info | LogLevel::Access | LogLevel::Qlog => {}
        }
    }
}

fn peer_from_attrs(attrs: &[(String, AttrValue)]) -> Option<PeerAddr> {
    let ip = attrs
        .iter()
        .find(|(k, _)| k == "net.peer.ip")
        .and_then(|(_, v)| match v {
            AttrValue::String(s) => s.parse().ok(),
            _ => None,
        });
    let port = attrs
        .iter()
        .find(|(k, _)| k == "net.peer.port")
        .and_then(|(_, v)| match v {
            AttrValue::String(s) => s.parse().ok(),
            _ => None,
        });
    match (ip, port) {
        (Some(ip), Some(port)) => Some(PeerAddr::Inet(std::net::SocketAddr::new(ip, port))),
        _ => None,
    }
}

/// Discarding hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopTelemetry;

impl TelemetryHook for NopTelemetry {}
