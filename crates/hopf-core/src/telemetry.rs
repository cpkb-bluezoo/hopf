// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Telemetry hook seams (OTLP / JSONL exporters live in `hopf-otel`).

use crate::peer_addr::PeerAddr;

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
}

/// Discarding hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopTelemetry;

impl TelemetryHook for NopTelemetry {}
