// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog record attribute names and export gating.

use std::sync::atomic::{AtomicBool, Ordering};

/// The URI of the event schema the event belongs to.
pub const QLOG_SCHEMA: &str = "qlog.schema";

/// The group id: the connection's original destination connection ID in hex.
pub const QLOG_GROUP_ID: &str = "qlog.group_id";

/// The vantage point: `client` or `server`.
pub const QLOG_VANTAGE_POINT: &str = "qlog.vantage_point";

/// draft-ietf-quic-qlog-quic-events: the QUIC event schema.
pub const QLOG_SCHEMA_QUIC: &str = "urn:ietf:params:qlog:events:quic";

/// draft-ietf-quic-qlog-h3-events: the HTTP/3 event schema.
pub const QLOG_SCHEMA_HTTP3: &str = "urn:ietf:params:qlog:events:http3";

/// draft-ietf-quic-qlog-h3-events: the HTTP event schema (capsules).
pub const QLOG_SCHEMA_HTTP: &str = "urn:ietf:params:qlog:events:http";

static QLOG_EXPORT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether any configured exporter accepts [`super::LogLevel::Qlog`].
pub fn qlog_export_enabled() -> bool {
    QLOG_EXPORT_ENABLED.load(Ordering::Relaxed)
}

/// Updated by [`hopf_otel::TelemetryPipeline::start`] (and cleared on shutdown).
pub fn set_qlog_export_enabled(enabled: bool) {
    QLOG_EXPORT_ENABLED.store(enabled, Ordering::Relaxed);
}
