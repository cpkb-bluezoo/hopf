// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog record attribute names and export gating.

use std::sync::atomic::{AtomicBool, Ordering};

/// The URI of the event schema the event belongs to.
pub const QLOG_SCHEMA: &str = "qlog.schema";

/// The group id: the connection's original destination connection ID in hex.
pub const QLOG_GROUP_ID: &str = "qlog.group_id";

/// The vantage point: `client` or `server`.
pub const QLOG_VANTAGE_POINT: &str = "qlog.vantage_point";

/// The draft suffix of the event schema URIs: `-` and the draft number.
///
/// draft-ietf-quic-qlog-quic-events ("Draft Event Schema Identification")
/// says an implementation of a draft MUST append `-` and the draft number to
/// the URI, and MUST NOT use the bare form until the RFC exists. This is the
/// one place the number is held: when the RFC is published, make the body
/// empty and every URI built from it becomes the bare registered one.
macro_rules! draft_suffix {
    () => {
        "-14"
    };
}

/// The draft suffix of the event schema URIs (see the module's `draft_suffix`).
pub const QLOG_EVENTS_DRAFT_SUFFIX: &str = draft_suffix!();

/// draft-ietf-quic-qlog-quic-events: the QUIC event schema, as the draft
/// revision hopf follows names it (`urn:ietf:params:qlog:events:quic-14`).
///
/// hopf writes no HTTP/3 events, so there is no constant for that schema: a
/// trace lists only the schemas whose events it holds.
pub const QLOG_SCHEMA_QUIC: &str = concat!("urn:ietf:params:qlog:events:quic", draft_suffix!());

static QLOG_EXPORT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether any configured exporter accepts [`super::LogLevel::Qlog`].
pub fn qlog_export_enabled() -> bool {
    QLOG_EXPORT_ENABLED.load(Ordering::Relaxed)
}

/// Updated by `hopf_otel::TelemetryPipeline::start` (and cleared on shutdown).
pub fn set_qlog_export_enabled(enabled: bool) {
    QLOG_EXPORT_ENABLED.store(enabled, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_schema_uri_carries_the_draft_number() {
        // draft-ietf-quic-qlog-quic-events, "Draft Event Schema
        // Identification": an implementation of a draft MUST append `-` and
        // the draft number, and MUST NOT use the bare URI before the RFC.
        assert_eq!(QLOG_SCHEMA_QUIC, "urn:ietf:params:qlog:events:quic-14");
    }
}
