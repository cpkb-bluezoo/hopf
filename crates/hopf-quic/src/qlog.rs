// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog event sink for one QUIC connection (forwards to telemetry).

use hopf_core::{
    emit_log, qlog_export_enabled, LogLevel, LogRecord, QLOG_GROUP_ID, QLOG_SCHEMA,
    QLOG_VANTAGE_POINT,
};

/// Factory for per-connection qlog sinks (`server`, original destination CID bytes).
pub type QlogSinkFactory =
    std::sync::Arc<dyn Fn(bool, &[u8]) -> std::sync::Arc<dyn QlogSink + Send + Sync> + Send + Sync>;

/// Where a QUIC connection reports qlog events.
pub trait QlogSink {
    /// Whether events are exported (`accepts(QLOG)` was true at connection setup).
    fn is_qlog_enabled(&self) -> bool;
    /// Report an event (`data_json` is the event `data` object as JSON text).
    fn emit_qlog(&self, schema: &str, event_name: &str, data_json: &str);
    /// Alias for [`Self::is_qlog_enabled`].
    fn is_enabled(&self) -> bool {
        self.is_qlog_enabled()
    }
    /// Alias for [`Self::emit_qlog`].
    fn emit(&self, schema: &str, event_name: &str, data_json: &str) {
        self.emit_qlog(schema, event_name, data_json);
    }
}

/// Discarding sink when qlog export is disabled.
#[derive(Debug, Default, Clone, Copy)]
pub struct NopQlogSink;

impl QlogSink for NopQlogSink {
    fn is_qlog_enabled(&self) -> bool {
        false
    }

    fn emit_qlog(&self, _schema: &str, _event_name: &str, _data_json: &str) {}
}

/// Forwards qlog events to the process [`hopf_core::TelemetryHook`].
#[derive(Debug, Clone)]
pub struct TelemetryQlogSink {
    group_id: String,
    vantage_point: &'static str,
}

impl TelemetryQlogSink {
    /// Returns a sink when qlog export is enabled, else [`None`].
    pub fn maybe_new(server: bool, original_dcid: &[u8]) -> Option<Self> {
        if !qlog_export_enabled() || original_dcid.is_empty() {
            return None;
        }
        Some(Self {
            group_id: hex_bytes(original_dcid),
            vantage_point: if server { "server" } else { "client" },
        })
    }
}

impl QlogSink for TelemetryQlogSink {
    fn is_qlog_enabled(&self) -> bool {
        true
    }

    fn emit_qlog(&self, schema: &str, event_name: &str, data_json: &str) {
        let record = LogRecord::new(LogLevel::Qlog, event_name)
            .with_body(data_json)
            .with_scope("hopf-quic")
            .attr(QLOG_SCHEMA, schema)
            .attr(QLOG_GROUP_ID, &self.group_id)
            .attr(QLOG_VANTAGE_POINT, self.vantage_point);
        emit_log(record);
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::{set_qlog_export_enabled, TelemetryHook};
    use std::sync::{Arc, Mutex};

    struct Capture(Arc<Mutex<Vec<LogRecord>>>);

    impl TelemetryHook for Capture {
        fn on_log(&self, record: &LogRecord) {
            self.0.lock().unwrap().push(record.clone());
        }
    }

    #[test]
    fn nop_sink_is_disabled() {
        let s = NopQlogSink;
        assert!(!s.is_qlog_enabled());
        s.emit_qlog("s", "quic:packet_sent", "{}");
    }

    #[test]
    fn telemetry_sink_forwards_when_enabled() {
        set_qlog_export_enabled(true);
        let buf = Arc::new(Mutex::new(Vec::new()));
        hopf_core::set_process_telemetry(Arc::new(Capture(Arc::clone(&buf))));
        let sink = TelemetryQlogSink::maybe_new(true, &[0xab, 0x01]).unwrap();
        sink.emit_qlog("urn:ietf:params:qlog:events:quic", "quic:packet_sent", "{\"x\":1}");
        let rec = buf.lock().unwrap().pop().unwrap();
        assert_eq!(rec.level, LogLevel::Qlog);
        assert_eq!(rec.name, "quic:packet_sent");
        assert_eq!(rec.body.as_deref(), Some("{\"x\":1}"));
        hopf_core::clear_process_telemetry();
        set_qlog_export_enabled(false);
    }

    #[test]
    fn maybe_new_none_when_disabled() {
        set_qlog_export_enabled(false);
        assert!(TelemetryQlogSink::maybe_new(true, &[1]).is_none());
    }
}
