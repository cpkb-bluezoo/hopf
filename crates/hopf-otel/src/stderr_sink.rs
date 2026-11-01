// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Console (stderr) log sink — synchronous, level-filtered.

use std::io::{self, Write};

use hopf_core::LogRecord;

use crate::config::{LevelSet, OtelConfig};
use crate::log_record::LogLevel;

fn attr_display(v: &hopf_core::AttrValue) -> String {
    match v {
        hopf_core::AttrValue::String(s) => s.clone(),
        hopf_core::AttrValue::Int(n) => n.to_string(),
        hopf_core::AttrValue::Bool(b) => b.to_string(),
        hopf_core::AttrValue::Double(d) => d.to_string(),
    }
}

/// Format one record as a single stderr line.
pub fn format_stderr_line(rec: &LogRecord) -> String {
    let body = rec.body.as_deref().unwrap_or("");
    let mut attrs = String::new();
    for (i, (k, v)) in rec.attrs.iter().enumerate() {
        if i > 0 {
            attrs.push(' ');
        }
        attrs.push_str(k);
        attrs.push('=');
        attrs.push_str(&attr_display(v));
    }
    format!(
        "{} [{}] {}: {}{}",
        rec.level.severity_text(),
        rec.scope,
        rec.name,
        body,
        if attrs.is_empty() {
            String::new()
        } else {
            format!(" ({attrs})")
        }
    )
}

/// Write exporter-internal diagnostics without re-entering telemetry hooks.
pub fn write_internal_diagnostic(message: impl AsRef<str>) {
    let _ = writeln!(io::stderr(), "{}", message.as_ref());
}

/// Stderr sink state (export worker thread).
pub struct StderrLogSink {
    levels: LevelSet,
}

impl StderrLogSink {
    /// Create with a level filter.
    pub fn new(levels: LevelSet) -> Self {
        Self { levels }
    }

    pub(crate) fn accepts(&self, level: LogLevel) -> bool {
        self.levels.accepts(level)
    }

    pub(crate) fn write(&mut self, _config: &OtelConfig, batch: &[LogRecord]) -> io::Result<()> {
        let mut err = io::stderr().lock();
        for rec in batch {
            writeln!(err, "{}", format_stderr_line(rec))?;
        }
        err.flush()
    }

    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::LogRecord;

    #[test]
    fn stderr_line_includes_level_scope_and_name() {
        let rec = LogRecord::new(LogLevel::Warn, "runtime.test")
            .with_scope("hopf-otel")
            .with_body("hello")
            .attr("host", "example.com");
        let line = format_stderr_line(&rec);
        assert!(line.contains("WARN"));
        assert!(line.contains("hopf-otel"));
        assert!(line.contains("runtime.test"));
        assert!(line.contains("hello"));
        assert!(line.contains("host=example.com"));
    }

    #[test]
    fn attributes_of_every_kind_are_shown_in_order_and_a_bare_record_has_none() {
        let mut rec = LogRecord::new(LogLevel::Info, "n").with_scope("s");
        rec.attrs.push(("count".into(), hopf_core::AttrValue::Int(3)));
        rec.attrs.push(("ok".into(), hopf_core::AttrValue::Bool(true)));
        rec.attrs.push(("ratio".into(), hopf_core::AttrValue::Double(0.5)));
        assert_eq!(format_stderr_line(&rec), "INFO [s] n:  (count=3 ok=true ratio=0.5)");
        let bare = LogRecord::new(LogLevel::Error, "n").with_scope("s").with_body("b");
        assert_eq!(format_stderr_line(&bare), "ERROR [s] n: b");
    }

    #[test]
    fn the_sink_takes_only_its_levels() {
        let sink = StderrLogSink::new(LevelSet::WARN.union(LevelSet::ERROR));
        assert!(sink.accepts(LogLevel::Warn) && sink.accepts(LogLevel::Error));
        assert!(!sink.accepts(LogLevel::Info));
    }

    #[test]
    fn writing_and_shutting_down_succeed() {
        let mut sink = StderrLogSink::new(LevelSet::OPERATIONAL);
        let batch = [LogRecord::new(LogLevel::Info, "stderr-sink-test").with_scope("t")];
        sink.write(&OtelConfig::new("t"), &batch).unwrap();
        sink.shutdown().unwrap();
    }
}
