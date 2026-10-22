// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Log export sinks and per-record level routing.

use crate::config::{LevelSet, LogSinkConfig, OtelConfig};
use crate::jsonl::JsonlAppender;
use crate::log_record::{LogLevel, LogRecord};
use crate::otlp_http::{post_protobuf, HttpEndpoint};
use crate::otlp_proto::encode_logs_request;
use crate::access_log::AccessLogFileSink;
use crate::qlog::QlogFileSink;
use crate::stderr_sink::{write_internal_diagnostic, StderrLogSink};

/// Writes accepted [`LogRecord`] batches on the export worker thread.
pub trait LogSink {
    /// Whether this sink wants records at `level`.
    fn accepts(&self, level: LogLevel) -> bool;
    /// Encode and export one batch (already filtered to accepted levels).
    fn write(&mut self, config: &OtelConfig, batch: &[LogRecord]) -> Result<(), String>;
    /// Optional fsync / socket flush.
    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
    /// Close resources.
    fn shutdown(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Concrete log sinks configured on [`OtelConfig`].
pub enum LogSinkInstance {
    /// OTLP JSON Lines file.
    Jsonl {
        appender: JsonlAppender,
        levels: LevelSet,
    },
    /// OTLP/HTTP protobuf logs endpoint.
    OtlpHttp {
        endpoint: HttpEndpoint,
        levels: LevelSet,
    },
    /// Process stderr (console).
    Stderr(StderrLogSink),
    /// HTTP access log file.
    AccessLog(AccessLogFileSink),
    /// qlog JSON-SEQ directory.
    Qlog(QlogFileSink),
}

impl LogSinkInstance {
    /// Build sinks from configuration (export worker only).
    pub fn from_config(config: &OtelConfig) -> Vec<Self> {
        config
            .log_sinks
            .iter()
            .filter_map(|spec| Self::from_spec(spec))
            .collect()
    }

    fn from_spec(spec: &LogSinkConfig) -> Option<Self> {
        match spec {
            LogSinkConfig::Jsonl { path, levels } => Some(Self::Jsonl {
                appender: JsonlAppender::new(path.clone()),
                levels: *levels,
            }),
            LogSinkConfig::OtlpHttp { endpoint, levels } => {
                HttpEndpoint::parse(endpoint).map(|endpoint| Self::OtlpHttp {
                    endpoint,
                    levels: *levels,
                })
            }
            LogSinkConfig::Stderr { levels } => Some(Self::Stderr(StderrLogSink::new(*levels))),
            LogSinkConfig::AccessLog {
                path,
                format,
                user_selection,
            } => Some(Self::AccessLog(AccessLogFileSink::new(
                path.clone(),
                *format,
                *user_selection,
            ))),
            LogSinkConfig::Qlog { directory } => {
                Some(Self::Qlog(QlogFileSink::new(directory.clone())))
            }
        }
    }

    /// Periodic maintenance (qlog idle file close).
    pub fn maintain(&mut self, now: std::time::Instant) {
        if let Self::Qlog(s) = self {
            s.close_idle(now);
        }
    }

    /// Partition `batch` by acceptance and write to each sink.
    pub fn flush_batch(
        sinks: &mut [Self],
        config: &OtelConfig,
        batch: &mut Vec<LogRecord>,
    ) {
        if batch.is_empty() {
            return;
        }
        for sink in sinks {
            let subset: Vec<LogRecord> = batch
                .iter()
                .filter(|r| sink.accepts(r.level))
                .cloned()
                .collect();
            if subset.is_empty() {
                continue;
            }
            if let Err(e) = sink.write(config, &subset) {
                write_internal_diagnostic(format!("hopf-otel: log sink write failed: {e}"));
            }
        }
        batch.clear();
    }

}

impl LogSink for LogSinkInstance {
    fn accepts(&self, level: LogLevel) -> bool {
        match self {
            Self::Jsonl { levels, .. } | Self::OtlpHttp { levels, .. } => levels.accepts(level),
            Self::Stderr(s) => s.accepts(level),
            Self::AccessLog(_) => level == LogLevel::Access,
            Self::Qlog(_) => level == LogLevel::Qlog,
        }
    }

    fn write(&mut self, config: &OtelConfig, batch: &[LogRecord]) -> Result<(), String> {
        match self {
            Self::Jsonl { appender, .. } => appender.append_logs(config, batch),
            Self::OtlpHttp { endpoint, .. } => {
                let body = encode_logs_request(config, batch);
                post_protobuf(endpoint, &body).map(|_| ())
            }
            Self::Stderr(s) => s.write(config, batch).map_err(|e| e.to_string()),
            Self::AccessLog(s) => s.write(batch),
            Self::Qlog(s) => s.write(batch),
        }
    }

    fn shutdown(&mut self) -> Result<(), String> {
        match self {
            Self::Stderr(s) => s.shutdown().map_err(|e| e.to_string()),
            Self::Qlog(s) => s.shutdown(),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OtelConfig;
    use std::fs;
    use std::path::PathBuf;

    fn temp_jsonl(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hopf-otel-{name}-{}.jsonl", std::process::id()))
    }

    #[test]
    fn disjoint_level_sets_route_to_separate_files() {
        let info_path = temp_jsonl("info-only");
        let err_path = temp_jsonl("err-only");
        let _ = fs::remove_file(&info_path);
        let _ = fs::remove_file(&err_path);

        let cfg = OtelConfig::new("route-test")
            .with_jsonl_log_sink(info_path.clone(), LevelSet::INFO)
            .with_jsonl_log_sink(err_path.clone(), LevelSet::ERROR);

        let mut sinks = LogSinkInstance::from_config(&cfg);
        let mut batch = vec![
            LogRecord::new(LogLevel::Info, "i").with_body("info-body"),
            LogRecord::new(LogLevel::Error, "e").with_body("err-body"),
            LogRecord::new(LogLevel::Warn, "w").with_body("warn-body"),
        ];
        LogSinkInstance::flush_batch(&mut sinks, &cfg, &mut batch);
        assert!(batch.is_empty());

        let info_body = fs::read_to_string(&info_path).unwrap();
        assert!(info_body.contains("info-body"));
        assert!(!info_body.contains("err-body"));

        let err_body = fs::read_to_string(&err_path).unwrap();
        assert!(err_body.contains("err-body"));
        assert!(!err_body.contains("info-body"));

        let _ = fs::remove_file(&info_path);
        let _ = fs::remove_file(&err_path);
    }
}
