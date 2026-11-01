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

    #[test]
    fn an_otlp_sink_posts_the_batch_as_protobuf() {
        let (port, rx) = crate::otlp_http::tests::serve_once("HTTP/1.1 200 OK\r\n\r\n");
        let cfg = OtelConfig::new("otlp-test")
            .with_otlp_log_sink(format!("http://127.0.0.1:{port}/v1/logs"), LevelSet::INFO);
        let mut sinks = LogSinkInstance::from_config(&cfg);
        assert_eq!(sinks.len(), 1);
        let mut batch = vec![LogRecord::new(LogLevel::Info, "n").with_body("wire-body")];
        LogSinkInstance::flush_batch(&mut sinks, &cfg, &mut batch);
        assert!(batch.is_empty());
        let req = rx.recv().unwrap();
        let text = String::from_utf8_lossy(&req).into_owned();
        assert!(text.starts_with("POST /v1/logs HTTP/1.1"), "{text}");
        assert!(req.windows(9).any(|w| w == b"wire-body"), "the body carries the record");
        assert!(req.windows(9).any(|w| w == b"otlp-test"), "and the service name");
    }

    #[test]
    fn a_failing_export_does_not_keep_the_batch() {
        let (port, _rx) = crate::otlp_http::tests::serve_once("HTTP/1.1 503 Busy\r\n\r\n");
        let cfg = OtelConfig::new("t")
            .with_otlp_log_sink(format!("http://127.0.0.1:{port}/v1/logs"), LevelSet::INFO);
        let mut sinks = LogSinkInstance::from_config(&cfg);
        let mut batch = vec![LogRecord::new(LogLevel::Info, "n").with_body("b")];
        LogSinkInstance::flush_batch(&mut sinks, &cfg, &mut batch);
        assert!(batch.is_empty(), "the failure is reported on stderr, not retried");
    }

    #[test]
    fn an_endpoint_that_is_not_a_plain_http_url_gives_no_sink() {
        let cfg = OtelConfig::new("t").with_otlp_log_sink("https://c/v1/logs", LevelSet::INFO);
        assert!(LogSinkInstance::from_config(&cfg).is_empty());
    }

    #[test]
    fn records_nobody_accepts_are_dropped_and_an_empty_batch_is_a_no_op() {
        let cfg = OtelConfig::new("t").with_stderr_log_sink(LevelSet::ERROR);
        let mut sinks = LogSinkInstance::from_config(&cfg);
        let mut none: Vec<LogRecord> = Vec::new();
        LogSinkInstance::flush_batch(&mut sinks, &cfg, &mut none);
        let mut batch = vec![LogRecord::new(LogLevel::Info, "n")];
        LogSinkInstance::flush_batch(&mut sinks, &cfg, &mut batch);
        assert!(batch.is_empty());
    }

    #[test]
    fn access_and_qlog_sinks_take_only_their_own_levels() {
        let dir = std::env::temp_dir().join(format!("hopf-otel-sinks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let cfg = OtelConfig::new("t")
            .with_access_log(
                dir.join("access.log"),
                crate::access_log::AccessLogFormat::Clf,
                crate::access_log::AccessLogUserSelection::ProtocolFirst,
            )
            .with_qlog_dir(dir.join("qlog"))
            .with_stderr_log_sink(LevelSet::WARN)
            .with_jsonl_log_sink(dir.join("o.jsonl"), LevelSet::INFO);
        let mut sinks = LogSinkInstance::from_config(&cfg);
        assert_eq!(sinks.len(), 4);
        let takes = |s: &LogSinkInstance| -> Vec<bool> {
            [LogLevel::Info, LogLevel::Warn, LogLevel::Error, LogLevel::Access, LogLevel::Qlog]
                .iter()
                .map(|l| s.accepts(*l))
                .collect()
        };
        assert_eq!(takes(&sinks[0]), [false, false, false, true, false]);
        assert_eq!(takes(&sinks[1]), [false, false, false, false, true]);
        assert_eq!(takes(&sinks[2]), [false, true, false, false, false]);
        assert_eq!(takes(&sinks[3]), [true, false, false, false, false]);
        for sink in &mut sinks {
            sink.maintain(std::time::Instant::now());
            sink.shutdown().unwrap();
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
