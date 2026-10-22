// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP access log records and CLF / W3C ELFF formatters.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hopf_core::{AttrValue, LogLevel, LogRecord, PeerAddr};

/// Event name for HTTP server access records.
pub const EVENT_NAME: &str = "http.server.request";

pub const CLIENT_ADDRESS: &str = "client.address";
pub const METHOD: &str = "http.request.method";
pub const TARGET: &str = "http.request.target";
pub const PROTOCOL_VERSION: &str = "network.protocol.version";
pub const STATUS_CODE: &str = "http.response.status_code";
pub const RESPONSE_BYTES: &str = "http.response.body.size";
pub const PROTOCOL_USER: &str = "enduser.id";
pub const APPLICATION_USER: &str = "hopf.application.user";

/// Access log file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLogFormat {
    /// Common Log Format.
    Clf,
    /// W3C Extended Log File Format.
    Elff,
}

/// Which authenticated identity appears in user columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessLogUserSelection {
    /// Protocol identity only.
    Protocol,
    /// Application identity only.
    Application,
    /// Protocol, else application.
    #[default]
    ProtocolFirst,
    /// Application, else protocol.
    ApplicationFirst,
    /// ELFF: separate columns; CLF uses protocol-first.
    Both,
}

/// Build an access [`LogRecord`] when export is enabled.
pub fn build_record(params: AccessRecordParams<'_>) -> LogRecord {
    let mut record = LogRecord::new(LogLevel::Access, EVENT_NAME)
        .with_scope("hopf-http");
    if let Some(body) = params.protocol_user {
        record
            .attrs
            .push((PROTOCOL_USER.into(), AttrValue::String(body.into())));
    }
    if let Some(body) = params.application_user {
        record
            .attrs
            .push((APPLICATION_USER.into(), AttrValue::String(body.into())));
    }
    record
        .attrs
        .push((CLIENT_ADDRESS.into(), AttrValue::String(params.client_address.into())));
    if let Some(m) = params.method {
        record
            .attrs
            .push((METHOD.into(), AttrValue::String(m.into())));
    }
    if let Some(t) = params.target {
        record
            .attrs
            .push((TARGET.into(), AttrValue::String(t.into())));
    }
    if let Some(v) = params.protocol_version {
        record
            .attrs
            .push((PROTOCOL_VERSION.into(), AttrValue::String(v.into())));
    }
    record.attrs.push((
        STATUS_CODE.into(),
        AttrValue::Int(i64::from(params.status_code)),
    ));
    record.attrs.push((
        RESPONSE_BYTES.into(),
        AttrValue::Int(params.response_bytes as i64),
    ));
    if let (Some(trace_id), Some(span_id)) = (params.trace_id, params.span_id) {
        record = record.with_trace_ids(trace_id, span_id);
    }
    record
}

/// Inputs for [`build_record`].
pub struct AccessRecordParams<'a> {
    /// Client host or address string.
    pub client_address: &'a str,
    /// Request method.
    pub method: Option<&'a str>,
    /// Request target (path and query).
    pub target: Option<&'a str>,
    /// Protocol version string (for example `HTTP/1.1`).
    pub protocol_version: Option<&'a str>,
    /// Protocol-authenticated user.
    pub protocol_user: Option<&'a str>,
    /// Application-authenticated user.
    pub application_user: Option<&'a str>,
    /// Response status.
    pub status_code: u16,
    /// Response body bytes sent.
    pub response_bytes: u64,
    /// Request span trace id.
    pub trace_id: Option<[u8; 16]>,
    /// Request span id.
    pub span_id: Option<[u8; 8]>,
}

/// Format access records as CLF or ELFF lines.
pub struct HttpAccessLogFormatter {
    format: AccessLogFormat,
    user_selection: AccessLogUserSelection,
}

impl HttpAccessLogFormatter {
    /// Create a formatter.
    pub fn new(format: AccessLogFormat, user_selection: AccessLogUserSelection) -> Self {
        Self {
            format,
            user_selection,
        }
    }

    /// ELFF preamble lines written once per new file.
    pub fn preamble_lines(&self) -> &'static [&'static str] {
        match self.format {
            AccessLogFormat::Clf => &[],
            AccessLogFormat::Elff if self.user_selection == AccessLogUserSelection::Both => &[
                "#Version: 1.0",
                "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes cs-username x-hopf-app-user cs-version",
            ],
            AccessLogFormat::Elff => &[
                "#Version: 1.0",
                "#Fields: date time c-ip cs-method cs-uri-stem sc-status sc-bytes cs-username cs-version",
            ],
        }
    }

    /// Format one record as a single log line (no trailing newline).
    pub fn format_line(&self, record: &LogRecord) -> String {
        match self.format {
            AccessLogFormat::Clf => self.format_clf(record),
            AccessLogFormat::Elff => self.format_elff(record),
        }
    }
}

impl HttpAccessLogFormatter {
    fn format_clf(&self, record: &LogRecord) -> String {
        let user = self.select_clf_user(record);
        let date = clf_date(record.time_unix_nano);
        let request_line = format_request_line(record);
        format!(
            "{} - {} {} \"{}\" {:03} {}",
            safe_token(attr_string(record, CLIENT_ADDRESS)),
            user.as_deref().unwrap_or("-"),
            date,
            request_line,
            number(record, STATUS_CODE),
            number(record, RESPONSE_BYTES),
        )
    }

    fn format_elff(&self, record: &LogRecord) -> String {
        let local = format_local_from_unix(Duration::from_nanos(record.time_unix_nano));
        let clf_user = self.select_clf_user(record);
        let mut line = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            local.date,
            local.time,
            safe_token(attr_string(record, CLIENT_ADDRESS)),
            safe_token(attr_string(record, METHOD)),
            safe_token(attr_string(record, TARGET)),
            number(record, STATUS_CODE),
            number(record, RESPONSE_BYTES),
            clf_user.as_deref().unwrap_or("-"),
        );
        if self.user_selection == AccessLogUserSelection::Both {
            let app = empty_to_none(attr_string(record, APPLICATION_USER));
            line.push('\t');
            line.push_str(app.as_deref().unwrap_or("-"));
        }
        line.push('\t');
        line.push_str(safe_token(attr_string(record, PROTOCOL_VERSION)));
        line
    }

    fn select_clf_user(&self, record: &LogRecord) -> Option<String> {
        let protocol = empty_to_none(attr_string(record, PROTOCOL_USER));
        let application = empty_to_none(attr_string(record, APPLICATION_USER));
        match self.user_selection {
            AccessLogUserSelection::Protocol => protocol,
            AccessLogUserSelection::Application => application,
            AccessLogUserSelection::ApplicationFirst => {
                application.or(protocol)
            }
            AccessLogUserSelection::Both => protocol.or(application),
            AccessLogUserSelection::ProtocolFirst => protocol.or(application),
        }
    }
}

/// Append-only access log file sink (export worker thread).
pub struct AccessLogFileSink {
    path: PathBuf,
    formatter: HttpAccessLogFormatter,
}

impl AccessLogFileSink {
    /// Open or create `path` for append-only access lines.
    pub fn new(
        path: impl Into<PathBuf>,
        format: AccessLogFormat,
        user_selection: AccessLogUserSelection,
    ) -> Self {
        Self {
            path: path.into(),
            formatter: HttpAccessLogFormatter::new(format, user_selection),
        }
    }

    pub(crate) fn write(&mut self, records: &[LogRecord]) -> Result<(), String> {
        if records.is_empty() {
            return Ok(());
        }
        let needs_preamble = file_is_empty(&self.path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        if needs_preamble {
            for line in self.formatter.preamble_lines() {
                writeln!(file, "{line}").map_err(|e| e.to_string())?;
            }
        }
        for rec in records {
            writeln!(file, "{}", self.formatter.format_line(rec)).map_err(|e| e.to_string())?;
        }
        file.flush().map_err(|e| e.to_string())
    }
}

/// Map a peer address to the `client.address` string.
pub fn client_host(peer: Option<PeerAddr>) -> String {
    match peer {
        Some(PeerAddr::Inet(addr)) => addr.ip().to_string(),
        Some(PeerAddr::Unix(path)) => path
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".into()),
        None => "-".into(),
    }
}

fn file_is_empty(path: &Path) -> Result<bool, String> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len() == 0),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

struct LocalParts {
    date: String,
    time: String,
}

fn format_local_from_unix(duration: Duration) -> LocalParts {
    let secs = duration.as_secs() as i64;
    // UTC calendar parts from Unix time.
    let days = secs / 86_400;
    let day_secs = (secs % 86_400) as u32;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;
    let (year, month, day) = civil_from_days(days);
    LocalParts {
        date: format!("{year:04}-{month:02}-{day:02}"),
        time: format!("{hour:02}:{minute:02}:{second:02}"),
    }
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mp < 10 { y } else { y + 1 };
    (y as i32, m as u32, d as u32)
}

fn clf_date(time_unix_nano: u64) -> String {
    let parts = format_local_from_unix(Duration::from_nanos(time_unix_nano));
    let month = match parts.date.as_str() {
        s if s.contains("-01-") => "Jan",
        s if s.contains("-02-") => "Feb",
        s if s.contains("-03-") => "Mar",
        s if s.contains("-04-") => "Apr",
        s if s.contains("-05-") => "May",
        s if s.contains("-06-") => "Jun",
        s if s.contains("-07-") => "Jul",
        s if s.contains("-08-") => "Aug",
        s if s.contains("-09-") => "Sep",
        s if s.contains("-10-") => "Oct",
        s if s.contains("-11-") => "Nov",
        _ => "Dec",
    };
    let day = parts.date.split('-').nth(2).unwrap_or("01");
    let year = parts.date.split('-').next().unwrap_or("2026");
    format!("[{day}/{month}/{year}:{} +0000]", parts.time)
}

fn format_request_line(record: &LogRecord) -> String {
    format!(
        "{} {} {}",
        attr_string(record, METHOD).unwrap_or("-"),
        attr_string(record, TARGET).unwrap_or("-"),
        attr_string(record, PROTOCOL_VERSION).unwrap_or("HTTP/1.1"),
    )
}

fn attr_string<'a>(record: &'a LogRecord, key: &str) -> Option<&'a str> {
    record.attrs.iter().find_map(|(k, v)| {
        if k == key {
            match v {
                AttrValue::String(s) => Some(s.as_str()),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn number(record: &LogRecord, key: &str) -> i64 {
    record
        .attrs
        .iter()
        .find_map(|(k, v)| {
            if k == key {
                match v {
                    AttrValue::Int(n) => Some(*n),
                    _ => None,
                }
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn safe_token(value: Option<&str>) -> &str {
    match value {
        Some(v) if !v.is_empty() => v,
        _ => "-",
    }
}

fn empty_to_none(value: Option<&str>) -> Option<String> {
    value.filter(|s| !s.is_empty()).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> LogRecord {
        build_record(AccessRecordParams {
            client_address: "10.0.0.1",
            method: Some("GET"),
            target: Some("/hello"),
            protocol_version: Some("HTTP/1.1"),
            protocol_user: Some("mtls-user"),
            application_user: Some("app-user"),
            status_code: 200,
            response_bytes: 42,
            trace_id: None,
            span_id: None,
        })
    }

    #[test]
    fn clf_contains_method_target_status_bytes() {
        let fmt = HttpAccessLogFormatter::new(
            AccessLogFormat::Clf,
            AccessLogUserSelection::ProtocolFirst,
        );
        let line = fmt.format_line(&sample_record());
        assert!(line.contains("10.0.0.1"));
        assert!(line.contains("\"GET /hello HTTP/1.1\""));
        assert!(line.ends_with(" 200 42"));
    }

    #[test]
    fn elff_new_file_gets_version_and_fields() {
        let path = std::env::temp_dir().join(format!(
            "hopf-access-elff-{}.log",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let mut sink = AccessLogFileSink::new(
            &path,
            AccessLogFormat::Elff,
            AccessLogUserSelection::Both,
        );
        sink.write(&[sample_record()]).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("#Version: 1.0\n"));
        assert!(body.contains("#Fields:"));
        assert!(body.contains("GET"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn accepts_access_false_skips_build_in_instrument_tests() {
        let cfg = crate::OtelConfig::new("no-access").with_stderr_logs();
        let pipeline = crate::TelemetryPipeline::start(cfg).unwrap();
        assert!(!pipeline.accepts(LogLevel::Access));
        pipeline.shutdown();
    }
}
