// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog JSON-SEQ file sink (draft-ietf-quic-qlog-main-schema-14).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hopf_core::{
    AttrValue, LogLevel, LogRecord, QLOG_GROUP_ID, QLOG_SCHEMA, QLOG_SCHEMA_HTTP,
    QLOG_SCHEMA_HTTP3, QLOG_SCHEMA_QUIC, QLOG_VANTAGE_POINT,
};

/// The revision of the qlog drafts the files follow.
pub const QLOG_REVISION: &str = "draft-ietf-quic-qlog-main-schema-14, \
draft-ietf-quic-qlog-quic-events-13, draft-ietf-quic-qlog-h3-events-13";

const IDLE_AFTER: Duration = Duration::from_secs(60);

/// Directory sink: one `{group_id}_{vantage}.sqlog` file per connection.
pub struct QlogFileSink {
    directory: PathBuf,
    idle_after: Duration,
    open: HashMap<String, TraceFile>,
    finished: HashMap<String, u64>,
}

impl QlogFileSink {
    /// Write qlog files under `directory` (created as needed).
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            idle_after: IDLE_AFTER,
            open: HashMap::new(),
            finished: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn with_idle_after(mut self, idle: Duration) -> Self {
        self.idle_after = idle;
        self
    }

    pub(crate) fn write(&mut self, records: &[LogRecord]) -> Result<(), String> {
        for record in records {
            if record.level != LogLevel::Qlog {
                continue;
            }
            self.write_one(record)?;
        }
        for file in self.open.values_mut() {
            file.flush()?;
        }
        Ok(())
    }

    pub(crate) fn close_idle(&mut self, now: Instant) {
        self.open.retain(|stem, file| {
            if now.duration_since(file.last_write) >= self.idle_after {
                let reference = file.reference_unix_nano;
                let _ = file.close();
                self.finished.insert(stem.clone(), reference);
                false
            } else {
                true
            }
        });
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), String> {
        for (stem, mut file) in self.open.drain() {
            let reference = file.reference_unix_nano;
            file.close()?;
            self.finished.insert(stem, reference);
        }
        Ok(())
    }

    fn write_one(&mut self, record: &LogRecord) -> Result<(), String> {
        let name = &record.name;
        let group = safe_name(attr_string(record, QLOG_GROUP_ID));
        let vantage = vantage_point(attr_string(record, QLOG_VANTAGE_POINT));
        let stem = format!("{group}_{vantage}");

        if !self.open.contains_key(&stem) {
            let reference = self.finished.get(&stem).copied();
            let file = open_trace_file(
                &self.directory,
                &stem,
                &group,
                &vantage,
                reference,
                record.time_unix_nano,
            )?;
            self.open.insert(stem.clone(), file);
        }

        let file = self.open.get_mut(&stem).expect("just inserted");
        file.write_event(record, name)?;
        file.last_write = Instant::now();

        if name == "quic:connection_closed" {
            let mut closed = self.open.remove(&stem).expect("open");
            let reference = closed.reference_unix_nano;
            closed.close()?;
            self.finished.insert(stem, reference);
        }
        Ok(())
    }
}

struct TraceFile {
    writer: BufWriter<File>,
    reference_unix_nano: u64,
    last_write: Instant,
}

impl TraceFile {
    fn flush(&mut self) -> Result<(), String> {
        self.writer.flush().map_err(|e| e.to_string())
    }

    fn close(&mut self) -> Result<(), String> {
        self.writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn write_event(&mut self, record: &LogRecord, name: &str) -> Result<(), String> {
        let delta = record.time_unix_nano as i128 - self.reference_unix_nano as i128;
        let data = record.body.as_deref().unwrap_or("{}");
        let data = if data.is_empty() { "{}" } else { data };
        let mut line = String::with_capacity(64 + data.len());
        line.push_str("{\"time\":");
        line.push_str(&milliseconds(delta));
        line.push_str(",\"name\":");
        json_escape_into(&mut line, name);
        line.push_str(",\"data\":");
        line.push_str(data);
        line.push('}');
        write_record(&mut self.writer, &line)
    }

    fn write_header(&mut self, group: &str, vantage: &str) -> Result<(), String> {
        let epoch = iso_millis_utc(self.reference_unix_nano);
        let mut sb = String::with_capacity(512);
        sb.push_str("{\"file_schema\":\"urn:ietf:params:qlog:file:sequential\",");
        sb.push_str("\"serialization_format\":\"application/qlog+json-seq\",");
        sb.push_str("\"trace\":{\"vantage_point\":{\"type\":");
        json_escape_into(&mut sb, vantage);
        sb.push_str("},\"description\":");
        json_escape_into(&mut sb, &format!("hopf, {QLOG_REVISION}"));
        sb.push_str(",\"event_schemas\":[");
        sb.push('"');
        sb.push_str(QLOG_SCHEMA_QUIC);
        sb.push_str("\",\"");
        sb.push_str(QLOG_SCHEMA_HTTP3);
        sb.push_str("\",\"");
        sb.push_str(QLOG_SCHEMA_HTTP);
        sb.push_str("\"],\"common_fields\":{\"group_id\":");
        json_escape_into(&mut sb, group);
        sb.push_str(",\"time_format\":\"relative_to_epoch\",\"reference_time\":{");
        sb.push_str("\"clock_type\":\"system\",\"epoch\":\"");
        sb.push_str(&epoch);
        sb.push_str("\",\"wall_clock_time\":\"");
        sb.push_str(&epoch);
        sb.push_str("\"}}}}");
        write_record(&mut self.writer, &sb)
    }
}

fn open_trace_file(
    directory: &Path,
    stem: &str,
    group: &str,
    vantage: &str,
    reference: Option<u64>,
    first_unix_nano: u64,
) -> Result<TraceFile, String> {
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let path = directory.join(format!("{stem}.sqlog"));
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let mut trace = if let Some(reference) = reference {
        TraceFile {
            writer: BufWriter::new(file),
            reference_unix_nano: reference,
            last_write: Instant::now(),
        }
    } else {
        let reference_unix_nano = (first_unix_nano / 1_000_000) * 1_000_000;
        TraceFile {
            writer: BufWriter::new(file),
            reference_unix_nano,
            last_write: Instant::now(),
        }
    };
    if reference.is_none() {
        trace.write_header(group, vantage)?;
    }
    Ok(trace)
}

fn write_record(writer: &mut BufWriter<File>, json: &str) -> Result<(), String> {
    writer.write_all(&[0x1e]).map_err(|e| e.to_string())?;
    writer.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(())
}

fn attr_string(record: &LogRecord, key: &str) -> Option<String> {
    record
        .attrs
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            AttrValue::String(s) => Some(s.clone()),
            _ => None,
        })
}

fn safe_name(value: Option<String>) -> String {
    let value = value.unwrap_or_else(|| "unknown".into());
    if value.is_empty() {
        return "unknown".into();
    }
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn vantage_point(value: Option<String>) -> String {
    match value.as_deref() {
        Some("client") => "client".into(),
        Some("server") => "server".into(),
        _ => "unknown".into(),
    }
}

fn iso_millis_utc(unix_nano: u64) -> String {
    let millis = unix_nano / 1_000_000;
    let secs = (millis / 1000) as i64;
    let ms = (millis % 1000) as u32;
    let days = secs / 86_400;
    let day_secs = (secs % 86_400) as u32;
    let hour = day_secs / 3600;
    let minute = (day_secs % 3600) / 60;
    let second = day_secs % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{ms:03}Z")
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
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m, d)
}

/// Milliseconds relative to reference, to the microsecond, as JSON number text.
pub(crate) fn milliseconds(delta_nanos: i128) -> String {
    let negative = delta_nanos < 0;
    let abs = delta_nanos.unsigned_abs();
    let micros = (abs / 1_000) % 1_000;
    let millis = abs / 1_000_000;
    let mut sb = String::with_capacity(24);
    if negative {
        sb.push('-');
    }
    sb.push_str(&millis.to_string());
    sb.push('.');
    if micros < 100 {
        sb.push('0');
    }
    if micros < 10 {
        sb.push('0');
    }
    sb.push_str(&micros.to_string());
    sb
}

fn json_escape_into(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < '\u{0020}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Build a qlog [`LogRecord`] for export.
pub fn qlog_event(
    name: impl Into<String>,
    group_id: impl Into<String>,
    vantage_point: impl Into<String>,
    schema: impl Into<String>,
    data_json: impl Into<String>,
) -> LogRecord {
    LogRecord::new(LogLevel::Qlog, name)
        .with_body(data_json)
        .with_scope("hopf-quic")
        .attr(QLOG_SCHEMA, schema)
        .attr(QLOG_GROUP_ID, group_id)
        .attr(QLOG_VANTAGE_POINT, vantage_point)
}

#[cfg(test)]
pub(crate) fn parse_json_seq_records(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if b == 0x1e {
            assert!(start.is_none(), "record start without prior terminator");
            start = Some(i + 1);
        } else if b == b'\n' {
            let s = start.expect("terminator without start");
            out.push(String::from_utf8(bytes[s..i].to_vec()).expect("utf8"));
            start = None;
        }
    }
    assert!(start.is_none(), "trailing partial record");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const T0: u64 = 1_700_000_000_000_000_000;

    fn event(
        time: u64,
        group: &str,
        vantage: &str,
        name: &str,
        data: &str,
    ) -> LogRecord {
        qlog_event(name, group, vantage, QLOG_SCHEMA_QUIC, data).tap_time(time)
    }

    trait TestLogRecord {
        fn tap_time(self, t: u64) -> Self;
    }

    impl TestLogRecord for LogRecord {
        fn tap_time(mut self, t: u64) -> Self {
            self.time_unix_nano = t;
            self
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hopf-qlog-{name}-{}", std::process::id()))
    }

    #[test]
    fn two_connections_two_files() {
        let dir = temp_dir("two-conn");
        let _ = fs::remove_dir_all(&dir);
        let mut sink = QlogFileSink::new(&dir);
        sink.write(&[
            event(T0, "aa01", "server", "quic:connection_started", "{}"),
            event(T0 + 1000, "bb02", "client", "quic:connection_started", "{}"),
            event(T0 + 2000, "aa01", "server", "quic:packet_lost", "{}"),
        ])
        .unwrap();
        sink.shutdown().unwrap();
        let aa = fs::read(dir.join("aa01_server.sqlog")).unwrap();
        let bb = fs::read(dir.join("bb02_client.sqlog")).unwrap();
        assert_eq!(parse_json_seq_records(&aa).len(), 3);
        assert_eq!(parse_json_seq_records(&bb).len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_and_framing() {
        let dir = temp_dir("header");
        let _ = fs::remove_dir_all(&dir);
        let mut sink = QlogFileSink::new(&dir);
        sink.write(&[event(T0, "aa01", "server", "quic:connection_started", "{}")])
            .unwrap();
        sink.shutdown().unwrap();
        let bytes = fs::read(dir.join("aa01_server.sqlog")).unwrap();
        assert_eq!(bytes[0], 0x1e);
        assert_eq!(bytes[bytes.len() - 1], b'\n');
        let records = parse_json_seq_records(&bytes);
        assert!(records[0].contains("urn:ietf:params:qlog:file:sequential"));
        assert!(records[0].contains("aa01"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_times_and_data() {
        let dir = temp_dir("times");
        let _ = fs::remove_dir_all(&dir);
        let mut sink = QlogFileSink::new(&dir);
        sink.write(&[
            event(T0, "aa01", "client", "quic:connection_started", "{\"src_port\":1}"),
            event(
                T0 + 1_500_250,
                "aa01",
                "client",
                "quic:packet_lost",
                "{\"header\":{\"packet_number\":7}}",
            ),
        ])
        .unwrap();
        sink.shutdown().unwrap();
        let records = parse_json_seq_records(&fs::read(dir.join("aa01_client.sqlog")).unwrap());
        assert_eq!(records.len(), 3);
        assert!(records[1].contains("\"time\":0."));
        assert!(records[1].contains("quic:connection_started"));
        assert!(records[2].contains("\"time\":1.500"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_closed_closes_file_and_reopen_appends() {
        let dir = temp_dir("closed");
        let _ = fs::remove_dir_all(&dir);
        let mut sink = QlogFileSink::new(&dir);
        sink.write(&[event(T0, "aa01", "server", "quic:connection_started", "{}")])
            .unwrap();
        assert_eq!(sink.open.len(), 1);
        sink.write(&[event(T0 + 5, "aa01", "server", "quic:connection_closed", "{}")])
            .unwrap();
        assert!(sink.open.is_empty());
        sink.write(&[event(T0 + 9, "aa01", "server", "quic:packet_lost", "{}")])
            .unwrap();
        sink.shutdown().unwrap();
        let records = parse_json_seq_records(&fs::read(dir.join("aa01_server.sqlog")).unwrap());
        assert_eq!(records.len(), 4);
        assert_eq!(
            records
                .iter()
                .filter(|r| r.contains("file_schema"))
                .count(),
            1
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_close() {
        let dir = temp_dir("idle");
        let _ = fs::remove_dir_all(&dir);
        let mut sink = QlogFileSink::new(&dir).with_idle_after(Duration::from_millis(1));
        sink.write(&[event(T0, "aa01", "server", "quic:connection_started", "{}")])
            .unwrap();
        assert_eq!(sink.open.len(), 1);
        std::thread::sleep(Duration::from_millis(5));
        sink.close_idle(Instant::now());
        assert!(sink.open.is_empty());
        sink.shutdown().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn milliseconds_to_microsecond() {
        assert_eq!(milliseconds(1_500_250), "1.500");
        assert_eq!(milliseconds(1_000), "0.001");
        assert_eq!(milliseconds(10_999), "0.010");
        assert_eq!(milliseconds(-100_000), "-0.100");
        assert_eq!(milliseconds(12_345_678_999), "12345.678");
    }

    #[test]
    fn group_id_sanitized() {
        let dir = temp_dir("safe");
        let _ = fs::remove_dir_all(&dir);
        let mut sink = QlogFileSink::new(&dir);
        sink.write(&[event(
            T0,
            "../../etc/passwd",
            "server",
            "quic:connection_started",
            "{}",
        )])
        .unwrap();
        sink.shutdown().unwrap();
        let entries: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].file_name().unwrap().to_string_lossy().ends_with("_server.sqlog"));
        let _ = fs::remove_dir_all(&dir);
    }
}
