// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! qlog JSON-SEQ file sink (draft-ietf-quic-qlog-main-schema-15, with the
//! QUIC events of draft-ietf-quic-qlog-quic-events; see
//! [`hopf_core::QLOG_SCHEMA_QUIC`] for the draft number).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hopf_core::{
    AttrValue, LogLevel, LogRecord, QLOG_EVENTS_DRAFT_SUFFIX, QLOG_GROUP_ID, QLOG_SCHEMA, QLOG_SCHEMA_QUIC,
    QLOG_VANTAGE_POINT,
};

/// The revision of the qlog drafts the files follow, as the trace description
/// names it. The draft number of the event schema is the one the schema URI
/// carries ([`hopf_core::QLOG_EVENTS_DRAFT_SUFFIX`]), so the two cannot differ.
pub fn qlog_revision() -> String {
    format!("draft-ietf-quic-qlog-main-schema-15, draft-ietf-quic-qlog-quic-events{QLOG_EVENTS_DRAFT_SUFFIX}")
}

const IDLE_AFTER: Duration = Duration::from_secs(60);

/// Directory sink: one `{group_id}_{vantage}.sqlog` file per connection.
pub struct QlogFileSink {
    directory: PathBuf,
    idle_after: Duration,
    open: HashMap<String, TraceFile>,
}

impl QlogFileSink {
    /// Write qlog files under `directory` (created as needed).
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            idle_after: IDLE_AFTER,
            open: HashMap::new(),
        }
    }

    #[cfg(test)]
    #[cfg_attr(not(feature = "integration"), allow(dead_code))]
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
        self.open.retain(|_, file| {
            if now.duration_since(file.last_write) >= self.idle_after {
                let _ = file.close();
                false
            } else {
                true
            }
        });
    }

    pub(crate) fn shutdown(&mut self) -> Result<(), String> {
        for (_, mut file) in self.open.drain() {
            file.close()?;
        }
        Ok(())
    }

    fn write_one(&mut self, record: &LogRecord) -> Result<(), String> {
        let name = &record.name;
        let group = safe_name(attr_string(record, QLOG_GROUP_ID));
        let vantage = vantage_point(attr_string(record, QLOG_VANTAGE_POINT));
        let stem = format!("{group}_{vantage}");

        if !self.open.contains_key(&stem) {
            let file = open_trace_file(&self.directory, &stem, &group, &vantage, record.time_unix_nano)?;
            self.open.insert(stem.clone(), file);
        }

        let file = self.open.get_mut(&stem).expect("just inserted");
        file.write_event(record, name)?;
        file.last_write = Instant::now();

        if name == "quic:connection_closed" {
            let mut closed = self.open.remove(&stem).expect("open");
            closed.close()?;
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
        json_escape_into(&mut sb, &format!("hopf, {}", qlog_revision()));
        // Only the schemas whose events the trace holds: hopf writes QUIC
        // events and no HTTP/3 ones.
        sb.push_str(",\"event_schemas\":[");
        sb.push('"');
        sb.push_str(QLOG_SCHEMA_QUIC);
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

/// Open the trace file for `stem`, appending to it if it exists.
///
/// An existing file already says which epoch its times are relative to, in its
/// header's `reference_time`, so a later event for the same connection (after
/// the file was closed for idleness or at `connection_closed`, or by another
/// sink over the same directory, as after a restart) goes on that epoch and
/// the sink needs to remember nothing about connections it has finished. A
/// file that is new, or whose header cannot be read, gets a header whose
/// reference is the first event's time.
fn open_trace_file(
    directory: &Path,
    stem: &str,
    group: &str,
    vantage: &str,
    first_unix_nano: u64,
) -> Result<TraceFile, String> {
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let path = directory.join(format!("{stem}.sqlog"));
    let existing = read_reference(&path);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let reference_unix_nano = existing.unwrap_or((first_unix_nano / 1_000_000) * 1_000_000);
    let mut trace = TraceFile {
        writer: BufWriter::new(file),
        reference_unix_nano,
        last_write: Instant::now(),
    };
    if existing.is_none() {
        trace.write_header(group, vantage)?;
    }
    Ok(trace)
}

/// The most of a header record that is read: it is a few hundred bytes.
const HEADER_READ_LIMIT: u64 = 16 * 1024;

/// The epoch of the trace file at `path`, in nanoseconds since the Unix epoch,
/// from the `reference_time` of its header (its first record). `None` if the
/// file does not exist, is empty, or does not begin with a readable header.
fn read_reference(path: &Path) -> Option<u64> {
    let file = File::open(path).ok()?;
    let mut line = Vec::new();
    BufReader::new(file.take(HEADER_READ_LIMIT)).read_until(b'\n', &mut line).ok()?;
    if line.first() != Some(&0x1e) {
        return None;
    }
    let header = std::str::from_utf8(&line[1..]).ok()?;
    if !header.contains("\"file_schema\"") {
        return None;
    }
    const KEY: &str = "\"epoch\":\"";
    let start = header.find(KEY)? + KEY.len();
    let end = start + header[start..].find('"')?;
    parse_iso_millis_utc(&header[start..end])
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

/// The inverse of [`iso_millis_utc`]: `YYYY-MM-DDTHH:MM:SS.mmmZ` as nanoseconds
/// since the Unix epoch. `None` for anything else.
fn parse_iso_millis_utc(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<u64> {
        let digits = text.get(from..to)?;
        if !digits.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let (year, month, day) = (num(0, 4)? as i64, num(5, 7)? as u32, num(8, 10)? as u32);
    let (hour, minute, second, ms) = (num(11, 13)?, num(14, 16)?, num(17, 19)?, num(20, 23)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    Some((((days * 24 + hour) * 60 + minute) * 60 + second) * 1_000_000_000 + ms * 1_000_000)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (the inverse of
/// [`civil_from_days`]).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
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
#[cfg(feature = "integration")]
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
    #[cfg_attr(not(feature = "integration"), allow(unused_imports))]
    use std::fs;

    #[cfg(feature = "integration")]
    const T0: u64 = 1_700_000_000_000_000_000;

    #[cfg(feature = "integration")]
    fn event(
        time: u64,
        group: &str,
        vantage: &str,
        name: &str,
        data: &str,
    ) -> LogRecord {
        qlog_event(name, group, vantage, QLOG_SCHEMA_QUIC, data).tap_time(time)
    }

    #[cfg(feature = "integration")]
    trait TestLogRecord {
        fn tap_time(self, t: u64) -> Self;
    }

    #[cfg(feature = "integration")]
    impl TestLogRecord for LogRecord {
        fn tap_time(mut self, t: u64) -> Self {
            self.time_unix_nano = t;
            self
        }
    }

    #[cfg(feature = "integration")]
    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("hopf-qlog-{name}-{}", std::process::id()))
    }

    #[cfg(feature = "integration")]
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

    #[cfg(feature = "integration")]
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
        // Only the schema whose events are written, in its draft form.
        assert!(
            records[0].contains("\"event_schemas\":[\"urn:ietf:params:qlog:events:quic-14\"]"),
            "{}",
            records[0]
        );
        assert!(!records[0].contains("http3") && !records[0].contains("events:http"), "{}", records[0]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "integration")]
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

    #[cfg(feature = "integration")]
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

    #[cfg(feature = "integration")]
    #[test]
    fn a_later_sink_appends_to_a_finished_file_on_its_original_epoch() {
        let dir = temp_dir("restart");
        let _ = fs::remove_dir_all(&dir);
        // The first event is not on a millisecond: the file's epoch is the
        // millisecond before it.
        let first = T0 + 7_654_321;
        let mut one = QlogFileSink::new(&dir);
        one.write(&[
            event(first, "aa01", "server", "quic:connection_started", "{}"),
            event(first + 1_000_000, "aa01", "server", "quic:packet_sent", "{}"),
        ])
        .unwrap();
        one.shutdown().unwrap();
        drop(one);

        // A sink that knows nothing of the first, as after a restart, or one
        // that has forgotten a connection it closed long ago.
        let mut two = QlogFileSink::new(&dir);
        two.write(&[event(first + 3_000_000_000, "aa01", "server", "quic:packet_lost", "{}")])
            .unwrap();
        two.shutdown().unwrap();

        let records = parse_json_seq_records(&fs::read(dir.join("aa01_server.sqlog")).unwrap());
        assert_eq!(records.len(), 4, "{records:?}");
        assert_eq!(records.iter().filter(|r| r.contains("file_schema")).count(), 1, "one header");
        // 3000.654 ms after the epoch the file's header names, not after the
        // time of the late event itself.
        assert!(records[3].contains("\"time\":3000.654"), "{}", records[3]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "integration")]
    #[test]
    fn a_file_without_a_readable_header_gets_one() {
        let dir = temp_dir("badhead");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("aa01_server.sqlog"), b"not a qlog file\n").unwrap();
        let mut sink = QlogFileSink::new(&dir);
        sink.write(&[event(T0 + 5_000_000, "aa01", "server", "quic:connection_started", "{}")])
            .unwrap();
        sink.shutdown().unwrap();
        let bytes = fs::read(dir.join("aa01_server.sqlog")).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // The first event is the new header's reference: time 0.
        assert!(text.contains("file_schema"), "{text}");
        assert!(text.contains("\"time\":0.000"), "{text}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "integration")]
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
    fn the_header_epoch_reads_back_as_the_time_it_was_written_from() {
        for nanos in [
            0,
            1_000_000,
            951_782_400_123_000_000,    // 2000-02-29
            1_700_000_000_007_000_000,
            4_102_444_800_999_000_000, // 2100-01-01
        ] {
            let text = iso_millis_utc(nanos);
            assert_eq!(parse_iso_millis_utc(&text), Some(nanos), "{text}");
        }
        for bad in ["", "2023-11-14", "2023-11-14T22:13:20Z", "2023-13-14T22:13:20.000Z", "2023-11-14T22:13:20.00xZ", "x023-11-14T22:13:20.000Z"] {
            assert_eq!(parse_iso_millis_utc(bad), None, "{bad}");
        }
    }

    #[test]
    fn milliseconds_to_microsecond() {
        assert_eq!(milliseconds(1_500_250), "1.500");
        assert_eq!(milliseconds(1_000), "0.001");
        assert_eq!(milliseconds(10_999), "0.010");
        assert_eq!(milliseconds(-100_000), "-0.100");
        assert_eq!(milliseconds(12_345_678_999), "12345.678");
    }

    #[cfg(feature = "integration")]
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
