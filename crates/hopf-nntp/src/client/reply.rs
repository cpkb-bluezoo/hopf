// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Status lines, multi-line responses and the records NNTP commands return.

/// A status line: three-digit code and the rest of the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NntpStatus {
    pub code: u16,
    pub text: String,
}

impl NntpStatus {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }
}

/// Parse `NNN text`; `None` unless the line starts with three digits.
pub fn parse_status(line: &str) -> Option<NntpStatus> {
    if line.len() < 3 || !line.is_char_boundary(3) {
        return None;
    }
    let code: u16 = line[..3].parse().ok()?;
    let text = line[3..].trim_start().to_string();
    Some(NntpStatus { code, text })
}

/// Response codes after which a multi-line block follows (RFC 3977 §3.1.1
/// and the commands that use them).
pub(crate) fn is_multiline_code(code: u16) -> bool {
    matches!(code, 100 | 101 | 215 | 220 | 221 | 222 | 224 | 225 | 230 | 231)
}

/// Splits inbound bytes into CRLF-terminated lines. Bytes after the last
/// CRLF wait for more input.
#[derive(Debug, Default)]
pub(crate) struct LineBuffer {
    buf: Vec<u8>,
}

impl LineBuffer {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next complete line without its CRLF, if there is one.
    pub fn next_line(&mut self) -> Option<Vec<u8>> {
        let end = self.buf.windows(2).position(|w| w == b"\r\n")?;
        let line = self.buf[..end].to_vec();
        self.buf.drain(..end + 2);
        Some(line)
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

/// One line of a multi-line block: `None` at the terminating `.`, else
/// the line with a stuffed leading dot removed.
pub(crate) fn unstuff_line(line: &[u8]) -> Option<&[u8]> {
    if line == b"." {
        None
    } else if line.starts_with(b"..") {
        Some(&line[1..])
    } else {
        Some(line)
    }
}

/// Prepare an article for `POST`: every line CRLF-terminated, a leading
/// `.` doubled, and the terminating `.` line appended.
pub fn dot_stuff(article: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(article.len() + 8);
    let mut at_line_start = true;
    let mut i = 0;
    while i < article.len() {
        let b = article[i];
        if at_line_start && b == b'.' {
            out.push(b'.');
        }
        if b == b'\n' {
            if !out.ends_with(b"\r") {
                out.push(b'\r');
            }
            out.push(b'\n');
            at_line_start = true;
        } else {
            out.push(b);
            at_line_start = false;
        }
        i += 1;
    }
    if !out.is_empty() && !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b".\r\n");
    out
}

/// A line of `LIST ACTIVE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewsgroupEntry {
    pub name: String,
    pub high: u64,
    pub low: u64,
    /// `y`, `n`, `m`, or whatever the server reports.
    pub status: char,
}

/// The `211` reply to `GROUP`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupResult {
    pub count: u64,
    pub first: u64,
    pub last: u64,
    pub name: String,
}

/// A line of `OVER` in the default overview format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverviewEntry {
    pub article_number: u64,
    pub subject: String,
    pub from: String,
    pub date: String,
    pub message_id: String,
    pub references: String,
    pub bytes: u64,
    pub lines: u64,
}

pub fn parse_overview_line(line: &str) -> Option<OverviewEntry> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < 8 {
        return None;
    }
    Some(OverviewEntry {
        article_number: fields[0].trim().parse().ok()?,
        subject: fields[1].to_string(),
        from: fields[2].to_string(),
        date: fields[3].to_string(),
        message_id: fields[4].to_string(),
        references: fields[5].to_string(),
        bytes: fields[6].trim().parse().unwrap_or(0),
        lines: fields[7].trim().parse().unwrap_or(0),
    })
}

pub fn parse_newsgroup_line(line: &str) -> Option<NewsgroupEntry> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let high: u64 = parts.next()?.parse().ok()?;
    let low: u64 = parts.next()?.parse().ok()?;
    let status = parts.next().and_then(|s| s.chars().next()).unwrap_or('y');
    Some(NewsgroupEntry { name, high, low, status })
}

pub fn parse_group_response(text: &str) -> Option<GroupResult> {
    let mut parts = text.split_whitespace();
    let count: u64 = parts.next()?.parse().ok()?;
    let first: u64 = parts.next()?.parse().ok()?;
    let last: u64 = parts.next()?.parse().ok()?;
    let name = parts.next()?.to_string();
    Some(GroupResult { count, first, last, name })
}

/// `CAPABILITIES` lines, upper-cased and trimmed.
pub(crate) fn normalize_capabilities(lines: &[Vec<u8>]) -> Vec<String> {
    lines
        .iter()
        .map(|l| String::from_utf8_lossy(l).trim().to_ascii_uppercase())
        .filter(|l| !l.is_empty())
        .collect()
}

pub(crate) fn has_capability(caps: &[String], name: &str) -> bool {
    caps.iter().any(|c| c == name || c.starts_with(&format!("{name} ")))
}

/// Mechanisms listed on the `SASL` capability line, in server order.
pub(crate) fn sasl_mechanisms(caps: &[String]) -> Vec<String> {
    caps.iter()
        .filter_map(|c| c.strip_prefix("SASL "))
        .flat_map(|rest| rest.split_whitespace().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_lines() {
        assert_eq!(parse_status("200 server ready"), Some(NntpStatus { code: 200, text: "server ready".into() }));
        assert_eq!(parse_status("381"), Some(NntpStatus { code: 381, text: String::new() }));
        assert_eq!(parse_status("hello"), None);
        assert_eq!(parse_status("20"), None);
    }

    #[test]
    fn line_buffer_splits_on_crlf_and_keeps_the_rest() {
        let mut b = LineBuffer::default();
        b.push(b"200 hi\r\n101 caps\r\nVERS");
        assert_eq!(b.next_line().as_deref(), Some(&b"200 hi"[..]));
        assert_eq!(b.next_line().as_deref(), Some(&b"101 caps"[..]));
        assert_eq!(b.next_line(), None);
        b.push(b"ION 2\r\n");
        assert_eq!(b.next_line().as_deref(), Some(&b"VERSION 2"[..]));
        assert!(b.is_empty());
    }

    #[test]
    fn unstuffing() {
        assert_eq!(unstuff_line(b"..dot"), Some(&b".dot"[..]));
        assert_eq!(unstuff_line(b"plain"), Some(&b"plain"[..]));
        assert_eq!(unstuff_line(b"."), None);
    }

    #[test]
    fn stuffing_doubles_leading_dots_and_terminates() {
        assert_eq!(dot_stuff(b"a\r\n.b\r\n"), b"a\r\n..b\r\n.\r\n");
        assert_eq!(dot_stuff(b"a\nb"), b"a\r\nb\r\n.\r\n");
        assert_eq!(dot_stuff(b""), b".\r\n");
    }

    #[test]
    fn records() {
        assert_eq!(
            parse_newsgroup_line("comp.lang.rust 1234 12 y"),
            Some(NewsgroupEntry { name: "comp.lang.rust".into(), high: 1234, low: 12, status: 'y' })
        );
        assert_eq!(
            parse_group_response("5 10 14 comp.lang.rust"),
            Some(GroupResult { count: 5, first: 10, last: 14, name: "comp.lang.rust".into() })
        );
        let o = parse_overview_line("12\tSubj\tme <me@x>\tMon\t<id@x>\t<ref@x>\t100\t3\tXref: x").unwrap();
        assert_eq!(o.article_number, 12);
        assert_eq!(o.message_id, "<id@x>");
        assert_eq!(o.lines, 3);
    }

    #[test]
    fn capabilities_helpers() {
        let caps = normalize_capabilities(&[b"VERSION 2".to_vec(), b"authinfo user".to_vec(), b"SASL plain scram-sha-256".to_vec()]);
        assert!(has_capability(&caps, "AUTHINFO"));
        assert!(has_capability(&caps, "VERSION"));
        assert!(!has_capability(&caps, "STARTTLS"));
        assert_eq!(sasl_mechanisms(&caps), vec!["PLAIN".to_string(), "SCRAM-SHA-256".to_string()]);
    }
}
