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

/// The longest status line, or line of a multi-line block, the lexer will
/// accept; past it the reply is a protocol error.
pub(crate) const MAX_REPLY_LINE: usize = 64 * 1024;

/// What the lexer found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyEvent {
    /// More bytes are needed.
    NeedMore,
    /// A status line: its three-digit code and the text after it.
    Status(NntpStatus),
    /// A line of a multi-line block, dot-unstuffed and without its CRLF;
    /// read it with [`NntpReplyLexer::line`] until the next call.
    Line,
    /// The `.` line that ends a multi-line block.
    BlockEnd,
    /// A status line that does not begin with three digits (what there was
    /// of it, to report; see [`NntpReplyLexer::take_malformed`]).
    Malformed,
    /// A line longer than [`MAX_REPLY_LINE`].
    TooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between items: the first byte decides, by what is expected.
    Idle,
    /// Reading the three digits of a status code.
    Digits { seen: u8, code: u16 },
    /// Reading the text of a status line.
    Text,
    /// Status text: saw CR.
    TextCr,
    /// A line that is not a status: skipping to its CRLF (kept to report).
    Bad,
    BadCr,
    /// Block: start of a line.
    LineStart,
    /// Block: the line so far is a single `.`.
    Dot,
    /// Block: the line so far is `.` and a CR.
    DotCr,
    /// Block: inside a line.
    InLine,
    /// Block: inside a line, saw CR.
    LineCr,
}

/// Incremental NNTP reply parser (RFC 3977 §3): status lines and
/// multi-line blocks, read straight out of the connection's ring.
///
/// A status code is read digit by digit and its text kept in a bounded
/// scratch buffer, so no line is ever copied out whole and parsed again. In a
/// block, byte stuffing and the `.` terminator are dealt with as the bytes
/// arrive, and each line is built in one reusable buffer. It stops after
/// every event, so the caller can say (with [`Self::expect_block`]) what
/// comes next.
#[derive(Debug)]
pub(crate) struct NntpReplyLexer {
    state: State,
    /// A multi-line block is due at the next item.
    block: bool,
    /// Status text, or a block line, or the start of a bad line.
    scratch: Vec<u8>,
    code: u16,
}

impl Default for NntpReplyLexer {
    fn default() -> Self {
        Self { state: State::Idle, block: false, scratch: Vec::new(), code: 0 }
    }
}

impl NntpReplyLexer {
    /// Whether the next item is a multi-line block (until a lone `.`) or a
    /// status line. Takes effect at the start of the next item.
    pub fn expect_block(&mut self, block: bool) {
        self.block = block;
    }

    /// The block line [`ReplyEvent::Line`] reported.
    pub fn line(&self) -> &[u8] {
        &self.scratch
    }

    /// The start of the line [`ReplyEvent::Malformed`] reported.
    pub fn take_malformed(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.scratch)
    }

    /// Reads from `buf` up to the next event, consuming what it reads.
    pub fn next_event(&mut self, buf: &mut hopf_core::LoopBuf) -> ReplyEvent {
        loop {
            let first = buf.readable_spans().0;
            if first.is_empty() {
                return ReplyEvent::NeedMore;
            }
            let (used, event) = self.scan(first);
            buf.advance(used);
            if let Some(event) = event {
                return event;
            }
        }
    }

    /// Reads from `data` up to the next event; returns how much it used.
    fn scan(&mut self, data: &[u8]) -> (usize, Option<ReplyEvent>) {
        let mut i = 0;
        while i < data.len() {
            let b = data[i];
            // Inside a line, take everything up to the next CR in one go.
            if matches!(self.state, State::InLine | State::Text | State::Bad) {
                let run = data[i..].iter().position(|&c| c == b'\r').unwrap_or(data.len() - i);
                if run > 0 {
                    if self.scratch.len() + run > MAX_REPLY_LINE {
                        self.reset();
                        return (i + run, Some(ReplyEvent::TooLong));
                    }
                    self.scratch.extend_from_slice(&data[i..i + run]);
                    i += run;
                    continue;
                }
            }
            i += 1;
            if let Some(event) = self.step(b) {
                return (i, Some(event));
            }
            if self.scratch.len() > MAX_REPLY_LINE {
                self.reset();
                return (i, Some(ReplyEvent::TooLong));
            }
        }
        (i, None)
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.scratch.clear();
    }

    fn step(&mut self, b: u8) -> Option<ReplyEvent> {
        loop {
            match self.state {
                State::Idle => {
                    self.scratch.clear();
                    self.state = if self.block { State::LineStart } else { State::Digits { seen: 0, code: 0 } };
                    continue;
                }
                State::Digits { seen, code } => {
                    if b.is_ascii_digit() {
                        let code = code * 10 + u16::from(b - b'0');
                        if seen == 2 {
                            self.code = code;
                            self.state = State::Text;
                        } else {
                            self.state = State::Digits { seen: seen + 1, code };
                        }
                        return None;
                    }
                    // Not a status line: keep what there is of it to report
                    // (the digits already read are the start of it).
                    self.scratch.clear();
                    if seen > 0 {
                        self.scratch.extend_from_slice(format!("{code:0width$}", width = seen as usize).as_bytes());
                    }
                    if b == b'\r' {
                        self.state = State::BadCr;
                    } else {
                        self.scratch.push(b);
                        self.state = State::Bad;
                    }
                    return None;
                }
                State::Text => {
                    // Only a CR gets here (a run takes the rest).
                    self.state = State::TextCr;
                    return None;
                }
                State::TextCr => {
                    if b == b'\n' {
                        let text = String::from_utf8_lossy(&self.scratch).trim_start().to_string();
                        let status = NntpStatus { code: self.code, text };
                        self.reset();
                        return Some(ReplyEvent::Status(status));
                    }
                    // A lone CR is part of the text.
                    self.scratch.push(b'\r');
                    if b == b'\r' {
                        return None; // still possibly the CR of the CRLF
                    }
                    self.scratch.push(b);
                    self.state = State::Text;
                    return None;
                }
                State::Bad => {
                    self.state = State::BadCr;
                    return None;
                }
                State::BadCr => {
                    if b == b'\n' {
                        self.state = State::Idle;
                        return Some(ReplyEvent::Malformed);
                    }
                    self.scratch.push(b'\r');
                    if b == b'\r' {
                        return None;
                    }
                    self.scratch.push(b);
                    self.state = State::Bad;
                    return None;
                }
                State::LineStart => {
                    match b {
                        b'.' => self.state = State::Dot,
                        b'\r' => self.state = State::LineCr,
                        _ => {
                            self.scratch.push(b);
                            self.state = State::InLine;
                        }
                    }
                    return None;
                }
                State::Dot => match b {
                    b'\r' => {
                        self.state = State::DotCr;
                        return None;
                    }
                    b'.' => {
                        // A stuffed dot: the line begins with this one.
                        self.scratch.push(b'.');
                        self.state = State::InLine;
                        return None;
                    }
                    _ => {
                        // A single leading dot is kept as it is.
                        self.scratch.push(b'.');
                        self.scratch.push(b);
                        self.state = State::InLine;
                        return None;
                    }
                },
                State::DotCr => {
                    if b == b'\n' {
                        self.state = State::Idle;
                        self.block = false;
                        return Some(ReplyEvent::BlockEnd);
                    }
                    // ".\r" and more: the dot and the CR are the line.
                    self.scratch.push(b'.');
                    self.state = State::LineCr;
                    continue;
                }
                State::InLine => {
                    // Only a CR gets here (a run takes the rest).
                    self.state = State::LineCr;
                    return None;
                }
                State::LineCr => {
                    if b == b'\n' {
                        // (`Idle` clears the scratch for the next line, and
                        // goes on in block mode until the block ends.)
                        self.state = State::Idle;
                        return Some(ReplyEvent::Line);
                    }
                    self.scratch.push(b'\r');
                    if b == b'\r' {
                        return None;
                    }
                    self.scratch.push(b);
                    self.state = State::InLine;
                    return None;
                }
            }
        }
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

    use hopf_core::LoopBuf;

    /// Feeds `wire` in chunks of `chunk` through a ring of `ring` bytes,
    /// collecting what the lexer reports; `blocks` says, for each status
    /// event in turn, whether a block follows it.
    fn lex(wire: &[u8], chunk: usize, ring: usize, blocks: &[bool]) -> Vec<String> {
        let mut lexer = NntpReplyLexer::default();
        let mut buf = LoopBuf::with_capacity(ring);
        let mut out = Vec::new();
        let mut statuses = 0;
        let mut rest = wire;
        loop {
            match lexer.next_event(&mut buf) {
                ReplyEvent::NeedMore => {
                    if rest.is_empty() {
                        break;
                    }
                    let n = buf.extend_from_slice(&rest[..chunk.min(rest.len())]);
                    rest = &rest[n..];
                }
                ReplyEvent::Status(s) => {
                    out.push(format!("S{} {}", s.code, s.text));
                    lexer.expect_block(blocks.get(statuses).copied().unwrap_or(false));
                    statuses += 1;
                }
                ReplyEvent::Line => out.push(format!("L{}", String::from_utf8_lossy(lexer.line()))),
                ReplyEvent::BlockEnd => out.push("E".to_string()),
                ReplyEvent::Malformed => out.push(format!("M{}", String::from_utf8_lossy(&lexer.take_malformed()))),
                ReplyEvent::TooLong => {
                    out.push("TOOLONG".to_string());
                    break;
                }
            }
        }
        out
    }

    #[test]
    fn status_and_block_are_read_the_same_under_every_chunking() {
        let wire = b"200 ready\r\n215 list\r\nalt.a 3 1 y\r\n..dot\r\n.keep\r\n\r\nlast\r\n.\r\n281 ok\r\n";
        let want = vec![
            "S200 ready",
            "S215 list",
            "Lalt.a 3 1 y",
            "L.dot",
            "L.keep",
            "L",
            "Llast",
            "E",
            "S281 ok",
        ];
        for chunk in [1, 2, 3, 5, 7, 11, 100] {
            assert_eq!(lex(wire, chunk, 64, &[false, true]), want, "chunk={chunk}");
        }
    }

    #[test]
    fn a_status_without_text_or_with_leading_spaces() {
        assert_eq!(lex(b"381\r\n200   hi\r\n", 3, 32, &[]), vec!["S381 ", "S200 hi"]);
    }

    #[test]
    fn a_lone_cr_or_lf_is_part_of_the_text_and_of_block_lines() {
        assert_eq!(lex(b"211 a\rb\nc\r\n", 1, 32, &[]), vec!["S211 a\rb\nc"]);
        assert_eq!(lex(b"215 x\r\na\rb\r\n.\rZ\r\n.\r\n", 2, 32, &[true]), vec!["S215 x", "La\rb", "L.\rZ", "E"]);
    }

    #[test]
    fn a_line_that_is_not_a_status_is_reported_with_what_there_was_of_it() {
        assert_eq!(lex(b"hello\r\n", 2, 32, &[]), vec!["Mhello"]);
        assert_eq!(lex(b"20\r\n", 5, 32, &[]), vec!["M20"]);
        assert_eq!(lex(b"200 ok\r\nx\r\n", 4, 32, &[]), vec!["S200 ok", "Mx"]);
    }

    #[test]
    fn a_line_over_the_limit_is_too_long() {
        let mut wire = b"200 ".to_vec();
        wire.extend(vec![b'x'; MAX_REPLY_LINE + 10]);
        wire.extend_from_slice(b"\r\n");
        assert_eq!(lex(&wire, 4096, 8192, &[]), vec!["TOOLONG"]);
        let mut block = b"215 l\r\n".to_vec();
        block.extend(vec![b'y'; MAX_REPLY_LINE + 10]);
        block.extend_from_slice(b"\r\n.\r\n");
        assert_eq!(lex(&block, 4096, 8192, &[true]), vec!["S215 l", "TOOLONG"]);
    }

    #[test]
    fn reads_across_the_wrap_of_the_ring() {
        let wire = b"215 l\r\nabc\r\n.\r\n";
        for lead in 0..10 {
            let mut lexer = NntpReplyLexer::default();
            let mut buf = LoopBuf::with_capacity(16);
            buf.extend_from_slice(&vec![0u8; lead]);
            buf.advance(lead);
            assert_eq!(buf.extend_from_slice(wire), wire.len());
            let mut got = Vec::new();
            loop {
                match lexer.next_event(&mut buf) {
                    ReplyEvent::Status(s) => {
                        got.push(format!("S{}", s.code));
                        lexer.expect_block(true);
                    }
                    ReplyEvent::Line => got.push(String::from_utf8_lossy(lexer.line()).into_owned()),
                    ReplyEvent::BlockEnd => got.push("E".into()),
                    _ => break,
                }
            }
            assert_eq!(got, vec!["S215", "abc", "E"], "lead={lead}");
            assert!(buf.is_empty());
        }
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
