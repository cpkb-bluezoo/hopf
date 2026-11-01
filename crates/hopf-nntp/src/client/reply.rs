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

/// The longest status line, or line of a structured block (not article
/// text, which is streamed), the lexer will accept; past it the reply is a
/// protocol error.
pub(crate) const MAX_REPLY_LINE: usize = 64 * 1024;

/// The shape of a multi-line block, which decides what its lines become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Block {
    /// Short text lines, one event each (`CAPABILITIES`).
    Lines,
    /// Article text: passed on as it arrives, dot-unstuffed, line ends
    /// kept, without regard to where lines begin or end.
    Raw,
    /// `LIST ACTIVE`, `NEWGROUPS`: `name high low status` per line.
    Newsgroups,
    /// `OVER`: the tab-separated overview fields per line.
    Overview,
}

/// What the lexer found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplyEvent {
    /// More bytes are needed.
    NeedMore,
    /// A status line: its three-digit code and the text after it.
    Status(NntpStatus),
    /// A `211` status whose text is `count first last group`.
    Group(NntpStatus, GroupResult),
    /// A `220`..`223` status whose text is `number message-id`.
    Article(NntpStatus, ArticleRef),
    /// A line of a [`Block::Lines`] block, without its CRLF; read it with
    /// [`NntpReplyLexer::line`] until the next call.
    Line,
    /// Some of a [`Block::Raw`] block, dot-unstuffed; read it with
    /// [`NntpReplyLexer::content`] until the next call.
    Content,
    /// A line of a [`Block::Newsgroups`] block.
    Newsgroup(NewsgroupEntry),
    /// A line of a [`Block::Overview`] block.
    Overview(OverviewEntry),
    /// A line of a structured block that is not a valid entry; skipped.
    BadEntry,
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

// ── Fields ────────────────────────────────────────────────────────────────────

/// What a field of a structured line is read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Digits; anything else spoils the line.
    Num,
    /// Digits; anything else is a 0.
    LenientNum,
    Str,
}

#[derive(Debug)]
enum Value {
    Num(u64),
    Str(String),
}

const NEWSGROUP: &[Kind] = &[Kind::Str, Kind::Num, Kind::Num, Kind::Str];
const OVERVIEW: &[Kind] = &[
    Kind::Num,
    Kind::Str,
    Kind::Str,
    Kind::Str,
    Kind::Str,
    Kind::Str,
    Kind::LenientNum,
    Kind::LenientNum,
];
const GROUP: &[Kind] = &[Kind::Num, Kind::Num, Kind::Num, Kind::Str];
const ARTICLE: &[Kind] = &[Kind::Num, Kind::Str];

/// Reads the fields of one line a byte at a time: digits are summed as they
/// come, text is gathered into its own field, and what is past the last
/// field is passed over. Nothing keeps the line.
#[derive(Debug)]
struct Fields {
    spec: &'static [Kind],
    /// Fields are split at tabs, exactly; otherwise at runs of blanks.
    tab: bool,
    /// How many fields make a line.
    required: usize,
    index: usize,
    /// A field has begun (when splitting at blanks).
    open: bool,
    text: Vec<u8>,
    num: u64,
    digits: bool,
    bad: bool,
    /// A strict number was missing or malformed.
    broken: bool,
    values: Vec<Value>,
}

impl Fields {
    fn new() -> Self {
        Self {
            spec: &[],
            tab: false,
            required: 0,
            index: 0,
            open: false,
            text: Vec::new(),
            num: 0,
            digits: false,
            bad: false,
            broken: false,
            values: Vec::new(),
        }
    }

    fn start(&mut self, spec: &'static [Kind], tab: bool, required: usize) {
        self.spec = spec;
        self.tab = tab;
        self.required = required;
        self.index = 0;
        self.open = false;
        self.text.clear();
        self.reset_field();
        self.broken = false;
        self.values.clear();
    }

    fn reset_field(&mut self) {
        self.num = 0;
        self.digits = false;
        self.bad = false;
    }

    fn feed(&mut self, b: u8) {
        let sep = if self.tab { b == b'\t' } else { b == b' ' || b == b'\t' };
        if sep {
            if self.tab || self.open {
                self.close();
            }
            return;
        }
        if self.index >= self.spec.len() {
            return;
        }
        self.open = true;
        match self.spec[self.index] {
            Kind::Num | Kind::LenientNum => {
                if b.is_ascii_digit() {
                    self.digits = true;
                    match self.num.checked_mul(10).and_then(|n| n.checked_add(u64::from(b - b'0'))) {
                        Some(n) => self.num = n,
                        None => self.bad = true,
                    }
                } else if !(self.tab && b == b' ') {
                    // (Blanks around a number between tabs are not part of it.)
                    self.bad = true;
                }
            }
            Kind::Str => self.text.push(b),
        }
    }

    fn close(&mut self) {
        self.open = false;
        if self.index >= self.spec.len() {
            return;
        }
        let value = match self.spec[self.index] {
            Kind::Num => {
                if self.bad || !self.digits {
                    self.broken = true;
                }
                Value::Num(self.num)
            }
            Kind::LenientNum => Value::Num(if self.bad || !self.digits { 0 } else { self.num }),
            Kind::Str => Value::Str(String::from_utf8_lossy(&std::mem::take(&mut self.text)).into_owned()),
        };
        self.values.push(value);
        self.index += 1;
        self.reset_field();
    }

    /// The end of the line: whether it had the fields it needs.
    fn finish(&mut self) -> bool {
        if self.tab || self.open {
            self.close();
        }
        !self.broken && self.values.len() >= self.required
    }

    fn num_at(&self, i: usize) -> u64 {
        match self.values.get(i) {
            Some(Value::Num(n)) => *n,
            _ => 0,
        }
    }

    fn string_at(&mut self, i: usize) -> String {
        match self.values.get_mut(i) {
            Some(Value::Str(s)) => std::mem::take(s),
            _ => String::new(),
        }
    }

    fn newsgroup(&mut self) -> NewsgroupEntry {
        let status = self.string_at(3).chars().next().unwrap_or('y');
        NewsgroupEntry { name: self.string_at(0), high: self.num_at(1), low: self.num_at(2), status }
    }

    fn overview(&mut self) -> OverviewEntry {
        OverviewEntry {
            article_number: self.num_at(0),
            subject: self.string_at(1),
            from: self.string_at(2),
            date: self.string_at(3),
            message_id: self.string_at(4),
            references: self.string_at(5),
            bytes: self.num_at(6),
            lines: self.num_at(7),
        }
    }

    fn group(&mut self) -> GroupResult {
        GroupResult { count: self.num_at(0), first: self.num_at(1), last: self.num_at(2), name: self.string_at(3) }
    }

    fn article(&mut self) -> ArticleRef {
        ArticleRef { number: self.num_at(0), message_id: self.string_at(1) }
    }
}

/// A status whose text is read as fields while it arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Typed {
    Group,
    Article,
}

// ── Lexer ─────────────────────────────────────────────────────────────────────

/// Incremental NNTP reply parser (RFC 3977 §3): status lines and
/// multi-line blocks, read straight out of the connection's ring.
///
/// A status code is read digit by digit; the text of a `GROUP` or article
/// reply is read into its fields as it arrives. In a block, byte stuffing
/// and the `.` terminator are dealt with as the bytes arrive, and what the
/// block is (see [`Block`]) decides what comes out: article text as it
/// comes, with no line kept; a newsgroup or overview entry as soon as its
/// line ends, its fields already read. It stops after every event, so the
/// caller can say (with [`Self::expect_block`]) what comes next.
#[derive(Debug)]
pub(crate) struct NntpReplyLexer {
    state: State,
    /// A multi-line block of this shape is due at the next item.
    block: Option<Block>,
    /// The shape of the block being read.
    cur: Option<Block>,
    /// Status text, a `Lines` line, a chunk of article text, or the start of
    /// a bad line.
    scratch: Vec<u8>,
    code: u16,
    typed: Option<Typed>,
    fields: Fields,
    /// Bytes of the line so far (structured blocks).
    line_len: usize,
    /// The last event handed out `scratch`; it can go.
    chunk_out: bool,
    /// The block's end was reached while a chunk was due: report it next.
    end_pending: bool,
}

impl Default for NntpReplyLexer {
    fn default() -> Self {
        Self {
            state: State::Idle,
            block: None,
            cur: None,
            scratch: Vec::new(),
            code: 0,
            typed: None,
            fields: Fields::new(),
            line_len: 0,
            chunk_out: false,
            end_pending: false,
        }
    }
}

impl NntpReplyLexer {
    /// Whether the next item is a multi-line block (of this shape, until a
    /// lone `.`) or a status line. Takes effect at the start of the next item.
    pub fn expect_block(&mut self, block: Option<Block>) {
        self.block = block;
    }

    /// The block line [`ReplyEvent::Line`] reported.
    pub fn line(&self) -> &[u8] {
        &self.scratch
    }

    /// The article text [`ReplyEvent::Content`] reported.
    pub fn content(&self) -> &[u8] {
        &self.scratch
    }

    /// The start of the line [`ReplyEvent::Malformed`] reported.
    pub fn take_malformed(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.scratch)
    }

    /// Reads from `buf` up to the next event, consuming what it reads.
    pub fn next_event(&mut self, buf: &mut hopf_core::LoopBuf) -> ReplyEvent {
        if self.chunk_out {
            self.scratch.clear();
            self.chunk_out = false;
        }
        if self.end_pending {
            self.end_pending = false;
            return ReplyEvent::BlockEnd;
        }
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
            // What article text there is goes on now, not when a line ends.
            if self.cur == Some(Block::Raw) && !self.scratch.is_empty() {
                self.chunk_out = true;
                return ReplyEvent::Content;
            }
        }
    }

    /// Reads from `data` up to the next event; returns how much it used.
    fn scan(&mut self, data: &[u8]) -> (usize, Option<ReplyEvent>) {
        let mut i = 0;
        while i < data.len() {
            // Inside a line, take everything up to the next CR in one go.
            if matches!(self.state, State::InLine | State::Text | State::Bad) {
                let run = data[i..].iter().position(|&c| c == b'\r').unwrap_or(data.len() - i);
                if run > 0 {
                    let bytes = &data[i..i + run];
                    match self.state {
                        State::InLine => self.put_run(bytes),
                        State::Text => self.text_run(bytes),
                        _ => self.scratch.extend_from_slice(bytes),
                    }
                    i += run;
                    if self.too_long() {
                        self.reset();
                        return (i, Some(ReplyEvent::TooLong));
                    }
                    continue;
                }
            }
            let b = data[i];
            i += 1;
            if let Some(event) = self.step(b) {
                return (i, Some(event));
            }
            if self.too_long() {
                self.reset();
                return (i, Some(ReplyEvent::TooLong));
            }
        }
        (i, None)
    }

    fn too_long(&self) -> bool {
        match self.cur {
            Some(Block::Raw) => false,
            Some(_) => self.line_len > MAX_REPLY_LINE,
            None => self.scratch.len() > MAX_REPLY_LINE,
        }
    }

    fn reset(&mut self) {
        self.state = State::Idle;
        self.scratch.clear();
    }

    /// A byte of the current block line.
    fn put(&mut self, b: u8) {
        match self.cur {
            Some(Block::Newsgroups | Block::Overview) => self.fields.feed(b),
            _ => self.scratch.push(b),
        }
        self.line_len += 1;
    }

    fn put_run(&mut self, bytes: &[u8]) {
        match self.cur {
            Some(Block::Newsgroups | Block::Overview) => bytes.iter().for_each(|&b| self.fields.feed(b)),
            _ => self.scratch.extend_from_slice(bytes),
        }
        self.line_len += bytes.len();
    }

    /// Some text of a status line.
    fn text_run(&mut self, bytes: &[u8]) {
        self.scratch.extend_from_slice(bytes);
        if self.typed.is_some() {
            bytes.iter().for_each(|&b| self.fields.feed(b));
        }
    }

    fn text_byte(&mut self, b: u8) {
        self.scratch.push(b);
        if self.typed.is_some() {
            self.fields.feed(b);
        }
    }

    /// The CRLF of a block line.
    fn line_end(&mut self) -> Option<ReplyEvent> {
        match self.cur {
            Some(Block::Raw) => {
                self.scratch.extend_from_slice(b"\r\n");
                self.state = State::LineStart;
                None
            }
            Some(Block::Newsgroups) => {
                self.state = State::Idle;
                Some(if self.fields.finish() { ReplyEvent::Newsgroup(self.fields.newsgroup()) } else { ReplyEvent::BadEntry })
            }
            Some(Block::Overview) => {
                self.state = State::Idle;
                Some(if self.fields.finish() { ReplyEvent::Overview(self.fields.overview()) } else { ReplyEvent::BadEntry })
            }
            Some(Block::Lines) | None => {
                self.state = State::Idle;
                Some(ReplyEvent::Line)
            }
        }
    }

    fn step(&mut self, b: u8) -> Option<ReplyEvent> {
        loop {
            match self.state {
                State::Idle => {
                    self.scratch.clear();
                    self.line_len = 0;
                    self.cur = self.block;
                    self.state = match self.block {
                        Some(shape) => {
                            match shape {
                                Block::Newsgroups => self.fields.start(NEWSGROUP, false, 3),
                                Block::Overview => self.fields.start(OVERVIEW, true, 8),
                                Block::Lines | Block::Raw => {}
                            }
                            State::LineStart
                        }
                        None => State::Digits { seen: 0, code: 0 },
                    };
                    continue;
                }
                State::Digits { seen, code } => {
                    if b.is_ascii_digit() {
                        let code = code * 10 + u16::from(b - b'0');
                        if seen == 2 {
                            self.code = code;
                            self.typed = match code {
                                211 => Some(Typed::Group),
                                220..=223 => Some(Typed::Article),
                                _ => None,
                            };
                            match self.typed {
                                Some(Typed::Group) => self.fields.start(GROUP, false, 4),
                                Some(Typed::Article) => self.fields.start(ARTICLE, false, 2),
                                None => {}
                            }
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
                        let typed = self.typed.take();
                        let event = match typed {
                            Some(Typed::Group) if self.fields.finish() => ReplyEvent::Group(status, self.fields.group()),
                            Some(Typed::Article) if self.fields.finish() => ReplyEvent::Article(status, self.fields.article()),
                            _ => ReplyEvent::Status(status),
                        };
                        self.reset();
                        return Some(event);
                    }
                    // A lone CR is part of the text.
                    self.text_byte(b'\r');
                    if b == b'\r' {
                        return None; // still possibly the CR of the CRLF
                    }
                    self.text_byte(b);
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
                            self.put(b);
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
                        self.put(b'.');
                        self.state = State::InLine;
                        return None;
                    }
                    _ => {
                        // A single leading dot is kept as it is.
                        self.put(b'.');
                        self.put(b);
                        self.state = State::InLine;
                        return None;
                    }
                },
                State::DotCr => {
                    if b == b'\n' {
                        self.state = State::Idle;
                        self.block = None;
                        let raw = self.cur == Some(Block::Raw);
                        self.cur = None;
                        if raw && !self.scratch.is_empty() {
                            // What came before goes on first.
                            self.chunk_out = true;
                            self.end_pending = true;
                            return Some(ReplyEvent::Content);
                        }
                        return Some(ReplyEvent::BlockEnd);
                    }
                    // ".\r" and more: the dot and the CR are the line.
                    self.put(b'.');
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
                        return self.line_end();
                    }
                    self.put(b'\r');
                    if b == b'\r' {
                        return None;
                    }
                    self.put(b);
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

/// The article a `22x` reply names: `number message-id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArticleRef {
    /// `0` when the article was asked for by message-id.
    pub number: u64,
    pub message_id: String,
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
    use hopf_core::LoopBuf;

    #[test]
    fn status_lines() {
        assert_eq!(parse_status("200 server ready"), Some(NntpStatus { code: 200, text: "server ready".into() }));
        assert_eq!(parse_status("381"), Some(NntpStatus { code: 381, text: String::new() }));
        assert_eq!(parse_status("hello"), None);
        assert_eq!(parse_status("20"), None);
    }

    /// Feeds `wire` in chunks of `chunk` through a ring of `ring` bytes,
    /// collecting what the lexer reports; `blocks` says, for each status
    /// event in turn, what block follows it. Consecutive pieces of article
    /// text are one `C` (how it is cut up is up to the connection).
    fn lex(wire: &[u8], chunk: usize, ring: usize, blocks: &[Option<Block>]) -> Vec<String> {
        let mut lexer = NntpReplyLexer::default();
        let mut buf = LoopBuf::with_capacity(ring);
        let mut out: Vec<String> = Vec::new();
        let mut statuses = 0;
        let mut rest = wire;
        let mut next = |lexer: &mut NntpReplyLexer| {
            lexer.expect_block(blocks.get(statuses).copied().flatten());
            statuses += 1;
        };
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
                    next(&mut lexer);
                }
                ReplyEvent::Group(s, g) => {
                    out.push(format!("G{} {} {} {} {} | {}", s.code, g.count, g.first, g.last, g.name, s.text));
                    next(&mut lexer);
                }
                ReplyEvent::Article(s, a) => {
                    out.push(format!("A{} {} {}", s.code, a.number, a.message_id));
                    next(&mut lexer);
                }
                ReplyEvent::Line => out.push(format!("L{}", String::from_utf8_lossy(lexer.line()))),
                ReplyEvent::Content => {
                    let text = String::from_utf8_lossy(lexer.content()).into_owned();
                    match out.last_mut() {
                        Some(last) if last.starts_with('C') => last.push_str(&text),
                        _ => out.push(format!("C{text}")),
                    }
                }
                ReplyEvent::Newsgroup(e) => out.push(format!("N{} {} {} {}", e.name, e.high, e.low, e.status)),
                ReplyEvent::Overview(e) => {
                    out.push(format!("O{}|{}|{}|{}|{}|{}|{}|{}", e.article_number, e.subject, e.from, e.date, e.message_id, e.references, e.bytes, e.lines))
                }
                ReplyEvent::BadEntry => out.push("B".to_string()),
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

    const CHUNKS: [usize; 8] = [1, 2, 3, 5, 7, 11, 64, 1000];

    #[test]
    fn status_and_lines_block_are_read_the_same_under_every_chunking() {
        let wire = b"200 ready\r\n101 list\r\nVERSION 2\r\n..dot\r\n.keep\r\n\r\nlast\r\n.\r\n281 ok\r\n";
        let want = vec!["S200 ready", "S101 list", "LVERSION 2", "L.dot", "L.keep", "L", "Llast", "E", "S281 ok"];
        for chunk in CHUNKS {
            assert_eq!(lex(wire, chunk, 64, &[None, Some(Block::Lines)]), want, "chunk={chunk}");
        }
    }

    #[test]
    fn a_status_without_text_or_with_leading_spaces() {
        assert_eq!(lex(b"381\r\n200   hi\r\n", 3, 32, &[]), vec!["S381 ", "S200 hi"]);
    }

    #[test]
    fn a_group_status_is_read_into_its_fields_as_it_arrives() {
        let wire = b"211 1234 3000234 3002322 misc.test list follows\r\n211  5  10 14   comp.lang.rust\r\n";
        let want = vec![
            "G211 1234 3000234 3002322 misc.test | 1234 3000234 3002322 misc.test list follows",
            "G211 5 10 14 comp.lang.rust | 5  10 14   comp.lang.rust",
        ];
        for chunk in CHUNKS {
            assert_eq!(lex(wire, chunk, 64, &[]), want, "chunk={chunk}");
        }
    }

    #[test]
    fn a_group_status_that_is_not_that_stays_a_status() {
        for text in ["211 only text\r\n", "211 1 2\r\n", "211 1 2 x grp\r\n", "211\r\n", "211 99999999999999999999 1 2 g\r\n"] {
            let got = lex(text.as_bytes(), 4, 64, &[]);
            assert!(got[0].starts_with("S211"), "{text:?}: {got:?}");
        }
    }

    #[test]
    fn an_article_status_is_read_into_its_fields() {
        let wire = b"223 3000234 <45223423@example.com>\r\n220 0 <i.am.a.message-id@example.com> article follows\r\n221 12\r\n";
        for chunk in CHUNKS {
            assert_eq!(
                lex(wire, chunk, 64, &[None, None, None]),
                vec!["A223 3000234 <45223423@example.com>", "A220 0 <i.am.a.message-id@example.com>", "S221 12"],
                "chunk={chunk}"
            );
        }
    }

    #[test]
    fn article_text_comes_as_it_arrives_with_nothing_held_but_a_terminator() {
        let wire = b"220 1 <a@b>\r\nFrom: x\r\n\r\n..dot\r\n.x\r\nbare\rcr\r\n\r\n.\r\n200 next\r\n";
        let want = vec!["A220 1 <a@b>", "CFrom: x\r\n\r\n.dot\r\n.x\r\nbare\rcr\r\n\r\n", "E", "S200 next"];
        for chunk in CHUNKS {
            assert_eq!(lex(wire, chunk, 64, &[Some(Block::Raw)]), want, "chunk={chunk}");
        }
    }

    #[test]
    fn article_text_is_passed_on_before_its_line_ends() {
        let mut lexer = NntpReplyLexer::default();
        let mut buf = LoopBuf::with_capacity(64);
        lexer.expect_block(Some(Block::Raw));
        buf.extend_from_slice(b"par");
        assert_eq!(lexer.next_event(&mut buf), ReplyEvent::Content);
        assert_eq!(lexer.content(), b"par");
        buf.extend_from_slice(b"tial\r");
        assert_eq!(lexer.next_event(&mut buf), ReplyEvent::Content);
        assert_eq!(lexer.content(), b"tial");
        buf.extend_from_slice(b"\n.\r\n");
        assert_eq!(lexer.next_event(&mut buf), ReplyEvent::Content);
        assert_eq!(lexer.content(), b"\r\n");
        assert_eq!(lexer.next_event(&mut buf), ReplyEvent::BlockEnd);
    }

    #[test]
    fn article_text_has_no_limit_on_the_length_of_a_line() {
        let mut wire = b"220 1 <a@b>\r\n".to_vec();
        wire.extend(vec![b'y'; MAX_REPLY_LINE * 3]);
        wire.extend_from_slice(b"\r\n.\r\n");
        let got = lex(&wire, 4096, 8192, &[Some(Block::Raw)]);
        assert_eq!(got.len(), 3, "{}", got.len());
        assert_eq!(got[1].len(), 1 + MAX_REPLY_LINE * 3 + 2);
        assert_eq!(got[2], "E");
    }

    #[test]
    fn newsgroup_lines_are_read_into_entries() {
        let wire = b"215 list\r\ncomp.lang.rust 1234 12 y\r\nalt.a   3\t1   m  extra\r\n..odd 5 4 n\r\nbad 1\r\nx 1 2\r\n.\r\n";
        let want = vec!["S215 list", "Ncomp.lang.rust 1234 12 y", "Nalt.a 3 1 m", "N.odd 5 4 n", "B", "Nx 1 2 y", "E"];
        for chunk in CHUNKS {
            assert_eq!(lex(wire, chunk, 64, &[Some(Block::Newsgroups)]), want, "chunk={chunk}");
        }
    }

    #[test]
    fn overview_lines_are_read_into_entries() {
        let wire = b"224 overview\r\n12\tSubj\tme <me@x>\tMon\t<id@x>\t<ref@x>\t100\t3\tXref: x\r\n\
                     13\t\t\t\t\t\t\t\r\n14\tshort\r\nnope\tS\tF\tD\t<i>\t\t1\t2\r\n15 \t S \tF\tD\t<i>\t\t:bytes\t 7 \r\n.\r\n";
        let want = vec![
            "S224 overview",
            "O12|Subj|me <me@x>|Mon|<id@x>|<ref@x>|100|3",
            "O13||||||0|0",
            "B",
            "B",
            "O15| S |F|D|<i>||0|7",
            "E",
        ];
        for chunk in CHUNKS {
            assert_eq!(lex(wire, chunk, 64, &[Some(Block::Overview)]), want, "chunk={chunk}");
        }
    }

    /// The text parsers are the oracles: the lexer reads the same entries.
    #[test]
    fn entries_agree_with_the_text_parsers() {
        let newsgroups = [
            "comp.lang.rust 1234 12 y",
            "a 1 2",
            "a 1",
            "a",
            "a  1   2   m   tail",
            "a\t1\t2\tn",
            "a 1 x y",
            "a 99999999999999999999 2 y",
            "a -1 2 y",
            "a 1 2 \u{e9}",
            "  lead 1 2 y",
        ];
        for line in newsgroups {
            let wire = format!("215 l\r\n{line}\r\n.\r\n");
            let got = lex(wire.as_bytes(), 3, 64, &[Some(Block::Newsgroups)]);
            let want = match parse_newsgroup_line(line) {
                Some(e) => format!("N{} {} {} {}", e.name, e.high, e.low, e.status),
                None => "B".to_string(),
            };
            assert_eq!(got[1], want, "{line:?}");
        }
        let overviews = [
            "12\tSubj\tme\tMon\t<id>\t<ref>\t100\t3",
            "12\tSubj\tme\tMon\t<id>\t<ref>\t100\t3\textra\tmore",
            "12\tSubj\tme\tMon\t<id>\t<ref>\t100",
            "x\tSubj\tme\tMon\t<id>\t<ref>\t100\t3",
            "12\tSubj\tme\tMon\t<id>\t<ref>\tn/a\t",
            " 12 \tS\tF\tD\t<i>\t\t 5 \t 6 ",
            "12\t\t\t\t\t\t\t",
            "",
        ];
        for line in overviews {
            let wire = format!("224 o\r\n{line}\r\n.\r\n");
            let got = lex(wire.as_bytes(), 5, 64, &[Some(Block::Overview)]);
            let want = match parse_overview_line(line) {
                Some(e) => format!("O{}|{}|{}|{}|{}|{}|{}|{}", e.article_number, e.subject, e.from, e.date, e.message_id, e.references, e.bytes, e.lines),
                None => "B".to_string(),
            };
            assert_eq!(got[1], want, "{line:?}");
        }
        for text in ["5 10 14 comp.lang.rust", "5 10 14 g and more", "5 10 14", "a 1 2 g", "5  10\t14 g"] {
            let wire = format!("211 {text}\r\n");
            let got = lex(wire.as_bytes(), 2, 64, &[]);
            match parse_group_response(text) {
                Some(g) => assert!(got[0].starts_with(&format!("G211 {} {} {} {}", g.count, g.first, g.last, g.name)), "{text:?}: {got:?}"),
                None => assert!(got[0].starts_with("S211"), "{text:?}: {got:?}"),
            }
        }
    }

    #[test]
    fn a_lone_cr_or_lf_is_part_of_the_text_and_of_block_lines() {
        assert_eq!(lex(b"213 a\rb\nc\r\n", 1, 32, &[]), vec!["S213 a\rb\nc"]);
        assert_eq!(lex(b"101 x\r\na\rb\r\n.\rZ\r\n.\r\n", 2, 32, &[Some(Block::Lines)]), vec!["S101 x", "La\rb", "L.\rZ", "E"]);
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
        for shape in [Block::Lines, Block::Newsgroups, Block::Overview] {
            let mut block = b"215 l\r\n".to_vec();
            block.extend(vec![b'y'; MAX_REPLY_LINE + 10]);
            block.extend_from_slice(b"\r\n.\r\n");
            assert_eq!(lex(&block, 4096, 8192, &[Some(shape)]), vec!["S215 l", "TOOLONG"], "{shape:?}");
        }
    }

    #[test]
    fn reads_across_the_wrap_of_the_ring() {
        let wire = b"215 l\r\nabc 3 1 y\r\n.\r\n";
        for lead in 0..10 {
            let mut lexer = NntpReplyLexer::default();
            let mut buf = LoopBuf::with_capacity(24);
            buf.extend_from_slice(&vec![0u8; lead]);
            buf.advance(lead);
            assert_eq!(buf.extend_from_slice(wire), wire.len());
            let mut got = Vec::new();
            loop {
                match lexer.next_event(&mut buf) {
                    ReplyEvent::Status(s) => {
                        got.push(format!("S{}", s.code));
                        lexer.expect_block(Some(Block::Newsgroups));
                    }
                    ReplyEvent::Newsgroup(e) => got.push(e.name),
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
