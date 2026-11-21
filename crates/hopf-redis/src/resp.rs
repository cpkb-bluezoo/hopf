// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RESP2 and RESP3: the command encoder, the incremental [`RespParser`] and the
//! events it produces ([`ReplySink`]), and the reply [`Value`] the crate's
//! callbacks still receive.
//!
//! The parser is push-fed, event-driven and holds none of the stream.
//! [`RespParser::feed`] is given whatever bytes have arrived, in any split, and
//! tells a [`ReplySink`] what they hold: a scalar, the start of an aggregate,
//! the start of a string, the string's payload as chunks that borrow from the
//! bytes it was given, the end of each. A payload is never copied or collected,
//! whatever its size. All the parser keeps is a header line that is not yet
//! finished (at most [`RespLimits::max_line`] bytes), a small explicit stack of
//! counts for the aggregates that are open (at most [`RespLimits::max_depth`]),
//! and a few counters. There is no recursion, so nesting depth is a limit and not
//! a stack overflow, and no size a server announces makes it reserve memory.
//!
//! A sink steers the parser with the [`Flow`] it returns: [`Flow::Pause`] stops
//! it after the event, leaving the unconsumed bytes with the caller;
//! [`Flow::Skip`] discards the rest of that reply as it arrives, in constant
//! memory, bounded by [`RespLimits::max_skip`]. RESP3 streamed strings and
//! aggregates have no announced length and are events like any other; attributes
//! are read and dropped.
//!
//! [`Value`] is a reply assembled whole, for the callbacks that take one. It is
//! built outside the parser, from the events, under [`RespLimits::max_bulk`] and
//! [`RespLimits::max_reply_bytes`]: a string announced as longer than the limit
//! is not buffered, not even its first chunk.

use hopf_core::Bytes;

/// An error a server sent in place of a reply, split into the upper-case code
/// word it starts with (`ERR`, `WRONGTYPE`, `MOVED`, ...) and the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerError {
    /// The leading code word, for example `WRONGTYPE`. Empty if the message
    /// has no upper-case first word.
    pub code: String,
    /// The text after the code.
    pub message: String,
}

impl ServerError {
    /// Split a server's error line (without the leading `-`).
    pub fn parse(line: &str) -> Self {
        match line.split_once(' ') {
            Some((code, rest)) if is_code(code) => Self {
                code: code.to_string(),
                message: rest.to_string(),
            },
            None if is_code(line) => Self {
                code: line.to_string(),
                message: String::new(),
            },
            _ => Self {
                code: String::new(),
                message: line.to_string(),
            },
        }
    }
}

fn is_code(word: &str) -> bool {
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code.is_empty() {
            f.write_str(&self.message)
        } else if self.message.is_empty() {
            f.write_str(&self.code)
        } else {
            write!(f, "{} {}", self.code, self.message)
        }
    }
}

/// One reply. RESP2 replies use `Null`, `Int`, `Simple`, `Bulk`, `Array` and
/// `Error`; the rest are RESP3.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Nil: a missing key, or a timed-out blocking command.
    Null,
    /// An integer.
    Int(i64),
    /// A simple string, such as `OK`.
    Simple(String),
    /// A bulk string: arbitrary bytes.
    Bulk(Bytes),
    /// An array.
    Array(Vec<Value>),
    /// A map (RESP3), in the order the server sent it.
    Map(Vec<(Value, Value)>),
    /// A set (RESP3).
    Set(Vec<Value>),
    /// A double (RESP3).
    Double(f64),
    /// A boolean (RESP3).
    Bool(bool),
    /// A number too large for `i64` (RESP3), as its decimal digits.
    BigNumber(String),
    /// A string with a three-letter format tag, such as `txt` or `mkd`
    /// (RESP3).
    Verbatim {
        /// The format tag.
        format: String,
        /// The text.
        data: Bytes,
    },
    /// An error, as an element of an aggregate (for example the result of one
    /// command in a transaction). A reply that is an error as a whole is
    /// reported as [`RedisError::Server`](crate::RedisError::Server) instead.
    Error(ServerError),
    /// Out-of-band data the server pushed (RESP3): the first element names the
    /// kind (`message`, `invalidate`, ...).
    Push(Vec<Value>),
}

impl Value {
    /// Whether this is `Null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The bytes of a bulk, simple or verbatim string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bulk(b) => Some(b),
            Value::Simple(s) => Some(s.as_bytes()),
            Value::Verbatim { data, .. } => Some(data),
            _ => None,
        }
    }

    /// A bulk, simple or verbatim string as text, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    /// An integer, or a string or double that is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            Value::Double(d) if d.fract() == 0.0 && d.is_finite() => Some(*d as i64),
            Value::BigNumber(s) => s.parse().ok(),
            other => other.as_str().and_then(|s| s.parse().ok()),
        }
    }

    /// A double, or an integer or string that is one.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Double(d) => Some(*d),
            Value::Int(n) => Some(*n as f64),
            other => other.as_str().and_then(|s| s.parse().ok()),
        }
    }

    /// The elements of an array, set or push.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(v) | Value::Set(v) | Value::Push(v) => Some(v),
            _ => None,
        }
    }

    /// Take the elements of an array, set or push.
    pub fn into_array(self) -> Option<Vec<Value>> {
        match self {
            Value::Array(v) | Value::Set(v) | Value::Push(v) => Some(v),
            _ => None,
        }
    }

    /// A map as pairs. A flat RESP2 array of alternating keys and values (as
    /// `HGETALL` returns) is read as one.
    pub fn into_pairs(self) -> Option<Vec<(Value, Value)>> {
        match self {
            Value::Map(m) => Some(m),
            Value::Array(v) if v.len() % 2 == 0 => {
                let mut it = v.into_iter();
                let mut out = Vec::new();
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    out.push((k, v));
                }
                Some(out)
            }
            _ => None,
        }
    }
}

/// Append `args` to `out` as one command: an array of bulk strings, the form
/// every Redis server accepts (RESP2 and RESP3 alike).
pub fn encode_command(args: &[&[u8]], out: &mut Vec<u8>) {
    encode_words(args, out);
}

/// [`encode_command`] for any words: the crate's `Command` holds `Vec<u8>`s.
pub(crate) fn encode_words<T: AsRef<[u8]>>(args: &[T], out: &mut Vec<u8>) {
    // One growth to the exact size, however large an argument is, and no
    // allocation for the numbers.
    out.reserve_exact(encoded_len(args));
    out.push(b'*');
    push_decimal(args.len(), out);
    out.extend_from_slice(b"\r\n");
    for a in args {
        let a = a.as_ref();
        out.push(b'$');
        push_decimal(a.len(), out);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
}

/// How many bytes [`encode_command`] appends for `args`.
fn encoded_len<T: AsRef<[u8]>>(args: &[T]) -> usize {
    // `*<n>\r\n`, then `$<len>\r\n<bytes>\r\n` for each.
    3 + decimal_len(args.len())
        + args.iter().map(|a| 5 + decimal_len(a.as_ref().len()) + a.as_ref().len()).sum::<usize>()
}

fn decimal_len(mut n: usize) -> usize {
    let mut digits = 1;
    while n >= 10 {
        n /= 10;
        digits += 1;
    }
    digits
}

fn push_decimal(mut n: usize, out: &mut Vec<u8>) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}

/// Bounds on what a server may make the client hold.
///
/// The parser itself holds only `max_line`, `max_depth` and what it takes to
/// discard a reply (`max_skip`); the rest bound the crate's own assembly of a
/// whole [`Value`] for a command's callback, and go away with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RespLimits {
    /// The largest bulk string, verbatim string or bulk error assembled into a
    /// value. A longer one is not buffered, not even its first chunk: it is
    /// skipped, and its command fails.
    pub max_bulk: usize,
    /// The most elements one aggregate assembled into a value may announce.
    pub max_aggregate: usize,
    /// The most levels of aggregate inside aggregate.
    pub max_depth: usize,
    /// The longest header or simple-string line.
    pub max_line: usize,
    /// The most memory one reply assembled into a value may take, counting bulk
    /// payloads and a small overhead per element.
    pub max_reply_bytes: usize,
    /// The most bytes of one reply that may be discarded (a sink that chose
    /// [`Flow::Skip`], a reply nobody waits for, an attribute): past it the
    /// stream is abandoned and the connection should be closed, since
    /// reading on only to discard has a cost of its own.
    pub max_skip: usize,
}

impl Default for RespLimits {
    fn default() -> Self {
        Self {
            max_bulk: 512 * 1024 * 1024,
            max_aggregate: 1 << 26,
            max_depth: 32,
            max_line: 64 * 1024,
            max_reply_bytes: 1024 * 1024 * 1024,
            max_skip: 256 * 1024 * 1024,
        }
    }
}

/// Why the parser gave up. After one the stream cannot be trusted and the
/// connection should be closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespError(pub String);

impl std::fmt::Display for RespError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RespError {}

fn bad(msg: impl Into<String>) -> RespError {
    RespError(msg.into())
}

// ---- events ----

/// What a [`ReplySink`] tells the parser to do after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Go on.
    Continue,
    /// Stop after this event: [`RespParser::feed`] returns [`Feed::Paused`] with
    /// the bytes not yet consumed left in the caller's slice, and the caller
    /// stops reading until it is ready for more.
    Pause,
    /// The consumer wants no more of this reply: the rest of it is discarded
    /// as it arrives, in constant memory, and the sink hears nothing more of it
    /// but [`ReplySink::end_reply`] with `skipped` true.
    Skip,
}

/// Whether [`RespParser::feed`] consumed all it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feed {
    /// All of the data was consumed.
    Consumed,
    /// A sink asked for [`Flow::Pause`]: the unconsumed rest of the data is
    /// left in the caller's slice, to be fed again when it can take more.
    Paused,
}

/// A reply, or a push, as it begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// The reply to the command at the head of the queue.
    Normal,
    /// RESP3 out-of-band data (`>`), which belongs to no command.
    Push,
}

/// A value with nothing in it that grows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scalar<'a> {
    /// RESP2's null bulk or array, and RESP3's `_`.
    Null,
    /// `:`.
    Int(i64),
    /// `,`.
    Double(f64),
    /// `#`.
    Bool(bool),
    /// `(`, as its digits.
    BigNumber(&'a str),
    /// `+`.
    Simple(&'a str),
}

/// The kind of an aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggKind {
    /// `*`.
    Array,
    /// `~`.
    Set,
    /// `>`.
    Push,
    /// `%`; its length counts pairs.
    Map,
}

/// The kind of a length-prefixed string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrKind {
    /// `$`.
    Bulk,
    /// `=`: the three-letter format (`txt`, `mkd`), then the text.
    Verbatim {
        /// The format tag.
        format: [u8; 3],
    },
    /// `!`: an error too long for a line.
    Error,
}

/// What a reply is, event by event, as the parser reads it.
///
/// The events of one reply come between [`begin_reply`](Self::begin_reply) and
/// [`end_reply`](Self::end_reply). They borrow from the bytes the parser was
/// fed, so a payload is handed over without a copy and nothing is held. A
/// string arrives as [`begin_string`](Self::begin_string), any number of
/// [`string_chunk`](Self::string_chunk)s in order, then
/// [`end_string`](Self::end_string); an aggregate as
/// [`begin_aggregate`](Self::begin_aggregate), its elements, then
/// [`end_aggregate`](Self::end_aggregate). RESP3 attributes are read and
/// discarded by the parser and produce no events.
///
/// Every event that can start or continue data returns a [`Flow`]. A sink runs
/// on the connection's reactor and must not block: to wait for something, it
/// returns [`Flow::Pause`] and the caller resumes later.
pub trait ReplySink {
    /// A reply or push begins. Nothing is announced before its first event.
    fn begin_reply(&mut self, _kind: ReplyKind) {}
    /// A scalar.
    fn scalar(&mut self, v: Scalar<'_>) -> Flow;
    /// An error line (`-`), without the dash or the CRLF.
    fn error(&mut self, line: &str) -> Flow;
    /// An aggregate begins. `len` is its element count (pairs, for a map), or
    /// `None` for a RESP3 streamed aggregate, which an `end_aggregate` closes.
    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow;
    /// The aggregate opened last is complete.
    fn end_aggregate(&mut self) -> Flow;
    /// A string begins. `len` is its length in bytes (for a verbatim string,
    /// that of the text without its format tag), or `None` for a RESP3
    /// streamed string.
    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow;
    /// The next bytes of the string, never empty.
    fn string_chunk(&mut self, data: &[u8]) -> Flow;
    /// The string is complete.
    fn end_string(&mut self) -> Flow;
    /// The reply is complete, or has been discarded to its end (`skipped`).
    fn end_reply(&mut self, _skipped: bool) {}
}

// ---- the parser ----

/// Which kind of aggregate a frame of the stack is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Agg,
    /// RESP3 attributes: read and dropped; the value that follows is the reply.
    Attribute,
}

struct Frame {
    kind: Open,
    /// Elements still to come: twice the pair count for a map or attributes.
    /// Not used by a streamed aggregate, which an `.` line ends.
    remaining: usize,
    streamed: bool,
}

/// Which kind of length-prefixed string is being read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    Bulk,
    Error,
    Verbatim,
}

enum State {
    /// Expecting the type byte of the next value.
    Tag,
    /// Reading a header or simple-string line, up to CRLF.
    Line(u8),
    /// Reading the payload of a length-prefixed string.
    Payload { body: Body, remaining: usize },
    /// Expecting the CRLF after a payload; `seen_cr` once the CR is in.
    PayloadEnd { seen_cr: bool },
}

/// The incremental RESP parser. See the [module documentation](self).
pub struct RespParser {
    limits: RespLimits,
    state: State,
    /// The line being read, bounded by `max_line`.
    line: Vec<u8>,
    /// The aggregates open, innermost last: counts only, never elements.
    stack: Vec<Frame>,
    /// Attribute frames open: while there are any, events are not forwarded.
    muted: usize,
    /// `begin_reply` has been sent for the reply in progress.
    in_reply: bool,
    /// A sink chose [`Flow::Skip`] for the reply in progress.
    skipping: bool,
    /// Bytes discarded so far in the reply in progress.
    skipped: usize,
    /// A sink asked for a pause.
    paused: bool,
    failed: bool,
    /// Inside a RESP3 streamed string: a `;` chunk header comes next, or `;0`.
    streamed_string: bool,
    /// A verbatim string's four-byte head (`txt:`) being collected, and the
    /// length announced for the whole.
    vhead: [u8; 4],
    vhead_len: usize,
    vtotal: usize,
    /// Assembles `Value`s for [`feed_values`](Self::feed_values).
    values: Option<Box<crate::collect::Collector>>,
}

impl RespParser {
    /// A parser with the default [`RespLimits`].
    pub fn new() -> Self {
        Self::with_limits(RespLimits::default())
    }

    /// A parser with these limits.
    pub fn with_limits(limits: RespLimits) -> Self {
        Self {
            limits,
            state: State::Tag,
            line: Vec::new(),
            stack: Vec::new(),
            muted: 0,
            in_reply: false,
            skipping: false,
            skipped: 0,
            paused: false,
            failed: false,
            streamed_string: false,
            vhead: [0; 4],
            vhead_len: 0,
            vtotal: 0,
            values: None,
        }
    }

    /// Whether the parser is between replies: nothing of the next one has
    /// arrived.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Tag) && self.stack.is_empty() && !self.streamed_string
    }

    /// Consume `data`, telling `sink` what it holds.
    ///
    /// Always consumes all of `data` unless it returns [`Feed::Paused`] or an
    /// error, however it is split: `data` is advanced past what was consumed.
    /// What has not yet made a whole token (a header line) is kept inside the
    /// parser, and that is all it keeps.
    pub fn feed(&mut self, data: &mut &[u8], sink: &mut dyn ReplySink) -> Result<Feed, RespError> {
        if self.failed {
            return Err(bad("the stream is not valid RESP"));
        }
        let result = self.run(data, sink);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Transitional, and removed with [`Value`]: feed `data` and hand each
    /// reply, assembled whole under [`RespLimits`], to `sink`. A reply over a
    /// limit is an error here, and poisons the parser.
    #[doc(hidden)]
    pub fn feed_values(&mut self, data: &mut &[u8], sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        let mut collector = self.values.take().unwrap_or_else(|| Box::new(crate::collect::Collector::new(&self.limits)));
        let mut adapter = crate::collect::Adapter {
            collector: &mut *collector,
            out: sink,
            error: None,
        };
        let fed = self.feed(data, &mut adapter);
        let error = adapter.error.take();
        self.values = Some(collector);
        fed?;
        if let Some(e) = error {
            self.failed = true;
            return Err(e);
        }
        Ok(())
    }

    fn run(&mut self, data: &mut &[u8], sink: &mut dyn ReplySink) -> Result<Feed, RespError> {
        while !data.is_empty() {
            match self.state {
                State::Tag => {
                    let tag = data[0];
                    *data = &data[1..];
                    if self.streamed_string != (tag == b';') {
                        return Err(bad("a RESP streamed string has something other than a chunk"));
                    }
                    match tag {
                        b'+' | b'-' | b':' | b',' | b'#' | b'_' | b'(' | b'$' | b'!' | b'=' | b'*' | b'~' | b'>'
                        | b'%' | b'|' | b';' => {
                            self.line.clear();
                            self.state = State::Line(tag);
                        }
                        b'.' if self.stack.last().is_some_and(|f| f.streamed) => {
                            self.line.clear();
                            self.state = State::Line(tag);
                        }
                        other => return Err(bad(format!("unknown RESP type byte 0x{other:02x}"))),
                    }
                }
                State::Line(tag) => {
                    // Everything up to and including the next LF.
                    let end = data.iter().position(|&b| b == b'\n');
                    let take = end.map_or(data.len(), |i| i + 1);
                    if self.line.len() + take > self.limits.max_line + 2 {
                        return Err(bad("a RESP line is too long"));
                    }
                    self.line.extend_from_slice(&data[..take]);
                    *data = &data[take..];
                    if end.is_some() {
                        if !self.line.ends_with(b"\r\n") {
                            return Err(bad("a RESP line does not end in CRLF"));
                        }
                        let n = self.line.len() - 2;
                        self.line.truncate(n);
                        self.discarding(n + 2)?;
                        self.header(tag, sink)?;
                    }
                }
                State::Payload { body, remaining } => {
                    let mut remaining = remaining;
                    // A verbatim string's first four bytes are its format tag.
                    if body == Body::Verbatim && self.vhead_len < 4 {
                        let head = remaining.min(data.len()).min(4 - self.vhead_len);
                        self.vhead[self.vhead_len..self.vhead_len + head].copy_from_slice(&data[..head]);
                        self.vhead_len += head;
                        *data = &data[head..];
                        remaining -= head;
                        if self.vhead_len == 4 {
                            if self.vhead[3] != b':' {
                                return Err(bad("a RESP verbatim string has no format tag"));
                            }
                            let format = [self.vhead[0], self.vhead[1], self.vhead[2]];
                            self.string_begin(sink, StrKind::Verbatim { format }, Some(self.vtotal - 4));
                        }
                    }
                    let take = if body == Body::Verbatim && self.vhead_len < 4 { 0 } else { remaining.min(data.len()) };
                    if take > 0 {
                        self.discarding(take)?;
                        self.string_chunk(sink, &data[..take]);
                        *data = &data[take..];
                        remaining -= take;
                    }
                    self.state = if remaining == 0 && (body != Body::Verbatim || self.vhead_len == 4) {
                        State::PayloadEnd { seen_cr: false }
                    } else {
                        State::Payload { body, remaining }
                    };
                }
                State::PayloadEnd { seen_cr } => {
                    let b = data[0];
                    *data = &data[1..];
                    match (seen_cr, b) {
                        (false, b'\r') => self.state = State::PayloadEnd { seen_cr: true },
                        (true, b'\n') => {
                            self.state = State::Tag;
                            self.payload_done(sink)?;
                        }
                        _ => return Err(bad("a RESP string does not end in CRLF")),
                    }
                }
            }
            if self.paused {
                break;
            }
        }
        Ok(if std::mem::take(&mut self.paused) { Feed::Paused } else { Feed::Consumed })
    }

    // ---- what the sink hears ----

    /// Count `n` bytes against the discard limit, if they are being discarded.
    fn discarding(&mut self, n: usize) -> Result<(), RespError> {
        if self.skipping || self.muted > 0 {
            self.skipped = self.skipped.saturating_add(n);
            if self.skipped > self.limits.max_skip {
                return Err(bad("a RESP reply to be discarded exceeds the discard limit"));
            }
        }
        Ok(())
    }

    fn apply(&mut self, flow: Flow) {
        match flow {
            Flow::Continue => {}
            Flow::Pause => self.paused = true,
            Flow::Skip => self.skipping = true,
        }
    }

    /// Whether events reach the sink.
    fn live(&self) -> bool {
        self.muted == 0 && !self.skipping
    }

    fn open_reply(&mut self, sink: &mut dyn ReplySink, kind: ReplyKind) {
        if !self.in_reply && self.muted == 0 {
            self.in_reply = true;
            self.skipping = false;
            self.skipped = 0;
            sink.begin_reply(kind);
        }
    }

    fn finish_reply(&mut self, sink: &mut dyn ReplySink) {
        if self.in_reply {
            sink.end_reply(self.skipping);
            self.in_reply = false;
            self.skipping = false;
            self.skipped = 0;
        }
    }

    fn scalar(&mut self, sink: &mut dyn ReplySink, v: Scalar<'_>) {
        self.open_reply(sink, ReplyKind::Normal);
        if self.live() {
            let f = sink.scalar(v);
            self.apply(f);
        }
    }

    fn error_line(&mut self, sink: &mut dyn ReplySink, line: &str) {
        self.open_reply(sink, ReplyKind::Normal);
        if self.live() {
            let f = sink.error(line);
            self.apply(f);
        }
    }

    fn aggregate_begin(&mut self, sink: &mut dyn ReplySink, kind: AggKind, len: Option<usize>) {
        let reply = if kind == AggKind::Push { ReplyKind::Push } else { ReplyKind::Normal };
        self.open_reply(sink, reply);
        if self.live() {
            let f = sink.begin_aggregate(kind, len);
            self.apply(f);
        }
    }

    fn aggregate_end(&mut self, sink: &mut dyn ReplySink) {
        if self.live() {
            let f = sink.end_aggregate();
            self.apply(f);
        }
    }

    fn string_begin(&mut self, sink: &mut dyn ReplySink, kind: StrKind, len: Option<usize>) {
        self.open_reply(sink, ReplyKind::Normal);
        if self.live() {
            let f = sink.begin_string(kind, len);
            self.apply(f);
        }
    }

    fn string_chunk(&mut self, sink: &mut dyn ReplySink, data: &[u8]) {
        if self.live() {
            let f = sink.string_chunk(data);
            self.apply(f);
        }
    }

    fn string_end(&mut self, sink: &mut dyn ReplySink) {
        if self.live() {
            let f = sink.end_string();
            self.apply(f);
        }
    }

    // ---- structure ----

    /// A header or simple line is complete in `line`.
    fn header(&mut self, tag: u8, sink: &mut dyn ReplySink) -> Result<(), RespError> {
        self.state = State::Tag;
        let line = std::mem::take(&mut self.line);
        let result = self.header_of(tag, &line, sink);
        self.line = line;
        result
    }

    fn header_of(&mut self, tag: u8, line: &[u8], sink: &mut dyn ReplySink) -> Result<(), RespError> {
        match tag {
            b'+' => {
                let text = String::from_utf8_lossy(line);
                self.scalar(sink, Scalar::Simple(&text));
                self.value_complete(sink)
            }
            b'-' => {
                let text = String::from_utf8_lossy(line);
                self.error_line(sink, &text);
                self.value_complete(sink)
            }
            b':' => {
                let n = parse_int(line)?;
                self.scalar(sink, Scalar::Int(n));
                self.value_complete(sink)
            }
            b',' => {
                let d = parse_double(line)?;
                self.scalar(sink, Scalar::Double(d));
                self.value_complete(sink)
            }
            b'#' => {
                let v = match line {
                    b"t" => true,
                    b"f" => false,
                    _ => return Err(bad("a RESP boolean is neither t nor f")),
                };
                self.scalar(sink, Scalar::Bool(v));
                self.value_complete(sink)
            }
            b'_' => {
                if !line.is_empty() {
                    return Err(bad("a RESP null has content"));
                }
                self.scalar(sink, Scalar::Null);
                self.value_complete(sink)
            }
            b'(' => {
                if line.is_empty() || !line.iter().enumerate().all(|(i, b)| b.is_ascii_digit() || (i == 0 && *b == b'-')) {
                    return Err(bad("a RESP big number is not a number"));
                }
                // Digits only, so this is valid UTF-8.
                let text = std::str::from_utf8(line).map_err(|_| bad("a RESP big number is not a number"))?;
                self.scalar(sink, Scalar::BigNumber(text));
                self.value_complete(sink)
            }
            b'$' | b'!' | b'=' => {
                if line == b"?" {
                    if tag != b'$' {
                        return Err(bad("only a RESP bulk string may be streamed"));
                    }
                    self.streamed_string = true;
                    self.string_begin(sink, StrKind::Bulk, None);
                    return Ok(());
                }
                let n = parse_int(line)?;
                let body = match tag {
                    b'$' => Body::Bulk,
                    b'!' => Body::Error,
                    _ => Body::Verbatim,
                };
                if n < 0 {
                    // RESP2's null bulk string.
                    if tag == b'$' && n == -1 {
                        self.scalar(sink, Scalar::Null);
                        return self.value_complete(sink);
                    }
                    return Err(bad("a RESP string has a negative length"));
                }
                let len = n as usize;
                match body {
                    Body::Bulk => self.string_begin(sink, StrKind::Bulk, Some(len)),
                    Body::Error => self.string_begin(sink, StrKind::Error, Some(len)),
                    Body::Verbatim => {
                        if len < 4 {
                            return Err(bad("a RESP verbatim string has no format tag"));
                        }
                        // Announced once its format tag has arrived.
                        self.vhead_len = 0;
                        self.vtotal = len;
                    }
                }
                self.state = if len == 0 {
                    State::PayloadEnd { seen_cr: false }
                } else {
                    State::Payload { body, remaining: len }
                };
                Ok(())
            }
            b';' => {
                // The header of a chunk of a streamed string.
                let n = parse_int(line)?;
                if n < 0 {
                    return Err(bad("a RESP streamed string chunk has a negative length"));
                }
                if n == 0 {
                    self.streamed_string = false;
                    self.string_end(sink);
                    return self.value_complete(sink);
                }
                self.state = State::Payload {
                    body: Body::Bulk,
                    remaining: n as usize,
                };
                Ok(())
            }
            b'.' => {
                if !line.is_empty() {
                    return Err(bad("the end of a RESP streamed aggregate has content"));
                }
                match self.stack.pop() {
                    Some(f) if f.streamed => {
                        self.aggregate_end(sink);
                        self.aggregate_done(f, sink)
                    }
                    _ => Err(bad("the end of a RESP streamed aggregate with none open")),
                }
            }
            b'*' | b'~' | b'>' | b'%' | b'|' => {
                if line == b"?" {
                    if !matches!(tag, b'*' | b'~' | b'%') {
                        return Err(bad("only a RESP array, set or map may be streamed"));
                    }
                    let kind = match tag {
                        b'*' => AggKind::Array,
                        b'~' => AggKind::Set,
                        _ => AggKind::Map,
                    };
                    if self.stack.len() >= self.limits.max_depth {
                        return Err(bad("RESP aggregates are nested too deeply"));
                    }
                    self.aggregate_begin(sink, kind, None);
                    self.stack.push(Frame {
                        kind: Open::Agg,
                        remaining: 0,
                        streamed: true,
                    });
                    return Ok(());
                }
                let n = parse_int(line)?;
                if n < 0 {
                    // RESP2's null array.
                    if tag == b'*' && n == -1 {
                        self.scalar(sink, Scalar::Null);
                        return self.value_complete(sink);
                    }
                    return Err(bad("a RESP aggregate has a negative length"));
                }
                let n = n as usize;
                if self.stack.len() >= self.limits.max_depth {
                    return Err(bad("RESP aggregates are nested too deeply"));
                }
                if tag == b'|' {
                    // Attributes describe the value that follows; they are
                    // read and dropped, and are not it.
                    if n > 0 {
                        self.stack.push(Frame {
                            kind: Open::Attribute,
                            remaining: n.saturating_mul(2),
                            streamed: false,
                        });
                        self.muted += 1;
                    }
                    return Ok(());
                }
                let kind = match tag {
                    b'*' => AggKind::Array,
                    b'~' => AggKind::Set,
                    b'>' => AggKind::Push,
                    _ => AggKind::Map,
                };
                self.aggregate_begin(sink, kind, Some(n));
                if n == 0 {
                    // An empty aggregate is complete at once.
                    self.aggregate_end(sink);
                    return self.value_complete(sink);
                }
                self.stack.push(Frame {
                    kind: Open::Agg,
                    remaining: if kind == AggKind::Map { n.saturating_mul(2) } else { n },
                    streamed: false,
                });
                Ok(())
            }
            _ => unreachable!("the tag was checked when it was read"),
        }
    }

    /// A length-prefixed string's payload and CRLF are complete.
    fn payload_done(&mut self, sink: &mut dyn ReplySink) -> Result<(), RespError> {
        if self.streamed_string {
            // Another chunk header, or `;0`, comes next.
            return Ok(());
        }
        self.string_end(sink);
        self.value_complete(sink)
    }

    /// A value is complete: count it in the aggregate it belongs to, closing
    /// each that it fills, and the reply when none is left open.
    fn value_complete(&mut self, sink: &mut dyn ReplySink) -> Result<(), RespError> {
        loop {
            let Some(frame) = self.stack.last_mut() else {
                self.finish_reply(sink);
                return Ok(());
            };
            if frame.streamed {
                return Ok(());
            }
            frame.remaining -= 1;
            if frame.remaining > 0 {
                return Ok(());
            }
            let frame = self.stack.pop().expect("there is a top frame");
            match frame.kind {
                Open::Attribute => {
                    self.muted -= 1;
                    return Ok(());
                }
                Open::Agg => self.aggregate_end(sink),
            }
        }
    }

    /// A streamed aggregate has ended: it is a value of the aggregate around it.
    fn aggregate_done(&mut self, _frame: Frame, sink: &mut dyn ReplySink) -> Result<(), RespError> {
        self.value_complete(sink)
    }
}

impl Default for RespParser {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_int(line: &[u8]) -> Result<i64, RespError> {
    std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("a RESP number is not a number"))
}

fn parse_double(line: &[u8]) -> Result<f64, RespError> {
    match line {
        b"inf" | b"+inf" => Ok(f64::INFINITY),
        b"-inf" => Ok(f64::NEG_INFINITY),
        b"nan" | b"-nan" => Ok(f64::NAN),
        _ => std::str::from_utf8(line)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("a RESP double is not a number")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encoder reserves exactly what it writes, whatever the digit counts.
    #[test]
    fn encoding_is_one_exact_allocation_and_numbers_are_written_right() {
        for len in [0usize, 1, 9, 10, 99, 100, 999, 1000, 12345, 100_000] {
            let value = vec![b'x'; len];
            let words: Vec<&[u8]> = vec![b"SET", b"key", &value];
            let mut out = Vec::new();
            encode_command(&words, &mut out);
            assert_eq!(out.len(), encoded_len(&words), "length {len}");
            assert_eq!(out.capacity(), out.len(), "length {len}: reserved exactly");
            let mut expect = format!("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n${len}\r\n").into_bytes();
            expect.extend_from_slice(&value);
            expect.extend_from_slice(b"\r\n");
            assert_eq!(out, expect, "length {len}");
        }
        // Many arguments: the count has more than one digit.
        let many: Vec<&[u8]> = (0..120).map(|_| &b"a"[..]).collect();
        let mut out = Vec::new();
        encode_command(&many, &mut out);
        assert!(out.starts_with(b"*120\r\n$1\r\na\r\n"));
        assert_eq!(out.len(), encoded_len(&many));
    }

    fn bulk(s: &str) -> Value {
        Value::Bulk(Bytes::copy_from_slice(s.as_bytes()))
    }

    /// Feed `wire` in chunks of `chunk` bytes and collect the replies.
    fn parse_chunked(wire: &[u8], chunk: usize) -> Result<Vec<Value>, RespError> {
        let mut p = RespParser::new();
        let mut out = Vec::new();
        for piece in wire.chunks(chunk) {
            let mut data = piece;
            p.feed_values(&mut data, &mut |v| out.push(v))?;
            assert!(data.is_empty(), "all of a chunk is consumed");
        }
        Ok(out)
    }

    /// The replies for `wire` are the same however it is split.
    fn parse(wire: &[u8]) -> Vec<Value> {
        let whole = parse_chunked(wire, wire.len().max(1)).unwrap();
        for chunk in [1, 2, 3, 5, 7, 16] {
            assert_eq!(parse_chunked(wire, chunk).unwrap(), whole, "split every {chunk} bytes");
        }
        whole
    }

    #[test]
    fn resp2_scalars() {
        assert_eq!(parse(b"+OK\r\n"), vec![Value::Simple("OK".into())]);
        assert_eq!(parse(b":-42\r\n"), vec![Value::Int(-42)]);
        assert_eq!(parse(b"$5\r\nhello\r\n"), vec![bulk("hello")]);
        assert_eq!(parse(b"$0\r\n\r\n"), vec![bulk("")]);
        assert_eq!(parse(b"$-1\r\n"), vec![Value::Null]);
        assert_eq!(parse(b"*-1\r\n"), vec![Value::Null]);
        assert_eq!(
            parse(b"-WRONGTYPE Operation against a key\r\n"),
            vec![Value::Error(ServerError {
                code: "WRONGTYPE".into(),
                message: "Operation against a key".into()
            })]
        );
    }

    #[test]
    fn a_bulk_string_may_contain_crlf_and_any_byte() {
        let wire = b"$8\r\na\r\nb\x00\xff\r\n\r\n";
        assert_eq!(parse(wire), vec![Value::Bulk(Bytes::from_static(b"a\r\nb\x00\xff\r\n"))]);
    }

    #[test]
    fn arrays_nest() {
        let wire = b"*3\r\n:1\r\n*2\r\n$1\r\na\r\n$-1\r\n*0\r\n";
        assert_eq!(
            parse(wire),
            vec![Value::Array(vec![
                Value::Int(1),
                Value::Array(vec![bulk("a"), Value::Null]),
                Value::Array(vec![]),
            ])]
        );
    }

    #[test]
    fn resp3_scalars() {
        assert_eq!(parse(b"_\r\n"), vec![Value::Null]);
        assert_eq!(parse(b"#t\r\n#f\r\n"), vec![Value::Bool(true), Value::Bool(false)]);
        assert_eq!(parse(b",1.5\r\n"), vec![Value::Double(1.5)]);
        assert_eq!(parse(b",inf\r\n,-inf\r\n"), vec![Value::Double(f64::INFINITY), Value::Double(f64::NEG_INFINITY)]);
        // NaN is not equal to itself, so it cannot go through `parse`.
        for chunk in [1, 2, 7] {
            let got = parse_chunked(b",nan\r\n", chunk).unwrap();
            assert!(matches!(&got[0], Value::Double(d) if d.is_nan()));
        }
        assert_eq!(
            parse(b"(3492890328409238509324850943850943825024385\r\n"),
            vec![Value::BigNumber("3492890328409238509324850943850943825024385".into())]
        );
        assert_eq!(
            parse(b"=15\r\ntxt:Some string\r\n"),
            vec![Value::Verbatim {
                format: "txt".into(),
                data: Bytes::from_static(b"Some string")
            }]
        );
        assert_eq!(
            parse(b"!21\r\nSYNTAX invalid syntax\r\n"),
            vec![Value::Error(ServerError {
                code: "SYNTAX".into(),
                message: "invalid syntax".into()
            })]
        );
    }

    #[test]
    fn resp3_aggregates() {
        assert_eq!(
            parse(b"%2\r\n+first\r\n:1\r\n+second\r\n:2\r\n"),
            vec![Value::Map(vec![
                (Value::Simple("first".into()), Value::Int(1)),
                (Value::Simple("second".into()), Value::Int(2)),
            ])]
        );
        assert_eq!(parse(b"~2\r\n:1\r\n:2\r\n"), vec![Value::Set(vec![Value::Int(1), Value::Int(2)])]);
        assert_eq!(
            parse(b">3\r\n$7\r\nmessage\r\n$2\r\nch\r\n$2\r\nhi\r\n"),
            vec![Value::Push(vec![bulk("message"), bulk("ch"), bulk("hi")])]
        );
        assert_eq!(parse(b"%0\r\n"), vec![Value::Map(vec![])]);
    }

    #[test]
    fn attributes_are_dropped_and_the_value_after_them_is_the_reply() {
        let wire = b"|1\r\n+ttl\r\n:3600\r\n$3\r\nfoo\r\n";
        assert_eq!(parse(wire), vec![bulk("foo")]);
        // Inside an aggregate, too, an attribute is not an element.
        let wire = b"*2\r\n:1\r\n|1\r\n+k\r\n+v\r\n:2\r\n";
        assert_eq!(parse(wire), vec![Value::Array(vec![Value::Int(1), Value::Int(2)])]);
    }

    #[test]
    fn several_replies_in_one_chunk() {
        assert_eq!(parse(b"+A\r\n:2\r\n$1\r\nc\r\n"), vec![Value::Simple("A".into()), Value::Int(2), bulk("c")]);
    }

    #[test]
    fn an_error_inside_an_array_is_an_element() {
        let wire = b"*2\r\n:1\r\n-ERR boom\r\n";
        assert_eq!(
            parse(wire),
            vec![Value::Array(vec![
                Value::Int(1),
                Value::Error(ServerError {
                    code: "ERR".into(),
                    message: "boom".into()
                })
            ])]
        );
    }

    #[test]
    fn a_large_bulk_arrives_in_pieces_and_is_one_value() {
        let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let mut wire = format!("${}\r\n", payload.len()).into_bytes();
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(b"\r\n");
        let got = parse_chunked(&wire, 1000).unwrap();
        assert_eq!(got, vec![Value::Bulk(Bytes::from(payload))]);
    }

    #[test]
    fn the_parser_is_idle_between_replies_and_not_inside_one() {
        let mut p = RespParser::new();
        let mut sink = |_v: Value| {};
        assert!(p.is_idle());
        let mut data: &[u8] = b"*2\r\n:1\r\n";
        p.feed_values(&mut data, &mut sink).unwrap();
        assert!(!p.is_idle());
        let mut data: &[u8] = b":2\r\n";
        p.feed_values(&mut data, &mut sink).unwrap();
        assert!(p.is_idle());
    }

    #[test]
    fn protocol_violations_are_errors_and_poison_the_parser() {
        for bad_wire in [
            &b"?x\r\n"[..],
            b":abc\r\n",
            b"$3\r\nabcde\r\n",
            b"$-5\r\n",
            b"#x\r\n",
            b"_x\r\n",
            b"=3\r\nabc\r\n",
            b"+OK\n",
        ] {
            let mut p = RespParser::new();
            let mut data = bad_wire;
            assert!(p.feed_values(&mut data, &mut |_| {}).is_err(), "{:?}", String::from_utf8_lossy(bad_wire));
            let mut more: &[u8] = b"+OK\r\n";
            assert!(p.feed_values(&mut more, &mut |_| {}).is_err(), "a failed parser stays failed");
        }
    }

    #[test]
    fn limits_are_enforced_before_memory_is_reserved() {
        let tiny = RespLimits {
            max_bulk: 10,
            max_aggregate: 3,
            max_depth: 2,
            max_line: 16,
            max_reply_bytes: 4096,
            max_skip: 1 << 20,
        };
        let run = |wire: &[u8]| {
            let mut p = RespParser::with_limits(tiny);
            let mut data = wire;
            p.feed_values(&mut data, &mut |_| {})
        };
        // A string or aggregate announced over the limit is refused when it is
        // announced, and what follows it is skipped.
        assert!(run(b"$11\r\n01234567890\r\n").is_err(), "a bulk over the limit");
        assert!(run(b"$10\r\n0123456789\r\n").is_ok());
        assert!(run(b"*4\r\n:1\r\n:2\r\n:3\r\n:4\r\n").is_err(), "an aggregate over the limit");
        assert!(run(b"*1\r\n*1\r\n*1\r\n").is_err(), "nested too deeply");
        assert!(run(b"+0123456789abcdefXXXX\r\n").is_err(), "a line over the limit");
    }

    #[test]
    fn a_reply_over_the_total_size_limit_is_refused_and_the_next_is_not() {
        let limits = RespLimits {
            max_reply_bytes: 100,
            ..RespLimits::default()
        };
        let mut p = RespParser::with_limits(limits);
        let mut wire = b"*3\r\n".to_vec();
        for _ in 0..3 {
            wire.extend_from_slice(b"$60\r\n");
            wire.extend_from_slice(&[b'x'; 60]);
            wire.extend_from_slice(b"\r\n");
        }
        let mut data = &wire[..];
        assert!(p.feed_values(&mut data, &mut |_| {}).is_err());
    }

    #[test]
    fn the_size_budget_is_per_reply() {
        let limits = RespLimits {
            max_reply_bytes: 100,
            ..RespLimits::default()
        };
        let mut p = RespParser::with_limits(limits);
        let mut wire = Vec::new();
        for _ in 0..10 {
            wire.extend_from_slice(b"$60\r\n");
            wire.extend_from_slice(&[b'x'; 60]);
            wire.extend_from_slice(b"\r\n");
        }
        let mut n = 0;
        let mut data = &wire[..];
        p.feed_values(&mut data, &mut |_| n += 1).unwrap();
        assert_eq!(n, 10);
    }

    // ---- the event parser ----

    /// What a sink was told, with adjacent chunks of one string merged so that
    /// the same reply gives the same events however it was split.
    #[derive(Debug, Clone, PartialEq)]
    enum Ev {
        Begin(ReplyKind),
        Null,
        Int(i64),
        Double(f64),
        Bool(bool),
        Big(String),
        Simple(String),
        Error(String),
        Agg(AggKind, Option<usize>),
        EndAgg,
        Str(StrKind, Option<usize>),
        Chunk(Vec<u8>),
        EndStr,
        End(bool),
    }

    /// Records events; may be told to pause or skip at the Nth event.
    #[derive(Default)]
    struct Rec {
        events: Vec<Ev>,
        count: usize,
        pause_at: Option<usize>,
        skip_at: Option<usize>,
        chunks: usize,
    }

    impl Rec {
        fn flow(&mut self) -> Flow {
            self.count += 1;
            if self.skip_at == Some(self.count) {
                return Flow::Skip;
            }
            if self.pause_at == Some(self.count) {
                return Flow::Pause;
            }
            Flow::Continue
        }
        fn push(&mut self, e: Ev) -> Flow {
            self.events.push(e);
            self.flow()
        }
        /// The events with each run of chunks made one.
        fn merged(&self) -> Vec<Ev> {
            let mut out: Vec<Ev> = Vec::new();
            for e in &self.events {
                match (out.last_mut(), e) {
                    (Some(Ev::Chunk(prev)), Ev::Chunk(more)) => prev.extend_from_slice(more),
                    _ => out.push(e.clone()),
                }
            }
            out
        }
    }

    impl ReplySink for Rec {
        fn begin_reply(&mut self, kind: ReplyKind) {
            self.events.push(Ev::Begin(kind));
        }
        fn scalar(&mut self, v: Scalar<'_>) -> Flow {
            self.push(match v {
                Scalar::Null => Ev::Null,
                Scalar::Int(n) => Ev::Int(n),
                Scalar::Double(d) => Ev::Double(d),
                Scalar::Bool(b) => Ev::Bool(b),
                Scalar::BigNumber(s) => Ev::Big(s.into()),
                Scalar::Simple(s) => Ev::Simple(s.into()),
            })
        }
        fn error(&mut self, line: &str) -> Flow {
            self.push(Ev::Error(line.into()))
        }
        fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
            self.push(Ev::Agg(kind, len))
        }
        fn end_aggregate(&mut self) -> Flow {
            self.push(Ev::EndAgg)
        }
        fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
            self.push(Ev::Str(kind, len))
        }
        fn string_chunk(&mut self, data: &[u8]) -> Flow {
            assert!(!data.is_empty(), "a chunk is never empty");
            self.chunks += 1;
            self.push(Ev::Chunk(data.to_vec()))
        }
        fn end_string(&mut self) -> Flow {
            self.push(Ev::EndStr)
        }
        fn end_reply(&mut self, skipped: bool) {
            self.events.push(Ev::End(skipped));
        }
    }

    /// Feed `wire` in pieces of `chunk` bytes.
    fn events_chunked(wire: &[u8], chunk: usize) -> Vec<Ev> {
        let mut p = RespParser::new();
        let mut rec = Rec::default();
        for piece in wire.chunks(chunk) {
            let mut data = piece;
            assert_eq!(p.feed(&mut data, &mut rec).unwrap(), Feed::Consumed);
            assert!(data.is_empty());
        }
        assert!(p.is_idle(), "the wire is whole replies");
        rec.merged()
    }

    /// The events for `wire`, checked to be the same at every split.
    fn events(wire: &[u8]) -> Vec<Ev> {
        let whole = events_chunked(wire, wire.len().max(1));
        for chunk in [1, 2, 3, 4, 5, 7, 11, 16, 64] {
            assert_eq!(events_chunked(wire, chunk), whole, "split every {chunk} bytes");
        }
        whole
    }

    fn st(kind: StrKind, len: usize, payload: &[u8]) -> Vec<Ev> {
        let mut v = vec![Ev::Str(kind, Some(len))];
        if !payload.is_empty() {
            v.push(Ev::Chunk(payload.to_vec()));
        }
        v.push(Ev::EndStr);
        v
    }

    #[test]
    fn every_kind_of_value_is_the_events_it_should_be() {
        use Ev::*;
        let normal = Begin(ReplyKind::Normal);
        assert_eq!(events(b"+OK\r\n"), vec![normal.clone(), Simple("OK".into()), End(false)]);
        assert_eq!(events(b"-ERR boom\r\n"), vec![normal.clone(), Error("ERR boom".into()), End(false)]);
        assert_eq!(events(b":-7\r\n"), vec![normal.clone(), Int(-7), End(false)]);
        assert_eq!(events(b",2.5\r\n"), vec![normal.clone(), Double(2.5), End(false)]);
        assert_eq!(events(b"#t\r\n"), vec![normal.clone(), Bool(true), End(false)]);
        assert_eq!(events(b"_\r\n"), vec![normal.clone(), Null, End(false)]);
        assert_eq!(events(b"$-1\r\n"), vec![normal.clone(), Null, End(false)]);
        assert_eq!(events(b"*-1\r\n"), vec![normal.clone(), Null, End(false)]);
        assert_eq!(events(b"(-12345678901234567890\r\n"), vec![normal.clone(), Big("-12345678901234567890".into()), End(false)]);

        let mut want = vec![normal.clone()];
        want.extend(st(StrKind::Bulk, 5, b"hello"));
        want.push(End(false));
        assert_eq!(events(b"$5\r\nhello\r\n"), want);

        let mut want = vec![normal.clone()];
        want.extend(st(StrKind::Bulk, 0, b""));
        want.push(End(false));
        assert_eq!(events(b"$0\r\n\r\n"), want);

        let mut want = vec![normal.clone()];
        want.extend(st(StrKind::Error, 3, b"bad"));
        want.push(End(false));
        assert_eq!(events(b"!3\r\nbad\r\n"), want);

        // The format tag is not part of the text.
        let mut want = vec![normal.clone()];
        want.extend(st(StrKind::Verbatim { format: *b"txt" }, 5, b"hello"));
        want.push(End(false));
        assert_eq!(events(b"=9\r\ntxt:hello\r\n"), want);
        let mut want = vec![normal.clone()];
        want.extend(st(StrKind::Verbatim { format: *b"mkd" }, 0, b""));
        want.push(End(false));
        assert_eq!(events(b"=4\r\nmkd:\r\n"), want);
    }

    #[test]
    fn aggregates_nest_and_hold_large_strings_between_their_events() {
        use Ev::*;
        let mut want = vec![
            Begin(ReplyKind::Normal),
            Agg(AggKind::Array, Some(3)),
            Int(1),
            Agg(AggKind::Map, Some(1)),
        ];
        want.extend(st(StrKind::Bulk, 1, b"k"));
        want.extend(st(StrKind::Bulk, 20000, &[b'v'; 20000]));
        want.push(EndAgg);
        want.push(Agg(AggKind::Set, Some(0)));
        want.push(EndAgg);
        want.push(EndAgg);
        want.push(End(false));
        let mut wire = b"*3\r\n:1\r\n%1\r\n$1\r\nk\r\n$20000\r\n".to_vec();
        wire.extend_from_slice(&[b'v'; 20000]);
        wire.extend_from_slice(b"\r\n~0\r\n");
        assert_eq!(events(&wire), want);
        // An empty aggregate at the top level is a whole reply.
        assert_eq!(
            events(b"*0\r\n"),
            vec![Begin(ReplyKind::Normal), Agg(AggKind::Array, Some(0)), EndAgg, End(false)]
        );
    }

    #[test]
    fn a_push_is_announced_as_one_and_replies_either_side_are_not() {
        use Ev::*;
        let got = events(b":1\r\n>2\r\n+message\r\n+hi\r\n:2\r\n");
        assert_eq!(
            got,
            vec![
                Begin(ReplyKind::Normal),
                Int(1),
                End(false),
                Begin(ReplyKind::Push),
                Agg(AggKind::Push, Some(2)),
                Simple("message".into()),
                Simple("hi".into()),
                EndAgg,
                End(false),
                Begin(ReplyKind::Normal),
                Int(2),
                End(false),
            ]
        );
    }

    #[test]
    fn attributes_are_discarded_wherever_they_come() {
        use Ev::*;
        // Before a reply, inside an aggregate before an element, and nested in
        // an attribute: none produces an event, none counts as an element.
        let wire = b"|1\r\n+ttl\r\n|1\r\n+x\r\n:1\r\n:3\r\n*2\r\n|1\r\n$1\r\nk\r\n$3\r\nabc\r\n:5\r\n:6\r\n";
        let mut want = vec![Begin(ReplyKind::Normal), Agg(AggKind::Array, Some(2))];
        want.push(Int(5));
        want.push(Int(6));
        want.push(EndAgg);
        want.push(End(false));
        assert_eq!(events(wire), want);
        // Skipping the attribute needs no memory for what is in it: this one is
        // 200 KB of payload.
        let mut big = b"|1\r\n+k\r\n$200000\r\n".to_vec();
        big.extend_from_slice(&vec![b'a'; 200_000]);
        big.extend_from_slice(b"\r\n+OK\r\n");
        assert_eq!(events(&big), vec![Begin(ReplyKind::Normal), Simple("OK".into()), End(false)]);
    }

    #[test]
    fn resp3_streamed_strings_and_aggregates_are_events_without_a_length() {
        use Ev::*;
        let want = vec![
            Begin(ReplyKind::Normal),
            Str(StrKind::Bulk, None),
            Chunk(b"Hello world".to_vec()),
            EndStr,
            End(false),
        ];
        assert_eq!(events(b"$?\r\n;4\r\nHell\r\n;5\r\no wor\r\n;2\r\nld\r\n;0\r\n"), want);
        let want = vec![
            Begin(ReplyKind::Normal),
            Agg(AggKind::Array, None),
            Int(1),
            Agg(AggKind::Set, None),
            Int(2),
            EndAgg,
            Simple("x".into()),
            EndAgg,
            End(false),
        ];
        assert_eq!(events(b"*?\r\n:1\r\n~?\r\n:2\r\n.\r\n+x\r\n.\r\n"), want);
    }

    #[test]
    fn a_stream_that_is_not_streamed_properly_is_an_error() {
        for wire in [
            &b";4\r\nabcd\r\n"[..],               // a chunk outside a streamed string
            b"$?\r\n:1\r\n",                       // something that is not a chunk inside one
            b"$?\r\n;-1\r\n",                      // a negative chunk
            b".\r\n",                              // an end with nothing open
            b"*?\r\n.x\r\n",                       // an end with content
            b"!?\r\n",                             // only bulk strings stream
            b">?\r\n",                             // and only some aggregates
            b"=3\r\nabc\r\n",                      // a verbatim string with no room for its tag
            b"=5\r\nabcde\r\n",                    // and one with no colon
        ] {
            let mut p = RespParser::new();
            let mut data = wire;
            assert!(p.feed(&mut data, &mut Rec::default()).is_err(), "{:?}", String::from_utf8_lossy(wire));
        }
    }

    #[test]
    fn skip_discards_the_rest_of_the_reply_and_not_the_next() {
        use Ev::*;
        let mut wire = b"*2\r\n$100000\r\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; 100_000]);
        wire.extend_from_slice(b"\r\n:9\r\n:7\r\n");
        for chunk in [1, 7, 4096, wire.len()] {
            let mut p = RespParser::new();
            // Skip at the third event: the first chunk of the string.
            let mut rec = Rec {
                skip_at: Some(3),
                ..Rec::default()
            };
            for piece in wire.chunks(chunk) {
                let mut data = piece;
                assert_eq!(p.feed(&mut data, &mut rec).unwrap(), Feed::Consumed);
            }
            let got = rec.merged();
            assert_eq!(
                got[..4],
                [
                    Begin(ReplyKind::Normal),
                    Agg(AggKind::Array, Some(2)),
                    Str(StrKind::Bulk, Some(100_000)),
                    Chunk(got_chunk(&got)),
                ],
                "chunk {chunk}"
            );
            // Nothing after the skip but the end of that reply, then the next reply whole.
            assert_eq!(
                got[4..],
                [End(true), Begin(ReplyKind::Normal), Int(7), End(false)],
                "chunk {chunk}"
            );
        }
    }

    fn got_chunk(events: &[Ev]) -> Vec<u8> {
        match &events[3] {
            Ev::Chunk(c) => c.clone(),
            other => panic!("not a chunk: {other:?}"),
        }
    }

    #[test]
    fn a_reply_discarded_past_the_limit_abandons_the_stream() {
        let limits = RespLimits {
            max_skip: 1000,
            ..RespLimits::default()
        };
        let mut wire = b"$5000\r\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; 5000]);
        wire.extend_from_slice(b"\r\n");
        // A sink that wants none of it.
        let mut p = RespParser::with_limits(limits);
        let mut rec = Rec {
            skip_at: Some(1),
            ..Rec::default()
        };
        let mut data = &wire[..];
        assert!(p.feed(&mut data, &mut rec).is_err());
        // Up to the limit is fine.
        let mut wire = b"$900\r\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; 900]);
        wire.extend_from_slice(b"\r\n");
        let mut p = RespParser::with_limits(limits);
        let mut rec = Rec {
            skip_at: Some(1),
            ..Rec::default()
        };
        let mut data = &wire[..];
        assert_eq!(p.feed(&mut data, &mut rec).unwrap(), Feed::Consumed);
        // And a reply that is not discarded has no limit at all.
        let mut wire = b"$5000\r\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; 5000]);
        wire.extend_from_slice(b"\r\n");
        let mut p = RespParser::with_limits(limits);
        let mut data = &wire[..];
        assert_eq!(p.feed(&mut data, &mut Rec::default()).unwrap(), Feed::Consumed);
    }

    #[test]
    fn a_pause_stops_after_the_event_leaving_the_rest_and_resuming_loses_nothing() {
        let mut wire = b"*3\r\n:1\r\n$20\r\n01234567890123456789\r\n%1\r\n+k\r\n,1.5\r\n".to_vec();
        wire.extend_from_slice(b"+tail\r\n");
        let whole = events_chunked(&wire, wire.len());
        let total_events = {
            let mut p = RespParser::new();
            let mut rec = Rec::default();
            let mut data = &wire[..];
            p.feed(&mut data, &mut rec).unwrap();
            rec.count
        };
        assert!(total_events > 8);
        for pause_at in 1..=total_events {
            for chunk in [wire.len(), 3, 1] {
                let mut p = RespParser::new();
                let mut rec = Rec {
                    pause_at: Some(pause_at),
                    ..Rec::default()
                };
                let mut pauses = 0;
                for piece in wire.chunks(chunk) {
                    let mut data = piece;
                    // Feed what is left until it is all taken.
                    loop {
                        match p.feed(&mut data, &mut rec).unwrap() {
                            Feed::Consumed => break,
                            Feed::Paused => {
                                pauses += 1;
                                // Resuming with nothing in between continues exactly.
                            }
                        }
                    }
                    assert!(data.is_empty());
                }
                assert_eq!(pauses, 1, "paused once, at event {pause_at}, chunk {chunk}");
                assert_eq!(rec.merged(), whole, "paused at event {pause_at}, chunk {chunk}");
            }
        }
    }

    // ---- a property test against an independent reference ----

    /// A deterministic generator.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_value(g: &mut Lcg, depth: usize) -> Value {
        let leaf = depth == 0 || g.below(3) > 0;
        if leaf {
            return match g.below(9) {
                0 => Value::Null,
                1 => Value::Int(g.next() as i64 - (1 << 30)),
                2 => Value::Bool(g.below(2) == 0),
                3 => Value::Double((g.below(1000) as f64) / 8.0),
                4 => Value::Simple(format!("s{}", g.below(1000))),
                5 => Value::BigNumber(format!("{}", g.next() * 1_000_000_007)),
                6 => Value::Error(ServerError::parse(&format!("ERR e{}", g.below(100)))),
                7 => Value::Verbatim {
                    format: "txt".into(),
                    data: Bytes::from(random_bytes(g)),
                },
                _ => Value::Bulk(Bytes::from(random_bytes(g))),
            };
        }
        let n = g.below(4) as usize;
        let mut items: Vec<Value> = (0..n).map(|_| random_value(g, depth - 1)).collect();
        match g.below(4) {
            0 => Value::Array(items),
            1 => Value::Set(items),
            2 => Value::Push(items),
            _ => Value::Map(
                items
                    .drain(..)
                    .map(|k| (k, random_value(g, depth - 1)))
                    .collect(),
            ),
        }
    }

    fn random_bytes(g: &mut Lcg) -> Vec<u8> {
        let n = match g.below(6) {
            0 => 0,
            1 => 1 + g.below(5),
            2 => 100 + g.below(900),
            _ => g.below(20),
        } as usize;
        (0..n).map(|_| g.next() as u8).collect()
    }

    /// Write `v` as RESP3, with an attribute sometimes in front.
    fn encode_value(g: &mut Lcg, v: &Value, out: &mut Vec<u8>) {
        if g.below(8) == 0 {
            out.extend_from_slice(b"|1\r\n+attr\r\n$3\r\nabc\r\n");
        }
        let body = |out: &mut Vec<u8>, tag: u8, bytes: &[u8]| {
            out.push(tag);
            out.extend_from_slice(bytes.len().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(bytes);
            out.extend_from_slice(b"\r\n");
        };
        match v {
            Value::Null => out.extend_from_slice(b"_\r\n"),
            Value::Int(n) => out.extend_from_slice(format!(":{n}\r\n").as_bytes()),
            Value::Bool(b) => out.extend_from_slice(if *b { b"#t\r\n" } else { b"#f\r\n" }),
            Value::Double(d) => out.extend_from_slice(format!(",{d}\r\n").as_bytes()),
            Value::Simple(s) => out.extend_from_slice(format!("+{s}\r\n").as_bytes()),
            Value::BigNumber(s) => out.extend_from_slice(format!("({s}\r\n").as_bytes()),
            Value::Error(e) => out.extend_from_slice(format!("-{e}\r\n").as_bytes()),
            Value::Bulk(b) => {
                if g.below(5) == 0 && !b.is_empty() {
                    // Streamed, in uneven chunks.
                    out.extend_from_slice(b"$?\r\n");
                    let mut rest = &b[..];
                    while !rest.is_empty() {
                        let n = (1 + g.below(rest.len() as u64)) as usize;
                        body(out, b';', &rest[..n]);
                        rest = &rest[n..];
                    }
                    out.extend_from_slice(b";0\r\n");
                } else {
                    body(out, b'$', b);
                }
            }
            Value::Verbatim { format, data } => {
                let mut text = format.as_bytes().to_vec();
                text.push(b':');
                text.extend_from_slice(data);
                body(out, b'=', &text);
            }
            Value::Array(items) | Value::Set(items) | Value::Push(items) => {
                let tag = match v {
                    Value::Array(_) => b'*',
                    Value::Set(_) => b'~',
                    _ => b'>',
                };
                let streamed = tag != b'>' && g.below(5) == 0;
                if streamed {
                    out.push(tag);
                    out.extend_from_slice(b"?\r\n");
                } else {
                    out.push(tag);
                    out.extend_from_slice(format!("{}\r\n", items.len()).as_bytes());
                }
                for item in items {
                    encode_value(g, item, out);
                }
                if streamed {
                    out.extend_from_slice(b".\r\n");
                }
            }
            Value::Map(pairs) => {
                out.extend_from_slice(format!("%{}\r\n", pairs.len()).as_bytes());
                for (k, val) in pairs {
                    encode_value(g, k, out);
                    encode_value(g, val, out);
                }
            }
        }
    }

    #[test]
    fn random_replies_at_random_splits_are_read_as_they_were_written() {
        let mut g = Lcg(0x5eed);
        for round in 0..400 {
            let n = 1 + g.below(4) as usize;
            let values: Vec<Value> = (0..n).map(|_| random_value(&mut g, 4)).collect();
            let mut wire = Vec::new();
            for v in &values {
                encode_value(&mut g, v, &mut wire);
            }
            // Split at random points, from single bytes to whole.
            let mut p = RespParser::new();
            let mut got = Vec::new();
            let mut rest = &wire[..];
            while !rest.is_empty() {
                let take = match g.below(4) {
                    0 => 1,
                    1 => 1 + g.below(8),
                    2 => 1 + g.below(200),
                    _ => rest.len() as u64,
                }
                .min(rest.len() as u64) as usize;
                let mut piece = &rest[..take];
                p.feed_values(&mut piece, &mut |v| got.push(v)).unwrap();
                assert!(piece.is_empty());
                rest = &rest[take..];
            }
            assert!(p.is_idle(), "round {round}");
            assert_eq!(got.len(), values.len(), "round {round}");
            for (g_, want) in got.iter().zip(&values) {
                assert_eq!(g_, want, "round {round}");
            }
        }
    }

    #[test]
    fn server_errors_split_into_code_and_message() {
        let e = ServerError::parse("MOVED 3999 127.0.0.1:6381");
        assert_eq!((e.code.as_str(), e.message.as_str()), ("MOVED", "3999 127.0.0.1:6381"));
        let e = ServerError::parse("NOAUTH");
        assert_eq!((e.code.as_str(), e.message.as_str()), ("NOAUTH", ""));
        let e = ServerError::parse("some lower case text");
        assert_eq!((e.code.as_str(), e.message.as_str()), ("", "some lower case text"));
        assert_eq!(ServerError::parse("ERR boom").to_string(), "ERR boom");
    }

    #[test]
    fn commands_encode_as_arrays_of_bulk_strings() {
        let mut out = Vec::new();
        encode_command(&[b"SET", b"k", b"va\r\nl"], &mut out);
        assert_eq!(out, b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$5\r\nva\r\nl\r\n");
        // And what is encoded parses back as the array it is.
        assert_eq!(
            parse(&out),
            vec![Value::Array(vec![bulk("SET"), bulk("k"), bulk("va\r\nl")])]
        );
    }

    #[test]
    fn value_accessors() {
        assert_eq!(bulk("12").as_int(), Some(12));
        assert_eq!(Value::Double(3.0).as_int(), Some(3));
        assert_eq!(bulk("2.5").as_f64(), Some(2.5));
        assert_eq!(Value::Simple("OK".into()).as_str(), Some("OK"));
        assert!(Value::Null.is_null());
        let pairs = Value::Array(vec![bulk("a"), Value::Int(1), bulk("b"), Value::Int(2)]).into_pairs().unwrap();
        assert_eq!(pairs.len(), 2);
        assert!(Value::Array(vec![Value::Int(1)]).into_pairs().is_none());
    }
}
