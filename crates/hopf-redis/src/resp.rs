// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RESP2 and RESP3: the reply [`Value`], the command encoder and the
//! incremental [`RespParser`].
//!
//! The parser is push-fed and holds none of the stream. [`RespParser::feed`] is
//! given whatever bytes have arrived, in any split, and consumes all of them:
//! a header line that is not finished is kept in a small scratch buffer, a
//! bulk payload is appended to the value it will become as it arrives, and
//! aggregates under construction wait on an explicit stack. A reply is handed
//! to the sink the moment its last byte is seen. There is no recursion, so the
//! nesting depth is a limit and not a stack overflow, and every size the
//! server announces is checked against [`RespLimits`] before any memory is
//! reserved for it.
//!
//! One reply is one [`Value`]; a reply is built whole because that is what a
//! command's callback receives, and [`RespLimits::max_reply_bytes`] bounds it.

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

/// Bounds on what a server may make the parser hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RespLimits {
    /// The largest bulk string, verbatim string or bulk error. Redis's own
    /// default for `proto-max-bulk-len` is 512 MiB, which is this default, so
    /// anything a default server can send fits. Lower it to bound memory.
    pub max_bulk: usize,
    /// The most elements one aggregate may announce.
    pub max_aggregate: usize,
    /// The most levels of aggregate inside aggregate.
    pub max_depth: usize,
    /// The longest header or simple-string line.
    pub max_line: usize,
    /// The most memory one reply may take, counting bulk payloads and a small
    /// overhead per element.
    pub max_reply_bytes: usize,
}

impl Default for RespLimits {
    fn default() -> Self {
        Self {
            max_bulk: 512 * 1024 * 1024,
            max_aggregate: 1 << 26,
            max_depth: 32,
            max_line: 64 * 1024,
            max_reply_bytes: 1024 * 1024 * 1024,
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

/// What an aggregate under construction will become.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Agg {
    Array,
    Set,
    Push,
    Map,
    /// Out-of-band attributes (RESP3): read and dropped; the value that follows
    /// is the reply.
    Attribute,
}

struct Frame {
    kind: Agg,
    /// Elements to collect: twice the pair count for a map or attributes.
    expected: usize,
    items: Vec<Value>,
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
    PayloadEnd { body: Body, seen_cr: bool },
}

/// The incremental RESP parser. See the [module documentation](self).
pub struct RespParser {
    limits: RespLimits,
    state: State,
    /// The line being read, or the payload being collected.
    scratch: Vec<u8>,
    stack: Vec<Frame>,
    /// Memory the reply under construction has taken so far.
    reply_bytes: usize,
    failed: bool,
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
            scratch: Vec::new(),
            stack: Vec::new(),
            reply_bytes: 0,
            failed: false,
        }
    }

    /// Whether the parser is between replies: nothing of the next one has
    /// arrived.
    pub fn is_idle(&self) -> bool {
        matches!(self.state, State::Tag) && self.stack.is_empty()
    }

    /// Consume `data`, handing each reply completed by it to `sink`.
    ///
    /// Always consumes all of `data` unless it returns an error, however it is
    /// split; what has not yet made a whole reply is kept inside the parser.
    pub fn feed(&mut self, data: &mut &[u8], sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        if self.failed {
            return Err(bad("the stream is not valid RESP"));
        }
        let result = self.run(data, sink);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn run(&mut self, data: &mut &[u8], sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        while !data.is_empty() {
            match self.state {
                State::Tag => {
                    let tag = data[0];
                    *data = &data[1..];
                    match tag {
                        b'+' | b'-' | b':' | b',' | b'#' | b'_' | b'(' | b'$' | b'!' | b'=' | b'*' | b'~' | b'>'
                        | b'%' | b'|' => {
                            self.scratch.clear();
                            self.state = State::Line(tag);
                        }
                        other => return Err(bad(format!("unknown RESP type byte 0x{other:02x}"))),
                    }
                }
                State::Line(tag) => {
                    // Everything up to and including the next LF.
                    let end = data.iter().position(|&b| b == b'\n');
                    let take = end.map_or(data.len(), |i| i + 1);
                    if self.scratch.len() + take > self.limits.max_line + 2 {
                        return Err(bad("a RESP line is too long"));
                    }
                    self.scratch.extend_from_slice(&data[..take]);
                    *data = &data[take..];
                    if end.is_some() {
                        if !self.scratch.ends_with(b"\r\n") {
                            return Err(bad("a RESP line does not end in CRLF"));
                        }
                        let n = self.scratch.len() - 2;
                        self.scratch.truncate(n);
                        self.line(tag, sink)?;
                    }
                }
                State::Payload { body, remaining } => {
                    let take = remaining.min(data.len());
                    self.scratch.extend_from_slice(&data[..take]);
                    *data = &data[take..];
                    self.state = if remaining == take {
                        State::PayloadEnd { body, seen_cr: false }
                    } else {
                        State::Payload {
                            body,
                            remaining: remaining - take,
                        }
                    };
                }
                State::PayloadEnd { body, seen_cr } => {
                    let b = data[0];
                    *data = &data[1..];
                    match (seen_cr, b) {
                        (false, b'\r') => self.state = State::PayloadEnd { body, seen_cr: true },
                        (true, b'\n') => {
                            self.state = State::Tag;
                            let payload = std::mem::take(&mut self.scratch);
                            self.payload(body, payload, sink)?;
                        }
                        _ => return Err(bad("a RESP string does not end in CRLF")),
                    }
                }
            }
        }
        Ok(())
    }

    /// A header or simple line is complete in `scratch`.
    fn line(&mut self, tag: u8, sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        let line = std::mem::take(&mut self.scratch);
        self.state = State::Tag;
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        match tag {
            b'+' => self.add(Value::Simple(text(&line)), 16 + line.len(), sink),
            b'-' => self.add(Value::Error(ServerError::parse(&text(&line))), 16 + line.len(), sink),
            b':' => {
                let n = parse_int(&line)?;
                self.add(Value::Int(n), 16, sink)
            }
            b',' => {
                let d = parse_double(&line)?;
                self.add(Value::Double(d), 16, sink)
            }
            b'#' => match &line[..] {
                b"t" => self.add(Value::Bool(true), 16, sink),
                b"f" => self.add(Value::Bool(false), 16, sink),
                _ => Err(bad("a RESP boolean is neither t nor f")),
            },
            b'_' => {
                if !line.is_empty() {
                    return Err(bad("a RESP null has content"));
                }
                self.add(Value::Null, 16, sink)
            }
            b'(' => {
                if line.is_empty() || !line.iter().enumerate().all(|(i, b)| b.is_ascii_digit() || (i == 0 && *b == b'-')) {
                    return Err(bad("a RESP big number is not a number"));
                }
                self.add(Value::BigNumber(text(&line)), 16 + line.len(), sink)
            }
            b'$' | b'!' | b'=' => {
                let n = parse_int(&line)?;
                let body = match tag {
                    b'$' => Body::Bulk,
                    b'!' => Body::Error,
                    _ => Body::Verbatim,
                };
                if n < 0 {
                    // RESP2's null bulk string.
                    if tag == b'$' && n == -1 {
                        return self.add(Value::Null, 16, sink);
                    }
                    return Err(bad("a RESP string has a negative length"));
                }
                let len = n as usize;
                if len > self.limits.max_bulk {
                    return Err(bad(format!("a RESP string of {len} bytes exceeds the limit")));
                }
                self.charge(len)?;
                self.scratch.reserve(len.min(64 * 1024));
                self.state = if len == 0 {
                    State::PayloadEnd { body, seen_cr: false }
                } else {
                    State::Payload { body, remaining: len }
                };
                Ok(())
            }
            b'*' | b'~' | b'>' | b'%' | b'|' => {
                let n = parse_int(&line)?;
                if n < 0 {
                    // RESP2's null array.
                    if tag == b'*' && n == -1 {
                        return self.add(Value::Null, 16, sink);
                    }
                    return Err(bad("a RESP aggregate has a negative length"));
                }
                let n = n as usize;
                if n > self.limits.max_aggregate {
                    return Err(bad(format!("a RESP aggregate of {n} elements exceeds the limit")));
                }
                let kind = match tag {
                    b'*' => Agg::Array,
                    b'~' => Agg::Set,
                    b'>' => Agg::Push,
                    b'%' => Agg::Map,
                    _ => Agg::Attribute,
                };
                let expected = if matches!(kind, Agg::Map | Agg::Attribute) { n * 2 } else { n };
                if self.stack.len() >= self.limits.max_depth {
                    return Err(bad("RESP aggregates are nested too deeply"));
                }
                self.charge(16 + expected.saturating_mul(16))?;
                if expected == 0 {
                    // An empty aggregate is complete at once.
                    return self.complete(
                        Frame {
                            kind,
                            expected,
                            items: Vec::new(),
                        },
                        sink,
                    );
                }
                self.stack.push(Frame {
                    kind,
                    expected,
                    items: Vec::with_capacity(expected.min(1024)),
                });
                Ok(())
            }
            _ => unreachable!("the tag was checked when it was read"),
        }
    }

    /// A length-prefixed string is complete.
    fn payload(&mut self, body: Body, payload: Vec<u8>, sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        let value = match body {
            Body::Bulk => Value::Bulk(Bytes::from(payload)),
            Body::Error => Value::Error(ServerError::parse(&String::from_utf8_lossy(&payload))),
            Body::Verbatim => {
                if payload.len() < 4 || payload[3] != b':' {
                    return Err(bad("a RESP verbatim string has no format tag"));
                }
                Value::Verbatim {
                    format: String::from_utf8_lossy(&payload[..3]).into_owned(),
                    data: Bytes::copy_from_slice(&payload[4..]),
                }
            }
        };
        self.add(value, 0, sink)
    }

    /// Count `bytes` against the limit for the reply under construction.
    fn charge(&mut self, bytes: usize) -> Result<(), RespError> {
        self.reply_bytes = self.reply_bytes.saturating_add(bytes);
        if self.reply_bytes > self.limits.max_reply_bytes {
            return Err(bad("a RESP reply exceeds the size limit"));
        }
        Ok(())
    }

    /// A scalar is complete.
    fn add(&mut self, value: Value, cost: usize, sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        self.charge(cost)?;
        self.place(value, sink)
    }

    /// An aggregate is complete.
    fn complete(&mut self, frame: Frame, sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        let value = match frame.kind {
            Agg::Array => Value::Array(frame.items),
            Agg::Set => Value::Set(frame.items),
            Agg::Push => Value::Push(frame.items),
            Agg::Map => {
                let mut it = frame.items.into_iter();
                let mut pairs = Vec::new();
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    pairs.push((k, v));
                }
                Value::Map(pairs)
            }
            // Attributes describe the value that follows; they are not it.
            Agg::Attribute => return Ok(()),
        };
        self.place(value, sink)
    }

    /// Put a completed value where it belongs: in the aggregate being built,
    /// or, with none, to the sink. A filled aggregate completes in turn.
    fn place(&mut self, value: Value, sink: &mut dyn FnMut(Value)) -> Result<(), RespError> {
        match self.stack.last_mut() {
            None => {
                self.reply_bytes = 0;
                sink(value);
                Ok(())
            }
            Some(frame) => {
                frame.items.push(value);
                if frame.items.len() < frame.expected {
                    return Ok(());
                }
                let frame = self.stack.pop().expect("there is a top frame");
                self.complete(frame, sink)
            }
        }
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
            p.feed(&mut data, &mut |v| out.push(v))?;
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
        p.feed(&mut data, &mut sink).unwrap();
        assert!(!p.is_idle());
        let mut data: &[u8] = b":2\r\n";
        p.feed(&mut data, &mut sink).unwrap();
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
            assert!(p.feed(&mut data, &mut |_| {}).is_err(), "{:?}", String::from_utf8_lossy(bad_wire));
            let mut more: &[u8] = b"+OK\r\n";
            assert!(p.feed(&mut more, &mut |_| {}).is_err(), "a failed parser stays failed");
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
        };
        let run = |wire: &[u8]| {
            let mut p = RespParser::with_limits(tiny);
            let mut data = wire;
            p.feed(&mut data, &mut |_| {})
        };
        assert!(run(b"$11\r\n").is_err(), "a bulk over the limit");
        assert!(run(b"$10\r\n0123456789\r\n").is_ok());
        assert!(run(b"*4\r\n").is_err(), "an aggregate over the limit");
        assert!(run(b"*1\r\n*1\r\n*1\r\n").is_err(), "nested too deep");
        assert!(run(b"+0123456789abcdefXXXX\r\n").is_err(), "a line over the limit");
        // The announced size is checked, not the bytes that happen to arrive.
        assert!(run(b"$9999999999\r\n").is_err());
    }

    #[test]
    fn a_reply_over_the_total_size_limit_is_refused() {
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
        assert!(p.feed(&mut data, &mut |_| {}).is_err());
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
        p.feed(&mut data, &mut |_| n += 1).unwrap();
        assert_eq!(n, 10);
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
