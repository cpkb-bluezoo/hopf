// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Assembling a reply into a [`Value`] from the parser's events, for the crate's
//! own use.
//!
//! This is the one place the crate builds a value, and it is not exposed: a
//! value built whole is for replies the crate itself reads (the handshake, the
//! cluster's layout, `WAITAOF`) or that a helper has declared to be small (an
//! integer, `OK`). Each use names how much it will take, a [`Cap`], and a reply
//! that exceeds it is never buffered past it: the rest is discarded in constant
//! memory ([`Flow::Skip`]) and the connection stays in step. A string or a list
//! that a caller's data decides the size of is not read this way; it is given to
//! a sink, chunk by chunk.

use hopf_core::Bytes;

use crate::resp::{AggKind, Flow, ReplySink, Scalar, ServerError, StrKind, Value};

/// How much of a reply the crate will assemble into a value for its own use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cap {
    /// The longest string.
    max_bulk: usize,
    /// The most elements an aggregate may announce.
    max_aggregate: usize,
    /// The most memory the whole reply may take.
    max_reply: usize,
    /// What to say of a string or an aggregate that is refused outright (a cap
    /// of none), so that whoever met it is told what to do instead.
    hint: &'static str,
}

impl Cap {
    /// A single value: a number, `OK`, nil. Nothing a caller's data sizes.
    pub(crate) const SCALAR: Cap = Cap {
        max_bulk: 0,
        max_aggregate: 0,
        max_reply: 4096,
        hint: "expected a single value, but the reply is a string or a collection, which can be of any \
               size: read it with send_streaming and a sink",
    };

    /// A short string: the SHA-1 a script is loaded under.
    pub(crate) const SHORT: Cap = Cap {
        max_bulk: 256,
        max_aggregate: 0,
        max_reply: 4096,
        hint: "expected a short string, but the reply is a collection",
    };

    /// A pair of counts: what `WAITAOF` answers.
    pub(crate) const PAIR: Cap = Cap {
        max_bulk: 0,
        max_aggregate: 2,
        max_reply: 4096,
        hint: "expected a pair of counts",
    };

    /// What the client reads about itself and the cluster (`HELLO`, `CLUSTER
    /// SHARDS`, `CLUSTER SLOTS`): structural, and as large as the cluster is.
    pub(crate) const CONTROL: Cap = Cap {
        max_bulk: 64 * 1024,
        max_aggregate: 1 << 20,
        max_reply: 32 * 1024 * 1024,
        hint: "the reply is larger than the client will read for itself",
    };

    /// A cap for tests, which build values to compare with.
    #[cfg(test)]
    pub(crate) const TEST: Cap = Cap {
        max_bulk: 16 * 1024 * 1024,
        max_aggregate: 1 << 20,
        max_reply: 64 * 1024 * 1024,
        hint: "over the cap",
    };
}

struct Build {
    kind: AggKind,
    items: Vec<Value>,
}

struct Text {
    kind: StrKind,
    buf: Vec<u8>,
    /// The length was announced, and so was checked and charged when it began.
    announced: bool,
    /// The most it may come to.
    limit: usize,
}

/// The most of an error's text that is kept, whatever the cap.
const MAX_ERROR_TEXT: usize = 4096;

/// Why a reply was not assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TooLarge(pub String);

/// Builds one reply at a time; reused for the next.
pub(crate) struct Collector {
    cap: Cap,
    stack: Vec<Build>,
    text: Option<Text>,
    done: Option<Value>,
    /// Memory the reply under construction has taken so far.
    bytes: usize,
    refused: Option<TooLarge>,
}

impl Collector {
    pub(crate) fn new(cap: Cap) -> Self {
        Self {
            cap,
            stack: Vec::new(),
            text: None,
            done: None,
            bytes: 0,
            refused: None,
        }
    }

    fn reset(&mut self) {
        self.stack.clear();
        self.text = None;
        self.done = None;
        self.bytes = 0;
        self.refused = None;
    }

    /// The reply, once `end_reply` has been seen.
    pub(crate) fn take(&mut self) -> Result<Value, TooLarge> {
        let result = match self.refused.take() {
            Some(why) => Err(why),
            None => self.done.take().ok_or_else(|| TooLarge("the reply was not complete".into())),
        };
        self.reset();
        result
    }

    fn refuse(&mut self, why: String) -> Flow {
        // Free what was built; the rest of the reply is skipped.
        self.stack.clear();
        self.text = None;
        self.refused = Some(TooLarge(why));
        Flow::Skip
    }

    fn charge(&mut self, bytes: usize) -> Result<(), Flow> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > self.cap.max_reply {
            return Err(self.refuse(format!("a RESP reply exceeds the size limit of {} bytes", self.cap.max_reply)));
        }
        Ok(())
    }

    /// Put a completed value where it belongs.
    fn place(&mut self, value: Value) {
        match self.stack.last_mut() {
            Some(open) => open.items.push(value),
            None => self.done = Some(value),
        }
    }
}

impl ReplySink for Collector {
    fn begin_reply(&mut self, _kind: crate::resp::ReplyKind) {
        self.reset();
    }

    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        let (value, cost) = match v {
            Scalar::Null => (Value::Null, 16),
            Scalar::Int(n) => (Value::Int(n), 16),
            Scalar::Double(d) => (Value::Double(d), 16),
            Scalar::Bool(b) => (Value::Bool(b), 16),
            Scalar::BigNumber(s) => (Value::BigNumber(s.to_string()), 16 + s.len()),
            Scalar::Simple(s) => (Value::Simple(s.to_string()), 16 + s.len()),
        };
        if let Err(flow) = self.charge(cost) {
            return flow;
        }
        self.place(value);
        Flow::Continue
    }

    fn error(&mut self, line: &str) -> Flow {
        if let Err(flow) = self.charge(16 + line.len()) {
            return flow;
        }
        self.place(Value::Error(ServerError::parse(line)));
        Flow::Continue
    }

    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        let announced = len.unwrap_or(0);
        if self.cap.max_aggregate == 0 {
            return self.refuse(self.cap.hint.into());
        }
        if announced > self.cap.max_aggregate {
            return self.refuse(format!("a RESP aggregate of {announced} elements exceeds the limit"));
        }
        if let Err(flow) = self.charge(16 + announced.saturating_mul(16)) {
            return flow;
        }
        self.stack.push(Build {
            kind,
            items: Vec::with_capacity(announced.min(1024)),
        });
        Flow::Continue
    }

    fn end_aggregate(&mut self) -> Flow {
        let Some(open) = self.stack.pop() else {
            return Flow::Continue;
        };
        let value = match open.kind {
            AggKind::Array => Value::Array(open.items),
            AggKind::Set => Value::Set(open.items),
            AggKind::Push => Value::Push(open.items),
            AggKind::Map => {
                if open.items.len() % 2 != 0 {
                    return self.refuse("a RESP map has an odd number of elements".into());
                }
                let mut it = open.items.into_iter();
                let mut pairs = Vec::new();
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    pairs.push((k, v));
                }
                Value::Map(pairs)
            }
        };
        self.place(value);
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        // The text of an error is kept (a little of it) whatever the cap: it is
        // what says why a command failed.
        let limit = if kind == StrKind::Error {
            self.cap.max_bulk.max(MAX_ERROR_TEXT)
        } else {
            self.cap.max_bulk
        };
        if limit == 0 {
            return self.refuse(self.cap.hint.into());
        }
        // Decided now, from the announced length: nothing of an over-long
        // string is ever buffered.
        if let Some(len) = len {
            if len > limit {
                return self.refuse(format!("a RESP string of {len} bytes exceeds the limit of {limit} bytes"));
            }
            if let Err(flow) = self.charge(len) {
                return flow;
            }
        }
        self.text = Some(Text {
            kind,
            buf: Vec::with_capacity(len.unwrap_or(0).min(64 * 1024)),
            announced: len.is_some(),
            limit,
        });
        Flow::Continue
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        let Some(text) = self.text.as_mut() else {
            return Flow::Continue;
        };
        text.buf.extend_from_slice(data);
        if !text.announced {
            // A streamed string has no announced length: check and charge as it
            // arrives.
            let (size, limit) = (text.buf.len(), text.limit);
            if size > limit {
                return self.refuse(format!("a RESP string exceeds the limit of {limit} bytes"));
            }
            if let Err(flow) = self.charge(data.len()) {
                return flow;
            }
        }
        Flow::Continue
    }

    fn end_string(&mut self) -> Flow {
        let Some(text) = self.text.take() else {
            return Flow::Continue;
        };
        let value = match text.kind {
            StrKind::Bulk => Value::Bulk(Bytes::from(text.buf)),
            StrKind::Error => Value::Error(ServerError::parse(&String::from_utf8_lossy(&text.buf))),
            StrKind::Verbatim { format } => Value::Verbatim {
                format: String::from_utf8_lossy(&format).into_owned(),
                data: Bytes::from(text.buf),
            },
        };
        self.place(value);
        Flow::Continue
    }
}

/// Feeds a callback with each reply a [`Collector`] completes: for the tests,
/// which compare the values the parser's events make.
#[cfg(test)]
pub(crate) struct Adapter<'a> {
    pub(crate) collector: &'a mut Collector,
    pub(crate) out: &'a mut dyn FnMut(Value),
    pub(crate) error: Option<crate::resp::RespError>,
}

#[cfg(test)]
impl ReplySink for Adapter<'_> {
    fn begin_reply(&mut self, kind: crate::resp::ReplyKind) {
        self.collector.begin_reply(kind);
    }
    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        self.collector.scalar(v)
    }
    fn error(&mut self, line: &str) -> Flow {
        self.collector.error(line)
    }
    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        self.collector.begin_aggregate(kind, len)
    }
    fn end_aggregate(&mut self) -> Flow {
        self.collector.end_aggregate()
    }
    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        self.collector.begin_string(kind, len)
    }
    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        self.collector.string_chunk(data)
    }
    fn end_string(&mut self) -> Flow {
        self.collector.end_string()
    }
    fn end_reply(&mut self, _skipped: bool) {
        match self.collector.take() {
            Ok(v) => (self.out)(v),
            Err(TooLarge(why)) => {
                self.error.get_or_insert(crate::resp::RespError(why));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::RespParser;

    fn run(cap: Cap, wire: &[u8]) -> Result<Vec<Value>, crate::resp::RespError> {
        let mut p = RespParser::new();
        let mut out = Vec::new();
        let mut data = wire;
        p.feed_values_with(cap, &mut data, &mut |v| out.push(v))?;
        Ok(out)
    }

    const SMALL: Cap = Cap {
        max_bulk: 10,
        max_aggregate: 3,
        max_reply: 4096,
        hint: "over the cap",
    };

    #[test]
    fn a_cap_is_enforced_before_memory_is_reserved() {
        // A string or aggregate announced over the cap is refused when it is
        // announced, and what follows it is skipped.
        assert!(run(SMALL, b"$11\r\n01234567890\r\n").is_err(), "a bulk over the cap");
        assert!(run(SMALL, b"$10\r\n0123456789\r\n").is_ok());
        assert!(run(SMALL, b"*4\r\n:1\r\n:2\r\n:3\r\n:4\r\n").is_err(), "an aggregate over the cap");
        assert!(run(SMALL, b"*3\r\n:1\r\n:2\r\n:3\r\n").is_ok());
    }

    #[test]
    fn a_reply_over_the_total_size_cap_is_refused_and_the_next_is_not() {
        let cap = Cap {
            max_reply: 100,
            ..Cap::TEST
        };
        let mut wire = b"*3\r\n".to_vec();
        for _ in 0..3 {
            wire.extend_from_slice(b"$60\r\n");
            wire.extend_from_slice(&[b'x'; 60]);
            wire.extend_from_slice(b"\r\n");
        }
        assert!(run(cap, &wire).is_err());
        // The budget is per reply.
        let mut ten = Vec::new();
        for _ in 0..10 {
            ten.extend_from_slice(b"$60\r\n");
            ten.extend_from_slice(&[b'x'; 60]);
            ten.extend_from_slice(b"\r\n");
        }
        assert_eq!(run(cap, &ten).unwrap().len(), 10);
    }

    #[test]
    fn a_scalar_cap_takes_only_single_values_and_says_what_to_do_about_the_rest() {
        assert_eq!(run(Cap::SCALAR, b":5\r\n").unwrap(), vec![Value::Int(5)]);
        assert_eq!(run(Cap::SCALAR, b"+OK\r\n").unwrap(), vec![Value::Simple("OK".into())]);
        assert_eq!(run(Cap::SCALAR, b"_\r\n").unwrap(), vec![Value::Null]);
        for wire in [&b"$1\r\nx\r\n"[..], b"*1\r\n:1\r\n", b"%0\r\n", b"~0\r\n"] {
            let e = run(Cap::SCALAR, wire).unwrap_err();
            assert!(e.0.contains("send_streaming"), "{e}");
        }
        // An error is still an error, and its text is kept: that says why a command failed.
        assert!(matches!(run(Cap::SCALAR, b"-ERR no\r\n").unwrap()[0], Value::Error(_)));
        assert!(matches!(run(Cap::SCALAR, b"!7\r\nERR bad\r\n").unwrap()[0], Value::Error(_)));
    }

    #[test]
    fn a_pair_and_a_short_string_have_room_for_exactly_that() {
        assert_eq!(run(Cap::PAIR, b"*2\r\n:1\r\n:0\r\n").unwrap().len(), 1);
        assert!(run(Cap::PAIR, b"*3\r\n:1\r\n:0\r\n:0\r\n").is_err());
        assert!(run(Cap::PAIR, b"$1\r\nx\r\n").is_err());
        assert_eq!(run(Cap::SHORT, b"$3\r\nabc\r\n").unwrap().len(), 1);
        assert!(run(Cap::SHORT, &[b"$300\r\n".as_slice(), &[b'x'; 300], b"\r\n"].concat()).is_err());
        assert!(run(Cap::SHORT, b"*1\r\n:1\r\n").is_err());
    }
}
