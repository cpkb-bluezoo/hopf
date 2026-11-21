// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Assembling a reply into a [`Value`] from the parser's events.
//!
//! Transitional: it is what lets the callbacks that still take a [`Value`] be
//! fed from the event parser, and it goes when they do. It is the only place
//! the crate builds a value, and it does so under a budget: a string longer than
//! [`RespLimits::max_bulk`] is never buffered, not even its first chunk, and a
//! reply that outgrows [`RespLimits::max_reply_bytes`] drops what it has built;
//! either way it returns [`Flow::Skip`], the rest of the reply is discarded in
//! constant memory, and the connection stays in step.

use hopf_core::Bytes;

use crate::resp::{AggKind, Flow, ReplySink, RespError, RespLimits, Scalar, ServerError, StrKind, Value};

struct Build {
    kind: AggKind,
    items: Vec<Value>,
}

struct Text {
    kind: StrKind,
    buf: Vec<u8>,
    /// The length was announced, and so was checked and charged when it began.
    announced: bool,
}

/// Why a reply was not assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TooLarge(pub String);

/// Builds one reply at a time; reused for the next.
pub(crate) struct Collector {
    max_bulk: usize,
    max_aggregate: usize,
    max_reply: usize,
    stack: Vec<Build>,
    text: Option<Text>,
    done: Option<Value>,
    /// Memory the reply under construction has taken so far.
    bytes: usize,
    refused: Option<TooLarge>,
}

impl Collector {
    pub(crate) fn new(limits: &RespLimits) -> Self {
        Self {
            max_bulk: limits.max_bulk,
            max_aggregate: limits.max_aggregate,
            max_reply: limits.max_reply_bytes,
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
        if self.bytes > self.max_reply {
            return Err(self.refuse(format!("a RESP reply exceeds the size limit of {} bytes", self.max_reply)));
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
        if announced > self.max_aggregate {
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
        // Decided now, from the announced length: nothing of an over-long
        // string is ever buffered.
        if let Some(len) = len {
            if len > self.max_bulk {
                return self.refuse(format!("a RESP string of {len} bytes exceeds the limit of {} bytes", self.max_bulk));
            }
            if let Err(flow) = self.charge(len) {
                return flow;
            }
        }
        self.text = Some(Text {
            kind,
            buf: Vec::with_capacity(len.unwrap_or(0).min(64 * 1024)),
            announced: len.is_some(),
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
            let size = text.buf.len();
            if size > self.max_bulk {
                return self.refuse(format!("a RESP string exceeds the limit of {} bytes", self.max_bulk));
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

/// Feeds a callback with each reply a [`Collector`] completes: what
/// [`RespParser::feed_values`](crate::resp::RespParser::feed_values) is built on.
pub(crate) struct Adapter<'a> {
    pub(crate) collector: &'a mut Collector,
    pub(crate) out: &'a mut dyn FnMut(Value),
    pub(crate) error: Option<RespError>,
}

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
                self.error.get_or_insert(RespError(why));
            }
        }
    }
}
