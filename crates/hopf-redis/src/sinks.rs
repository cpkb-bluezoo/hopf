// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reply shapes: [`ReplySink`]s for the common forms of a reply, so that nobody
//! has to write a state machine over the raw events.
//!
//! The rule they follow is the one the whole crate follows: *payloads stream,
//! identifiers are bounded and delivered whole*. A value, a list element or a
//! hash value is a payload, and arrives only as chunks; a key or a hash field
//! name is an identifier, and arrives whole, up to a limit
//! ([`DEFAULT_MAX_FIELD`] unless set), past which that reply fails with
//! [`RedisError::FieldTooLong`] and is skipped.
//!
//! | sink | the reply is | for |
//! |---|---|---|
//! | [`BulkSink`] | one string, or null | `GET`, `GETRANGE`, `HGET`, `LPOP`, `DUMP`, `INFO` |
//! | [`ElementsSink`] | an array of payload strings, some perhaps null | `MGET`, `LRANGE`, `SMEMBERS`, `ZRANGE` |
//! | [`KeysSink`] | an array of identifiers | `KEYS`, `SMEMBERS` of keys |
//! | [`FieldsSink`] | a map, or flat pairs, of identifier to payload | `HGETALL` |
//!
//! An error reply, or a reply of some other shape, ends the command with
//! [`RedisError::Server`] or [`RedisError::Unexpected`] in the handler's
//! `finished`, and the rest of the reply is skipped. For any other shape,
//! implement [`ReplySink`] directly.

use crate::client::{Deadline, RedisClient, StreamHandle};
use crate::cluster::RedisCluster;
use crate::error::RedisError;
use crate::resp::{AggKind, Flow, ReplySink, Scalar, ServerError, StrKind};
use crate::Command;

/// The longest identifier (a key, a hash field name) the shape sinks deliver,
/// unless told otherwise.
pub const DEFAULT_MAX_FIELD: usize = 64 * 1024;

/// The most of a bulk error's text that is kept to say what the error was.
const MAX_ERROR_TEXT: usize = 4096;

/// Prefer how the command ended to a problem the shape found, but not a
/// cancellation that the problem caused.
fn merge(outcome: Result<(), RedisError>, problem: Option<RedisError>) -> Result<(), RedisError> {
    match (outcome, problem) {
        (Ok(()) | Err(RedisError::Cancelled), Some(p)) => Err(p),
        (outcome, _) => outcome,
    }
}

/// What is common to the shapes: a problem found, and the text of a bulk error
/// being read.
#[derive(Default)]
struct Common {
    problem: Option<RedisError>,
    /// The text of a bulk error (`!`) in progress.
    error_text: Option<Vec<u8>>,
}

impl Common {
    fn mismatch(&mut self, expected: &str) -> Flow {
        self.problem
            .get_or_insert_with(|| RedisError::Unexpected(format!("expected {expected}")));
        Flow::Skip
    }

    fn server_error(&mut self, line: &str) -> Flow {
        self.problem.get_or_insert_with(|| RedisError::Server(ServerError::parse(line)));
        Flow::Skip
    }

    fn begin_error_text(&mut self) {
        self.error_text = Some(Vec::new());
    }

    /// Keep the start of a bulk error's text. Returns whether it is one.
    fn error_chunk(&mut self, data: &[u8]) -> bool {
        match self.error_text.as_mut() {
            Some(text) => {
                let room = MAX_ERROR_TEXT.saturating_sub(text.len());
                text.extend_from_slice(&data[..data.len().min(room)]);
                true
            }
            None => false,
        }
    }

    fn end_error_text(&mut self) -> bool {
        match self.error_text.take() {
            Some(text) => {
                self.server_error(&String::from_utf8_lossy(&text));
                true
            }
            None => false,
        }
    }
}

// ---- a single string ----

/// What a [`BulkSink`] tells: one string, or null.
pub trait BulkHandler: Send {
    /// The reply is null: no such key, no such element.
    fn nil(&mut self) {}
    /// The string begins. `len` is its length in bytes, if announced.
    fn begin(&mut self, _len: Option<u64>) {}
    /// The next bytes of the string, never empty. Return [`Flow::Pause`] to wait
    /// (and [`StreamHandle::resume`] later) or [`Flow::Skip`] to stop.
    fn chunk(&mut self, data: &[u8]) -> Flow;
    /// The string is complete.
    fn end(&mut self) {}
    /// The command is over: this is the last call. `Err` is a server error, a
    /// reply that was not a string, or any failure of the command.
    fn finished(&mut self, outcome: Result<(), RedisError>);
}

/// A [`ReplySink`] for a reply that is one string, or null. See the
/// [crate documentation](crate).
pub struct BulkSink<H> {
    handler: H,
    common: Common,
    in_string: bool,
}

impl<H: BulkHandler> BulkSink<H> {
    /// A sink that tells `handler`.
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            common: Common::default(),
            in_string: false,
        }
    }
}

impl<H: BulkHandler> ReplySink for BulkSink<H> {
    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        match v {
            Scalar::Null => {
                self.handler.nil();
                Flow::Continue
            }
            _ => self.common.mismatch("a string"),
        }
    }

    fn error(&mut self, line: &str) -> Flow {
        self.common.server_error(line)
    }

    fn begin_aggregate(&mut self, _kind: AggKind, _len: Option<usize>) -> Flow {
        self.common.mismatch("a string")
    }

    fn end_aggregate(&mut self) -> Flow {
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        match kind {
            StrKind::Error => {
                self.common.begin_error_text();
                Flow::Continue
            }
            _ => {
                self.in_string = true;
                self.handler.begin(len.map(|n| n as u64));
                Flow::Continue
            }
        }
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        if self.common.error_chunk(data) {
            return Flow::Continue;
        }
        self.handler.chunk(data)
    }

    fn end_string(&mut self) -> Flow {
        if self.common.end_error_text() {
            return Flow::Continue;
        }
        if std::mem::take(&mut self.in_string) {
            self.handler.end();
        }
        Flow::Continue
    }

    fn finished(&mut self, outcome: Result<(), RedisError>) {
        let outcome = merge(outcome, self.common.problem.take());
        self.handler.finished(outcome);
    }
}

// ---- an array of payloads ----

/// What an [`ElementsSink`] tells: an array of strings.
pub trait ElementsHandler: Send {
    /// The array begins, with its length if announced.
    fn begin(&mut self, _len: Option<usize>) {}
    /// Element `index` is null.
    fn nil(&mut self, _index: usize) {}
    /// Element `index` begins, with its length in bytes if announced.
    fn element_begin(&mut self, _index: usize, _len: Option<u64>) {}
    /// The next bytes of element `index`, never empty. Return [`Flow::Pause`] to
    /// wait or [`Flow::Skip`] to stop.
    fn element_chunk(&mut self, index: usize, data: &[u8]) -> Flow;
    /// Element `index` is complete.
    fn element_end(&mut self, _index: usize) {}
    /// The command is over: this is the last call.
    fn finished(&mut self, outcome: Result<(), RedisError>);
}

/// A [`ReplySink`] for a reply that is an array of payload strings. See the
/// [crate documentation](crate).
pub struct ElementsSink<H> {
    handler: H,
    common: Common,
    depth: usize,
    index: usize,
    in_element: bool,
}

impl<H: ElementsHandler> ElementsSink<H> {
    /// A sink that tells `handler`.
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            common: Common::default(),
            depth: 0,
            index: 0,
            in_element: false,
        }
    }
}

impl<H: ElementsHandler> ReplySink for ElementsSink<H> {
    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        match (self.depth, v) {
            (1, Scalar::Null) => {
                self.handler.nil(self.index);
                self.index += 1;
                Flow::Continue
            }
            (0, _) => self.common.mismatch("an array"),
            _ => self.common.mismatch("an array of strings"),
        }
    }

    fn error(&mut self, line: &str) -> Flow {
        self.common.server_error(line)
    }

    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        match (self.depth, kind) {
            (0, AggKind::Array | AggKind::Set) => {
                self.depth = 1;
                self.handler.begin(len);
                Flow::Continue
            }
            (0, _) => self.common.mismatch("an array"),
            _ => self.common.mismatch("an array of strings"),
        }
    }

    fn end_aggregate(&mut self) -> Flow {
        self.depth = self.depth.saturating_sub(1);
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        if self.depth != 1 {
            return self.common.mismatch("an array");
        }
        match kind {
            StrKind::Error => {
                self.common.begin_error_text();
                Flow::Continue
            }
            _ => {
                self.in_element = true;
                self.handler.element_begin(self.index, len.map(|n| n as u64));
                Flow::Continue
            }
        }
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        if self.common.error_chunk(data) {
            return Flow::Continue;
        }
        self.handler.element_chunk(self.index, data)
    }

    fn end_string(&mut self) -> Flow {
        if self.common.end_error_text() {
            return Flow::Skip;
        }
        if std::mem::take(&mut self.in_element) {
            self.handler.element_end(self.index);
            self.index += 1;
        }
        Flow::Continue
    }

    fn finished(&mut self, outcome: Result<(), RedisError>) {
        let outcome = merge(outcome, self.common.problem.take());
        self.handler.finished(outcome);
    }
}

// ---- identifiers, whole ----

/// An identifier being assembled, whole, under a limit.
pub(crate) struct Whole {
    buf: Vec<u8>,
    max: usize,
}

impl Whole {
    pub(crate) fn new(max: usize) -> Self {
        Self { buf: Vec::new(), max }
    }

    /// What has been assembled.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// An identifier begins; `Err` if it is announced as too long.
    pub(crate) fn begin(&mut self, len: Option<usize>) -> Result<(), RedisError> {
        self.buf.clear();
        if len.is_some_and(|n| n > self.max) {
            return Err(RedisError::FieldTooLong { limit: self.max });
        }
        self.buf.reserve(len.unwrap_or(0).min(self.max));
        Ok(())
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Result<(), RedisError> {
        if self.buf.len() + data.len() > self.max {
            return Err(RedisError::FieldTooLong { limit: self.max });
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }
}

/// What a [`KeysSink`] tells: an array of identifiers.
pub trait KeysHandler: Send {
    /// The array begins, with its length if announced.
    fn begin(&mut self, _len: Option<usize>) {}
    /// The next identifier, whole. Return [`Flow::Pause`] to wait or
    /// [`Flow::Skip`] to stop.
    fn key(&mut self, key: &[u8]) -> Flow;
    /// The command is over: this is the last call.
    fn finished(&mut self, outcome: Result<(), RedisError>);
}

/// A [`ReplySink`] for a reply that is an array of identifiers, each delivered
/// whole. See the [crate documentation](crate).
pub struct KeysSink<H> {
    handler: H,
    common: Common,
    depth: usize,
    key: Whole,
}

impl<H: KeysHandler> KeysSink<H> {
    /// A sink that tells `handler`, with identifiers of up to
    /// [`DEFAULT_MAX_FIELD`] bytes.
    pub fn new(handler: H) -> Self {
        Self::with_max_field(handler, DEFAULT_MAX_FIELD)
    }

    /// A sink that tells `handler`, with identifiers of up to `max_field` bytes.
    pub fn with_max_field(handler: H, max_field: usize) -> Self {
        Self {
            handler,
            common: Common::default(),
            depth: 0,
            key: Whole::new(max_field),
        }
    }

    fn fail(&mut self, e: RedisError) -> Flow {
        self.common.problem.get_or_insert(e);
        Flow::Skip
    }
}

impl<H: KeysHandler> ReplySink for KeysSink<H> {
    fn scalar(&mut self, _v: Scalar<'_>) -> Flow {
        self.common.mismatch("an array of strings")
    }

    fn error(&mut self, line: &str) -> Flow {
        self.common.server_error(line)
    }

    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        match (self.depth, kind) {
            (0, AggKind::Array | AggKind::Set) => {
                self.depth = 1;
                self.handler.begin(len);
                Flow::Continue
            }
            _ => self.common.mismatch("an array of strings"),
        }
    }

    fn end_aggregate(&mut self) -> Flow {
        self.depth = self.depth.saturating_sub(1);
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        if self.depth != 1 {
            return self.common.mismatch("an array");
        }
        if kind == StrKind::Error {
            self.common.begin_error_text();
            return Flow::Continue;
        }
        match self.key.begin(len) {
            Ok(()) => Flow::Continue,
            Err(e) => self.fail(e),
        }
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        if self.common.error_chunk(data) {
            return Flow::Continue;
        }
        match self.key.push(data) {
            Ok(()) => Flow::Continue,
            Err(e) => self.fail(e),
        }
    }

    fn end_string(&mut self) -> Flow {
        if self.common.end_error_text() {
            return Flow::Skip;
        }
        self.handler.key(&self.key.buf)
    }

    fn finished(&mut self, outcome: Result<(), RedisError>) {
        let outcome = merge(outcome, self.common.problem.take());
        self.handler.finished(outcome);
    }
}

// ---- identifier to payload ----

/// What a [`FieldsSink`] tells: a map, or flat pairs, of identifier to payload.
pub trait FieldsHandler: Send {
    /// The reply begins, with its number of pairs if announced.
    fn begin(&mut self, _pairs: Option<usize>) {}
    /// The next field name, whole. Return [`Flow::Pause`] to wait or
    /// [`Flow::Skip`] to stop.
    fn field(&mut self, field: &[u8]) -> Flow;
    /// The value of the field just given is null.
    fn value_nil(&mut self) {}
    /// The value of the field just given begins, with its length in bytes if
    /// announced.
    fn value_begin(&mut self, _len: Option<u64>) {}
    /// The next bytes of the value, never empty.
    fn value_chunk(&mut self, data: &[u8]) -> Flow;
    /// The value is complete.
    fn value_end(&mut self) {}
    /// The command is over: this is the last call.
    fn finished(&mut self, outcome: Result<(), RedisError>);
}

/// A [`ReplySink`] for a reply that is a map, or an array of flat pairs, from an
/// identifier (delivered whole) to a payload (streamed): `HGETALL`. See the
/// [crate documentation](crate).
pub struct FieldsSink<H> {
    handler: H,
    common: Common,
    depth: usize,
    /// Elements seen: even ones are field names, odd ones are values.
    index: usize,
    field: Whole,
    in_value: bool,
}

impl<H: FieldsHandler> FieldsSink<H> {
    /// A sink that tells `handler`, with field names of up to
    /// [`DEFAULT_MAX_FIELD`] bytes.
    pub fn new(handler: H) -> Self {
        Self::with_max_field(handler, DEFAULT_MAX_FIELD)
    }

    /// A sink that tells `handler`, with field names of up to `max_field` bytes.
    pub fn with_max_field(handler: H, max_field: usize) -> Self {
        Self {
            handler,
            common: Common::default(),
            depth: 0,
            index: 0,
            field: Whole::new(max_field),
            in_value: false,
        }
    }

    fn fail(&mut self, e: RedisError) -> Flow {
        self.common.problem.get_or_insert(e);
        Flow::Skip
    }

    fn at_field(&self) -> bool {
        self.index % 2 == 0
    }
}

impl<H: FieldsHandler> ReplySink for FieldsSink<H> {
    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        match (self.depth, self.at_field(), v) {
            (1, false, Scalar::Null) => {
                self.handler.value_nil();
                self.index += 1;
                Flow::Continue
            }
            (0, _, _) => self.common.mismatch("a map or an array of pairs"),
            _ => self.common.mismatch("pairs of strings"),
        }
    }

    fn error(&mut self, line: &str) -> Flow {
        self.common.server_error(line)
    }

    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        match (self.depth, kind) {
            (0, AggKind::Map) => {
                self.depth = 1;
                self.handler.begin(len);
                Flow::Continue
            }
            (0, AggKind::Array) => {
                self.depth = 1;
                self.handler.begin(len.map(|n| n / 2));
                Flow::Continue
            }
            (0, _) => self.common.mismatch("a map or an array of pairs"),
            _ => self.common.mismatch("pairs of strings"),
        }
    }

    fn end_aggregate(&mut self) -> Flow {
        self.depth = self.depth.saturating_sub(1);
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        if self.depth != 1 {
            return self.common.mismatch("a map or an array of pairs");
        }
        if kind == StrKind::Error {
            self.common.begin_error_text();
            return Flow::Continue;
        }
        if self.at_field() {
            match self.field.begin(len) {
                Ok(()) => Flow::Continue,
                Err(e) => self.fail(e),
            }
        } else {
            self.in_value = true;
            self.handler.value_begin(len.map(|n| n as u64));
            Flow::Continue
        }
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        if self.common.error_chunk(data) {
            return Flow::Continue;
        }
        if self.at_field() {
            match self.field.push(data) {
                Ok(()) => Flow::Continue,
                Err(e) => self.fail(e),
            }
        } else {
            self.handler.value_chunk(data)
        }
    }

    fn end_string(&mut self) -> Flow {
        if self.common.end_error_text() {
            return Flow::Skip;
        }
        let flow = if self.at_field() {
            self.handler.field(&self.field.buf)
        } else if std::mem::take(&mut self.in_value) {
            self.handler.value_end();
            Flow::Continue
        } else {
            Flow::Continue
        };
        self.index += 1;
        flow
    }

    fn finished(&mut self, outcome: Result<(), RedisError>) {
        let outcome = merge(outcome, self.common.problem.take());
        self.handler.finished(outcome);
    }
}

// ---- commands, as sugar ----

fn keyed(name: &str, key: impl AsRef<[u8]>) -> Command {
    Command::new(name).arg(key)
}

/// The streaming methods, for a client and for a cluster alike.
macro_rules! stream_methods {
    ($ty:ty) => {
        impl $ty {
        /// `GET`: the value goes to `handler` as chunks, whatever its size.
        pub fn get(&self, key: impl AsRef<[u8]>, handler: impl BulkHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("GET", key), BulkSink::new(handler))
        }

        /// `GETDEL`: the value goes to `handler` as chunks.
        pub fn getdel(&self, key: impl AsRef<[u8]>, handler: impl BulkHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("GETDEL", key), BulkSink::new(handler))
        }

        /// `GETRANGE key start end`: the bytes go to `handler` as chunks.
        pub fn getrange(
            &self,
            key: impl AsRef<[u8]>,
            start: i64,
            end: i64,
            handler: impl BulkHandler + 'static,
        ) -> StreamHandle {
            let command = keyed("GETRANGE", key).arg(start.to_string()).arg(end.to_string());
            self.send_streaming(&command, BulkSink::new(handler))
        }

        /// `HGET`: the value goes to `handler` as chunks.
        pub fn hget(
            &self,
            key: impl AsRef<[u8]>,
            field: impl AsRef<[u8]>,
            handler: impl BulkHandler + 'static,
        ) -> StreamHandle {
            self.send_streaming(&keyed("HGET", key).arg(field), BulkSink::new(handler))
        }

        /// `LINDEX`: the value goes to `handler` as chunks.
        pub fn lindex(&self, key: impl AsRef<[u8]>, index: i64, handler: impl BulkHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("LINDEX", key).arg(index.to_string()), BulkSink::new(handler))
        }

        /// `LPOP`: the value goes to `handler` as chunks.
        pub fn lpop(&self, key: impl AsRef<[u8]>, handler: impl BulkHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("LPOP", key), BulkSink::new(handler))
        }

        /// `RPOP`: the value goes to `handler` as chunks.
        pub fn rpop(&self, key: impl AsRef<[u8]>, handler: impl BulkHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("RPOP", key), BulkSink::new(handler))
        }

        /// `MGET`: each value goes to `handler` as chunks, in key order.
        pub fn mget(&self, keys: &[impl AsRef<[u8]>], handler: impl ElementsHandler + 'static) -> StreamHandle {
            let command = Command::new("MGET").args(keys);
            self.send_streaming(&command, ElementsSink::new(handler))
        }

        /// `HMGET`: each value goes to `handler` as chunks, in field order.
        pub fn hmget(
            &self,
            key: impl AsRef<[u8]>,
            fields: &[impl AsRef<[u8]>],
            handler: impl ElementsHandler + 'static,
        ) -> StreamHandle {
            self.send_streaming(&keyed("HMGET", key).args(fields), ElementsSink::new(handler))
        }

        /// `LRANGE`: each element goes to `handler` as chunks.
        pub fn lrange(
            &self,
            key: impl AsRef<[u8]>,
            start: i64,
            stop: i64,
            handler: impl ElementsHandler + 'static,
        ) -> StreamHandle {
            let command = keyed("LRANGE", key).arg(start.to_string()).arg(stop.to_string());
            self.send_streaming(&command, ElementsSink::new(handler))
        }

        /// `SMEMBERS`: each member goes to `handler` as chunks.
        pub fn smembers(&self, key: impl AsRef<[u8]>, handler: impl ElementsHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("SMEMBERS", key), ElementsSink::new(handler))
        }

        /// `ZRANGE key start stop`: each member goes to `handler` as chunks.
        pub fn zrange(
            &self,
            key: impl AsRef<[u8]>,
            start: i64,
            stop: i64,
            handler: impl ElementsHandler + 'static,
        ) -> StreamHandle {
            let command = keyed("ZRANGE", key).arg(start.to_string()).arg(stop.to_string());
            self.send_streaming(&command, ElementsSink::new(handler))
        }

        /// `HGETALL`: each field name whole, each value as chunks.
        pub fn hgetall(&self, key: impl AsRef<[u8]>, handler: impl FieldsHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("HGETALL", key), FieldsSink::new(handler))
        }

        /// `EVAL script numkeys key... arg...`: the script's result is told to
        /// `sink` as the events of a reply, however large and of whatever shape.
        /// Use a [`ReplySink`] of your own, or one of the shapes if the script
        /// returns one.
        pub fn eval(
            &self,
            script: impl AsRef<[u8]>,
            keys: &[impl AsRef<[u8]>],
            args: &[impl AsRef<[u8]>],
            sink: impl ReplySink + Send + 'static,
        ) -> StreamHandle {
            let command = Command::new("EVAL").arg(script).arg(keys.len().to_string()).args(keys).args(args);
            self.send_streaming(&command, sink)
        }

        /// `EVALSHA sha1 numkeys key... arg...`, as [`eval`](Self::eval). A server
        /// that has not seen the script answers a `NOSCRIPT` error, which the
        /// sink is told as an error reply: load the script with
        /// [`script_load`](Self::script_load) and try again.
        pub fn evalsha(
            &self,
            sha1: impl AsRef<[u8]>,
            keys: &[impl AsRef<[u8]>],
            args: &[impl AsRef<[u8]>],
            sink: impl ReplySink + Send + 'static,
        ) -> StreamHandle {
            let command = Command::new("EVALSHA").arg(sha1).arg(keys.len().to_string()).args(keys).args(args);
            self.send_streaming(&command, sink)
        }

        /// `KEYS pattern`, each key whole.
        pub fn keys(&self, pattern: impl AsRef<[u8]>, handler: impl KeysHandler + 'static) -> StreamHandle {
            self.send_streaming(&keyed("KEYS", pattern), KeysSink::new(handler))
        }

        /// [`get`](Self::get) with a deadline of its own.
        pub fn get_with_deadline(
            &self,
            key: impl AsRef<[u8]>,
            deadline: Deadline,
            handler: impl BulkHandler + 'static,
        ) -> StreamHandle {
            self.send_streaming_with_deadline(&keyed("GET", key), deadline, BulkSink::new(handler))
        }
        }
    };
}

stream_methods!(RedisClient);
stream_methods!(RedisCluster);
