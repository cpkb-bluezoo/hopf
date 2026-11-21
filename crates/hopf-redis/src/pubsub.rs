// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Publish/subscribe and push messages.
//!
//! A connection that has subscribed to channels cannot be used for ordinary
//! commands (in RESP2 the server refuses them), and what it receives are not
//! replies: they arrive when someone publishes. So subscriptions live on a
//! connection of their own, a [`RedisSubscriber`]: it reconnects by itself,
//! subscribes again to everything on the new connection, and tells a
//! [`SubscriberHandler`] of each message and each change of subscription.
//!
//! # Messages stream
//!
//! A message is the crate's rule in miniature. The channel (and the pattern, for
//! a pattern subscription) is an *identifier*: delivered whole in a
//! [`MessageHeader`], up to [`RedisConfig::max_field`]. The body is a *payload*:
//! delivered as chunks, however large, with nothing held. So a handler never
//! holds more of a message than it chooses to, a body of any size costs the same
//! constant memory, and a handler that cannot take more now can pause the
//! connection ([`Flow::Pause`], then [`RedisSubscriber::resume`]) and let TCP
//! hold the server back.
//!
//! A handler that wants a message it knows to be small accumulates it in its own
//! `message_chunk`, with its own limit and `Flow::Skip` for a message that
//! exceeds it; the library offers no call that does so for it.
//!
//! A message that cannot be delivered is dropped on its own, in constant memory,
//! and the handler is told ([`SubscriberHandler::on_dropped`]): its channel was
//! longer than `max_field`, or it was not shaped as a message is. Neither
//! disturbs the messages after it, or the connection.
//!
//! Publishing is an ordinary command, [`RedisClient::publish`](crate::RedisClient::publish)
//! and [`spublish`](crate::RedisClient::spublish), on a [`RedisClient`](crate::RedisClient).
//!
//! # Pushes
//!
//! RESP3 also lets a server push data to any connection: a key invalidation
//! (`CLIENT TRACKING`), for one. A command connection gives each push to a sink
//! of the application's own, as the events of a reply:
//! [`RedisClient::set_push_sink`](crate::RedisClient::set_push_sink), and for a
//! cluster [`RedisCluster::set_push_sinks`](crate::RedisCluster::set_push_sinks).
//! [`InvalidationSink`] is the ready one for invalidations, which is what
//! pushes nearly always are.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hopf_core::{Bytes, Endpoint};

use crate::client::{self, Inner, Phase};
use crate::error::RedisError;
use crate::resp::{encode_command, AggKind, Flow, ReplyKind, ReplySink, Scalar, ServerError, StrKind};
use crate::sinks::Whole;
use crate::RedisConfig;

/// Where a message was published to, as a subscriber heard it. The channel and
/// the pattern are identifiers: whole, and no longer than
/// [`RedisConfig::max_field`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageHeader<'a> {
    /// Published to a channel subscribed to by name (`SUBSCRIBE`).
    Channel {
        /// The channel.
        channel: &'a [u8],
    },
    /// Published to a channel matching a pattern subscribed to (`PSUBSCRIBE`).
    Pattern {
        /// The pattern that matched.
        pattern: &'a [u8],
        /// The channel published to.
        channel: &'a [u8],
    },
    /// Published to a shard channel (`SSUBSCRIBE`, `SPUBLISH`; Redis 7).
    Shard {
        /// The shard channel.
        channel: &'a [u8],
    },
}

impl<'a> MessageHeader<'a> {
    /// The channel published to.
    pub fn channel(&self) -> &'a [u8] {
        match *self {
            Self::Channel { channel } | Self::Pattern { channel, .. } | Self::Shard { channel } => channel,
        }
    }

    /// The pattern that matched, for a pattern subscription.
    pub fn pattern(&self) -> Option<&'a [u8]> {
        match *self {
            Self::Pattern { pattern, .. } => Some(pattern),
            _ => None,
        }
    }

    /// Which kind of subscription this message came through.
    pub fn kind(&self) -> SubscriptionKind {
        match self {
            Self::Channel { .. } => SubscriptionKind::Channel,
            Self::Pattern { .. } => SubscriptionKind::Pattern,
            Self::Shard { .. } => SubscriptionKind::Shard,
        }
    }
}

/// What a subscription names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionKind {
    /// A channel (`SUBSCRIBE`).
    Channel,
    /// A pattern (`PSUBSCRIBE`).
    Pattern,
    /// A shard channel (`SSUBSCRIBE`).
    Shard,
}

/// The server's acknowledgement of a change of subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionChange {
    /// A subscription is in place. `count` is how many the connection has of
    /// this kind (of every kind, for channels and patterns).
    Subscribed {
        /// Channel, pattern or shard channel.
        kind: SubscriptionKind,
        /// What was subscribed to.
        name: Bytes,
        /// The connection's subscription count.
        count: i64,
    },
    /// A subscription is gone. `name` is `None` when `UNSUBSCRIBE` with no
    /// arguments found nothing to remove.
    Unsubscribed {
        /// Channel, pattern or shard channel.
        kind: SubscriptionKind,
        /// What was unsubscribed from.
        name: Option<Bytes>,
        /// The connection's subscription count.
        count: i64,
    },
}

/// What a subscriber's connection reports. Called on the reactor the
/// subscriber is bound to, one call at a time, in the order things happened.
///
/// A message arrives as [`message_begin`](Self::message_begin), any number of
/// [`message_chunk`](Self::message_chunk)s, then
/// [`message_end`](Self::message_end). Each of the first two returns a [`Flow`]:
/// [`Flow::Skip`] drops the rest of that message only (and no `message_end`
/// follows), [`Flow::Pause`] stops the connection being read until
/// [`RedisSubscriber::resume`]. A message that has begun and not ended when the
/// connection is lost is abandoned: `on_disconnected` is what follows.
pub trait SubscriberHandler: Send {
    /// A message begins. `len` is the body's length, or `None` if the server
    /// is sending it as a RESP3 streamed string.
    fn message_begin(&mut self, header: &MessageHeader<'_>, len: Option<u64>) -> Flow;

    /// The next bytes of the message's body, never empty. Called in order, any
    /// number of times, with nothing held by the library.
    fn message_chunk(&mut self, data: &[u8]) -> Flow;

    /// The message is complete.
    fn message_end(&mut self) {}

    /// The server acknowledged a subscription or an unsubscription.
    fn on_subscription(&mut self, _change: SubscriptionChange) {}

    /// The server pushed something this crate does not interpret (a RESP3 push
    /// such as `invalidate`, or a type a newer server adds), of the given
    /// `kind`. Return a sink to be given it, as the events of a reply from its
    /// kind on (it sees the whole push, the kind included), or `None` to
    /// discard it. [`InvalidationSink`] is one for invalidations. The sink may
    /// answer [`Flow::Skip`] but not pause: a push is not a stream.
    fn on_push(&mut self, _kind: &str) -> Option<Box<dyn ReplySink + Send>> {
        None
    }

    /// A message was dropped, on its own, in constant memory: its channel was
    /// longer than [`RedisConfig::max_field`]
    /// ([`FieldTooLong`](RedisError::FieldTooLong)), or what the server sent was
    /// not shaped as a message ([`Protocol`](RedisError::Protocol)). The
    /// connection and the next messages are unaffected. Count these: a handler
    /// that never hears of one has seen every message.
    fn on_dropped(&mut self, _why: &RedisError) {}

    /// The server refused something with an error reply, for example a
    /// subscription an ACL forbids (`NOPERM`).
    fn on_error(&mut self, _error: ServerError) {}

    /// The connection is up and every subscription has been (re)sent.
    /// `reconnect` is `false` the first time.
    fn on_connected(&mut self, _reconnect: bool) {}

    /// An established connection ended. The subscriber dials again on its own
    /// and subscribes again to everything; messages published meanwhile are
    /// not delivered (Redis does not keep them).
    fn on_disconnected(&mut self, _reason: &RedisError) {}
}

/// What an [`InvalidationSink`] tells: what a server said has changed, for a
/// client that caches (`CLIENT TRACKING`).
pub trait InvalidationHandler: Send {
    /// This key has changed. A key is an identifier: whole, and no longer than
    /// the sink's limit.
    fn key(&mut self, key: &[u8]);

    /// Everything may have changed: a `FLUSHALL` or `FLUSHDB`, or a key too long
    /// to deliver whole. Being told too much is safe, where being told too
    /// little is not, so an invalidation that cannot be delivered precisely
    /// is delivered as this.
    fn all(&mut self);
}

/// A [`ReplySink`] for RESP3 `invalidate` pushes, telling an
/// [`InvalidationHandler`]. Any other kind of push is discarded. Set it with
/// [`RedisClient::set_push_sink`](crate::RedisClient::set_push_sink), or return
/// it from [`SubscriberHandler::on_push`].
pub struct InvalidationSink<H> {
    handler: H,
    stage: InvStage,
    kind: Whole,
    key: Whole,
    /// The key being read is too long: its remaining chunks are not kept.
    over: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InvStage {
    Idle,
    /// In the push; the kind is next.
    Kind,
    KindText,
    /// The kind was `invalidate`; its subject is next.
    Subject,
    /// In the array of keys.
    Keys,
    KeyText,
    /// Nothing more of this push is wanted.
    Done,
}

/// The longest push kind an [`InvalidationSink`] reads to compare.
const MAX_KIND: usize = 64;

impl<H: InvalidationHandler> InvalidationSink<H> {
    /// A sink that tells `handler`, with keys of up to
    /// [`DEFAULT_MAX_FIELD`](crate::DEFAULT_MAX_FIELD) bytes.
    pub fn new(handler: H) -> Self {
        Self::with_max_field(handler, crate::DEFAULT_MAX_FIELD)
    }

    /// A sink that tells `handler`, with keys of up to `max_field` bytes.
    pub fn with_max_field(handler: H, max_field: usize) -> Self {
        Self {
            handler,
            stage: InvStage::Idle,
            kind: Whole::new(MAX_KIND),
            key: Whole::new(max_field),
            over: false,
        }
    }

    /// The handler.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Stop reading this push.
    fn ignore(&mut self) -> Flow {
        self.stage = InvStage::Done;
        Flow::Skip
    }

    /// A key could not be delivered: say everything may have changed, once.
    fn everything(&mut self) -> Flow {
        self.handler.all();
        self.ignore()
    }
}

impl<H: InvalidationHandler> ReplySink for InvalidationSink<H> {
    fn begin_reply(&mut self, _kind: ReplyKind) {
        self.stage = InvStage::Idle;
        self.over = false;
    }

    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        match (self.stage, v) {
            (InvStage::Subject, Scalar::Null) => {
                self.handler.all();
                self.stage = InvStage::Done;
                Flow::Continue
            }
            (InvStage::Done, _) => Flow::Continue,
            _ => self.ignore(),
        }
    }

    fn error(&mut self, _line: &str) -> Flow {
        self.ignore()
    }

    fn begin_aggregate(&mut self, kind: AggKind, _len: Option<usize>) -> Flow {
        match (self.stage, kind) {
            (InvStage::Idle, AggKind::Push | AggKind::Array) => {
                self.stage = InvStage::Kind;
                Flow::Continue
            }
            (InvStage::Subject, AggKind::Array | AggKind::Set) => {
                self.stage = InvStage::Keys;
                Flow::Continue
            }
            _ => self.ignore(),
        }
    }

    fn end_aggregate(&mut self) -> Flow {
        Flow::Continue
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        if kind == StrKind::Error {
            return self.ignore();
        }
        match self.stage {
            InvStage::Kind => match self.kind.begin(len) {
                Ok(()) => {
                    self.stage = InvStage::KindText;
                    Flow::Continue
                }
                // A kind that long is not `invalidate`.
                Err(_) => self.ignore(),
            },
            InvStage::Keys => {
                self.over = false;
                match self.key.begin(len) {
                    Ok(()) => {
                        self.stage = InvStage::KeyText;
                        Flow::Continue
                    }
                    Err(_) => self.everything(),
                }
            }
            InvStage::Done => Flow::Continue,
            _ => self.ignore(),
        }
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        match self.stage {
            InvStage::KindText => match self.kind.push(data) {
                Ok(()) => Flow::Continue,
                Err(_) => self.ignore(),
            },
            InvStage::KeyText => match self.key.push(data) {
                Ok(()) => Flow::Continue,
                Err(_) => self.everything(),
            },
            _ => Flow::Continue,
        }
    }

    fn end_string(&mut self) -> Flow {
        match self.stage {
            InvStage::KindText => {
                if self.kind.bytes().eq_ignore_ascii_case(b"invalidate") {
                    self.stage = InvStage::Subject;
                    Flow::Continue
                } else {
                    self.ignore()
                }
            }
            InvStage::KeyText => {
                self.handler.key(self.key.bytes());
                self.stage = InvStage::Keys;
                Flow::Continue
            }
            _ => Flow::Continue,
        }
    }
}

/// What a subscriber wants to be subscribed to. Kept so a new connection can
/// subscribe again to all of it.
#[derive(Default)]
pub(crate) struct Desired {
    channels: BTreeSet<Vec<u8>>,
    patterns: BTreeSet<Vec<u8>>,
    shards: BTreeSet<Vec<u8>>,
}

impl Desired {
    fn set(&mut self, kind: SubscriptionKind) -> &mut BTreeSet<Vec<u8>> {
        match kind {
            SubscriptionKind::Channel => &mut self.channels,
            SubscriptionKind::Pattern => &mut self.patterns,
            SubscriptionKind::Shard => &mut self.shards,
        }
    }

    /// The commands that subscribe to all of it.
    fn subscribe_all(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (kind, set) in [
            (SubscriptionKind::Channel, &self.channels),
            (SubscriptionKind::Pattern, &self.patterns),
            (SubscriptionKind::Shard, &self.shards),
        ] {
            if !set.is_empty() {
                let mut words: Vec<&[u8]> = vec![subscribe_word(kind)];
                words.extend(set.iter().map(Vec::as_slice));
                encode_command(&words, &mut out);
            }
        }
        out
    }
}

fn subscribe_word(kind: SubscriptionKind) -> &'static [u8] {
    match kind {
        SubscriptionKind::Channel => b"SUBSCRIBE",
        SubscriptionKind::Pattern => b"PSUBSCRIBE",
        SubscriptionKind::Shard => b"SSUBSCRIBE",
    }
}

fn unsubscribe_word(kind: SubscriptionKind) -> &'static [u8] {
    match kind {
        SubscriptionKind::Channel => b"UNSUBSCRIBE",
        SubscriptionKind::Pattern => b"PUNSUBSCRIBE",
        SubscriptionKind::Shard => b"SUNSUBSCRIBE",
    }
}

/// Whether `word` is a command that changes a connection's subscriptions.
pub(crate) fn is_subscription_command(word: &[u8]) -> bool {
    [
        &b"SUBSCRIBE"[..],
        b"PSUBSCRIBE",
        b"SSUBSCRIBE",
        b"UNSUBSCRIBE",
        b"PUNSUBSCRIBE",
        b"SUNSUBSCRIBE",
    ]
    .iter()
    .any(|c| word.eq_ignore_ascii_case(c))
}

// ---- reading what a subscriber's connection receives ----

/// What a message or an acknowledgement is, once its kind is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plan {
    Message(SubscriptionKind),
    Ack { kind: SubscriptionKind, subscribed: bool },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Between replies.
    Idle,
    /// A reply has begun; nothing yet.
    Begun,
    /// In the push, expecting its kind.
    Kind,
    KindText,
    /// A message's identifier (pattern, then channel) is next.
    Ident,
    IdentText,
    /// An acknowledgement's name, then its count.
    AckName,
    AckNameText,
    AckCount,
    /// A message's body is next.
    Payload,
    InPayload,
    /// All that was wanted of this reply is read.
    Done,
    /// The rest goes to the sink a handler gave for a push of some other kind.
    Forward,
    /// Dropped: the rest is being skipped.
    Dropped,
}

/// Reads what a subscriber's connection receives, as events, into calls on its
/// handler. It lives with the connection and holds an identifier or two (each
/// bounded by `max_field`), never a body.
pub(crate) struct Dispatch {
    stage: Stage,
    plan: Plan,
    top_kind: AggKind,
    top_len: Option<usize>,
    /// Identifiers of a message read so far.
    at: usize,
    kind: Whole,
    channel: Whole,
    pattern: Whole,
    name: Option<Bytes>,
    sink: Option<Box<dyn ReplySink + Send>>,
}

impl Dispatch {
    pub(crate) fn new(max_field: usize) -> Self {
        Self {
            stage: Stage::Idle,
            plan: Plan::Message(SubscriptionKind::Channel),
            top_kind: AggKind::Push,
            top_len: None,
            at: 0,
            kind: Whole::new(max_field),
            channel: Whole::new(max_field),
            pattern: Whole::new(max_field),
            name: None,
            sink: None,
        }
    }

    /// The reply is not what a subscriber's connection is sent: tell the
    /// handler, and skip the rest of it.
    fn drop_reply(&mut self, h: &mut dyn SubscriberHandler, why: RedisError) -> Flow {
        self.stage = Stage::Dropped;
        h.on_dropped(&why);
        Flow::Skip
    }

    fn malformed(&mut self, h: &mut dyn SubscriberHandler, what: &str) -> Flow {
        self.drop_reply(h, RedisError::Protocol(format!("a message was dropped: {what}")))
    }

    fn too_long(&mut self, h: &mut dyn SubscriberHandler, e: RedisError) -> Flow {
        self.drop_reply(h, e)
    }

    fn forward(&mut self, f: impl FnOnce(&mut dyn ReplySink) -> Flow) -> Flow {
        match self.sink.as_mut() {
            // A push is not a stream: it is not held.
            Some(s) => match f(&mut **s) {
                Flow::Pause => Flow::Continue,
                other => other,
            },
            None => Flow::Skip,
        }
    }

    /// Where the identifier being read goes.
    fn ident_slot(&mut self) -> &mut Whole {
        match (self.plan, self.at) {
            (Plan::Message(SubscriptionKind::Pattern), 0) => &mut self.pattern,
            _ => &mut self.channel,
        }
    }

    fn begin_reply(&mut self) {
        self.stage = Stage::Begun;
        self.at = 0;
        self.name = None;
        self.sink = None;
    }

    fn scalar(&mut self, h: &mut dyn SubscriberHandler, v: Scalar<'_>) -> Flow {
        match (self.stage, v) {
            (Stage::Forward, v) => self.forward(|s| s.scalar(v)),
            (Stage::Begun, Scalar::Simple(s)) if s.eq_ignore_ascii_case("PONG") => {
                self.stage = Stage::Done;
                Flow::Continue
            }
            (Stage::Begun, _) => self.malformed(h, "a bare value where a push was expected"),
            // A kind sent as a simple string.
            (Stage::Kind, Scalar::Simple(s)) => {
                self.kind.begin(Some(s.len())).ok();
                match self.kind.push(s.as_bytes()) {
                    Ok(()) => self.kind_known(h),
                    Err(e) => self.too_long(h, e),
                }
            }
            (Stage::AckName, Scalar::Null) => {
                self.name = None;
                self.stage = Stage::AckCount;
                Flow::Continue
            }
            (Stage::AckCount, Scalar::Int(count)) => self.acknowledged(h, count),
            (Stage::Done, _) => Flow::Skip,
            (Stage::Dropped, _) => Flow::Skip,
            _ => self.malformed(h, "a value where a string was expected"),
        }
    }

    fn error(&mut self, h: &mut dyn SubscriberHandler, line: &str) -> Flow {
        match self.stage {
            Stage::Forward => self.forward(|s| s.error(line)),
            Stage::Begun => {
                h.on_error(ServerError::parse(line));
                self.stage = Stage::Done;
                Flow::Continue
            }
            Stage::Done | Stage::Dropped => Flow::Skip,
            _ => self.malformed(h, "an error inside a message"),
        }
    }

    fn begin_aggregate(&mut self, h: &mut dyn SubscriberHandler, kind: AggKind, len: Option<usize>) -> Flow {
        match self.stage {
            Stage::Forward => self.forward(|s| s.begin_aggregate(kind, len)),
            Stage::Begun => match (kind, len) {
                (AggKind::Push | AggKind::Array, Some(0)) => {
                    self.stage = Stage::Done;
                    Flow::Continue
                }
                (AggKind::Push | AggKind::Array, _) => {
                    self.top_kind = kind;
                    self.top_len = len;
                    self.stage = Stage::Kind;
                    Flow::Continue
                }
                _ => self.malformed(h, "not a list"),
            },
            Stage::Done | Stage::Dropped => Flow::Skip,
            _ => self.malformed(h, "a list inside a message"),
        }
    }

    fn end_aggregate(&mut self, h: &mut dyn SubscriberHandler) -> Flow {
        match self.stage {
            Stage::Forward => self.forward(|s| s.end_aggregate()),
            // Ended before the message or acknowledgement was whole (a streamed
            // aggregate can).
            Stage::Kind | Stage::Ident | Stage::AckName | Stage::AckCount | Stage::Payload => {
                self.malformed(h, "it ended early")
            }
            _ => Flow::Continue,
        }
    }

    fn begin_string(&mut self, h: &mut dyn SubscriberHandler, kind: StrKind, len: Option<usize>) -> Flow {
        if self.stage == Stage::Forward {
            return self.forward(|s| s.begin_string(kind, len));
        }
        if matches!(self.stage, Stage::Done | Stage::Dropped) {
            return Flow::Skip;
        }
        if kind == StrKind::Error {
            return self.malformed(h, "a bulk error inside a message");
        }
        match self.stage {
            Stage::Kind => match self.kind.begin(len) {
                Ok(()) => {
                    self.stage = Stage::KindText;
                    Flow::Continue
                }
                Err(e) => self.too_long(h, e),
            },
            Stage::Ident => match self.ident_slot().begin(len) {
                Ok(()) => {
                    self.stage = Stage::IdentText;
                    Flow::Continue
                }
                Err(e) => self.too_long(h, e),
            },
            Stage::AckName => match self.channel.begin(len) {
                Ok(()) => {
                    self.stage = Stage::AckNameText;
                    Flow::Continue
                }
                Err(e) => self.too_long(h, e),
            },
            Stage::Payload => {
                let Plan::Message(which) = self.plan else {
                    return self.malformed(h, "a body of an acknowledgement");
                };
                let header = match which {
                    SubscriptionKind::Channel => MessageHeader::Channel {
                        channel: self.channel.bytes(),
                    },
                    SubscriptionKind::Pattern => MessageHeader::Pattern {
                        pattern: self.pattern.bytes(),
                        channel: self.channel.bytes(),
                    },
                    SubscriptionKind::Shard => MessageHeader::Shard {
                        channel: self.channel.bytes(),
                    },
                };
                let flow = h.message_begin(&header, len.map(|n| n as u64));
                self.stage = if flow == Flow::Skip { Stage::Dropped } else { Stage::InPayload };
                flow
            }
            _ => self.malformed(h, "a string where there should not be one"),
        }
    }

    fn string_chunk(&mut self, h: &mut dyn SubscriberHandler, data: &[u8]) -> Flow {
        let pushed = match self.stage {
            Stage::InPayload => {
                let flow = h.message_chunk(data);
                if flow == Flow::Skip {
                    self.stage = Stage::Dropped;
                }
                return flow;
            }
            Stage::Forward => return self.forward(|s| s.string_chunk(data)),
            Stage::KindText => self.kind.push(data),
            Stage::IdentText => self.ident_slot().push(data),
            Stage::AckNameText => self.channel.push(data),
            _ => return Flow::Skip,
        };
        match pushed {
            Ok(()) => Flow::Continue,
            Err(e) => self.too_long(h, e),
        }
    }

    fn end_string(&mut self, h: &mut dyn SubscriberHandler) -> Flow {
        match self.stage {
            Stage::Forward => self.forward(|s| s.end_string()),
            Stage::KindText => self.kind_known(h),
            Stage::IdentText => {
                self.at += 1;
                let idents = if self.plan == Plan::Message(SubscriptionKind::Pattern) { 2 } else { 1 };
                self.stage = if self.at == idents { Stage::Payload } else { Stage::Ident };
                Flow::Continue
            }
            Stage::AckNameText => {
                self.name = Some(Bytes::copy_from_slice(self.channel.bytes()));
                self.stage = Stage::AckCount;
                Flow::Continue
            }
            Stage::InPayload => {
                self.stage = Stage::Done;
                h.message_end();
                Flow::Continue
            }
            _ => Flow::Continue,
        }
    }

    fn end_reply(&mut self, skipped: bool) {
        if self.stage == Stage::Forward {
            if let Some(mut sink) = self.sink.take() {
                sink.end_reply(skipped);
            }
        }
        self.stage = Stage::Idle;
    }

    /// The push's first element is read: what is the rest?
    fn kind_known(&mut self, h: &mut dyn SubscriberHandler) -> Flow {
        let word = self.kind.bytes();
        let is = |w: &str| word.eq_ignore_ascii_case(w.as_bytes());
        use SubscriptionKind::{Channel, Pattern, Shard};
        let (plan, elements) = if is("message") {
            (Plan::Message(Channel), 3)
        } else if is("pmessage") {
            (Plan::Message(Pattern), 4)
        } else if is("smessage") {
            (Plan::Message(Shard), 3)
        } else if is("subscribe") {
            (Plan::Ack { kind: Channel, subscribed: true }, 3)
        } else if is("psubscribe") {
            (Plan::Ack { kind: Pattern, subscribed: true }, 3)
        } else if is("ssubscribe") {
            (Plan::Ack { kind: Shard, subscribed: true }, 3)
        } else if is("unsubscribe") {
            (Plan::Ack { kind: Channel, subscribed: false }, 3)
        } else if is("punsubscribe") {
            (Plan::Ack { kind: Pattern, subscribed: false }, 3)
        } else if is("sunsubscribe") {
            (Plan::Ack { kind: Shard, subscribed: false }, 3)
        } else if is("pong") {
            // The answer to a keepalive.
            self.stage = Stage::Done;
            return Flow::Continue;
        } else {
            return self.other(h);
        };
        if self.top_len.is_some_and(|n| n < elements) {
            return self.malformed(h, "too few parts");
        }
        self.plan = plan;
        self.at = 0;
        self.stage = match plan {
            Plan::Message(_) => Stage::Ident,
            Plan::Ack { .. } => Stage::AckName,
        };
        Flow::Continue
    }

    /// A push of a kind this crate does not interpret: to the sink the handler
    /// gives for it, which is told the whole push, or discarded.
    fn other(&mut self, h: &mut dyn SubscriberHandler) -> Flow {
        let kind = String::from_utf8_lossy(self.kind.bytes()).into_owned();
        let Some(mut sink) = h.on_push(&kind) else {
            // Not wanted: not a defect either.
            self.stage = Stage::Dropped;
            return Flow::Skip;
        };
        let word = self.kind.bytes();
        sink.begin_reply(ReplyKind::Push);
        let mut flow = sink.begin_aggregate(self.top_kind, self.top_len);
        if flow != Flow::Skip {
            flow = sink.begin_string(StrKind::Bulk, Some(word.len()));
        }
        if flow != Flow::Skip && !word.is_empty() {
            flow = sink.string_chunk(word);
        }
        if flow != Flow::Skip {
            flow = sink.end_string();
        }
        self.sink = Some(sink);
        self.stage = Stage::Forward;
        match flow {
            Flow::Skip => Flow::Skip,
            _ => Flow::Continue,
        }
    }

    /// An acknowledgement is whole.
    fn acknowledged(&mut self, h: &mut dyn SubscriberHandler, count: i64) -> Flow {
        let Plan::Ack { kind, subscribed } = self.plan else {
            return self.malformed(h, "a count in a message");
        };
        self.stage = Stage::Done;
        let change = if subscribed {
            match self.name.take() {
                Some(name) => SubscriptionChange::Subscribed { kind, name, count },
                None => return self.malformed(h, "a subscription without a name"),
            }
        } else {
            SubscriptionChange::Unsubscribed {
                kind,
                name: self.name.take(),
                count,
            }
        };
        h.on_subscription(change);
        Flow::Continue
    }
}

/// A subscriber's handler and its reader, as one sink for the parser's events.
pub(crate) struct SubSink<'a> {
    pub(crate) dispatch: &'a mut Dispatch,
    pub(crate) handler: &'a mut dyn SubscriberHandler,
}

impl ReplySink for SubSink<'_> {
    fn begin_reply(&mut self, _kind: ReplyKind) {
        self.dispatch.begin_reply();
    }

    fn scalar(&mut self, v: Scalar<'_>) -> Flow {
        self.dispatch.scalar(self.handler, v)
    }

    fn error(&mut self, line: &str) -> Flow {
        self.dispatch.error(self.handler, line)
    }

    fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
        self.dispatch.begin_aggregate(self.handler, kind, len)
    }

    fn end_aggregate(&mut self) -> Flow {
        self.dispatch.end_aggregate(self.handler)
    }

    fn begin_string(&mut self, kind: StrKind, len: Option<usize>) -> Flow {
        self.dispatch.begin_string(self.handler, kind, len)
    }

    fn string_chunk(&mut self, data: &[u8]) -> Flow {
        self.dispatch.string_chunk(self.handler, data)
    }

    fn end_string(&mut self) -> Flow {
        self.dispatch.end_string(self.handler)
    }

    fn end_reply(&mut self, skipped: bool) {
        self.dispatch.end_reply(skipped);
    }
}

/// A connection for subscriptions. See the module documentation.
///
/// Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct RedisSubscriber {
    inner: Arc<Inner>,
}

impl RedisSubscriber {
    /// A subscriber bound to `reactor`, dialling `config`'s server now and
    /// again whenever the connection is lost, until [`close`](Self::close).
    /// `handler`'s methods run on `reactor`.
    pub fn connect(reactor: &hopf_core::ReactorHandle, config: RedisConfig, handler: impl SubscriberHandler + 'static) -> Self {
        Self {
            inner: client::start(reactor, config, Some(Box::new(handler))),
        }
    }

    /// Subscribe to channels by name. Takes effect at once if the connection is
    /// up, and on every later connection.
    ///
    /// A name longer than [`RedisConfig::max_field`] is sent, but a message to
    /// it cannot be delivered whole and is dropped
    /// ([`on_dropped`](SubscriberHandler::on_dropped)).
    pub fn subscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.add(SubscriptionKind::Channel, channels);
    }

    /// Subscribe to patterns (`news.*`).
    pub fn psubscribe(&self, patterns: &[impl AsRef<[u8]>]) {
        self.add(SubscriptionKind::Pattern, patterns);
    }

    /// Subscribe to shard channels (Redis 7).
    pub fn ssubscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.add(SubscriptionKind::Shard, channels);
    }

    /// Unsubscribe from channels; with none named, from all of them.
    pub fn unsubscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.remove(SubscriptionKind::Channel, channels);
    }

    /// Unsubscribe from patterns; with none named, from all of them.
    pub fn punsubscribe(&self, patterns: &[impl AsRef<[u8]>]) {
        self.remove(SubscriptionKind::Pattern, patterns);
    }

    /// Unsubscribe from shard channels; with none named, from all of them.
    pub fn sunsubscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.remove(SubscriptionKind::Shard, channels);
    }

    fn add(&self, kind: SubscriptionKind, names: &[impl AsRef<[u8]>]) {
        if names.is_empty() {
            return;
        }
        let bytes = {
            let mut st = self.inner.state.lock().unwrap();
            for n in names {
                st.desired.set(kind).insert(n.as_ref().to_vec());
            }
            if st.phase != Phase::Ready {
                // Sent with everything else when the connection is up.
                return;
            }
            let mut words: Vec<&[u8]> = vec![subscribe_word(kind)];
            words.extend(names.iter().map(|n| n.as_ref()));
            let mut out = Vec::new();
            encode_command(&words, &mut out);
            out
        };
        client::write_raw(&self.inner, bytes);
    }

    fn remove(&self, kind: SubscriptionKind, names: &[impl AsRef<[u8]>]) {
        let bytes = {
            let mut st = self.inner.state.lock().unwrap();
            if names.is_empty() {
                st.desired.set(kind).clear();
            } else {
                for n in names {
                    st.desired.set(kind).remove(n.as_ref());
                }
            }
            if st.phase != Phase::Ready {
                return;
            }
            let mut words: Vec<&[u8]> = vec![unsubscribe_word(kind)];
            words.extend(names.iter().map(|n| n.as_ref()));
            let mut out = Vec::new();
            encode_command(&words, &mut out);
            out
        };
        client::write_raw(&self.inner, bytes);
    }

    /// What this subscriber is subscribed to, or will subscribe to when its
    /// connection is up: channels, patterns and shard channels.
    pub fn subscriptions(&self) -> (Vec<Bytes>, Vec<Bytes>, Vec<Bytes>) {
        let st = self.inner.state.lock().unwrap();
        let v = |s: &BTreeSet<Vec<u8>>| s.iter().map(|b| Bytes::copy_from_slice(b)).collect();
        (v(&st.desired.channels), v(&st.desired.patterns), v(&st.desired.shards))
    }

    /// Whether the connection is up and subscribed.
    pub fn is_connected(&self) -> bool {
        self.inner.state.lock().unwrap().phase == Phase::Ready
    }

    /// Start reading again after the handler returned [`Flow::Pause`]. It may be
    /// called from any thread at any time: even while the handler is still
    /// running, before it has returned the `Pause` (the pause is then
    /// cancelled), or when nothing is paused (when it does nothing).
    ///
    /// While the connection is paused the server's output for it builds up on
    /// the server, which Redis limits (`client-output-buffer-limit pubsub`) by
    /// disconnecting a subscriber that falls too far behind: a handler that
    /// pauses is choosing to fall behind, and for no longer than that allows.
    pub fn resume(&self) {
        if self.inner.flow.resume() {
            let inner = Arc::clone(&self.inner);
            self.inner.reactor.execute(Box::new(move || client::resume_read(&inner)));
        }
    }

    /// Close the connection and stop reconnecting.
    pub fn close(&self) {
        client::close(&self.inner);
    }
}

// ---- the subscriber's side of a connection ----

/// The handshake is done on a subscriber connection: subscribe to everything
/// wanted, tell the handler, and start watching the connection's health.
pub(crate) fn sub_ready(inner: &Arc<Inner>, conn_id: u64, endpoint: &mut dyn Endpoint) {
    let bytes = {
        let mut st = inner.state.lock().unwrap();
        if st.conn_id != conn_id {
            return;
        }
        st.phase = Phase::Ready;
        st.failures = 0;
        st.retry_at = None;
        st.last_error = None;
        st.last_rx = Instant::now();
        st.desired.subscribe_all()
    };
    if !bytes.is_empty() {
        endpoint.send(&bytes);
    }
    let reconnect = inner.sub_connected_before.swap(true, Ordering::SeqCst);
    with_handler(inner, |h| h.on_connected(reconnect));
    arm_ping(inner, conn_id);
}

/// An established subscriber connection ended.
pub(crate) fn sub_lost(inner: &Arc<Inner>, reason: &RedisError) {
    with_handler(inner, |h| h.on_disconnected(reason));
}

fn with_handler(inner: &Inner, f: impl FnOnce(&mut dyn SubscriberHandler)) {
    if let Some(h) = &inner.sub {
        f(h.lock().unwrap().as_mut());
    }
}

/// Dial again when the hold-off after a failure is over.
pub(crate) fn schedule_redial(inner: &Arc<Inner>) {
    if inner.sub.is_none() || inner.closed.load(Ordering::SeqCst) {
        return;
    }
    let delay = {
        let st = inner.state.lock().unwrap();
        st.retry_at.map_or(Duration::ZERO, |at| at.saturating_duration_since(Instant::now()))
    };
    let weak = Arc::downgrade(inner);
    inner.reactor.schedule_timer(
        delay,
        Box::new(move || {
            if let Some(inner) = weak.upgrade() {
                client::redial(&inner);
            }
        }),
    );
}

/// Watch a subscriber connection that may have died without saying so: a
/// `PING` when it has been quiet for the ping interval, and a drop when it has
/// been silent for three. A handler that has paused the connection is silent
/// by its own choice, and is not watched while it has.
fn arm_ping(inner: &Arc<Inner>, conn_id: u64) {
    let Some(interval) = inner.config.ping_interval else {
        return;
    };
    let weak = Arc::downgrade(inner);
    inner.reactor.schedule_timer(
        interval,
        Box::new(move || {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            enum Act {
                /// The connection this watches is gone.
                Stop,
                /// Heard from recently, or held by the handler: look again later.
                Wait,
                Ping,
                Drop,
            }
            let act = {
                let st = inner.state.lock().unwrap();
                if st.conn_id != conn_id || st.phase != Phase::Ready {
                    Act::Stop
                } else if st.read_paused {
                    Act::Wait
                } else if st.last_rx.elapsed() >= interval * 3 {
                    Act::Drop
                } else if st.last_rx.elapsed() >= interval {
                    Act::Ping
                } else {
                    Act::Wait
                }
            };
            match act {
                Act::Stop => return,
                Act::Wait => {}
                Act::Ping => {
                    let mut out = Vec::new();
                    encode_command(&[b"PING"], &mut out);
                    client::write_raw(&inner, out);
                }
                Act::Drop => {
                    let handle = inner.state.lock().unwrap().handle.clone();
                    client::lost(&inner, conn_id, "the server stopped answering");
                    if let Some(h) = handle {
                        h.close();
                    }
                    return;
                }
            }
            arm_ping(&inner, conn_id);
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resp::{Feed, RespParser};
    use std::sync::{Arc, Mutex};

    /// What a handler or a sink was told.
    type Log = Arc<Mutex<Vec<String>>>;

    /// A handler that records what it is told, and does what it is set to.
    struct Rec {
        log: Log,
        /// Return `Skip` from `message_begin` for a channel of this name.
        skip: Option<Vec<u8>>,
        /// Return `Pause` from the first chunk of each message.
        pause_on_chunk: bool,
        /// Sink for pushes of this kind.
        push_kind: Option<&'static str>,
        /// Bytes of body seen in the current message.
        seen: usize,
        /// The most of a message's body held at once: none.
        chunks: usize,
    }

    impl Rec {
        fn new() -> (Self, Log) {
            let log: Log = Arc::default();
            (
                Self {
                    log: Arc::clone(&log),
                    skip: None,
                    pause_on_chunk: false,
                    push_kind: None,
                    seen: 0,
                    chunks: 0,
                },
                log,
            )
        }
    }

    struct PushLog(Log);

    impl ReplySink for PushLog {
        fn begin_reply(&mut self, kind: ReplyKind) {
            self.0.lock().unwrap().push(format!("push {kind:?}"));
        }
        fn scalar(&mut self, v: Scalar<'_>) -> Flow {
            self.0.lock().unwrap().push(format!("push scalar {v:?}"));
            Flow::Continue
        }
        fn error(&mut self, line: &str) -> Flow {
            self.0.lock().unwrap().push(format!("push error {line}"));
            Flow::Continue
        }
        fn begin_aggregate(&mut self, kind: AggKind, len: Option<usize>) -> Flow {
            self.0.lock().unwrap().push(format!("push agg {kind:?} {len:?}"));
            Flow::Continue
        }
        fn end_aggregate(&mut self) -> Flow {
            self.0.lock().unwrap().push("push end agg".into());
            Flow::Continue
        }
        fn begin_string(&mut self, _kind: StrKind, len: Option<usize>) -> Flow {
            self.0.lock().unwrap().push(format!("push str {len:?}"));
            Flow::Continue
        }
        fn string_chunk(&mut self, data: &[u8]) -> Flow {
            self.0.lock().unwrap().push(format!("push chunk {}", String::from_utf8_lossy(data)));
            Flow::Pause // never honoured: a push is not a stream
        }
        fn end_string(&mut self) -> Flow {
            Flow::Continue
        }
        fn end_reply(&mut self, skipped: bool) {
            self.0.lock().unwrap().push(format!("push end {skipped}"));
        }
    }

    impl SubscriberHandler for Rec {
        fn message_begin(&mut self, header: &MessageHeader<'_>, len: Option<u64>) -> Flow {
            self.seen = 0;
            self.chunks = 0;
            let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
            self.log.lock().unwrap().push(format!(
                "begin {:?} pattern={:?} channel={} len={len:?}",
                header.kind(),
                header.pattern().map(text),
                text(header.channel())
            ));
            if self.skip.as_deref() == Some(header.channel()) {
                return Flow::Skip;
            }
            Flow::Continue
        }
        fn message_chunk(&mut self, data: &[u8]) -> Flow {
            self.seen += data.len();
            self.chunks += 1;
            if self.pause_on_chunk && self.chunks == 1 {
                return Flow::Pause;
            }
            Flow::Continue
        }
        fn message_end(&mut self) {
            self.log.lock().unwrap().push(format!("end {} bytes", self.seen));
        }
        fn on_subscription(&mut self, change: SubscriptionChange) {
            self.log.lock().unwrap().push(format!("{change:?}"));
        }
        fn on_push(&mut self, kind: &str) -> Option<Box<dyn ReplySink + Send>> {
            self.log.lock().unwrap().push(format!("on_push {kind}"));
            (self.push_kind == Some(kind)).then(|| Box::new(PushLog(Arc::clone(&self.log))) as Box<dyn ReplySink + Send>)
        }
        fn on_dropped(&mut self, why: &RedisError) {
            self.log.lock().unwrap().push(format!("dropped: {why}"));
        }
        fn on_error(&mut self, error: ServerError) {
            self.log.lock().unwrap().push(format!("error {} {}", error.code, error.message));
        }
    }

    /// Feed `bytes` to a parser and a dispatcher in pieces of `piece` bytes. A
    /// pause is resumed at once, as a consumer that does so promptly would.
    /// Returns how many times the dispatcher paused.
    fn feed(d: &mut Dispatch, p: &mut RespParser, h: &mut Rec, bytes: &[u8], piece: usize) -> usize {
        let mut pauses = 0;
        for chunk in bytes.chunks(piece) {
            let mut data = chunk;
            loop {
                let mut sink = SubSink { dispatch: d, handler: h };
                match p.feed(&mut data, &mut sink).expect("valid RESP") {
                    Feed::Consumed => break,
                    Feed::Paused => pauses += 1,
                }
            }
        }
        pauses
    }

    fn run(h: &mut Rec, d: &mut Dispatch, bytes: &[u8]) {
        // Whole, then one byte at a time, then in odd pieces: the same events.
        feed(d, &mut RespParser::new(), h, bytes, bytes.len().max(1));
    }

    fn lines(log: &Log) -> Vec<String> {
        log.lock().unwrap().clone()
    }

    const PIECES: [usize; 5] = [1, 2, 3, 7, 4096];

    fn each_split(bytes: &[u8], mut check: impl FnMut(Vec<String>)) {
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            let mut d = Dispatch::new(64);
            feed(&mut d, &mut RespParser::new(), &mut h, bytes, piece);
            check(lines(&log));
        }
    }

    #[test]
    fn a_message_is_a_header_then_chunks_then_an_end_over_resp3_and_resp2() {
        let want = vec!["begin Channel pattern=None channel=news len=Some(5)".to_string(), "end 5 bytes".to_string()];
        each_split(b">3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n", |got| assert_eq!(got, want));
        each_split(b"*3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n", |got| assert_eq!(got, want));
        // A pattern message carries the pattern and the channel; a shard one is like a channel's.
        each_split(b">4\r\n$8\r\npmessage\r\n$2\r\nn*\r\n$4\r\nnews\r\n$2\r\nhi\r\n", |got| {
            assert_eq!(
                got,
                vec!["begin Pattern pattern=Some(\"n*\") channel=news len=Some(2)".to_string(), "end 2 bytes".to_string()]
            )
        });
        each_split(b">3\r\n$8\r\nsmessage\r\n$5\r\nshard\r\n$1\r\nx\r\n", |got| {
            assert_eq!(got, vec!["begin Shard pattern=None channel=shard len=Some(1)".to_string(), "end 1 bytes".to_string()])
        });
    }

    #[test]
    fn acknowledgements_carry_the_kind_and_the_count_and_an_unsubscribe_may_have_no_name() {
        let mut bytes = Vec::new();
        for (word, n) in [("subscribe", 1), ("psubscribe", 2), ("ssubscribe", 3)] {
            bytes.extend_from_slice(format!(">3\r\n${}\r\n{word}\r\n$1\r\nc\r\n:{n}\r\n", word.len()).as_bytes());
        }
        bytes.extend_from_slice(b">3\r\n$11\r\nunsubscribe\r\n$1\r\nc\r\n:0\r\n");
        bytes.extend_from_slice(b"*3\r\n$11\r\nunsubscribe\r\n$-1\r\n:0\r\n");
        each_split(&bytes, |got| {
            assert_eq!(
                got,
                vec![
                    "Subscribed { kind: Channel, name: b\"c\", count: 1 }".to_string(),
                    "Subscribed { kind: Pattern, name: b\"c\", count: 2 }".to_string(),
                    "Subscribed { kind: Shard, name: b\"c\", count: 3 }".to_string(),
                    "Unsubscribed { kind: Channel, name: Some(b\"c\"), count: 0 }".to_string(),
                    "Unsubscribed { kind: Channel, name: None, count: 0 }".to_string(),
                ]
            )
        });
    }

    #[test]
    fn a_handler_that_skips_a_message_loses_that_one_and_no_other() {
        let bytes = b">3\r\n$7\r\nmessage\r\n$1\r\na\r\n$3\r\none\r\n\
                      >3\r\n$7\r\nmessage\r\n$4\r\nskip\r\n$10\r\nnot-wanted\r\n\
                      >3\r\n$7\r\nmessage\r\n$1\r\nb\r\n$3\r\ntwo\r\n";
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            h.skip = Some(b"skip".to_vec());
            let mut d = Dispatch::new(64);
            feed(&mut d, &mut RespParser::new(), &mut h, bytes, piece);
            assert_eq!(
                lines(&log),
                vec![
                    "begin Channel pattern=None channel=a len=Some(3)".to_string(),
                    "end 3 bytes".to_string(),
                    "begin Channel pattern=None channel=skip len=Some(10)".to_string(),
                    "begin Channel pattern=None channel=b len=Some(3)".to_string(),
                    "end 3 bytes".to_string(),
                ],
                "piece {piece}: no end for the skipped one, and the next is whole"
            );
        }
    }

    #[test]
    fn a_channel_over_the_limit_drops_that_message_and_says_so() {
        let bytes = b">3\r\n$7\r\nmessage\r\n$1\r\na\r\n$1\r\n1\r\n\
                      >3\r\n$7\r\nmessage\r\n$13\r\nway-too-long!\r\n$5\r\nhello\r\n\
                      >3\r\n$7\r\nmessage\r\n$1\r\nb\r\n$1\r\n2\r\n";
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            let mut d = Dispatch::new(8);
            feed(&mut d, &mut RespParser::new(), &mut h, bytes, piece);
            assert_eq!(
                lines(&log),
                vec![
                    "begin Channel pattern=None channel=a len=Some(1)".to_string(),
                    "end 1 bytes".to_string(),
                    "dropped: an identifier in the reply is longer than 8 bytes".to_string(),
                    "begin Channel pattern=None channel=b len=Some(1)".to_string(),
                    "end 1 bytes".to_string(),
                ],
                "piece {piece}"
            );
        }
        // A pattern over the limit is the same, however it is announced.
        let streamed = b">4\r\n$8\r\npmessage\r\n$?\r\n;5\r\nabcde\r\n;5\r\nfghij\r\n;0\r\n$1\r\nc\r\n$1\r\nx\r\n\
                         >3\r\n$7\r\nmessage\r\n$1\r\nb\r\n$1\r\n2\r\n";
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            let mut d = Dispatch::new(8);
            feed(&mut d, &mut RespParser::new(), &mut h, streamed, piece);
            assert_eq!(
                lines(&log),
                vec![
                    "dropped: an identifier in the reply is longer than 8 bytes".to_string(),
                    "begin Channel pattern=None channel=b len=Some(1)".to_string(),
                    "end 1 bytes".to_string(),
                ],
                "piece {piece}"
            );
        }
    }

    #[test]
    fn a_body_streams_in_chunks_and_a_streamed_body_is_the_same() {
        let (mut h, log) = Rec::new();
        let mut d = Dispatch::new(64);
        let mut bytes = b">3\r\n$7\r\nmessage\r\n$1\r\nc\r\n$1048576\r\n".to_vec();
        bytes.extend(std::iter::repeat(b'z').take(1 << 20));
        bytes.extend_from_slice(b"\r\n");
        feed(&mut d, &mut RespParser::new(), &mut h, &bytes, 4096);
        assert_eq!(
            lines(&log),
            vec!["begin Channel pattern=None channel=c len=Some(1048576)".to_string(), "end 1048576 bytes".to_string()]
        );
        assert!(h.chunks > 100, "it came in many chunks, not one: {}", h.chunks);

        let (mut h, log) = Rec::new();
        let mut d = Dispatch::new(64);
        feed(&mut d, &mut RespParser::new(), &mut h, b">3\r\n$7\r\nmessage\r\n$1\r\nc\r\n$?\r\n;3\r\nabc\r\n;2\r\nde\r\n;0\r\n", 3);
        assert_eq!(lines(&log), vec!["begin Channel pattern=None channel=c len=None".to_string(), "end 5 bytes".to_string()]);
    }

    #[test]
    fn a_pause_in_a_body_stops_the_parser_and_resuming_continues_the_same_message() {
        let (mut h, log) = Rec::new();
        h.pause_on_chunk = true;
        let mut d = Dispatch::new(64);
        let mut p = RespParser::new();
        let bytes = b">3\r\n$7\r\nmessage\r\n$1\r\nc\r\n$10\r\n0123456789\r\n>3\r\n$7\r\nmessage\r\n$1\r\nd\r\n$1\r\nx\r\n";
        let pauses = {
            let mut data = &bytes[..];
            let mut pauses = 0;
            loop {
                let mut sink = SubSink { dispatch: &mut d, handler: &mut h };
                match p.feed(&mut data, &mut sink).unwrap() {
                    Feed::Consumed => break,
                    Feed::Paused => {
                        pauses += 1;
                        // What the connection does: stops, then goes on when resumed.
                        assert!(!data.is_empty(), "what follows the pause stays unread");
                    }
                }
            }
            pauses
        };
        assert_eq!(pauses, 2, "one pause in each message");
        assert_eq!(
            lines(&log),
            vec![
                "begin Channel pattern=None channel=c len=Some(10)".to_string(),
                "end 10 bytes".to_string(),
                "begin Channel pattern=None channel=d len=Some(1)".to_string(),
                "end 1 bytes".to_string(),
            ]
        );
    }

    #[test]
    fn keepalive_answers_and_errors_are_recognised() {
        for bytes in [&b"+PONG\r\n"[..], b"*2\r\n$4\r\npong\r\n$0\r\n\r\n", b">2\r\n$4\r\npong\r\n$0\r\n\r\n"] {
            each_split(bytes, |got| assert_eq!(got, Vec::<String>::new()));
        }
        each_split(b"-NOPERM no\r\n", |got| assert_eq!(got, vec!["error NOPERM no".to_string()]));
    }

    #[test]
    fn a_push_of_another_kind_goes_to_the_handlers_sink_whole_or_is_discarded() {
        let bytes = b">3\r\n$5\r\nweird\r\n:7\r\n$1\r\nx\r\n\
                      >3\r\n$7\r\nmessage\r\n$1\r\nc\r\n$1\r\n1\r\n";
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            h.push_kind = Some("weird");
            let mut d = Dispatch::new(64);
            feed(&mut d, &mut RespParser::new(), &mut h, bytes, piece);
            let got = lines(&log);
            // The sink sees the whole push, from its kind on, and an ordinary message follows.
            assert_eq!(got[0], "on_push weird");
            let sink_part: Vec<_> = got.iter().filter(|l| l.starts_with("push ")).cloned().collect();
            let text: String = sink_part.iter().map(|l| l.trim_start_matches("push ")).collect::<Vec<_>>().join("|");
            assert!(text.starts_with("Push|agg Push Some(3)|str Some(5)|chunk weird"), "{text}");
            assert!(text.contains("scalar Int(7)") && text.ends_with("end false"), "{text}");
            assert_eq!(
                got[got.len() - 2..],
                ["begin Channel pattern=None channel=c len=Some(1)".to_string(), "end 1 bytes".to_string()],
                "piece {piece}"
            );
        }
        // Declined: discarded, not reported as a defect, and the next one is whole.
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            let mut d = Dispatch::new(64);
            feed(&mut d, &mut RespParser::new(), &mut h, bytes, piece);
            assert_eq!(
                lines(&log),
                vec![
                    "on_push weird".to_string(),
                    "begin Channel pattern=None channel=c len=Some(1)".to_string(),
                    "end 1 bytes".to_string()
                ]
            );
        }
    }

    #[test]
    fn something_that_is_not_shaped_as_a_message_is_dropped_and_reported_without_harm() {
        // A list where the channel should be; a message with too few parts; a bare integer.
        let bytes = b">3\r\n$7\r\nmessage\r\n*1\r\n$1\r\na\r\n$1\r\nx\r\n\
                      >2\r\n$7\r\nmessage\r\n$1\r\na\r\n\
                      :5\r\n\
                      >3\r\n$7\r\nmessage\r\n$1\r\nb\r\n$1\r\ny\r\n";
        for piece in PIECES {
            let (mut h, log) = Rec::new();
            let mut d = Dispatch::new(64);
            feed(&mut d, &mut RespParser::new(), &mut h, bytes, piece);
            let got = lines(&log);
            assert_eq!(got.iter().filter(|l| l.starts_with("dropped")).count(), 3, "{got:?}");
            assert_eq!(
                got[got.len() - 2..],
                ["begin Channel pattern=None channel=b len=Some(1)".to_string(), "end 1 bytes".to_string()],
                "piece {piece}"
            );
        }
    }

    // ---- invalidations ----

    #[derive(Default)]
    struct Inv {
        log: Log,
    }

    impl InvalidationHandler for Inv {
        fn key(&mut self, key: &[u8]) {
            self.log.lock().unwrap().push(format!("key {}", String::from_utf8_lossy(key)));
        }
        fn all(&mut self) {
            self.log.lock().unwrap().push("all".into());
        }
    }

    fn invalidations(bytes: &[u8], piece: usize, max_field: usize) -> Vec<String> {
        let inv = Inv::default();
        let log = Arc::clone(&inv.log);
        let mut sink = InvalidationSink::with_max_field(inv, max_field);
        let mut p = RespParser::new();
        for chunk in bytes.chunks(piece) {
            let mut data = chunk;
            while !data.is_empty() {
                p.feed(&mut data, &mut sink).unwrap();
            }
        }
        let got = log.lock().unwrap().clone();
        got
    }

    #[test]
    fn invalidation_pushes_say_which_keys_or_that_it_is_all() {
        let bytes = b">2\r\n$10\r\ninvalidate\r\n*2\r\n$1\r\na\r\n$2\r\nbb\r\n\
                      >2\r\n$10\r\ninvalidate\r\n_\r\n\
                      >2\r\n$10\r\ninvalidate\r\n*1\r\n$1\r\nc\r\n";
        for piece in PIECES {
            assert_eq!(invalidations(bytes, piece, 64), vec!["key a", "key bb", "all", "key c"], "piece {piece}");
        }
    }

    #[test]
    fn other_pushes_are_ignored_and_a_key_too_long_to_deliver_is_everything() {
        let bytes = b">3\r\n$21\r\ntracking-redir-broken\r\n:1\r\n$1\r\nx\r\n\
                      >2\r\n$10\r\ninvalidate\r\n*3\r\n$1\r\na\r\n$13\r\nway-too-long!\r\n$1\r\nb\r\n\
                      >2\r\n$10\r\ninvalidate\r\n*1\r\n$1\r\nc\r\n";
        for piece in PIECES {
            // `a` is delivered; the long key cannot be, so it is "all", and the rest of that push is not read.
            assert_eq!(invalidations(bytes, piece, 8), vec!["key a", "all", "key c"], "piece {piece}");
        }
    }

    #[test]
    fn what_is_wanted_is_subscribed_to_in_one_command_per_kind() {
        let mut d = Desired::default();
        assert!(d.subscribe_all().is_empty());
        d.set(SubscriptionKind::Channel).insert(b"b".to_vec());
        d.set(SubscriptionKind::Channel).insert(b"a".to_vec());
        d.set(SubscriptionKind::Shard).insert(b"s".to_vec());
        let mut want = Vec::new();
        encode_command(&[b"SUBSCRIBE", b"a", b"b"], &mut want);
        encode_command(&[b"SSUBSCRIBE", b"s"], &mut want);
        assert_eq!(d.subscribe_all(), want);
    }

    #[test]
    fn subscription_commands_are_recognised_in_any_case() {
        for w in ["SUBSCRIBE", "subscribe", "PsUbScRiBe", "SSUBSCRIBE", "UNSUBSCRIBE", "punsubscribe", "SUNSUBSCRIBE"] {
            assert!(is_subscription_command(w.as_bytes()), "{w}");
        }
        for w in ["PUBLISH", "GET", "SPUBLISH", "PUBSUB"] {
            assert!(!is_subscription_command(w.as_bytes()), "{w}");
        }
    }

    #[test]
    fn the_header_says_where_a_message_was_published() {
        let c = MessageHeader::Channel { channel: b"c" };
        let p = MessageHeader::Pattern { pattern: b"p*", channel: b"pc" };
        let s = MessageHeader::Shard { channel: b"s" };
        assert_eq!((c.channel(), c.pattern(), c.kind()), (&b"c"[..], None, SubscriptionKind::Channel));
        assert_eq!((p.channel(), p.pattern(), p.kind()), (&b"pc"[..], Some(&b"p*"[..]), SubscriptionKind::Pattern));
        assert_eq!((s.channel(), s.pattern(), s.kind()), (&b"s"[..], None, SubscriptionKind::Shard));
    }

    #[test]
    fn a_one_byte_feed_makes_the_same_events_as_a_whole_one() {
        let bytes = b">3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$5\r\nhello\r\n:5\r\n";
        // A trailing integer is not a push on a subscriber's connection, and is dropped.
        let (mut a, la) = Rec::new();
        run(&mut a, &mut Dispatch::new(64), bytes);
        let (mut b, lb) = Rec::new();
        feed(&mut Dispatch::new(64), &mut RespParser::new(), &mut b, bytes, 1);
        assert_eq!(lines(&la), lines(&lb));
    }
}
