// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Publish/subscribe and push messages.
//!
//! A connection that has subscribed to channels cannot be used for ordinary
//! commands (in RESP2 the server refuses them), and what it receives are not
//! replies: they arrive when someone publishes. So subscriptions live on a
//! connection of their own, a [`RedisSubscriber`]: it reconnects by itself,
//! subscribes again to everything on the new connection, and hands each message
//! and each change of subscription to a [`SubscriberHandler`].
//!
//! Publishing is an ordinary command, [`RedisClient::publish`](crate::RedisClient::publish)
//! and [`spublish`](crate::RedisClient::spublish), on a [`RedisClient`](crate::RedisClient).
//!
//! RESP3 also lets a server push data to any connection: a key invalidation
//! (`CLIENT TRACKING`), for one. [`RedisClient::set_push_handler`](crate::RedisClient::set_push_handler)
//! receives every push a command connection gets, whatever its kind: a kind this
//! crate does not know is delivered as a [`Push`], never dropped.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hopf_core::{Bytes, Endpoint};

use crate::client::{self, Inner, Phase};
use crate::error::RedisError;
use crate::resp::{encode_command, ServerError, Value};
use crate::RedisConfig;

/// A message a subscription delivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Published to a channel subscribed to by name (`SUBSCRIBE`).
    Channel {
        /// The channel.
        channel: Bytes,
        /// The message.
        payload: Bytes,
    },
    /// Published to a channel matching a pattern subscribed to (`PSUBSCRIBE`).
    Pattern {
        /// The pattern that matched.
        pattern: Bytes,
        /// The channel published to.
        channel: Bytes,
        /// The message.
        payload: Bytes,
    },
    /// Published to a shard channel (`SSUBSCRIBE`, `SPUBLISH`; Redis 7).
    Shard {
        /// The shard channel.
        channel: Bytes,
        /// The message.
        payload: Bytes,
    },
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

/// RESP3 out-of-band data, as the server sent it: the kind (`invalidate`,
/// `message`, ...) and the rest.
#[derive(Debug, Clone, PartialEq)]
pub struct Push {
    /// The first element, as text.
    pub kind: String,
    /// The elements after it.
    pub data: Vec<Value>,
}

/// What a client-side-caching `invalidate` push says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalidation {
    /// These keys changed.
    Keys(Vec<Bytes>),
    /// Everything: a `FLUSHALL` or `FLUSHDB`.
    All,
}

impl Push {
    /// The invalidation, if this is an `invalidate` push.
    pub fn invalidation(&self) -> Option<Invalidation> {
        if self.kind != "invalidate" {
            return None;
        }
        match self.data.first() {
            Some(Value::Null) | None => Some(Invalidation::All),
            Some(v) => {
                let keys = v.as_array()?.iter().filter_map(|k| k.as_bytes().map(Bytes::copy_from_slice)).collect();
                Some(Invalidation::Keys(keys))
            }
        }
    }
}

/// What a subscriber's connection reports. Called on the reactor the
/// subscriber is bound to, one call at a time, in the order things happened.
///
/// Only [`on_message`](Self::on_message) is required; a closure
/// `FnMut(Message) + Send` is a handler that wants just that.
pub trait SubscriberHandler: Send {
    /// A message was published to a subscription.
    fn on_message(&mut self, message: Message);

    /// The server acknowledged a subscription or an unsubscription.
    fn on_subscription(&mut self, _change: SubscriptionChange) {}

    /// Out-of-band data of a kind this crate does not interpret (a RESP3 push
    /// such as `invalidate`, or a type a newer server adds). It is delivered
    /// rather than dropped.
    fn on_push(&mut self, _push: Push) {}

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

impl<F: FnMut(Message) + Send> SubscriberHandler for F {
    fn on_message(&mut self, message: Message) {
        self(message)
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

/// What a subscriber's connection received.
#[derive(Debug, PartialEq)]
pub(crate) enum Incoming {
    Message(Message),
    Change(SubscriptionChange),
    Push(Push),
    /// The answer to a keepalive `PING`.
    Pong,
    Error(ServerError),
}

fn bytes_of(v: &Value) -> Option<Bytes> {
    v.as_bytes().map(Bytes::copy_from_slice)
}

/// Read a RESP3 push or a RESP2 array on a subscribed connection.
pub(crate) fn classify(value: Value) -> Incoming {
    let items = match value {
        Value::Push(items) | Value::Array(items) => items,
        Value::Error(e) => return Incoming::Error(e),
        // A bare PONG, or anything else a server says that is not a message.
        other => {
            return match other.as_str() {
                Some(s) if s.eq_ignore_ascii_case("PONG") => Incoming::Pong,
                _ => Incoming::Push(Push {
                    kind: String::new(),
                    data: vec![other],
                }),
            }
        }
    };
    let kind = items.first().and_then(Value::as_str).unwrap_or("").to_string();
    let rest = &items[items.len().min(1)..];
    let as_push = |items: Vec<Value>| Incoming::Push(Push {
        kind: kind.clone(),
        data: items.into_iter().skip(1).collect(),
    });
    let count = |v: &Value| v.as_int().unwrap_or(0);
    match (kind.to_ascii_lowercase().as_str(), rest) {
        ("message", [ch, payload]) => match (bytes_of(ch), bytes_of(payload)) {
            (Some(channel), Some(payload)) => Incoming::Message(Message::Channel { channel, payload }),
            _ => as_push(items),
        },
        ("pmessage", [pat, ch, payload]) => match (bytes_of(pat), bytes_of(ch), bytes_of(payload)) {
            (Some(pattern), Some(channel), Some(payload)) => {
                Incoming::Message(Message::Pattern { pattern, channel, payload })
            }
            _ => as_push(items),
        },
        ("smessage", [ch, payload]) => match (bytes_of(ch), bytes_of(payload)) {
            (Some(channel), Some(payload)) => Incoming::Message(Message::Shard { channel, payload }),
            _ => as_push(items),
        },
        (k @ ("subscribe" | "psubscribe" | "ssubscribe"), [name, n]) => match bytes_of(name) {
            Some(name) => Incoming::Change(SubscriptionChange::Subscribed {
                kind: kind_of(k),
                name,
                count: count(n),
            }),
            None => as_push(items),
        },
        (k @ ("unsubscribe" | "punsubscribe" | "sunsubscribe"), [name, n]) => Incoming::Change(SubscriptionChange::Unsubscribed {
            kind: kind_of(k),
            name: bytes_of(name),
            count: count(n),
        }),
        ("pong", _) => Incoming::Pong,
        _ => as_push(items),
    }
}

fn kind_of(command: &str) -> SubscriptionKind {
    match command {
        "psubscribe" | "punsubscribe" => SubscriptionKind::Pattern,
        "ssubscribe" | "sunsubscribe" => SubscriptionKind::Shard,
        _ => SubscriptionKind::Channel,
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

/// Something arrived on a subscriber's connection.
pub(crate) fn sub_reply(inner: &Arc<Inner>, value: Value) {
    match classify(value) {
        Incoming::Message(m) => with_handler(inner, |h| h.on_message(m)),
        Incoming::Change(c) => with_handler(inner, |h| h.on_subscription(c)),
        Incoming::Push(p) => with_handler(inner, |h| h.on_push(p)),
        Incoming::Error(e) => with_handler(inner, |h| h.on_error(e)),
        Incoming::Pong => {}
    }
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
/// been silent for three.
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
                /// Heard from recently: look again later.
                Wait,
                Ping,
                Drop,
            }
            let act = {
                let st = inner.state.lock().unwrap();
                if st.conn_id != conn_id || st.phase != Phase::Ready {
                    Act::Stop
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

    fn bulk(s: &str) -> Value {
        Value::Bulk(Bytes::copy_from_slice(s.as_bytes()))
    }

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    /// The same event as a RESP3 push and as a RESP2 array.
    fn both(items: Vec<Value>) -> [Value; 2] {
        [Value::Push(items.clone()), Value::Array(items)]
    }

    #[test]
    fn messages_are_read_from_pushes_and_from_arrays() {
        for v in both(vec![bulk("message"), bulk("news"), bulk("hello")]) {
            assert_eq!(
                classify(v),
                Incoming::Message(Message::Channel {
                    channel: b("news"),
                    payload: b("hello")
                })
            );
        }
        for v in both(vec![bulk("pmessage"), bulk("n*"), bulk("news"), bulk("hi")]) {
            assert_eq!(
                classify(v),
                Incoming::Message(Message::Pattern {
                    pattern: b("n*"),
                    channel: b("news"),
                    payload: b("hi")
                })
            );
        }
        for v in both(vec![bulk("smessage"), bulk("shard"), bulk("x")]) {
            assert_eq!(
                classify(v),
                Incoming::Message(Message::Shard {
                    channel: b("shard"),
                    payload: b("x")
                })
            );
        }
    }

    #[test]
    fn acknowledgements_carry_the_kind_and_the_count() {
        for (word, kind) in [
            ("subscribe", SubscriptionKind::Channel),
            ("psubscribe", SubscriptionKind::Pattern),
            ("ssubscribe", SubscriptionKind::Shard),
        ] {
            for v in both(vec![bulk(word), bulk("c"), Value::Int(2)]) {
                assert_eq!(
                    classify(v),
                    Incoming::Change(SubscriptionChange::Subscribed {
                        kind,
                        name: b("c"),
                        count: 2
                    })
                );
            }
        }
        for (word, kind) in [
            ("unsubscribe", SubscriptionKind::Channel),
            ("punsubscribe", SubscriptionKind::Pattern),
            ("sunsubscribe", SubscriptionKind::Shard),
        ] {
            assert_eq!(
                classify(Value::Push(vec![bulk(word), bulk("c"), Value::Int(0)])),
                Incoming::Change(SubscriptionChange::Unsubscribed {
                    kind,
                    name: Some(b("c")),
                    count: 0
                })
            );
        }
        // Unsubscribing from everything when there was nothing: no name.
        assert_eq!(
            classify(Value::Array(vec![bulk("unsubscribe"), Value::Null, Value::Int(0)])),
            Incoming::Change(SubscriptionChange::Unsubscribed {
                kind: SubscriptionKind::Channel,
                name: None,
                count: 0
            })
        );
    }

    #[test]
    fn an_unknown_kind_is_delivered_as_a_push_not_dropped() {
        for v in both(vec![bulk("weird"), Value::Int(7), bulk("x")]) {
            assert_eq!(
                classify(v),
                Incoming::Push(Push {
                    kind: "weird".into(),
                    data: vec![Value::Int(7), bulk("x")]
                })
            );
        }
        // A message-shaped push whose parts are not strings is not a message.
        assert!(matches!(
            classify(Value::Push(vec![bulk("message"), Value::Int(1), Value::Int(2)])),
            Incoming::Push(p) if p.kind == "message"
        ));
        // Something that is not even a list is kept too.
        assert!(matches!(classify(Value::Int(5)), Incoming::Push(_)));
    }

    #[test]
    fn keepalive_answers_and_errors_are_recognised() {
        assert_eq!(classify(Value::Simple("PONG".into())), Incoming::Pong);
        assert_eq!(classify(Value::Array(vec![bulk("pong"), bulk("")])), Incoming::Pong);
        assert_eq!(classify(bulk("PONG")), Incoming::Pong);
        let e = ServerError::parse("NOPERM no");
        assert_eq!(classify(Value::Error(e.clone())), Incoming::Error(e));
    }

    #[test]
    fn invalidation_pushes_say_which_keys() {
        let keys = Push {
            kind: "invalidate".into(),
            data: vec![Value::Array(vec![bulk("a"), bulk("b")])],
        };
        assert_eq!(keys.invalidation(), Some(Invalidation::Keys(vec![b("a"), b("b")])));
        let all = Push {
            kind: "invalidate".into(),
            data: vec![Value::Null],
        };
        assert_eq!(all.invalidation(), Some(Invalidation::All));
        assert_eq!(
            Push {
                kind: "other".into(),
                data: vec![]
            }
            .invalidation(),
            None
        );
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
    fn a_closure_is_a_handler_for_messages() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&seen);
        let mut h: Box<dyn SubscriberHandler> = Box::new(move |m: Message| log.lock().unwrap().push(m));
        h.on_message(Message::Channel {
            channel: b("c"),
            payload: b("p"),
        });
        h.on_connected(false); // the rest default to doing nothing
        assert_eq!(seen.lock().unwrap().len(), 1);
    }
}
