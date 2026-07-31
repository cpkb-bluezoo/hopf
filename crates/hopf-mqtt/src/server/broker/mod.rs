// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Broker state: topics, subscriptions, retained messages, cross-reactor
//! fan-out, and (MQTT 5.0) Receive Maximum flow control + Session Expiry.
//!
//! [`BrokerState`] is held behind `Arc` and shared by every connection's
//! [`crate::server::MqttControlHandler`], regardless of which reactor owns
//! that connection. Delivery to a subscriber never touches that
//! subscriber's `Endpoint` directly from another thread — it always goes
//! through [`hopf_core::ConnHandle::send`], which hops to the owning
//! reactor internally. Per-subscriber outbound packet-id / in-flight-count
//! bookkeeping is plain atomic state on the registry entry rather than a
//! `with_endpoint` round-trip, since `Endpoint` doesn't expose the
//! connection's `ProtocolHandler` state to reach into.
//!
//! **Session persistence** is limited to what fits in memory for the
//! Session Expiry window: a session with `session_expiry > 0` that
//! disconnects without Clean Start keeps its [`SubscriberId`], topic
//! subscriptions, and packet-id counter alive as an "orphan" (see
//! [`BrokerState::orphan`]) until either a matching CONNECT resumes it
//! ([`BrokerState::register`] with `clean_start = false`) or its expiry
//! timer reaps it ([`BrokerState::expire_orphan`]). Messages published
//! while orphaned are **not** queued — that's the "durable offline queue"
//! future work the plan explicitly defers; only the subscription state
//! survives, not in-flight application data.

mod retained;
mod topic;

pub use retained::{RetainedMessage, RetainedSnapshot, RetainedStore};
pub use topic::{validate_topic_name, MatchOptions, TopicTree};

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use hopf_core::ConnHandle;

use crate::codec::{Properties, ProtocolVersion, QoS, SubscribeFilter};

/// Effectively-unlimited Receive Maximum (MQTT 5.0 default when the CONNECT
/// property is absent, and the value used for v3.1.1 connections, which
/// have no flow control concept).
pub const UNLIMITED_RECEIVE_MAXIMUM: u16 = u16::MAX;

/// Opaque identifier for one connected (or orphaned) MQTT session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId(pub(crate) u64);

/// The parts of a subscriber's state that change on reconnect/resume.
struct ConnState {
    /// `None` while orphaned (disconnected, Session Expiry still pending).
    conn: Option<ConnHandle>,
    version: ProtocolVersion,
    receive_maximum: u16,
    /// `true` when `conn` needs each PUBLISH delivered as a single write
    /// (MQTT-over-WebSocket requires exactly one Control Packet per WS
    /// message, and this codebase's WS layer doesn't support constructing
    /// one WS message out of several sends) — such connections never get
    /// the live per-chunk QoS-0 fast path in [`BrokerState::begin_publish`],
    /// even at QoS 0; they're always resolved like a QoS-1/2 recipient,
    /// from a fully-spooled, bounded (`max_publish_payload`-capped) copy.
    atomic_send: bool,
}

struct Subscriber {
    state: Mutex<ConnState>,
    client_id: String,
    next_packet_id: AtomicU16,
    /// Outbound QoS 1/2 messages sent but not yet acked, for Receive
    /// Maximum enforcement (MQTT 5.0 §3.3.4).
    in_flight: AtomicU16,
    /// Bumped every time this subscriber is orphaned, so a stale expiry
    /// timer from an earlier orphan episode can't reap a session that has
    /// since been resumed (and possibly orphaned again).
    expiry_epoch: AtomicU64,
}

/// Shared broker state: topic subscriptions, retained messages, and the
/// registry used for cross-reactor publish fan-out, session takeover, and
/// session resume.
#[derive(Default)]
pub struct BrokerState {
    next_subscriber_id: AtomicU64,
    topics: RwLock<TopicTree>,
    retained: RwLock<RetainedStore>,
    subscribers: RwLock<HashMap<SubscriberId, Subscriber>>,
    /// Client id -> current subscriber, for session-takeover / resume lookup.
    sessions: RwLock<HashMap<String, SubscriberId>>,
}

impl BrokerState {
    /// Shared, empty broker state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly-CONNECTed session for `client_id`.
    ///
    /// - If no session exists for `client_id`, or `clean_start` is set, or
    ///   an existing session is still **live** (a genuine takeover of an
    ///   active connection), this starts a fresh session: any previous
    ///   subscriptions are dropped, and `session_present` is `false`. The
    ///   previous connection's [`ConnHandle`] is returned so the caller can
    ///   close it, if it was live.
    /// - If an existing session is **orphaned** (disconnected, Session
    ///   Expiry still pending) and `clean_start` is false, this *resumes*
    ///   it: the same [`SubscriberId`], topic subscriptions, and packet-id
    ///   counter carry over, `session_present` is `true`, and no
    ///   [`ConnHandle`] is returned (there was nothing live to evict).
    pub fn register(
        &self,
        client_id: &str,
        version: ProtocolVersion,
        receive_maximum: u16,
        clean_start: bool,
        conn: ConnHandle,
        atomic_send: bool,
    ) -> (SubscriberId, Option<ConnHandle>, bool) {
        if !clean_start {
            let existing_id = self.sessions.read().unwrap().get(client_id).copied();
            if let Some(existing_id) = existing_id {
                let subs = self.subscribers.read().unwrap();
                if let Some(sub) = subs.get(&existing_id) {
                    let mut state = sub.state.lock().unwrap();
                    if state.conn.is_none() {
                        state.conn = Some(conn);
                        state.version = version;
                        state.receive_maximum = receive_maximum;
                        state.atomic_send = atomic_send;
                        drop(state);
                        sub.in_flight.store(0, Ordering::Relaxed);
                        return (existing_id, None, true);
                    }
                }
            }
        }

        let id = SubscriberId(self.next_subscriber_id.fetch_add(1, Ordering::Relaxed));
        let old_id = self.sessions.write().unwrap().insert(client_id.to_string(), id);
        let evicted_conn = if let Some(old_id) = old_id {
            self.topics.write().unwrap().unsubscribe_all(old_id);
            self.subscribers
                .write()
                .unwrap()
                .remove(&old_id)
                .and_then(|s| s.state.into_inner().unwrap().conn)
        } else {
            None
        };

        self.subscribers.write().unwrap().insert(
            id,
            Subscriber {
                state: Mutex::new(ConnState {
                    conn: Some(conn),
                    version,
                    receive_maximum,
                    atomic_send,
                }),
                client_id: client_id.to_string(),
                next_packet_id: AtomicU16::new(1),
                in_flight: AtomicU16::new(0),
                expiry_epoch: AtomicU64::new(0),
            },
        );
        (id, evicted_conn, false)
    }

    /// Tear down a session immediately: drop its subscriptions and registry
    /// entry. Used when there's no Session Expiry to honour (Clean
    /// Session/Start, `session_expiry == 0`, or v3.1.1).
    pub fn unregister(&self, id: SubscriberId) {
        self.topics.write().unwrap().unsubscribe_all(id);
        if let Some(sub) = self.subscribers.write().unwrap().remove(&id) {
            let mut sessions = self.sessions.write().unwrap();
            if sessions.get(&sub.client_id) == Some(&id) {
                sessions.remove(&sub.client_id);
            }
        }
    }

    /// Mark a session orphaned (disconnected, but its Session Expiry
    /// interval hasn't elapsed) instead of tearing it down: subscriptions
    /// and packet-id state stay live for a possible [`Self::register`]
    /// resume. Returns the epoch to pass to [`Self::expire_orphan`]'s timer.
    pub fn orphan(&self, id: SubscriberId) -> u64 {
        let subs = self.subscribers.read().unwrap();
        let Some(sub) = subs.get(&id) else {
            return 0;
        };
        sub.state.lock().unwrap().conn = None;
        sub.expiry_epoch.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Reap an orphaned session if it's still orphaned under the same
    /// epoch [`Self::orphan`] returned (i.e. it wasn't resumed, or was
    /// resumed and orphaned again before this timer fired).
    pub fn expire_orphan(&self, id: SubscriberId, epoch: u64) {
        let client_id = {
            let subs = self.subscribers.read().unwrap();
            let Some(sub) = subs.get(&id) else {
                return;
            };
            let still_this_orphan = sub.state.lock().unwrap().conn.is_none()
                && sub.expiry_epoch.load(Ordering::Relaxed) == epoch;
            if !still_this_orphan {
                return;
            }
            sub.client_id.clone()
        };
        self.subscribers.write().unwrap().remove(&id);
        self.topics.write().unwrap().unsubscribe_all(id);
        let mut sessions = self.sessions.write().unwrap();
        if sessions.get(&client_id) == Some(&id) {
            sessions.remove(&client_id);
        }
    }

    /// Subscribe `id` to `filter`. Errors on a malformed filter. Returns
    /// whether this is a brand new subscription (see
    /// [`TopicTree::subscribe`] / MQTT 5.0 Retain Handling `1`).
    pub fn subscribe(&self, id: SubscriberId, filter: &SubscribeFilter) -> Result<bool, &'static str> {
        self.topics
            .write()
            .unwrap()
            .subscribe(&filter.topic_filter, id, MatchOptions::from_filter(filter))
    }

    /// Unsubscribe `id` from `filter`. Returns whether it was subscribed.
    pub fn unsubscribe(&self, id: SubscriberId, filter: &str) -> bool {
        self.topics.write().unwrap().unsubscribe(filter, id)
    }

    /// A subscriber acked delivery of one QoS 1 (PUBACK) or QoS 2 (PUBCOMP)
    /// message we sent it — frees one Receive Maximum credit.
    pub fn ack_delivered(&self, id: SubscriberId) {
        if let Some(sub) = self.subscribers.read().unwrap().get(&id) {
            let _ = sub
                .in_flight
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_sub(1)));
        }
    }

    /// Begin fan-out for a PUBLISH of `payload_len` bytes arriving (or
    /// about to arrive) in chunks: snapshots matching subscribers
    /// (including the publisher itself, if subscribed and it didn't
    /// request No Local) and, for every QoS-0 recipient, sends its PUBLISH
    /// header immediately — its payload is forwarded live via
    /// [`PublishFanout::feed`] as chunks arrive, never assembled into one
    /// buffer.
    ///
    /// QoS-1/2 recipients can't be given a live streamed header this way:
    /// each needs its own freshly-allocated packet id (only handed out if
    /// Receive Maximum credit is free *once delivery is actually
    /// possible*, not before), so they're recorded in the returned
    /// [`PublishFanout`] for the caller to resolve with
    /// [`Self::deliver_deferred`] once the complete payload is available
    /// (spooled to disk — see the module docs' note on why QoS-1/2/retain
    /// re-reads the spool once per recipient instead of buffering the
    /// payload in memory for the whole delivery). A subscriber already at
    /// Receive Maximum, or currently orphaned (Session Expiry pending), is
    /// silently skipped (no retry / offline queue — see the module docs).
    /// `publisher` is `None` for messages with no originating subscriber
    /// (e.g. Will messages).
    pub fn begin_publish(
        &self,
        publisher: Option<SubscriberId>,
        topic: &str,
        payload_len: u64,
        qos: QoS,
        retain: bool,
        properties: &Properties,
    ) -> PublishFanout {
        let matches = self.topics.read().unwrap().matching_subscribers(topic);
        let mut live = Vec::new();
        let mut deferred = Vec::new();
        if !matches.is_empty() {
            let subscribers = self.subscribers.read().unwrap();
            for (sub_id, opts) in matches {
                if opts.no_local && Some(sub_id) == publisher {
                    continue;
                }
                let Some(sub) = subscribers.get(&sub_id) else {
                    continue;
                };
                let effective_qos = min_qos(qos, opts.max_qos);
                let effective_retain = retain && opts.retain_as_published;
                let atomic_send = sub.state.lock().unwrap().atomic_send;
                if effective_qos == QoS::AtMostOnce && !atomic_send {
                    let Some((conn, version, _, _)) = try_reserve_delivery(sub, effective_qos) else {
                        continue;
                    };
                    let header = crate::codec::encode::encode_publish_header(
                        topic, effective_qos, false, effective_retain, 0, payload_len, properties, version,
                    );
                    conn.send(header);
                    live.push(conn);
                } else {
                    // QoS-1/2, or a connection that needs every PUBLISH
                    // delivered as a single write (see `ConnState::atomic_send`)
                    // even at QoS 0 — resolved from the spool once complete.
                    deferred.push((sub_id, effective_qos, effective_retain));
                }
            }
        }
        PublishFanout { live, deferred }
    }

    /// Deliver the now-complete payload to every QoS-1/2 recipient
    /// [`Self::begin_publish`] deferred, each with its own freshly
    /// allocated packet id. `spool` is `Some((path, len))` re-read once per
    /// recipient (never held whole in memory for the group), or `None` for
    /// a zero-length payload.
    pub fn deliver_deferred(
        &self,
        fanout: &PublishFanout,
        topic: &str,
        properties: &Properties,
        spool: Option<(&Path, u64)>,
    ) {
        for &(sub_id, effective_qos, effective_retain) in &fanout.deferred {
            let (conn, version, packet_id, atomic_send) = {
                let subscribers = self.subscribers.read().unwrap();
                let Some(sub) = subscribers.get(&sub_id) else {
                    continue;
                };
                let Some(reserved) = try_reserve_delivery(sub, effective_qos) else {
                    continue;
                };
                reserved
            };
            match spool {
                Some((path, len)) => stream_file_publish(
                    &conn, topic, effective_qos, effective_retain, packet_id, path, len, properties, version,
                    atomic_send,
                ),
                None => {
                    let header = crate::codec::encode::encode_publish_header(
                        topic, effective_qos, false, effective_retain, packet_id, 0, properties, version,
                    );
                    conn.send(header);
                }
            }
        }
    }

    /// Set or clear the retained message for `topic`, handing off ownership
    /// of `spool`'s file (if any) to the retained-message store — see
    /// [`RetainedStore::publish`].
    pub fn retain(&self, topic: &str, qos: QoS, spool: Option<(std::path::PathBuf, u64)>, properties: Properties) {
        let (path, len) = match spool {
            Some((p, l)) => (Some(p), l),
            None => (None, 0),
        };
        self.retained.write().unwrap().publish(topic, qos, path, len, properties);
    }

    /// Retained messages matching a freshly-subscribed `filter`, to deliver
    /// immediately (MQTT 3.1.1 §3.8.4).
    pub fn retained_matching(&self, filter: &str) -> Vec<(String, RetainedSnapshot)> {
        self.retained
            .read()
            .unwrap()
            .matching(filter)
            .into_iter()
            .map(|(topic, msg)| (topic.to_string(), msg))
            .collect()
    }

    /// Deliver one retained message to a single newly-subscribed connection
    /// at `max_qos` (the RETAIN flag is always set on this delivery path,
    /// independent of Retain As Published — that option only affects live
    /// fan-out via [`Self::begin_publish`]).
    pub fn deliver_retained(&self, id: SubscriberId, topic: &str, msg: &RetainedSnapshot, max_qos: QoS) {
        let subscribers = self.subscribers.read().unwrap();
        let Some(sub) = subscribers.get(&id) else {
            return;
        };
        let effective_qos = min_qos(msg.qos, max_qos);
        let Some((conn, version, packet_id, atomic_send)) = try_reserve_delivery(sub, effective_qos) else {
            return;
        };
        drop(subscribers);
        match &msg.path {
            Some(path) => stream_file_publish(
                &conn, topic, effective_qos, true, packet_id, path, msg.payload_len, &msg.properties, version,
                atomic_send,
            ),
            None => {
                let header = crate::codec::encode::encode_publish_header(
                    topic, effective_qos, false, true, packet_id, 0, &msg.properties, version,
                );
                conn.send(header);
            }
        }
    }
}

/// Fan-out plan produced by [`BrokerState::begin_publish`]: live QoS-0
/// connections (headers already sent, ready for [`Self::feed`]) plus the
/// QoS-1/2 subscribers deferred until the payload is fully known.
pub struct PublishFanout {
    live: Vec<ConnHandle>,
    deferred: Vec<(SubscriberId, QoS, bool)>,
}

impl PublishFanout {
    /// Forward one payload chunk to every live QoS-0 recipient.
    pub fn feed(&self, chunk: &[u8]) {
        for conn in &self.live {
            conn.send(chunk.to_vec());
        }
    }

    /// Whether any QoS-1/2 recipient is waiting on
    /// [`BrokerState::deliver_deferred`].
    pub fn has_deferred(&self) -> bool {
        !self.deferred.is_empty()
    }
}

/// Send a PUBLISH header for `payload_size` bytes, then stream `path`'s
/// contents to `conn` in bounded chunks — used for retained-message and
/// deferred QoS-1/2 delivery, where the payload lives on disk rather than
/// in memory.
///
/// `atomic`, when set, sends the whole encoded packet (header + payload) in
/// one write instead — required for a connection whose transport frames
/// every write as an independent message (MQTT-over-WebSocket: see
/// `ConnState::atomic_send`). Still bounded, never buffering more than one
/// `max_publish_payload`-capped packet at a time.
#[allow(clippy::too_many_arguments)]
fn stream_file_publish(
    conn: &ConnHandle,
    topic: &str,
    qos: QoS,
    retain: bool,
    packet_id: u16,
    path: &Path,
    payload_size: u64,
    properties: &Properties,
    version: ProtocolVersion,
    atomic: bool,
) {
    let mut header = crate::codec::encode::encode_publish_header(
        topic, qos, false, retain, packet_id, payload_size, properties, version,
    );
    if atomic {
        if let Ok(mut f) = std::fs::File::open(path) {
            let _ = f.read_to_end(&mut header);
        }
        conn.send(header);
        return;
    }
    conn.send(header);
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    let mut buf = [0u8; 8192];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => conn.send(buf[..n].to_vec()),
            Err(_) => break,
        }
    }
}

/// Try to claim capacity to deliver at `effective_qos` to `sub`: `None` if
/// orphaned or at its Receive Maximum, otherwise `(conn, version,
/// packet_id, atomic_send)` with a freshly allocated packet id (0 for QoS
/// 0) and the in-flight counter already incremented for QoS 1/2.
fn try_reserve_delivery(sub: &Subscriber, effective_qos: QoS) -> Option<(ConnHandle, ProtocolVersion, u16, bool)> {
    let (conn, version, receive_maximum, atomic_send) = {
        let state = sub.state.lock().unwrap();
        (state.conn.clone()?, state.version, state.receive_maximum, state.atomic_send)
    };
    if effective_qos == QoS::AtMostOnce {
        return Some((conn, version, 0, atomic_send));
    }
    let reserved = sub
        .in_flight
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            if n < receive_maximum {
                Some(n + 1)
            } else {
                None
            }
        })
        .is_ok();
    if !reserved {
        return None;
    }
    Some((conn, version, next_packet_id(&sub.next_packet_id), atomic_send))
}

fn min_qos(a: QoS, b: QoS) -> QoS {
    if a.value() <= b.value() {
        a
    } else {
        b
    }
}

fn next_packet_id(counter: &AtomicU16) -> u16 {
    let id = counter.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        counter.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::packet::SubscribeFilter;
    use hopf_core::ConnHandle;

    fn noop_handle() -> ConnHandle {
        ConnHandle::from_execute(std::sync::Arc::new(|task| task()))
    }

    fn filter(topic_filter: &str, max_qos: QoS) -> SubscribeFilter {
        SubscribeFilter {
            topic_filter: topic_filter.to_string(),
            max_qos,
            no_local: false,
            retain_as_published: false,
            retain_handling: 0,
        }
    }

    #[test]
    fn session_takeover_evicts_old_connection() {
        let broker = BrokerState::new();
        let (id1, evicted1, present1) =
            broker.register("client-a", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, noop_handle(), false);
        assert!(evicted1.is_none());
        assert!(!present1);
        broker.subscribe(id1, &filter("a/b", QoS::AtMostOnce)).unwrap();

        let (id2, evicted2, present2) =
            broker.register("client-a", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, noop_handle(), false);
        assert!(evicted2.is_some());
        assert!(!present2);
        assert_ne!(id1, id2);

        // Old subscriptions are gone after a clean-start takeover.
        assert!(broker.topics.read().unwrap().matching_subscribers("a/b").is_empty());
    }

    #[test]
    fn unregister_drops_subscriptions() {
        let broker = BrokerState::new();
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, noop_handle(), false);
        broker.subscribe(id, &filter("x/y", QoS::AtLeastOnce)).unwrap();
        broker.unregister(id);
        assert!(broker.topics.read().unwrap().matching_subscribers("x/y").is_empty());
    }

    #[test]
    fn orphan_then_resume_preserves_subscriptions_and_reports_session_present() {
        let broker = BrokerState::new();
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.subscribe(id, &filter("x/y", QoS::AtLeastOnce)).unwrap();

        let epoch = broker.orphan(id);
        assert!(epoch > 0);
        // Orphaned: publish shouldn't be delivered anywhere, but the
        // subscription itself is still registered.
        assert_eq!(broker.topics.read().unwrap().matching_subscribers("x/y").len(), 1);

        let (resumed_id, evicted, present) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        assert_eq!(resumed_id, id);
        assert!(evicted.is_none());
        assert!(present);
        assert_eq!(broker.topics.read().unwrap().matching_subscribers("x/y").len(), 1);
    }

    #[test]
    fn expire_orphan_reaps_only_matching_epoch() {
        let broker = BrokerState::new();
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.subscribe(id, &filter("x/y", QoS::AtMostOnce)).unwrap();
        let epoch = broker.orphan(id);

        // A resume bumps things back to live; the stale timer must not reap it.
        broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.expire_orphan(id, epoch);
        assert_eq!(broker.topics.read().unwrap().matching_subscribers("x/y").len(), 1);

        // Orphan again (new epoch) and reap for real.
        let epoch2 = broker.orphan(id);
        broker.expire_orphan(id, epoch2);
        assert!(broker.topics.read().unwrap().matching_subscribers("x/y").is_empty());
    }

    #[test]
    fn clean_start_ignores_orphaned_session() {
        let broker = BrokerState::new();
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.subscribe(id, &filter("x/y", QoS::AtMostOnce)).unwrap();
        broker.orphan(id);

        let (id2, _, present) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, noop_handle(), false);
        assert_ne!(id, id2);
        assert!(!present);
        assert!(broker.topics.read().unwrap().matching_subscribers("x/y").is_empty());
    }

    #[test]
    fn receive_maximum_caps_in_flight_qos1_deliveries() {
        let broker = BrokerState::new();
        let (sub_id, _, _) = broker.register("sub", ProtocolVersion::V5, 1, true, noop_handle(), false);
        broker.subscribe(sub_id, &filter("t", QoS::AtLeastOnce)).unwrap();

        // First delivery consumes the one credit; a second while still
        // unacked should be dropped rather than sent.
        let subs = broker.subscribers.read().unwrap();
        let sub = subs.get(&sub_id).unwrap();
        assert!(try_reserve_delivery(sub, QoS::AtLeastOnce).is_some());
        assert!(try_reserve_delivery(sub, QoS::AtLeastOnce).is_none());
        drop(subs);

        broker.ack_delivered(sub_id);
        let subs = broker.subscribers.read().unwrap();
        let sub = subs.get(&sub_id).unwrap();
        assert!(try_reserve_delivery(sub, QoS::AtLeastOnce).is_some());
    }

    #[test]
    fn no_local_suppresses_delivery_to_publisher() {
        let broker = BrokerState::new();
        let (id, _, _) = broker.register("c1", ProtocolVersion::V5, UNLIMITED_RECEIVE_MAXIMUM, true, noop_handle(), false);
        broker
            .subscribe(
                id,
                &SubscribeFilter {
                    topic_filter: "t".into(),
                    max_qos: QoS::AtMostOnce,
                    no_local: true,
                    retain_as_published: false,
                    retain_handling: 0,
                },
            )
            .unwrap();
        // No assertion on delivery here (no_local is exercised end-to-end in
        // the integration tests); this just checks registration succeeds
        // with no_local set and the match options carry it through.
        let matches = broker.topics.read().unwrap().matching_subscribers("t");
        assert!(matches[0].1.no_local);
        let fanout = broker.begin_publish(Some(id), "t", 1, QoS::AtMostOnce, false, &Properties::new());
        fanout.feed(b"x");
    }

    #[test]
    fn packet_id_allocation_skips_zero_and_increments() {
        let counter = AtomicU16::new(0);
        let first = next_packet_id(&counter);
        assert_ne!(first, 0);
        let second = next_packet_id(&counter);
        assert_ne!(second, 0);
        assert_ne!(first, second);
    }
}
