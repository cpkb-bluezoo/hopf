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
//! **Session persistence** for the Session Expiry window keeps
//! [`SubscriberId`], topic subscriptions, and the packet-id counter as an
//! "orphan" (see [`BrokerState::orphan`]) until resume or
//! [`BrokerState::expire_orphan`]. QoS ≥ 1 publishes matching an orphaned
//! subscriber are queued in [`crate::server::store::MqttMessageStore`] and
//! drained on resume via [`BrokerState::drain_offline`].

mod retained;
mod topic;

pub use retained::{RetainedMessage, RetainedSnapshot, RetainedStore};
pub use topic::{validate_topic_name, MatchOptions, TopicTree};

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use hopf_core::{ConnHandle, Runtime, StorageError};

use crate::codec::packet::Will;
use crate::codec::{Properties, ProtocolVersion, QoS, SubscribeFilter};
use crate::server::expiry::{expiry_deadline, is_expired};
use crate::server::spool_file::SpoolHandle;
use crate::server::store::{queued_message, InMemoryMessageStore, MqttMessageStore, QueuedMessage};

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

/// Pending Will Delay publish, keyed by client id.
struct DelayedWill {
    will: Will,
    /// Cancels a stale timer after reconnect / clean-start replacement.
    epoch: u64,
}

/// Shared broker state: topic subscriptions, retained messages, and the
/// registry used for cross-reactor publish fan-out, session takeover, and
/// session resume.
pub struct BrokerState {
    next_subscriber_id: AtomicU64,
    topics: RwLock<TopicTree>,
    retained: RwLock<RetainedStore>,
    subscribers: RwLock<HashMap<SubscriberId, Subscriber>>,
    /// Client id -> current subscriber, for session-takeover / resume lookup.
    sessions: RwLock<HashMap<String, SubscriberId>>,
    /// Unclean-disconnect Wills waiting on Will Delay Interval.
    delayed_wills: Mutex<HashMap<String, DelayedWill>>,
    next_will_epoch: AtomicU64,
    /// Offline QoS ≥ 1 queues and in-flight retransmission bookkeeping.
    pub store: Arc<dyn MqttMessageStore>,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            next_subscriber_id: AtomicU64::new(0),
            topics: RwLock::new(TopicTree::default()),
            retained: RwLock::new(RetainedStore::default()),
            subscribers: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            delayed_wills: Mutex::new(HashMap::new()),
            next_will_epoch: AtomicU64::new(0),
            store: Arc::new(InMemoryMessageStore::new()),
        }
    }
}

impl BrokerState {
    /// Shared, empty broker state with an in-memory message store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Shared broker state using a custom [`MqttMessageStore`].
    pub fn with_store(store: Arc<dyn MqttMessageStore>) -> Self {
        Self {
            store,
            ..Self::default()
        }
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
        // Reconnect / takeover cancels any pending Will Delay for this client.
        self.cancel_delayed_will(client_id);

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
            self.store.clear_offline(old_id);
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
        self.store.clear_offline(id);
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
    /// resume. Unacked outbound QoS 1/2 messages are moved into the offline
    /// queue for delivery on resume. Returns the epoch to pass to
    /// [`Self::expire_orphan`]'s timer.
    pub fn orphan(&self, id: SubscriberId) -> u64 {
        let subs = self.subscribers.read().unwrap();
        let Some(sub) = subs.get(&id) else {
            return 0;
        };
        sub.state.lock().unwrap().conn = None;
        let epoch = sub.expiry_epoch.fetch_add(1, Ordering::Relaxed) + 1;
        drop(subs);

        // Unacked outbound becomes offline — the live connection is gone.
        let pending: Vec<_> = self
            .store
            .due_retransmits(std::time::Duration::ZERO)
            .into_iter()
            .filter(|(sid, _, _)| *sid == id)
            .collect();
        for (_, packet_id, msg) in pending {
            self.store.ack_inflight(id, packet_id);
            self.store.enqueue_offline(id, msg);
        }
        epoch
    }

    /// Reap an orphaned session if it's still orphaned under the same
    /// epoch [`Self::orphan`] returned (i.e. it wasn't resumed, or was
    /// resumed and orphaned again before this timer fired). `self_arc` is
    /// `self` as an `Arc` — needed to offload a delayed Will's spool write
    /// (issue #187), which must move an owned `Arc<BrokerState>` into a
    /// `'static` storage closure; a plain `&self` can't provide that.
    pub fn expire_orphan(
        &self,
        self_arc: &Arc<BrokerState>,
        id: SubscriberId,
        epoch: u64,
        runtime: Arc<Runtime>,
        handle: ConnHandle,
    ) {
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
        self.store.clear_offline(id);
        let mut sessions = self.sessions.write().unwrap();
        if sessions.get(&client_id) == Some(&id) {
            sessions.remove(&client_id);
        }
        // Session lifetime ended — publish any Will still waiting on delay
        // (MQTT: Will Delay capped by Session Expiry means the Will fires
        // when the session expires if it hasn't already).
        self.fire_delayed_will(self_arc, &client_id, u64::MAX, runtime, handle);
    }

    /// Park `will` for `client_id` until [`Self::fire_delayed_will`]. Returns
    /// the epoch the caller must pass to the timer callback.
    pub fn park_delayed_will(&self, client_id: &str, will: Will) -> u64 {
        let epoch = self.next_will_epoch.fetch_add(1, Ordering::Relaxed) + 1;
        self.delayed_wills.lock().unwrap().insert(
            client_id.to_string(),
            DelayedWill { will, epoch },
        );
        epoch
    }

    /// Drop a parked Will Delay (reconnect / clean disconnect / takeover).
    pub fn cancel_delayed_will(&self, client_id: &str) {
        self.delayed_wills.lock().unwrap().remove(client_id);
    }

    /// Publish a parked Will if it is still pending under `epoch`.
    /// Pass `u64::MAX` to fire regardless of epoch (session expiry path).
    /// `self_arc` — see [`Self::expire_orphan`]'s doc comment.
    pub fn fire_delayed_will(
        &self,
        self_arc: &Arc<BrokerState>,
        client_id: &str,
        epoch: u64,
        runtime: Arc<Runtime>,
        handle: ConnHandle,
    ) {
        let will = {
            let mut map = self.delayed_wills.lock().unwrap();
            match map.get(client_id) {
                Some(dw) if epoch == u64::MAX || dw.epoch == epoch => {
                    map.remove(client_id).map(|dw| dw.will)
                }
                _ => None,
            }
        };
        if let Some(will) = will {
            crate::server::publish_spool::publish_whole(
                self_arc,
                None,
                &will.topic,
                &will.payload,
                will.qos,
                will.retain,
                &will.properties,
                runtime,
                handle,
            );
        }
    }

    /// Look up the client id for a live or orphaned subscriber.
    pub fn client_id(&self, id: SubscriberId) -> Option<String> {
        self.subscribers
            .read()
            .unwrap()
            .get(&id)
            .map(|s| s.client_id.clone())
    }

    /// Whether `id` currently has a live connection (not orphaned).
    pub fn is_connected(&self, id: SubscriberId) -> bool {
        self.subscribers
            .read()
            .unwrap()
            .get(&id)
            .is_some_and(|sub| sub.state.lock().unwrap().conn.is_some())
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
    /// Receive Maximum is silently skipped. An orphaned subscriber with
    /// effective QoS ≥ 1 is deferred so [`Self::deliver_deferred`] can
    /// enqueue into the message store; QoS 0 to an orphan is dropped.
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
        let now = Instant::now();
        // Message Expiry Interval of 0 (or already elapsed) → drop before fan-out.
        if is_expired(properties, now, now) {
            return PublishFanout {
                live: Vec::new(),
                deferred: Vec::new(),
            };
        }

        let matches = self.topics.write().unwrap().matching_subscribers(topic);
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
    /// allocated packet id. `spool` is `Some((handle, len))`, re-read once
    /// per recipient (never held whole in memory for the group), or `None`
    /// for a zero-length payload. Every recipient's read+delivery (and
    /// orphaned recipients' offline-queue write) is offloaded to
    /// `hopf_core::StorageExecutor` (issue #187) — `conn.send()` and every
    /// [`crate::server::store::MqttMessageStore`] method are thread-safe,
    /// so each can run entirely on the storage thread with a no-op or
    /// bookkeeping-only completion callback; nothing here needs to hop
    /// back to a reactor thread.
    ///
    /// Orphaned recipients with effective QoS ≥ 1 are enqueued into
    /// [`Self::store`] instead of being delivered.
    pub fn deliver_deferred(
        &self,
        fanout: &PublishFanout,
        topic: &str,
        properties: &Properties,
        spool: Option<(SpoolHandle, u64)>,
        runtime: &Arc<Runtime>,
    ) {
        for &(sub_id, effective_qos, effective_retain) in &fanout.deferred {
            let orphaned = {
                let subscribers = self.subscribers.read().unwrap();
                match subscribers.get(&sub_id) {
                    Some(sub) => sub.state.lock().unwrap().conn.is_none(),
                    None => continue,
                }
            };
            if orphaned {
                if effective_qos == QoS::AtMostOnce {
                    continue;
                }
                let store = Arc::clone(&self.store);
                let topic_owned = topic.to_string();
                let properties_owned = properties.clone();
                let spool_op = spool.clone();
                runtime.storage().submit_on(
                    detached_handle(),
                    move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                        let payload = match &spool_op {
                            Some((sh, _)) => read_spool_payload(sh.path()).unwrap_or_default(),
                            None => Vec::new(),
                        };
                        store.enqueue_offline(
                            sub_id,
                            queued_message(&topic_owned, &payload, effective_qos, effective_retain, &properties_owned),
                        );
                        Ok(())
                    },
                    |_: Result<(), StorageError>| {},
                );
                continue;
            }

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
            let topic_op = topic.to_string();
            let properties_op = properties.clone();
            let spool_op = spool.clone();
            let store = Arc::clone(&self.store);
            let topic_cb = topic.to_string();
            let properties_cb = properties.clone();
            runtime.storage().submit_streamed(
                conn,
                move |c: &ConnHandle| -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
                    match &spool_op {
                        Some((sh, len)) => {
                            stream_file_publish(
                                c, &topic_op, effective_qos, effective_retain, packet_id, sh.path(), *len,
                                &properties_op, version, atomic_send,
                            );
                            if effective_qos != QoS::AtMostOnce {
                                Ok(read_spool_payload(sh.path()))
                            } else {
                                Ok(None)
                            }
                        }
                        None => {
                            let header = crate::codec::encode::encode_publish_header(
                                &topic_op, effective_qos, false, effective_retain, packet_id, 0, &properties_op, version,
                            );
                            c.send(header);
                            Ok(None)
                        }
                    }
                },
                move |result: Result<Option<Vec<u8>>, StorageError>| {
                    if effective_qos == QoS::AtMostOnce {
                        return;
                    }
                    let payload = result.ok().flatten().unwrap_or_default();
                    store.track_inflight(
                        sub_id,
                        packet_id,
                        queued_message(&topic_cb, &payload, effective_qos, effective_retain, &properties_cb),
                    );
                },
            );
        }
    }

    /// Deliver every offline message queued for `id` (session resume).
    /// Messages that cannot be reserved (Receive Maximum exhausted) are
    /// re-enqueued.
    pub fn drain_offline(&self, id: SubscriberId) {
        let msgs = self.store.take_offline(id);
        for msg in msgs {
            if !self.deliver_queued(id, &msg, false) {
                self.store.enqueue_offline(id, msg);
            }
        }
    }

    /// Async counterpart of [`Self::drain_offline`] (issue #216) — reads
    /// the offline queue off the reactor thread via
    /// [`MqttMessageStore::take_offline_async`], delivering the drained
    /// messages and calling `done` once finished. `handle` is the resuming
    /// connection's own `ConnHandle`, threaded through so a store that
    /// offloads (e.g. `FileBackedMessageStore`) routes completion back to
    /// that connection's reactor rather than an unrelated one.
    pub fn drain_offline_async(
        self: &Arc<Self>,
        id: SubscriberId,
        handle: ConnHandle,
        done: Box<dyn FnOnce() + Send>,
    ) {
        let broker = Arc::clone(self);
        self.store.take_offline_async(
            id,
            handle,
            Box::new(move |msgs| {
                for msg in msgs {
                    if !broker.deliver_queued(id, &msg, false) {
                        broker.store.enqueue_offline(id, msg);
                    }
                }
                done();
            }),
        );
    }

    /// Re-send outbound QoS 1/2 publishes whose in-flight timer has elapsed
    /// for `id`. Returns how many were retransmitted.
    pub fn retransmit_due(&self, id: SubscriberId, older_than: std::time::Duration) -> usize {
        let due = self.store.due_retransmits(older_than);
        let mut n = 0;
        for (sub_id, packet_id, msg) in due {
            if sub_id != id {
                continue;
            }
            if self.deliver_queued_inner(id, &msg, true, Some(packet_id)) {
                // Refresh the sent timestamp for the next retry window.
                self.store.track_inflight(id, packet_id, msg);
                n += 1;
            }
        }
        n
    }

    /// Deliver one queued message to a single subscriber (`dup` = retransmission).
    fn deliver_queued(&self, id: SubscriberId, msg: &QueuedMessage, dup: bool) -> bool {
        self.deliver_queued_inner(id, msg, dup, None)
    }

    /// When `forced_packet_id` is `Some`, reuse that id (retransmission — do
    /// not bump in-flight; credit was taken on the first send).
    fn deliver_queued_inner(
        &self,
        id: SubscriberId,
        msg: &QueuedMessage,
        dup: bool,
        forced_packet_id: Option<u16>,
    ) -> bool {
        let subscribers = self.subscribers.read().unwrap();
        let Some(sub) = subscribers.get(&id) else {
            return false;
        };
        let (conn, version, packet_id) = if let Some(pid) = forced_packet_id {
            let state = sub.state.lock().unwrap();
            let Some(conn) = state.conn.clone() else {
                return false;
            };
            (conn, state.version, pid)
        } else {
            match try_reserve_delivery(sub, msg.qos) {
                Some((conn, version, packet_id, _)) => (conn, version, packet_id),
                None => return false,
            }
        };
        drop(subscribers);
        let wire = crate::codec::encode::encode_publish(
            &msg.topic,
            msg.qos,
            dup,
            msg.retain,
            packet_id,
            &msg.payload,
            &msg.properties,
            version,
        );
        conn.send(wire);
        if msg.qos != QoS::AtMostOnce && forced_packet_id.is_none() {
            self.store.track_inflight(id, packet_id, msg.clone());
        }
        true
    }

    /// Set or clear the retained message for `topic`, handing off ownership
    /// of `spool`'s handle (if any) to the retained-message store — see
    /// [`RetainedStore::publish`]. No blocking I/O here: replacing or
    /// clearing an entry just drops an [`SpoolHandle`], which self-offloads
    /// its own file deletion (issue #187) once nothing else — including any
    /// in-flight [`Self::deliver_retained`] read — still holds a clone.
    pub fn retain(&self, topic: &str, qos: QoS, spool: Option<(SpoolHandle, u64)>, properties: Properties) {
        let now = Instant::now();
        let expires_at = expiry_deadline(&properties, now);
        if expires_at.is_some_and(|d| now >= d) {
            // Expired at retain time — clear any prior retained message.
            self.retained
                .write()
                .unwrap()
                .publish(topic, qos, None, 0, properties, None);
            return;
        }
        let (handle, len) = match spool {
            Some((h, l)) => (Some(h), l),
            None => (None, 0),
        };
        self.retained
            .write()
            .unwrap()
            .publish(topic, qos, handle, len, properties, expires_at);
    }

    /// Retained messages matching a freshly-subscribed `filter`, to deliver
    /// immediately (MQTT 3.1.1 §3.8.4). Expired retained messages are purged.
    pub fn retained_matching(&self, filter: &str) -> Vec<(String, RetainedSnapshot)> {
        self.retained.write().unwrap().matching(filter)
    }

    /// Deliver one retained message to a single newly-subscribed connection
    /// at `max_qos` (the RETAIN flag is always set on this delivery path,
    /// independent of Retain As Published — that option only affects live
    /// fan-out via [`Self::begin_publish`]). The spool read is offloaded
    /// (issue #187); `msg`'s own `SpoolHandle` clone, captured into the
    /// storage job, keeps the file alive for the read even if the retained
    /// entry is replaced or cleared before the job runs.
    pub fn deliver_retained(
        &self,
        id: SubscriberId,
        topic: &str,
        msg: &RetainedSnapshot,
        max_qos: QoS,
        runtime: &Arc<Runtime>,
    ) {
        if msg.expires_at.is_some_and(|d| Instant::now() >= d) {
            return;
        }
        let mut props = msg.properties.clone();
        if let Some(expires_at) = msg.expires_at {
            // Reconstruct received_at ≈ expires_at - original interval is unknown;
            // rewrite remaining from absolute deadline.
            let now = Instant::now();
            if now >= expires_at {
                return;
            }
            let remaining = expires_at.saturating_duration_since(now).as_secs();
            props.set_u32(
                crate::codec::properties::property::MESSAGE_EXPIRY_INTERVAL,
                u32::try_from(remaining).unwrap_or(u32::MAX),
            );
        }
        let subscribers = self.subscribers.read().unwrap();
        let Some(sub) = subscribers.get(&id) else {
            return;
        };
        let effective_qos = min_qos(msg.qos, max_qos);
        let Some((conn, version, packet_id, atomic_send)) = try_reserve_delivery(sub, effective_qos) else {
            return;
        };
        drop(subscribers);
        let topic_owned = topic.to_string();
        let payload_len = msg.payload_len;
        let path = msg.path.clone();
        runtime.storage().submit_streamed(
            conn,
            move |c: &ConnHandle| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                match &path {
                    Some(sh) => stream_file_publish(
                        c, &topic_owned, effective_qos, true, packet_id, sh.path(), payload_len, &props, version,
                        atomic_send,
                    ),
                    None => {
                        let header = crate::codec::encode::encode_publish_header(
                            &topic_owned, effective_qos, false, true, packet_id, 0, &props, version,
                        );
                        c.send(header);
                    }
                }
                Ok(())
            },
            |_: Result<(), StorageError>| {},
        );
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

/// A `ConnHandle` whose only valid use is as a `submit_on`/`submit_streamed`
/// routing target for a job whose callback does nothing publisher/
/// subscriber-connection-specific (issue #187) — e.g. an orphaned
/// subscriber's offline-queue write, which isn't tied to any live
/// connection. `submit_on`'s callback dispatch only ever calls
/// `ConnHandle::execute` on the handle it's given, never `with_endpoint`,
/// so a task-only handle works correctly here.
fn detached_handle() -> ConnHandle {
    ConnHandle::from_execute(Arc::new(|task| task()))
}

/// Read a spool file into memory (offline enqueue / inflight tracking).
fn read_spool_payload(path: &Path) -> Option<Vec<u8>> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
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

    fn test_runtime() -> Arc<Runtime> {
        Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap())
    }

    /// Issue #187: `publish_whole`'s spool write (and the `deliver_deferred`
    /// it triggers) is now offloaded, so an orphaned subscriber's message
    /// doesn't land in the offline queue synchronously. `take_offline` is
    /// destructive (no peek API), so poll by taking-and-re-enqueueing until
    /// something shows up, rather than a fixed sleep.
    fn wait_for_offline_message(broker: &BrokerState, id: SubscriberId, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            let msgs = broker.store.take_offline(id);
            if !msgs.is_empty() {
                for m in msgs {
                    broker.store.enqueue_offline(id, m);
                }
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        false
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
        assert!(broker.topics.write().unwrap().matching_subscribers("a/b").is_empty());
    }

    #[test]
    fn unregister_drops_subscriptions() {
        let broker = BrokerState::new();
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, noop_handle(), false);
        broker.subscribe(id, &filter("x/y", QoS::AtLeastOnce)).unwrap();
        broker.unregister(id);
        assert!(broker.topics.write().unwrap().matching_subscribers("x/y").is_empty());
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
        assert_eq!(broker.topics.write().unwrap().matching_subscribers("x/y").len(), 1);

        let (resumed_id, evicted, present) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        assert_eq!(resumed_id, id);
        assert!(evicted.is_none());
        assert!(present);
        assert_eq!(broker.topics.write().unwrap().matching_subscribers("x/y").len(), 1);
    }

    #[test]
    fn expire_orphan_reaps_only_matching_epoch() {
        let broker = Arc::new(BrokerState::new());
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.subscribe(id, &filter("x/y", QoS::AtMostOnce)).unwrap();
        let epoch = broker.orphan(id);

        // A resume bumps things back to live; the stale timer must not reap it.
        broker.register("c1", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.expire_orphan(&broker, id, epoch, test_runtime(), noop_handle());
        assert_eq!(broker.topics.write().unwrap().matching_subscribers("x/y").len(), 1);

        // Orphan again (new epoch) and reap for real.
        let epoch2 = broker.orphan(id);
        broker.expire_orphan(&broker, id, epoch2, test_runtime(), noop_handle());
        assert!(broker.topics.write().unwrap().matching_subscribers("x/y").is_empty());
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
        assert!(broker.topics.write().unwrap().matching_subscribers("x/y").is_empty());
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
        let matches = broker.topics.write().unwrap().matching_subscribers("t");
        assert!(matches[0].1.no_local);
        let fanout = broker.begin_publish(Some(id), "t", 1, QoS::AtMostOnce, false, &Properties::new());
        fanout.feed(b"x");
    }

    #[test]
    fn orphaned_qos1_is_queued_and_drained_on_resume() {
        let broker = Arc::new(BrokerState::new());
        let (id, _, _) =
            broker.register("c1", ProtocolVersion::V5, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        broker.subscribe(id, &filter("t", QoS::AtLeastOnce)).unwrap();
        broker.orphan(id);

        crate::server::publish_spool::publish_whole(
            &broker,
            None,
            "t",
            b"offline",
            QoS::AtLeastOnce,
            false,
            &Properties::new(),
            test_runtime(),
            noop_handle(),
        );
        assert!(
            wait_for_offline_message(&broker, id, 2000),
            "offloaded publish_whole must still enqueue the offline message"
        );

        let (resumed, _, present) =
            broker.register("c1", ProtocolVersion::V5, UNLIMITED_RECEIVE_MAXIMUM, false, noop_handle(), false);
        assert!(present);
        assert_eq!(resumed, id);
        broker.drain_offline(id);
        assert!(broker.store.take_offline(id).is_empty());
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
