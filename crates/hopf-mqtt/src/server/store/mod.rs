// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Durable message store SPI — offline QoS 1/2 queues and optional file backing.
//!
//! Retained messages stay in [`crate::server::broker::RetainedStore`]. This
//! module covers messages published while a session is orphaned (Session
//! Expiry pending) and in-flight retransmission bookkeeping while connected.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hopf_core::{ConnHandle, Runtime, StorageError};

use crate::codec::properties::property;
use crate::codec::{Properties, QoS};
use crate::server::broker::SubscriberId;
use crate::server::expiry::{expiry_deadline, is_expired};

/// One queued application message awaiting delivery to an offline session.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    /// Topic name.
    pub topic: String,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// Publish QoS (1 or 2; QoS 0 is not queued).
    pub qos: QoS,
    /// RETAIN flag from the original publish.
    pub retain: bool,
    /// MQTT 5 properties (Message Expiry rewritten on dequeue).
    pub properties: Properties,
    /// When the message was accepted (for Message Expiry).
    pub received_at: Instant,
}

/// SPI for durable / offline message storage.
pub trait MqttMessageStore: Send + Sync {
    /// Enqueue `msg` for an orphaned `subscriber` (QoS ≥ 1 only).
    fn enqueue_offline(&self, subscriber: SubscriberId, msg: QueuedMessage);

    /// Drain every queued message for `subscriber` (session resumed).
    fn take_offline(&self, subscriber: SubscriberId) -> Vec<QueuedMessage>;

    /// Async, offload-capable alternative to [`Self::take_offline`] for a
    /// store whose read can block (issue #216 — e.g. a file-backed store).
    /// `handle` is the resuming connection's own `ConnHandle`; an
    /// implementation that actually offloads uses it to route `done` back
    /// to that connection's reactor thread rather than an unrelated one.
    ///
    /// Default implementation just calls the synchronous
    /// [`Self::take_offline`] and invokes `done` immediately — correct
    /// as-is for a store (like [`InMemoryMessageStore`]) with no blocking
    /// I/O to speak of, so implementing this is opt-in.
    fn take_offline_async(
        &self,
        subscriber: SubscriberId,
        handle: ConnHandle,
        done: Box<dyn FnOnce(Vec<QueuedMessage>) + Send>,
    ) {
        let _ = handle;
        done(self.take_offline(subscriber));
    }

    /// Drop offline state when a session is fully torn down.
    fn clear_offline(&self, subscriber: SubscriberId);

    /// Record an in-flight outbound QoS 1/2 publish for retransmission.
    fn track_inflight(&self, subscriber: SubscriberId, packet_id: u16, msg: QueuedMessage);

    /// Remove an in-flight entry after PUBACK / PUBCOMP.
    fn ack_inflight(&self, subscriber: SubscriberId, packet_id: u16);

    /// Messages whose retransmission timer should fire (`older_than`).
    fn due_retransmits(&self, older_than: Duration) -> Vec<(SubscriberId, u16, QueuedMessage)>;
}

/// In-memory store (default). Survives Session Expiry orphan windows within
/// one process; not durable across broker restarts.
#[derive(Default)]
pub struct InMemoryMessageStore {
    offline: Mutex<HashMap<SubscriberId, VecDeque<QueuedMessage>>>,
    inflight: Mutex<HashMap<(SubscriberId, u16), (QueuedMessage, Instant)>>,
}

impl InMemoryMessageStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl MqttMessageStore for InMemoryMessageStore {
    fn enqueue_offline(&self, subscriber: SubscriberId, msg: QueuedMessage) {
        if msg.qos == QoS::AtMostOnce {
            return;
        }
        self.offline
            .lock()
            .unwrap()
            .entry(subscriber)
            .or_default()
            .push_back(msg);
    }

    fn take_offline(&self, subscriber: SubscriberId) -> Vec<QueuedMessage> {
        let now = Instant::now();
        self.offline
            .lock()
            .unwrap()
            .remove(&subscriber)
            .map(|q| {
                q.into_iter()
                    .filter(|m| !is_expired(&m.properties, m.received_at, now))
                    .map(|mut m| {
                        let _ = crate::server::expiry::adjust_remaining_expiry(
                            &mut m.properties,
                            m.received_at,
                            now,
                        );
                        m
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn clear_offline(&self, subscriber: SubscriberId) {
        self.offline.lock().unwrap().remove(&subscriber);
        let mut inflight = self.inflight.lock().unwrap();
        inflight.retain(|&(id, _), _| id != subscriber);
    }

    fn track_inflight(&self, subscriber: SubscriberId, packet_id: u16, msg: QueuedMessage) {
        self.inflight
            .lock()
            .unwrap()
            .insert((subscriber, packet_id), (msg, Instant::now()));
    }

    fn ack_inflight(&self, subscriber: SubscriberId, packet_id: u16) {
        self.inflight.lock().unwrap().remove(&(subscriber, packet_id));
    }

    fn due_retransmits(&self, older_than: Duration) -> Vec<(SubscriberId, u16, QueuedMessage)> {
        let now = Instant::now();
        self.inflight
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, (_, sent))| now.duration_since(*sent) >= older_than)
            .map(|(&(id, pid), (msg, _))| (id, pid, msg.clone()))
            .collect()
    }
}

/// One queued disk operation for a subscriber's offline-queue file (issue
/// #187) — see [`FileBackedMessageStore::queues`].
enum StoreJob {
    Append(QueuedMessage),
    ClearFile,
    /// Issue #216: routed through the same per-subscriber ordering as
    /// `Append`/`ClearFile` rather than read out-of-band, so it's
    /// guaranteed to run after every job already queued for this
    /// subscriber at the time it's submitted — closing the residual race
    /// the old synchronous `take_offline` could only narrow (a job
    /// already mid-flight when it ran could still land after it).
    TakeOffline {
        subscriber: SubscriberId,
        inner: Arc<InMemoryMessageStore>,
        handle: ConnHandle,
        done: Box<dyn FnOnce(Vec<QueuedMessage>) + Send>,
    },
}

/// What a [`StoreJob`] handed back once its storage-pool `op` completes —
/// `Append`/`ClearFile` have nothing to report; `TakeOffline` carries its
/// result forward to [`drain_next_store_job`]'s completion closure, which
/// runs `done` before draining the next job.
enum StoreJobOutcome {
    None,
    TakeOffline(Vec<QueuedMessage>, Box<dyn FnOnce(Vec<QueuedMessage>) + Send>),
}

/// Per-subscriber ordered queue of pending [`StoreJob`]s — separate from
/// [`FileBackedMessageStore`] so the storage-pool callback (which only
/// ever gets a cloned `Arc`, never `&FileBackedMessageStore`) can safely
/// reach it.
#[derive(Default)]
struct SubQueue {
    queue: VecDeque<StoreJob>,
    /// One job in flight at a time — set while a job is submitted to the
    /// storage pool, cleared once its callback lands and the queue is
    /// empty.
    draining: bool,
}

/// File-backed offline queue: one JSONL-ish binary record file per subscriber
/// under `root`. In-flight state stays in memory (process-local).
///
/// `append_file`/`clear_offline`'s file write/remove are offloaded to
/// `hopf_core::StorageExecutor` (issue #187) rather than done inline on the
/// reactor thread, one queue per subscriber so two publishes queued for the
/// *same* offline subscriber still land on disk in the order they were
/// enqueued (`StorageExecutor::submit_on` doesn't guarantee ordering across
/// separate calls) — mirrors `hopf_smtp::server::spool`'s
/// `drain_next`/`hopf_mqtt::server::publish_spool`'s
/// `drain_next_publish_chunk`, just keyed by subscriber instead of having
/// one queue per connection.
///
/// [`Self::take_offline`] (the `MqttMessageStore` trait's required
/// synchronous method) still reads the disk inline — kept for API
/// compatibility and any caller without a `ConnHandle` to offload against.
/// [`MqttMessageStore::take_offline_async`] (issue #216) is the offload-
/// capable path `BrokerState::drain_offline` actually uses: it queues a
/// `StoreJob::TakeOffline` job on the *same* per-subscriber ordering as
/// `Append`/`ClearFile`, so it's guaranteed to run after every job already
/// queued for that subscriber — closing the race the synchronous version's
/// "clear not-yet-started jobs" workaround could only narrow.
pub struct FileBackedMessageStore {
    root: PathBuf,
    inner: Arc<InMemoryMessageStore>,
    queues: Mutex<HashMap<SubscriberId, Arc<Mutex<SubQueue>>>>,
    runtime: Arc<Runtime>,
    /// Routing target for `Append`/`ClearFile` jobs' `submit_on` callbacks
    /// — no live connection is relevant to those, so a task-only handle
    /// (`submit_on`'s callback dispatch only ever calls `ConnHandle::execute`
    /// on it, never `with_endpoint`) is enough. A `TakeOffline` job instead
    /// carries its own caller-supplied handle (see [`StoreJob::TakeOffline`])
    /// so its completion reaches the resuming connection's own reactor.
    detached: ConnHandle,
}

impl FileBackedMessageStore {
    /// Store offline payloads under `root` (created if missing). `runtime`
    /// lets writes offload to `hopf_core::StorageExecutor` (issue #187).
    pub fn new(root: impl Into<PathBuf>, runtime: Arc<Runtime>) -> std::io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            inner: Arc::new(InMemoryMessageStore::new()),
            queues: Mutex::new(HashMap::new()),
            runtime,
            detached: ConnHandle::from_execute(Arc::new(|task| task())),
        })
    }

    fn path_for(&self, subscriber: SubscriberId) -> PathBuf {
        self.root.join(format!("offline-{}.bin", subscriber.0))
    }

    fn queue_for(&self, subscriber: SubscriberId) -> Arc<Mutex<SubQueue>> {
        Arc::clone(
            self.queues
                .lock()
                .unwrap()
                .entry(subscriber)
                .or_insert_with(|| Arc::new(Mutex::new(SubQueue::default()))),
        )
    }

    /// Queue `job` for `subscriber`, kicking off the drain if nothing else
    /// is already in flight for it.
    fn submit_job(&self, subscriber: SubscriberId, job: StoreJob) {
        let state = self.queue_for(subscriber);
        let mut g = state.lock().unwrap();
        g.queue.push_back(job);
        let should_start = !g.draining;
        if should_start {
            g.draining = true;
        }
        drop(g);
        if should_start {
            drain_next_store_job(
                self.path_for(subscriber),
                state,
                Arc::clone(&self.runtime),
                self.detached.clone(),
            );
        }
    }

    fn append_file(path: &Path, msg: &QueuedMessage) -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let topic = msg.topic.as_bytes();
        let props = encode_props_simple(&msg.properties);
        let received = msg
            .received_at
            .elapsed()
            .as_millis() // not portable across restart — best-effort
            ;
        let _ = received;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // layout: u16 topic_len | topic | u8 qos | u8 retain | u32 props_len | props
        //         | u64 payload_len | payload | u64 unix_received
        f.write_all(&(topic.len() as u16).to_be_bytes())?;
        f.write_all(topic)?;
        f.write_all(&[msg.qos.value(), msg.retain as u8])?;
        f.write_all(&(props.len() as u32).to_be_bytes())?;
        f.write_all(&props)?;
        f.write_all(&(msg.payload.len() as u64).to_be_bytes())?;
        f.write_all(&msg.payload)?;
        f.write_all(&now_secs.to_be_bytes())?;
        Ok(())
    }

    fn read_all(path: &Path) -> std::io::Result<Vec<QueuedMessage>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        let mut out = Vec::new();
        let mut i = 0;
        while i + 2 <= data.len() {
            let topic_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
            i += 2;
            if i + topic_len + 2 + 4 > data.len() {
                break;
            }
            let topic = String::from_utf8_lossy(&data[i..i + topic_len]).into_owned();
            i += topic_len;
            let qos = QoS::from_value(data[i]).unwrap_or(QoS::AtLeastOnce);
            let retain = data[i + 1] != 0;
            i += 2;
            let props_len = u32::from_be_bytes(data[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            if i + props_len + 8 > data.len() {
                break;
            }
            let properties = decode_props_simple(&data[i..i + props_len]);
            i += props_len;
            let payload_len = u64::from_be_bytes(data[i..i + 8].try_into().unwrap()) as usize;
            i += 8;
            if i + payload_len + 8 > data.len() {
                break;
            }
            let payload = data[i..i + payload_len].to_vec();
            i += payload_len;
            let _unix = u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
            i += 8;
            out.push(QueuedMessage {
                topic,
                payload,
                qos,
                retain,
                properties,
                received_at: Instant::now(),
            });
        }
        Ok(out)
    }
}

/// Drain the next queued job (if any) for one subscriber's offline-queue
/// file by submitting it to the storage pool; on completion, either drains
/// the next one or clears `draining` once the queue is empty. Free
/// function (not a method) since it needs to re-invoke itself from inside
/// a `'static` storage callback, which only has cloned `Arc`s/a
/// `ConnHandle`, not `&FileBackedMessageStore`. A job's own error (e.g. a
/// failed append) doesn't stop later queued jobs — each is an independent
/// unit (a distinct message, or a clear), unlike an ordered spool write
/// where one chunk's failure invalidates the rest of the same file.
///
/// `detached` is the store's generic, connection-agnostic handle, used to
/// dispatch `Append`/`ClearFile` jobs (issue #216: a `TakeOffline` job
/// carries its own caller-supplied handle instead, so its completion
/// reaches the *resuming* connection's reactor, not an arbitrary one).
fn drain_next_store_job(path: PathBuf, state: Arc<Mutex<SubQueue>>, runtime: Arc<Runtime>, detached: ConnHandle) {
    let job = {
        let mut g = state.lock().unwrap();
        match g.queue.pop_front() {
            Some(j) => j,
            None => {
                g.draining = false;
                return;
            }
        }
    };
    let cb_state = Arc::clone(&state);
    let cb_runtime = Arc::clone(&runtime);
    let cb_detached = detached.clone();
    let op_path = path.clone();
    let dispatch_handle = match &job {
        StoreJob::TakeOffline { handle, .. } => handle.clone(),
        _ => detached.clone(),
    };
    runtime.storage().submit_on(
        dispatch_handle,
        move || -> Result<StoreJobOutcome, Box<dyn std::error::Error + Send + Sync>> {
            match job {
                StoreJob::Append(msg) => {
                    FileBackedMessageStore::append_file(&op_path, &msg)?;
                    Ok(StoreJobOutcome::None)
                }
                StoreJob::ClearFile => {
                    let _ = fs::remove_file(&op_path);
                    Ok(StoreJobOutcome::None)
                }
                StoreJob::TakeOffline { subscriber, inner, handle: _, done } => {
                    let from_disk = FileBackedMessageStore::read_all(&op_path).unwrap_or_default();
                    let _ = fs::remove_file(&op_path);
                    // Ordering guarantees this job runs only after every
                    // `Append` queued ahead of it for this subscriber has
                    // already landed on disk — so `from_disk` is already a
                    // superset of whatever this session put in `inner`
                    // (the old synchronous `take_offline` needed to merge
                    // both because its "clear not-yet-started jobs" trick
                    // could leave memory ahead of disk; ordering removes
                    // that gap entirely). `inner`'s copy is still drained
                    // here — discarding the result, not merging it — so it
                    // doesn't linger and get double-delivered next time.
                    let _ = inner.take_offline(subscriber);
                    Ok(StoreJobOutcome::TakeOffline(from_disk, done))
                }
            }
        },
        move |result: Result<StoreJobOutcome, StorageError>| {
            if let Ok(StoreJobOutcome::TakeOffline(msgs, done)) = result {
                done(msgs);
            }
            drain_next_store_job(path, cb_state, cb_runtime, cb_detached);
        },
    );
}

fn encode_props_simple(props: &Properties) -> Vec<u8> {
    // Persist Message Expiry Interval only (enough for offline dequeue).
    let mut out = Vec::new();
    if let Some(secs) = props.get_u32(property::MESSAGE_EXPIRY_INTERVAL) {
        out.push(property::MESSAGE_EXPIRY_INTERVAL);
        out.extend_from_slice(&secs.to_be_bytes());
    }
    out
}

fn decode_props_simple(data: &[u8]) -> Properties {
    let mut props = Properties::new();
    let mut i = 0;
    while i < data.len() {
        let id = data[i];
        i += 1;
        if id == property::MESSAGE_EXPIRY_INTERVAL && i + 4 <= data.len() {
            let secs = u32::from_be_bytes(data[i..i + 4].try_into().unwrap());
            props.set_u32(property::MESSAGE_EXPIRY_INTERVAL, secs);
            i += 4;
        } else {
            break;
        }
    }
    props
}

impl MqttMessageStore for FileBackedMessageStore {
    fn enqueue_offline(&self, subscriber: SubscriberId, msg: QueuedMessage) {
        if msg.qos == QoS::AtMostOnce {
            return;
        }
        self.submit_job(subscriber, StoreJob::Append(msg.clone()));
        self.inner.enqueue_offline(subscriber, msg);
    }

    /// Synchronous fallback, kept for API compatibility with callers that
    /// have no `ConnHandle` to offload against — `BrokerState::drain_offline`
    /// uses [`Self::take_offline_async`] instead (issue #216). Discarding
    /// this subscriber's not-yet-started queued jobs keeps any of them from
    /// resurrecting the file (with an already-in-memory-covered message)
    /// after it's removed here; a job already mid-flight on a storage
    /// thread at this exact moment can still race it — the async path
    /// doesn't have this gap, since it's ordered *through* the same queue
    /// rather than racing it.
    fn take_offline(&self, subscriber: SubscriberId) -> Vec<QueuedMessage> {
        if let Some(state) = self.queues.lock().unwrap().get(&subscriber) {
            state.lock().unwrap().queue.clear();
        }
        let path = self.path_for(subscriber);
        let from_disk = Self::read_all(&path).unwrap_or_default();
        let _ = fs::remove_file(&path);
        let mut from_mem = self.inner.take_offline(subscriber);
        if from_mem.is_empty() {
            from_disk
        } else {
            from_mem.extend(from_disk);
            from_mem
        }
    }

    /// Issue #216: reads the disk off the reactor thread, ordered against
    /// this subscriber's pending `Append`/`ClearFile` jobs by running on
    /// the same [`SubQueue`] rather than racing it — see the type-level
    /// doc comment.
    fn take_offline_async(
        &self,
        subscriber: SubscriberId,
        handle: ConnHandle,
        done: Box<dyn FnOnce(Vec<QueuedMessage>) + Send>,
    ) {
        self.submit_job(
            subscriber,
            StoreJob::TakeOffline {
                subscriber,
                inner: Arc::clone(&self.inner),
                handle,
                done,
            },
        );
    }

    fn clear_offline(&self, subscriber: SubscriberId) {
        self.submit_job(subscriber, StoreJob::ClearFile);
        self.inner.clear_offline(subscriber);
    }

    fn track_inflight(&self, subscriber: SubscriberId, packet_id: u16, msg: QueuedMessage) {
        self.inner.track_inflight(subscriber, packet_id, msg);
    }

    fn ack_inflight(&self, subscriber: SubscriberId, packet_id: u16) {
        self.inner.ack_inflight(subscriber, packet_id);
    }

    fn due_retransmits(&self, older_than: Duration) -> Vec<(SubscriberId, u16, QueuedMessage)> {
        self.inner.due_retransmits(older_than)
    }
}

/// Build a [`QueuedMessage`] from publish fields.
pub fn queued_message(
    topic: &str,
    payload: &[u8],
    qos: QoS,
    retain: bool,
    properties: &Properties,
) -> QueuedMessage {
    let received_at = Instant::now();
    let _ = expiry_deadline(properties, received_at);
    QueuedMessage {
        topic: topic.to_string(),
        payload: payload.to_vec(),
        qos,
        retain,
        properties: properties.clone(),
        received_at,
    }
}

#[cfg(test)]
mod file_backed_tests {
    use super::*;

    fn wait_for(mut pred: impl FnMut() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    /// Issue #187: back-to-back `enqueue_offline` calls for the *same*
    /// subscriber must still land on disk in submission order, even though
    /// each call's write is independently offloaded (`submit_on` gives no
    /// cross-call ordering guarantee on its own — `SubQueue`'s per-
    /// subscriber drain is what restores it).
    #[test]
    fn per_subscriber_appends_land_in_order_despite_offloading() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let store = FileBackedMessageStore::new(dir.path(), Arc::clone(&rt)).unwrap();
        let id = SubscriberId(42);

        let mut expected_topics = Vec::new();
        for i in 0..20 {
            let topic = format!("t/{i:02}");
            expected_topics.push(topic.clone());
            store.enqueue_offline(
                id,
                queued_message(
                    &topic,
                    format!("payload{i:02}").as_bytes(),
                    QoS::AtLeastOnce,
                    false,
                    &Properties::new(),
                ),
            );
        }

        assert!(
            wait_for(
                || {
                    let state = store.queue_for(id);
                    let g = state.lock().unwrap();
                    !g.draining && g.queue.is_empty()
                },
                3000
            ),
            "all offloaded appends must eventually drain"
        );

        let path = store.path_for(id);
        let on_disk = FileBackedMessageStore::read_all(&path).unwrap();
        let topics: Vec<String> = on_disk.iter().map(|m| m.topic.clone()).collect();
        assert_eq!(
            topics, expected_topics,
            "messages for one subscriber must land on disk in enqueue order despite offloaded writes"
        );
    }

    /// A subscriber-scoped `clear_offline` queued behind pending appends
    /// must still run after them (folded into the same per-subscriber
    /// queue), leaving no on-disk file — not racing ahead and being
    /// resurrected by a later append landing after it.
    #[test]
    fn clear_offline_queued_behind_appends_runs_last() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let store = FileBackedMessageStore::new(dir.path(), Arc::clone(&rt)).unwrap();
        let id = SubscriberId(7);

        for i in 0..5 {
            store.enqueue_offline(
                id,
                queued_message(&format!("t/{i}"), b"x", QoS::AtLeastOnce, false, &Properties::new()),
            );
        }
        store.clear_offline(id);

        assert!(
            wait_for(
                || {
                    let state = store.queue_for(id);
                    let g = state.lock().unwrap();
                    !g.draining && g.queue.is_empty()
                },
                3000
            ),
            "append + clear jobs must eventually drain"
        );
        assert!(!store.path_for(id).exists(), "clear must run after the appends it was queued behind");
    }

    /// Issue #216: `take_offline_async` reads the disk off the reactor
    /// thread and still recovers messages already drained there in an
    /// earlier process (`InMemoryMessageStore`'s copy alone wouldn't
    /// have them — only the disk read does).
    #[test]
    fn take_offline_async_reads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let store = FileBackedMessageStore::new(dir.path(), Arc::clone(&rt)).unwrap();
        let id = SubscriberId(11);

        for i in 0..5 {
            store.enqueue_offline(
                id,
                queued_message(&format!("t/{i}"), b"x", QoS::AtLeastOnce, false, &Properties::new()),
            );
        }
        assert!(
            wait_for(
                || {
                    let state = store.queue_for(id);
                    let g = state.lock().unwrap();
                    !g.draining && g.queue.is_empty()
                },
                3000
            ),
            "appends must land on disk before the take_offline_async below"
        );
        assert!(store.path_for(id).exists(), "sanity: appends also landed on disk");
        for i in 5..10 {
            store.enqueue_offline(
                id,
                queued_message(&format!("t/{i}"), b"x", QoS::AtLeastOnce, false, &Properties::new()),
            );
        }
        assert!(
            wait_for(
                || {
                    let state = store.queue_for(id);
                    let g = state.lock().unwrap();
                    !g.draining && g.queue.is_empty()
                },
                3000
            ),
            "second batch of appends must also land"
        );

        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        let result: Arc<Mutex<Option<Vec<QueuedMessage>>>> = Arc::new(Mutex::new(None));
        let result2 = Arc::clone(&result);
        store.take_offline_async(id, handle, Box::new(move |msgs| *result2.lock().unwrap() = Some(msgs)));

        assert!(
            wait_for(|| result.lock().unwrap().is_some(), 3000),
            "take_offline_async must eventually call done"
        );
        let msgs = result.lock().unwrap().take().unwrap();
        let topics: std::collections::HashSet<String> = msgs.iter().map(|m| m.topic.clone()).collect();
        let expected: std::collections::HashSet<String> = (0..10).map(|i| format!("t/{i}")).collect();
        assert_eq!(topics, expected, "must recover every enqueued message from disk+memory");
        assert!(!store.path_for(id).exists(), "offline file must be removed once drained");
    }

    /// Issue #216: a `take_offline_async` call queued immediately behind
    /// still-pending appends for the same subscriber must still see all
    /// of them — it's ordered *through* the same `SubQueue`, not racing
    /// it, so there's no window where a not-yet-landed append gets lost
    /// (the gap the old synchronous `take_offline` could only narrow).
    #[test]
    fn take_offline_async_ordered_behind_pending_appends() {
        let dir = tempfile::tempdir().unwrap();
        let rt = Arc::new(Runtime::start(hopf_core::RuntimeConfig::default()).unwrap());
        let store = FileBackedMessageStore::new(dir.path(), Arc::clone(&rt)).unwrap();
        let id = SubscriberId(23);

        // Enqueue, then immediately call take_offline_async — before any
        // of these appends could plausibly have drained to disk yet, so
        // the ordering guarantee (not a timing coincidence) is what makes
        // this pass reliably.
        for i in 0..20 {
            store.enqueue_offline(
                id,
                queued_message(&format!("t/{i:02}"), b"x", QoS::AtLeastOnce, false, &Properties::new()),
            );
        }
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        let result: Arc<Mutex<Option<Vec<QueuedMessage>>>> = Arc::new(Mutex::new(None));
        let result2 = Arc::clone(&result);
        store.take_offline_async(id, handle, Box::new(move |msgs| *result2.lock().unwrap() = Some(msgs)));

        assert!(wait_for(|| result.lock().unwrap().is_some(), 3000), "take_offline_async must eventually call done");
        let msgs = result.lock().unwrap().take().unwrap();
        assert_eq!(msgs.len(), 20, "every append queued ahead of the read must be reflected in it");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_round_trip_memory() {
        let store = InMemoryMessageStore::new();
        let id = SubscriberId(1);
        store.enqueue_offline(
            id,
            queued_message("a/b", b"hi", QoS::AtLeastOnce, false, &Properties::new()),
        );
        let msgs = store.take_offline(id);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, b"hi");
        assert!(store.take_offline(id).is_empty());
    }

    #[test]
    fn inflight_ack_and_retransmit() {
        let store = InMemoryMessageStore::new();
        let id = SubscriberId(2);
        store.track_inflight(
            id,
            7,
            queued_message("t", b"x", QoS::ExactlyOnce, false, &Properties::new()),
        );
        assert_eq!(store.due_retransmits(Duration::ZERO).len(), 1);
        store.ack_inflight(id, 7);
        assert!(store.due_retransmits(Duration::ZERO).is_empty());
    }
}
