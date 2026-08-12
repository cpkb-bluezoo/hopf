// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared PUBLISH-spooling helpers used by both the TCP control handler
//! ([`super::control::MqttControlHandler`]) and the WebSocket bridge
//! (`super::ws::MqttWsHandler`, feature `websocket`).
//!
//! A client's PUBLISH payload is never buffered whole in memory. QoS-0
//! recipients are streamed their payload live, chunk by chunk, as it
//! arrives ([`PublishFanout::feed`], already sent its header up front via
//! [`BrokerState::begin_publish`]). If any recipient is QoS 1/2, or the
//! publish is retained, the same chunks are *also* written to a temp
//! file — read back once per deferred recipient (and handed to the
//! retained store) in [`PendingPublish::finish`], rather than ever being
//! held whole in memory here.
//!
//! Chunk writes are offloaded to [`hopf_core::StorageExecutor`] (issue
//! #187) rather than done inline on the reactor thread — `feed` only
//! enqueues and returns immediately. Writes to the same file must land in
//! order, and `StorageExecutor::submit_on` doesn't guarantee same-thread/
//! ordered execution across separate calls, so chunks are drained one at a
//! time: the next chunk's write is only submitted once the previous one's
//! completion callback confirms it landed (`drain_next_publish_chunk`) —
//! mirrors `hopf_smtp::server::spool`/`hopf_imap`'s `AppendSpoolState`.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hopf_core::{ConnHandle, Runtime, StorageError};

use crate::codec::packet::{PublishHeader, QoS};
use crate::codec::Properties;
use crate::server::broker::{BrokerState, PublishFanout, SubscriberId};
use crate::server::spool_file::SpoolHandle;

pub(crate) fn unique_spool_path() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hopf-mqtt-spool-{}-{}-{}.tmp",
        std::process::id(),
        nanos,
        n
    ))
}

/// Shared, mutex-guarded spool-write state — separate from [`PendingPublish`]
/// so the storage-pool write callback (which only ever gets a cloned
/// `Arc`, never `&mut PendingPublish`) can safely reach it.
#[derive(Default)]
struct SpoolWriteState {
    file: Option<File>,
    path: Option<PathBuf>,
    bytes_written: u64,
    /// Set once a write fails — subsequent chunks are dropped and deferred/
    /// retained delivery for this publish is simply skipped in `finish`.
    error: bool,
    queue: VecDeque<Vec<u8>>,
    /// One write in flight at a time — set while a chunk is submitted to
    /// the storage pool, cleared once its callback lands and the queue is
    /// empty.
    draining: bool,
    /// Set by [`PendingPublish::finish_when_ready`] when the queue isn't
    /// already empty at that point — run once, right here on the storage
    /// thread, the moment the queue actually empties. Used by the
    /// WebSocket bridge (`server::ws`), which has no `poke_handler`-style
    /// hook to re-enter its own handler the way TCP's
    /// `MqttControlHandler`/`sync_pending_publish_finish` does, so the
    /// callback must be fully self-contained (safe to run from any
    /// thread, no `&mut` handler access) — see that call site.
    on_drained: Option<Box<dyn FnOnce() + Send>>,
}

/// Drain the next queued chunk (if any) by submitting its write to the
/// storage pool; on completion, either drains the next one or clears
/// `draining` once the queue is empty. Free function (not a method) since
/// it needs to re-invoke itself from inside a `'static` storage callback,
/// which only has cloned `Arc`s/a `ConnHandle`, not `&mut PendingPublish`.
fn drain_next_publish_chunk(state: Arc<Mutex<SpoolWriteState>>, runtime: Arc<Runtime>, handle: ConnHandle) {
    let chunk = {
        let mut g = state.lock().unwrap();
        match g.queue.pop_front() {
            Some(c) => c,
            None => {
                g.draining = false;
                let on_drained = g.on_drained.take();
                drop(g);
                if let Some(cb) = on_drained {
                    cb();
                }
                return;
            }
        }
    };
    let chunk_len = chunk.len() as u64;
    let op_state = Arc::clone(&state);
    let cb_state = Arc::clone(&state);
    let cb_runtime = Arc::clone(&runtime);
    let cb_handle = handle.clone();
    runtime.storage().submit_on(
        handle,
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut g = op_state.lock().unwrap();
            if g.file.is_none() {
                let path = unique_spool_path();
                let f = File::create(&path)?;
                g.file = Some(f);
                g.path = Some(path);
            }
            g.file.as_mut().unwrap().write_all(&chunk)?;
            Ok(())
        },
        move |result: Result<(), StorageError>| {
            let ok = result.is_ok();
            let on_drained = {
                let mut g = cb_state.lock().unwrap();
                if result.is_err() {
                    g.error = true;
                    g.queue.clear();
                    g.draining = false;
                    // Nothing will call `drain_next_publish_chunk` again
                    // (below, only on `ok`) to reach the queue-empty branch
                    // that normally fires this — take it here instead, or
                    // a WebSocket-bridge publish deferred via
                    // `finish_when_ready` would hang forever on a write
                    // error.
                    g.on_drained.take()
                } else {
                    g.bytes_written += chunk_len;
                    None
                }
            };
            cb_handle.with_endpoint(|ep| {
                // Lets `sync_pending_publish_finish` (issue #187) re-check
                // readiness promptly once this was the last outstanding
                // write, instead of waiting for the client's next input to
                // trigger another `receive()`.
                ep.poke_handler();
            });
            if let Some(cb) = on_drained {
                cb();
            }
            if ok {
                drain_next_publish_chunk(cb_state, cb_runtime, cb_handle);
            }
        },
    );
}

/// One in-progress PUBLISH from the client.
pub(crate) struct PendingPublish {
    pub(crate) header: PublishHeader,
    fanout: PublishFanout,
    needs_spool: bool,
    spool_state: Option<Arc<Mutex<SpoolWriteState>>>,
    runtime: Arc<Runtime>,
    handle: ConnHandle,
}

impl PendingPublish {
    /// Begin fan-out for `header` (live QoS-0 headers already sent by the
    /// time this returns — see [`BrokerState::begin_publish`]). `runtime`/
    /// `handle` are the publisher's own connection, used to offload spool
    /// writes (issue #187).
    pub(crate) fn begin(
        broker: &BrokerState,
        publisher: SubscriberId,
        header: PublishHeader,
        runtime: Arc<Runtime>,
        handle: ConnHandle,
    ) -> Self {
        let fanout = broker.begin_publish(
            Some(publisher),
            &header.topic,
            header.payload_len as u64,
            header.qos,
            header.retain,
            &header.properties,
        );
        let needs_spool = header.payload_len > 0 && (header.retain || fanout.has_deferred());
        Self {
            header,
            fanout,
            needs_spool,
            spool_state: None,
            runtime,
            handle,
        }
    }

    /// Forward one chunk to live QoS-0 recipients and, if needed, queue it
    /// for the (offloaded) spool write. Never blocks.
    pub(crate) fn feed(&mut self, data: &[u8]) {
        self.fanout.feed(data);
        if !self.needs_spool {
            return;
        }
        let state = self
            .spool_state
            .get_or_insert_with(|| Arc::new(Mutex::new(SpoolWriteState::default())));
        let mut g = state.lock().unwrap();
        if g.error {
            return;
        }
        g.queue.push_back(data.to_vec());
        let should_start = !g.draining;
        if should_start {
            g.draining = true;
        }
        drop(g);
        if should_start {
            drain_next_publish_chunk(Arc::clone(state), Arc::clone(&self.runtime), self.handle.clone());
        }
    }

    /// True once every queued chunk has landed (or there was never
    /// anything to spool) — `finish` must not run until this is `true`.
    pub(crate) fn is_ready(&self) -> bool {
        match &self.spool_state {
            None => true,
            Some(s) => {
                let g = s.lock().unwrap();
                !g.draining && g.queue.is_empty()
            }
        }
    }

    /// Resolve any deferred QoS-1/2 recipients and/or retain the payload,
    /// from the spool if one was opened. Must only be called once
    /// [`Self::is_ready`] is `true`.
    pub(crate) fn finish(self, broker: &BrokerState) {
        let PendingPublish { header, fanout, spool_state, runtime, handle, .. } = self;
        if header.retain || fanout.has_deferred() {
            let (path, bytes_written, error) = match &spool_state {
                None => (None, 0, false),
                Some(s) => {
                    let g = s.lock().unwrap();
                    (g.path.clone(), g.bytes_written, g.error)
                }
            };
            let spooled = if error {
                None
            } else {
                path.filter(|_| bytes_written > 0)
            }
            .map(|p| SpoolHandle::new(p, Arc::clone(&runtime), handle));
            broker.deliver_deferred(
                &fanout,
                &header.topic,
                &header.properties,
                spooled.as_ref().map(|sh| (sh.clone(), bytes_written)),
                &runtime,
            );
            if header.retain {
                broker.retain(
                    &header.topic,
                    header.qos,
                    spooled.map(|sh| (sh, bytes_written)),
                    header.properties.clone(),
                );
            }
            // else: `spooled`'s last clone (this one, plus whatever
            // `deliver_deferred` captured) drops here or once its async
            // jobs finish, self-offloading the delete — no explicit
            // `remove_file` needed.
        }
    }

    /// Like [`Self::finish`], but self-scheduling: if every queued chunk
    /// has already landed, runs `self.finish(&broker)` (and `on_finished`)
    /// immediately; otherwise both run later, directly from the storage
    /// callback that drains the last queued write, once it does. For a
    /// caller with no way to re-enter its own handler later (issue #187 —
    /// the WebSocket bridge has no `poke_handler`-equivalent hook), so
    /// `on_finished` must itself be safe to run from any thread with no
    /// `&mut` handler access — e.g. a `ConnHandle::send` plus `Arc`-shared
    /// bookkeeping, the way `server::ws`'s `end_publish` builds it.
    ///
    /// Only `server::ws` (feature `websocket`) calls this today — gated
    /// the same way so a default build doesn't warn about it as unused.
    #[cfg(feature = "websocket")]
    pub(crate) fn finish_when_ready(self, broker: Arc<BrokerState>, on_finished: impl FnOnce() + Send + 'static) {
        let Some(state) = self.spool_state.clone() else {
            self.finish(&broker);
            on_finished();
            return;
        };
        let mut g = state.lock().unwrap();
        if !g.draining && g.queue.is_empty() {
            drop(g);
            self.finish(&broker);
            on_finished();
            return;
        }
        g.on_drained = Some(Box::new(move || {
            self.finish(&broker);
            on_finished();
        }));
    }
}

/// Publish a payload that's already fully known in memory — used for the
/// CONNECT Will message, which (unlike a client PUBLISH) is decoded whole
/// as part of CONNECT and never arrives in wire chunks. Still never hands a
/// whole in-memory buffer to the retained store or a QoS-1/2 recipient: if
/// either needs it, `payload` is spooled to a temp file first (offloaded,
/// issue #187) and delivered from there via the same
/// [`BrokerState::deliver_deferred`] / [`BrokerState::retain`] path
/// [`PendingPublish::finish`] uses.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_whole(
    broker: &Arc<BrokerState>,
    publisher: Option<SubscriberId>,
    topic: &str,
    payload: &[u8],
    qos: QoS,
    retain: bool,
    properties: &Properties,
    runtime: Arc<Runtime>,
    handle: ConnHandle,
) {
    let fanout = broker.begin_publish(publisher, topic, payload.len() as u64, qos, retain, properties);
    fanout.feed(payload);
    if !retain && !fanout.has_deferred() {
        return;
    }
    if payload.is_empty() {
        broker.deliver_deferred(&fanout, topic, properties, None, &runtime);
        if retain {
            broker.retain(topic, qos, None, properties.clone());
        }
        return;
    }

    let payload_len = payload.len() as u64;
    let payload = payload.to_vec();
    let topic_owned = topic.to_string();
    let properties_owned = properties.clone();
    let broker = Arc::clone(broker);
    let runtime_for_op = Arc::clone(&runtime);
    let handle_for_op = handle.clone();
    runtime.storage().submit_on(
        handle,
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let path = unique_spool_path();
            let mut f = File::create(&path)?;
            f.write_all(&payload)?;
            drop(f);
            let sh = SpoolHandle::new(path, Arc::clone(&runtime_for_op), handle_for_op.clone());
            broker.deliver_deferred(
                &fanout,
                &topic_owned,
                &properties_owned,
                Some((sh.clone(), payload_len)),
                &runtime_for_op,
            );
            if retain {
                broker.retain(&topic_owned, qos, Some((sh, payload_len)), properties_owned);
            }
            Ok(())
        },
        |_: Result<(), StorageError>| {},
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::packet::ProtocolVersion;
    use crate::server::broker::UNLIMITED_RECEIVE_MAXIMUM;
    use hopf_core::RuntimeConfig;

    fn test_runtime_and_handle() -> (Arc<Runtime>, ConnHandle) {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        (rt, handle)
    }

    fn wait_for(pred: impl Fn() -> bool, max_ms: u64) -> bool {
        for _ in 0..(max_ms / 5).max(1) {
            if pred() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        pred()
    }

    fn retained_header(topic: &str, payload_len: u32) -> PublishHeader {
        PublishHeader {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: true,
            topic: topic.to_string(),
            packet_id: 0,
            properties: Properties::new(),
            payload_len,
        }
    }

    /// Issue #187: many `feed()` calls, each offloaded independently, must
    /// still land on disk in submission order (mirrors the equivalent
    /// `hopf-smtp`/`hopf-imap` "many chunks in order" tests).
    #[test]
    fn feed_chunks_land_in_order_despite_offloading() {
        let (rt, handle) = test_runtime_and_handle();
        let broker = BrokerState::new();
        let (publisher, _, _) = broker.register(
            "pub", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, handle.clone(), false,
        );

        let mut expected = Vec::new();
        for i in 0..20 {
            expected.extend_from_slice(format!("chunk{i:02}-").as_bytes());
        }
        let mut pending = PendingPublish::begin(
            &broker,
            publisher,
            retained_header("t/retain", expected.len() as u32),
            Arc::clone(&rt),
            handle.clone(),
        );
        for i in 0..20 {
            pending.feed(format!("chunk{i:02}-").as_bytes());
        }
        assert!(
            wait_for(|| pending.is_ready(), 2000),
            "spool writes must eventually drain"
        );
        pending.finish(&broker);

        let snap = broker.retained_matching("t/retain");
        assert_eq!(snap.len(), 1);
        let path = snap[0].1.path.as_ref().expect("spooled").path().to_path_buf();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            expected,
            "chunks must land on disk in submission order despite being offloaded"
        );
    }

    /// A publish with nothing deferred and nothing retained never spools
    /// at all — `is_ready()` is `true` from the start.
    #[test]
    fn no_deferred_or_retain_never_spools() {
        let (rt, handle) = test_runtime_and_handle();
        let broker = BrokerState::new();
        let (publisher, _, _) = broker.register(
            "pub", ProtocolVersion::V311, UNLIMITED_RECEIVE_MAXIMUM, true, handle.clone(), false,
        );
        let header = PublishHeader {
            dup: false,
            qos: QoS::AtMostOnce,
            retain: false,
            topic: "t/plain".to_string(),
            packet_id: 0,
            properties: Properties::new(),
            payload_len: 5,
        };
        let mut pending = PendingPublish::begin(&broker, publisher, header, rt, handle);
        assert!(pending.is_ready());
        pending.feed(b"hello");
        assert!(pending.is_ready(), "no subscriber/retain means nothing is queued for spooling");
        pending.finish(&broker);
        assert!(broker.retained_matching("t/plain").is_empty());
    }
}
