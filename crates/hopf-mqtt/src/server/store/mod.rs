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
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// File-backed offline queue: one JSONL-ish binary record file per subscriber
/// under `root`. In-flight state stays in memory (process-local).
pub struct FileBackedMessageStore {
    root: PathBuf,
    inner: InMemoryMessageStore,
}

impl FileBackedMessageStore {
    /// Store offline payloads under `root` (created if missing).
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            inner: InMemoryMessageStore::new(),
        })
    }

    fn path_for(&self, subscriber: SubscriberId) -> PathBuf {
        self.root.join(format!("offline-{}.bin", subscriber.0))
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
        let path = self.path_for(subscriber);
        let _ = Self::append_file(&path, &msg);
        self.inner.enqueue_offline(subscriber, msg);
    }

    fn take_offline(&self, subscriber: SubscriberId) -> Vec<QueuedMessage> {
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

    fn clear_offline(&self, subscriber: SubscriberId) {
        let _ = fs::remove_file(self.path_for(subscriber));
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
