// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Retained-message store: one message per topic, replaced or cleared on
//! each retained publish (MQTT 3.1.1 §3.3.1.3 / MQTT 5.0 §3.3.1.3).
//!
//! Payloads are never held in memory here — each [`RetainedMessage`] just
//! owns a spooled file on disk (handed off from the transient per-publish
//! spool in `server::control` once a PUBLISH with `retain` set finishes
//! arriving, instead of being deleted); delivering it to a newly-subscribed
//! connection reads that file in bounded chunks. The file is deleted, off
//! the reactor thread (issue #187), once nothing — including any in-flight
//! [`crate::server::broker::BrokerState::deliver_retained`] read — still
//! holds a [`SpoolHandle`] clone to it: see that type's own doc comment for
//! why ordinary `Arc` refcounting, not a hand-written `Drop`, is what makes
//! replacing or clearing an entry safe once reads of it can be async.

use std::collections::HashMap;
use std::time::Instant;

use crate::codec::{Properties, QoS};
use crate::server::spool_file::SpoolHandle;

/// A stored retained message.
#[derive(Debug)]
pub struct RetainedMessage {
    /// Publish QoS at the time it was retained.
    pub qos: QoS,
    /// Spooled payload file. `None` for a zero-length payload.
    pub path: Option<SpoolHandle>,
    /// Payload length in bytes (0 iff `path` is `None`).
    pub payload_len: u64,
    /// MQTT 5.0 properties at the time it was retained.
    pub properties: Properties,
    /// Absolute expiry deadline (Message Expiry Interval), if any.
    pub expires_at: Option<Instant>,
}

/// A `Clone`-able view of a [`RetainedMessage`] for delivery — safe to hand
/// out after releasing the store's lock and to keep across the store's own
/// entry being replaced or cleared, since `path`'s `SpoolHandle` clone
/// keeps the file alive independently (see the module doc comment).
#[derive(Debug, Clone)]
pub struct RetainedSnapshot {
    /// Publish QoS at the time it was retained.
    pub qos: QoS,
    /// Spooled payload file. `None` for a zero-length payload.
    pub path: Option<SpoolHandle>,
    /// Payload length in bytes (0 iff `path` is `None`).
    pub payload_len: u64,
    /// MQTT 5.0 properties at the time it was retained.
    pub properties: Properties,
    /// Absolute expiry deadline (Message Expiry Interval), if any.
    pub expires_at: Option<Instant>,
}

impl From<&RetainedMessage> for RetainedSnapshot {
    fn from(msg: &RetainedMessage) -> Self {
        Self {
            qos: msg.qos,
            path: msg.path.clone(),
            payload_len: msg.payload_len,
            properties: msg.properties.clone(),
            expires_at: msg.expires_at,
        }
    }
}

/// One retained message per topic name.
#[derive(Default)]
pub struct RetainedStore {
    by_topic: HashMap<String, RetainedMessage>,
}

impl RetainedStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set or clear the retained message for `topic`, taking ownership of
    /// `path` (its file is deleted, off the reactor thread, once nothing —
    /// including this entry, once later replaced or cleared — still holds
    /// a clone).
    ///
    /// `path: None` (zero-length payload) clears any retained message for
    /// the topic (MQTT 3.1.1 §3.3.1.3) rather than storing an empty one.
    /// Either way, whatever was previously stored for `topic` is dropped
    /// here.
    pub fn publish(
        &mut self,
        topic: &str,
        qos: QoS,
        path: Option<SpoolHandle>,
        payload_len: u64,
        properties: Properties,
        expires_at: Option<Instant>,
    ) {
        match path {
            None => {
                self.by_topic.remove(topic);
            }
            Some(path) => {
                // Don't store an already-expired retained message — `path`
                // just drops here (self-offloading its delete) instead of
                // being inserted.
                if expires_at.is_some_and(|d| Instant::now() >= d) {
                    self.by_topic.remove(topic);
                    return;
                }
                self.by_topic.insert(
                    topic.to_string(),
                    RetainedMessage {
                        qos,
                        path: Some(path),
                        payload_len,
                        properties,
                        expires_at,
                    },
                );
            }
        }
    }

    /// Every retained message whose topic matches `filter` (used when a
    /// new SUBSCRIBE arrives — MQTT 3.1.1 §3.8.4). Expired entries are
    /// purged as a side effect of matching.
    pub fn matching(&mut self, filter: &str) -> Vec<(String, RetainedSnapshot)> {
        let now = Instant::now();
        self.by_topic.retain(|_, msg| match msg.expires_at {
            Some(deadline) => now < deadline,
            None => true,
        });
        let filter_segments: Vec<&str> = filter.split('/').collect();
        self.by_topic
            .iter()
            .filter(|(topic, _)| topic_matches_filter(topic, &filter_segments))
            .map(|(topic, msg)| (topic.clone(), RetainedSnapshot::from(msg)))
            .collect()
    }
}

fn topic_matches_filter(topic: &str, filter_segments: &[&str]) -> bool {
    let topic_segments: Vec<&str> = topic.split('/').collect();
    let topic_is_dollar = topic_segments.first().is_some_and(|s| s.starts_with('$'));
    let filter_starts_with_wildcard = matches!(filter_segments.first(), Some(&"+") | Some(&"#"));
    if topic_is_dollar && filter_starts_with_wildcard {
        return false;
    }
    matches_from(&topic_segments, filter_segments)
}

fn matches_from(topic: &[&str], filter: &[&str]) -> bool {
    match (topic.first(), filter.first()) {
        (_, Some(&"#")) => true,
        (Some(_), Some(&"+")) => matches_from(&topic[1..], &filter[1..]),
        (Some(t), Some(f)) => *t == *f && matches_from(&topic[1..], &filter[1..]),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::{ConnHandle, Runtime, RuntimeConfig};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn test_runtime_and_handle() -> (Arc<Runtime>, ConnHandle) {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let handle = ConnHandle::from_execute(Arc::new(|task| task()));
        (rt, handle)
    }

    fn spool_path(contents: &[u8]) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hopf-mqtt-retained-test-{}-{}-{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            n,
        ));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents).unwrap();
        path
    }

    fn spool(rt: &Arc<Runtime>, handle: &ConnHandle, contents: &[u8]) -> SpoolHandle {
        SpoolHandle::new(spool_path(contents), Arc::clone(rt), handle.clone())
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

    #[test]
    fn set_then_clear_with_empty_payload() {
        let (rt, handle) = test_runtime_and_handle();
        let mut store = RetainedStore::new();
        let sh = spool(&rt, &handle, b"hi");
        let path = sh.path().to_path_buf();
        store.publish("a/b", QoS::AtMostOnce, Some(sh), 2, Properties::new(), None);
        assert_eq!(store.matching("a/b").len(), 1);
        assert!(path.exists());

        store.publish("a/b", QoS::AtMostOnce, None, 0, Properties::new(), None);
        assert!(store.matching("a/b").is_empty());
        // Clearing drops the old entry, which self-offloads deleting its
        // spooled file (issue #187) once nothing else holds a clone.
        assert!(
            wait_for(|| !path.exists(), 2000),
            "spooled file must be removed once the offloaded delete lands"
        );
    }

    #[test]
    fn replacing_an_entry_deletes_the_old_spool_file() {
        let (rt, handle) = test_runtime_and_handle();
        let mut store = RetainedStore::new();
        let old_sh = spool(&rt, &handle, b"old");
        let old_path = old_sh.path().to_path_buf();
        store.publish("a/b", QoS::AtMostOnce, Some(old_sh), 3, Properties::new(), None);
        let new_sh = spool(&rt, &handle, b"new");
        let new_path = new_sh.path().to_path_buf();
        store.publish("a/b", QoS::AtMostOnce, Some(new_sh), 3, Properties::new(), None);

        assert!(
            wait_for(|| !old_path.exists(), 2000),
            "old spool file should have been removed"
        );
        assert!(new_path.exists());
        let (_, snap) = &store.matching("a/b")[0];
        assert_eq!(snap.path.as_ref().map(SpoolHandle::path), Some(new_path.as_path()));
    }

    /// Issue #187: a delivery read still holding a `SpoolHandle` clone for
    /// the *old* retained entry must keep that file alive even after the
    /// entry itself is replaced — proves the ref-counted handle, not the
    /// old `Drop`-on-replace timing, is what governs deletion now.
    #[test]
    fn replaced_entrys_file_survives_while_an_extra_clone_is_held() {
        let (rt, handle) = test_runtime_and_handle();
        let mut store = RetainedStore::new();
        let old_sh = spool(&rt, &handle, b"old");
        let old_path = old_sh.path().to_path_buf();
        // Simulate an in-flight `deliver_retained` read still holding a
        // clone from before the entry was replaced.
        let in_flight_clone = old_sh.clone();
        store.publish("a/b", QoS::AtMostOnce, Some(old_sh), 3, Properties::new(), None);

        let new_sh = spool(&rt, &handle, b"new");
        store.publish("a/b", QoS::AtMostOnce, Some(new_sh), 3, Properties::new(), None);

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            old_path.exists(),
            "file must survive while the in-flight read's clone is still held"
        );

        drop(in_flight_clone);
        assert!(
            wait_for(|| !old_path.exists(), 2000),
            "file must be removed once the last clone (the simulated in-flight read) drops"
        );
    }

    #[test]
    fn matching_respects_wildcards_and_dollar_rule() {
        let (rt, handle) = test_runtime_and_handle();
        let mut store = RetainedStore::new();
        store.publish(
            "sport/tennis/player1", QoS::AtMostOnce, Some(spool(&rt, &handle, b"x")), 1, Properties::new(), None,
        );
        store.publish(
            "$SYS/uptime", QoS::AtMostOnce, Some(spool(&rt, &handle, b"y")), 1, Properties::new(), None,
        );

        assert_eq!(store.matching("sport/tennis/+").len(), 1);
        assert_eq!(store.matching("sport/#").len(), 1);
        assert!(store.matching("#").iter().all(|(t, _)| *t != "$SYS/uptime"));
        assert_eq!(store.matching("$SYS/#").len(), 1);
    }
}
