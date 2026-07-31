// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Retained-message store: one message per topic, replaced or cleared on
//! each retained publish (MQTT 3.1.1 §3.3.1.3 / MQTT 5.0 §3.3.1.3).
//!
//! Payloads are never held in memory here — each [`RetainedMessage`] just
//! owns a spooled file on disk (handed off from the transient per-publish
//! spool in `server::control` once a PUBLISH with `retain` set finishes
//! arriving, instead of being deleted); delivering it to a newly-subscribed
//! connection reads that file in bounded chunks. The file is deleted
//! automatically when its entry is replaced or cleared (or the store itself
//! is dropped).

use std::collections::HashMap;
use std::path::PathBuf;

use crate::codec::{Properties, QoS};

/// A stored retained message. Owns its spooled payload file — dropping this
/// value deletes it.
#[derive(Debug)]
pub struct RetainedMessage {
    /// Publish QoS at the time it was retained.
    pub qos: QoS,
    /// Spooled payload file. `None` for a zero-length payload.
    pub path: Option<PathBuf>,
    /// Payload length in bytes (0 iff `path` is `None`).
    pub payload_len: u64,
    /// MQTT 5.0 properties at the time it was retained.
    pub properties: Properties,
}

impl Drop for RetainedMessage {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// A `Clone`-able, non-owning view of a [`RetainedMessage`] for delivery —
/// safe to hand out after releasing the store's lock, since it doesn't
/// delete `path` on drop (the store's own entry still owns that).
#[derive(Debug, Clone)]
pub struct RetainedSnapshot {
    /// Publish QoS at the time it was retained.
    pub qos: QoS,
    /// Spooled payload file. `None` for a zero-length payload.
    pub path: Option<PathBuf>,
    /// Payload length in bytes (0 iff `path` is `None`).
    pub payload_len: u64,
    /// MQTT 5.0 properties at the time it was retained.
    pub properties: Properties,
}

impl From<&RetainedMessage> for RetainedSnapshot {
    fn from(msg: &RetainedMessage) -> Self {
        Self {
            qos: msg.qos,
            path: msg.path.clone(),
            payload_len: msg.payload_len,
            properties: msg.properties.clone(),
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
    /// the spooled file at `path` (deleted automatically when this entry is
    /// later replaced or cleared).
    ///
    /// `path: None` (zero-length payload) clears any retained message for
    /// the topic (MQTT 3.1.1 §3.3.1.3) rather than storing an empty one.
    /// Either way, whatever was previously stored for `topic` is dropped
    /// here, deleting its spooled file.
    pub fn publish(
        &mut self,
        topic: &str,
        qos: QoS,
        path: Option<PathBuf>,
        payload_len: u64,
        properties: Properties,
    ) {
        match path {
            None => {
                self.by_topic.remove(topic);
            }
            Some(path) => {
                self.by_topic.insert(
                    topic.to_string(),
                    RetainedMessage {
                        qos,
                        path: Some(path),
                        payload_len,
                        properties,
                    },
                );
            }
        }
    }

    /// Every retained message whose topic matches `filter` (used when a
    /// new SUBSCRIBE arrives — MQTT 3.1.1 §3.8.4).
    pub fn matching(&self, filter: &str) -> Vec<(&str, RetainedSnapshot)> {
        let filter_segments: Vec<&str> = filter.split('/').collect();
        self.by_topic
            .iter()
            .filter(|(topic, _)| topic_matches_filter(topic, &filter_segments))
            .map(|(topic, msg)| (topic.as_str(), RetainedSnapshot::from(msg)))
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
    use std::io::Write;

    fn spool(contents: &[u8]) -> PathBuf {
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

    #[test]
    fn set_then_clear_with_empty_payload() {
        let mut store = RetainedStore::new();
        let path = spool(b"hi");
        store.publish("a/b", QoS::AtMostOnce, Some(path.clone()), 2, Properties::new());
        assert_eq!(store.matching("a/b").len(), 1);
        assert!(path.exists());

        store.publish("a/b", QoS::AtMostOnce, None, 0, Properties::new());
        assert!(store.matching("a/b").is_empty());
        // Clearing drops the old entry, deleting its spooled file.
        assert!(!path.exists());
    }

    #[test]
    fn replacing_an_entry_deletes_the_old_spool_file() {
        let mut store = RetainedStore::new();
        let old_path = spool(b"old");
        store.publish("a/b", QoS::AtMostOnce, Some(old_path.clone()), 3, Properties::new());
        let new_path = spool(b"new");
        store.publish("a/b", QoS::AtMostOnce, Some(new_path.clone()), 3, Properties::new());

        assert!(!old_path.exists(), "old spool file should have been deleted");
        assert!(new_path.exists());
        let (_, snap) = &store.matching("a/b")[0];
        assert_eq!(snap.path.as_deref(), Some(new_path.as_path()));
    }

    #[test]
    fn matching_respects_wildcards_and_dollar_rule() {
        let mut store = RetainedStore::new();
        store.publish("sport/tennis/player1", QoS::AtMostOnce, Some(spool(b"x")), 1, Properties::new());
        store.publish("$SYS/uptime", QoS::AtMostOnce, Some(spool(b"y")), 1, Properties::new());

        assert_eq!(store.matching("sport/tennis/+").len(), 1);
        assert_eq!(store.matching("sport/#").len(), 1);
        assert!(store.matching("#").iter().all(|(t, _)| *t != "$SYS/uptime"));
        assert_eq!(store.matching("$SYS/#").len(), 1);
    }
}
