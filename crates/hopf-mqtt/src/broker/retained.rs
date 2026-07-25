// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Retained-message store: one message per topic, replaced or cleared on
//! each retained publish (MQTT 3.1.1 §3.3.1.3 / MQTT 5.0 §3.3.1.3).

use std::collections::HashMap;

use crate::codec::{Properties, QoS};

/// A stored retained message.
#[derive(Debug, Clone)]
pub struct RetainedMessage {
    /// Publish QoS at the time it was retained.
    pub qos: QoS,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// MQTT 5.0 properties at the time it was retained.
    pub properties: Properties,
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

    /// Set or clear the retained message for `topic`.
    ///
    /// A zero-length `payload` clears any retained message for the topic
    /// (MQTT 3.1.1 §3.3.1.3) rather than storing an empty one.
    pub fn publish(&mut self, topic: &str, qos: QoS, payload: Vec<u8>, properties: Properties) {
        if payload.is_empty() {
            self.by_topic.remove(topic);
        } else {
            self.by_topic.insert(
                topic.to_string(),
                RetainedMessage {
                    qos,
                    payload,
                    properties,
                },
            );
        }
    }

    /// Every retained message whose topic matches `filter` (used when a
    /// new SUBSCRIBE arrives — MQTT 3.1.1 §3.8.4).
    pub fn matching(&self, filter: &str) -> Vec<(&str, &RetainedMessage)> {
        let filter_segments: Vec<&str> = filter.split('/').collect();
        self.by_topic
            .iter()
            .filter(|(topic, _)| topic_matches_filter(topic, &filter_segments))
            .map(|(topic, msg)| (topic.as_str(), msg))
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

    #[test]
    fn set_then_clear_with_empty_payload() {
        let mut store = RetainedStore::new();
        store.publish("a/b", QoS::AtMostOnce, b"hi".to_vec(), Properties::new());
        assert_eq!(store.matching("a/b").len(), 1);
        store.publish("a/b", QoS::AtMostOnce, Vec::new(), Properties::new());
        assert!(store.matching("a/b").is_empty());
    }

    #[test]
    fn matching_respects_wildcards_and_dollar_rule() {
        let mut store = RetainedStore::new();
        store.publish("sport/tennis/player1", QoS::AtMostOnce, b"x".to_vec(), Properties::new());
        store.publish("$SYS/uptime", QoS::AtMostOnce, b"y".to_vec(), Properties::new());

        assert_eq!(store.matching("sport/tennis/+").len(), 1);
        assert_eq!(store.matching("sport/#").len(), 1);
        assert!(store.matching("#").iter().all(|(t, _)| *t != "$SYS/uptime"));
        assert_eq!(store.matching("$SYS/#").len(), 1);
    }
}
