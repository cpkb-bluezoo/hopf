// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Topic filter trie: subscription registry and publish-time matching.
//!
//! MQTT 3.1.1 §4.7 / MQTT 5.0 §4.7: `+` matches exactly one topic level,
//! `#` matches zero or more trailing levels and must be the final token of
//! a filter, and a filter beginning with a wildcard never matches a topic
//! whose first level begins with `$` (reserved for server-internal topics
//! such as `$SYS`).

use std::collections::HashMap;

use super::SubscriberId;

/// What a matching subscriber should receive a publish at (MQTT 5.0 §3.8.3.1
/// subscription options; v3.1.1 subscriptions use the defaults below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatchOptions {
    /// Effective delivery QoS is `min(publish_qos, max_qos)`.
    pub max_qos: crate::codec::QoS,
    /// No Local: don't forward a publish back to the connection that sent it.
    pub no_local: bool,
    /// Retain As Published: forward the original RETAIN flag on live
    /// fan-out. When false (the v3.1.1 default), live fan-out always
    /// carries RETAIN=0 — only a delivery triggered by this subscription
    /// matching an existing retained message sets RETAIN=1.
    pub retain_as_published: bool,
}

impl MatchOptions {
    /// From a decoded [`crate::codec::SubscribeFilter`].
    pub fn from_filter(filter: &crate::codec::SubscribeFilter) -> Self {
        Self {
            max_qos: filter.max_qos,
            no_local: filter.no_local,
            retain_as_published: filter.retain_as_published,
        }
    }
}

#[derive(Default)]
struct TopicNode {
    children: HashMap<String, TopicNode>,
    subscribers: HashMap<SubscriberId, MatchOptions>,
}

/// Subscription registry: a trie over `/`-separated topic filter segments.
#[derive(Default)]
pub struct TopicTree {
    root: TopicNode,
    /// Reverse index so `unsubscribe_all` doesn't need the caller to
    /// remember which filters a subscriber registered.
    by_subscriber: HashMap<SubscriberId, Vec<String>>,
}

impl TopicTree {
    /// Empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `subscriber` for `filter`. Replaces any existing options
    /// for the same (subscriber, filter) pair, matching MQTT's "a new
    /// subscription on an existing filter replaces the old one" rule.
    ///
    /// Returns whether this is a brand new subscription (`true`) or a
    /// replacement of one that already existed (`false`) — used to honour
    /// MQTT 5.0 Retain Handling `1` ("send retained only for new subscriptions").
    pub fn subscribe(&mut self, filter: &str, subscriber: SubscriberId, options: MatchOptions) -> Result<bool, &'static str> {
        validate_filter(filter)?;
        let mut node = &mut self.root;
        for seg in filter.split('/') {
            node = node.children.entry(seg.to_string()).or_default();
        }
        let is_new = node.subscribers.insert(subscriber, options).is_none();
        if is_new {
            self.by_subscriber
                .entry(subscriber)
                .or_default()
                .push(filter.to_string());
        }
        Ok(is_new)
    }

    /// Remove `subscriber` from `filter`. Returns whether it was subscribed.
    pub fn unsubscribe(&mut self, filter: &str, subscriber: SubscriberId) -> bool {
        let mut node = &mut self.root;
        for seg in filter.split('/') {
            match node.children.get_mut(seg) {
                Some(child) => node = child,
                None => return false,
            }
        }
        let removed = node.subscribers.remove(&subscriber).is_some();
        if removed {
            if let Some(filters) = self.by_subscriber.get_mut(&subscriber) {
                filters.retain(|f| f != filter);
            }
        }
        removed
    }

    /// Remove every subscription `subscriber` holds (connection closed).
    pub fn unsubscribe_all(&mut self, subscriber: SubscriberId) {
        if let Some(filters) = self.by_subscriber.remove(&subscriber) {
            for filter in filters {
                let mut node = &mut self.root;
                let mut path_ok = true;
                for seg in filter.split('/') {
                    match node.children.get_mut(seg) {
                        Some(child) => node = child,
                        None => {
                            path_ok = false;
                            break;
                        }
                    }
                }
                if path_ok {
                    node.subscribers.remove(&subscriber);
                }
            }
        }
    }

    /// Every (subscriber, match options) whose filter matches `topic`.
    ///
    /// A subscriber matched by more than one filter appears once per
    /// matching filter (delivered once per subscription at the highest
    /// matching QoS is a policy decision left to the caller).
    pub fn matching_subscribers(&self, topic: &str) -> Vec<(SubscriberId, MatchOptions)> {
        let mut out = Vec::new();
        let segments: Vec<&str> = topic.split('/').collect();
        collect(&self.root, &segments, true, &mut out);
        out
    }
}

fn collect(node: &TopicNode, segments: &[&str], is_root: bool, out: &mut Vec<(SubscriberId, MatchOptions)>) {
    if segments.is_empty() {
        out.extend(node.subscribers.iter().map(|(id, opt)| (*id, *opt)));
        if let Some(hash) = node.children.get("#") {
            out.extend(hash.subscribers.iter().map(|(id, opt)| (*id, *opt)));
        }
        return;
    }
    let seg = segments[0];
    let rest = &segments[1..];
    let dollar_blocked = is_root && seg.starts_with('$');

    if let Some(child) = node.children.get(seg) {
        collect(child, rest, false, out);
    }
    if !dollar_blocked {
        if let Some(plus) = node.children.get("+") {
            collect(plus, rest, false, out);
        }
        if let Some(hash) = node.children.get("#") {
            out.extend(hash.subscribers.iter().map(|(id, opt)| (*id, *opt)));
        }
    }
}

/// Validate a topic filter (subscribe side): non-empty, `#` only as the
/// final whole segment, `+` only as a whole segment.
fn validate_filter(filter: &str) -> Result<(), &'static str> {
    if filter.is_empty() {
        return Err("empty topic filter");
    }
    let segments: Vec<&str> = filter.split('/').collect();
    for (i, seg) in segments.iter().enumerate() {
        if seg.contains('#') && *seg != "#" {
            return Err("'#' must occupy an entire topic level");
        }
        if *seg == "#" && i != segments.len() - 1 {
            return Err("'#' must be the last level of a topic filter");
        }
        if seg.contains('+') && *seg != "+" {
            return Err("'+' must occupy an entire topic level");
        }
    }
    Ok(())
}

/// Validate a topic name (publish side): non-empty, no wildcards.
pub fn validate_topic_name(topic: &str) -> Result<(), &'static str> {
    if topic.is_empty() {
        return Err("empty topic name");
    }
    if topic.contains('+') || topic.contains('#') {
        return Err("topic name must not contain wildcards");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::QoS;

    fn opt(qos: QoS) -> MatchOptions {
        MatchOptions {
            max_qos: qos,
            no_local: false,
            retain_as_published: false,
        }
    }

    fn ids(mut v: Vec<(SubscriberId, MatchOptions)>) -> Vec<SubscriberId> {
        v.sort_by_key(|(id, _)| id.0);
        v.into_iter().map(|(id, _)| id).collect()
    }

    #[test]
    fn exact_match() {
        let mut tree = TopicTree::new();
        tree.subscribe("a/b/c", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        assert_eq!(ids(tree.matching_subscribers("a/b/c")), vec![SubscriberId(1)]);
        assert!(tree.matching_subscribers("a/b").is_empty());
    }

    #[test]
    fn plus_matches_one_level() {
        let mut tree = TopicTree::new();
        tree.subscribe("sport/+/player1", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        assert_eq!(
            ids(tree.matching_subscribers("sport/tennis/player1")),
            vec![SubscriberId(1)]
        );
        assert!(tree.matching_subscribers("sport/tennis/bourse/player1").is_empty());
    }

    #[test]
    fn hash_matches_trailing_levels_and_parent() {
        let mut tree = TopicTree::new();
        tree.subscribe("sport/tennis/#", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        assert_eq!(ids(tree.matching_subscribers("sport/tennis")), vec![SubscriberId(1)]);
        assert_eq!(
            ids(tree.matching_subscribers("sport/tennis/player1")),
            vec![SubscriberId(1)]
        );
        assert_eq!(
            ids(tree.matching_subscribers("sport/tennis/player1/ranking")),
            vec![SubscriberId(1)]
        );
        assert!(tree.matching_subscribers("sport/football").is_empty());
    }

    #[test]
    fn bare_wildcards_do_not_match_dollar_topics() {
        let mut tree = TopicTree::new();
        tree.subscribe("#", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        tree.subscribe("+/status", SubscriberId(2), opt(QoS::AtMostOnce)).unwrap();
        tree.subscribe("$SYS/#", SubscriberId(3), opt(QoS::AtMostOnce)).unwrap();

        assert!(tree.matching_subscribers("$SYS/broker/uptime").iter().all(|(id, _)| *id != SubscriberId(1)));
        assert!(tree.matching_subscribers("$SYS/status").iter().all(|(id, _)| *id != SubscriberId(2)));
        assert_eq!(
            ids(tree.matching_subscribers("$SYS/broker/uptime")),
            vec![SubscriberId(3)]
        );
        // Non-dollar topics still match the bare wildcards normally.
        assert_eq!(ids(tree.matching_subscribers("plain/topic")), vec![SubscriberId(1)]);
    }

    #[test]
    fn unsubscribe_removes_entry() {
        let mut tree = TopicTree::new();
        tree.subscribe("a/b", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        assert!(tree.unsubscribe("a/b", SubscriberId(1)));
        assert!(tree.matching_subscribers("a/b").is_empty());
        assert!(!tree.unsubscribe("a/b", SubscriberId(1)));
    }

    #[test]
    fn unsubscribe_all_clears_every_filter() {
        let mut tree = TopicTree::new();
        tree.subscribe("a/b", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        tree.subscribe("c/#", SubscriberId(1), opt(QoS::AtMostOnce)).unwrap();
        tree.subscribe("c/#", SubscriberId(2), opt(QoS::AtMostOnce)).unwrap();
        tree.unsubscribe_all(SubscriberId(1));
        assert!(tree.matching_subscribers("a/b").is_empty());
        assert_eq!(ids(tree.matching_subscribers("c/d")), vec![SubscriberId(2)]);
    }

    #[test]
    fn rejects_malformed_filters() {
        let mut tree = TopicTree::new();
        assert!(tree.subscribe("a/#/b", SubscriberId(1), opt(QoS::AtMostOnce)).is_err());
        assert!(tree.subscribe("a/b#", SubscriberId(1), opt(QoS::AtMostOnce)).is_err());
        assert!(tree.subscribe("a/+b", SubscriberId(1), opt(QoS::AtMostOnce)).is_err());
        assert!(tree.subscribe("", SubscriberId(1), opt(QoS::AtMostOnce)).is_err());
    }

    #[test]
    fn rejects_wildcards_in_topic_names() {
        assert!(validate_topic_name("a/+/b").is_err());
        assert!(validate_topic_name("a/#").is_err());
        assert!(validate_topic_name("").is_err());
        assert!(validate_topic_name("a/b/c").is_ok());
    }
}
