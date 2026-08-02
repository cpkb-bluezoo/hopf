// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Topic filter trie: subscription registry and publish-time matching.
//!
//! MQTT 3.1.1 §4.7 / MQTT 5.0 §4.7: `+` matches exactly one topic level,
//! `#` matches zero or more trailing levels and must be the final token of
//! a filter, and a filter beginning with a wildcard never matches a topic
//! whose first level begins with `$` (reserved for server-internal topics
//! such as `$SYS`).
//!
//! Shared subscriptions (`$share/<ShareName>/<TopicFilter>`, MQTT 5.0
//! §4.8.2) register under the underlying topic filter; each matching
//! PUBLISH is delivered to **one** member of each share group (round-robin).

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

/// One share group's members + round-robin cursor.
#[derive(Default)]
struct SharedGroup {
    members: Vec<(SubscriberId, MatchOptions)>,
    next: usize,
}

impl SharedGroup {
    fn pick(&mut self) -> Option<(SubscriberId, MatchOptions)> {
        if self.members.is_empty() {
            return None;
        }
        let i = self.next % self.members.len();
        self.next = self.next.wrapping_add(1);
        Some(self.members[i])
    }
}

#[derive(Default)]
struct TopicNode {
    children: HashMap<String, TopicNode>,
    subscribers: HashMap<SubscriberId, MatchOptions>,
    /// ShareName → members subscribed via `$share/ShareName/<this filter>`.
    shared: HashMap<String, SharedGroup>,
}

/// Parsed subscribe filter: either a normal filter or a shared subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedFilter<'a> {
    Normal(&'a str),
    Shared { share_name: &'a str, filter: &'a str },
}

fn parse_filter(filter: &str) -> Result<ParsedFilter<'_>, &'static str> {
    if let Some(rest) = filter.strip_prefix("$share/") {
        let Some((share_name, topic_filter)) = rest.split_once('/') else {
            return Err("shared subscription missing topic filter");
        };
        if share_name.is_empty() || share_name.contains('+') || share_name.contains('#') {
            return Err("invalid share name");
        }
        if topic_filter.is_empty() {
            return Err("shared subscription missing topic filter");
        }
        validate_filter(topic_filter)?;
        Ok(ParsedFilter::Shared {
            share_name,
            filter: topic_filter,
        })
    } else {
        validate_filter(filter)?;
        Ok(ParsedFilter::Normal(filter))
    }
}

/// Subscription registry: a trie over `/`-separated topic filter segments.
#[derive(Default)]
pub struct TopicTree {
    root: TopicNode,
    /// Reverse index so `unsubscribe_all` doesn't need the caller to
    /// remember which filters a subscriber registered. Values are the
    /// original subscribe strings (including `$share/...` when shared).
    by_subscriber: HashMap<SubscriberId, Vec<String>>,
}

impl TopicTree {
    /// Empty tree.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `subscriber` for `filter`. Replaces any existing options
    /// for the same (subscriber, filter) pair.
    ///
    /// Returns whether this is a brand new subscription (`true`) or a
    /// replacement — used for MQTT 5.0 Retain Handling `1`.
    pub fn subscribe(
        &mut self,
        filter: &str,
        subscriber: SubscriberId,
        options: MatchOptions,
    ) -> Result<bool, &'static str> {
        let parsed = parse_filter(filter)?;
        let (path, share) = match parsed {
            ParsedFilter::Normal(f) => (f, None),
            ParsedFilter::Shared {
                share_name,
                filter: f,
            } => (f, Some(share_name)),
        };
        let mut node = &mut self.root;
        for seg in path.split('/') {
            node = node.children.entry(seg.to_string()).or_default();
        }
        let is_new = if let Some(share_name) = share {
            let group = node.shared.entry(share_name.to_string()).or_default();
            if let Some(existing) = group.members.iter_mut().find(|(id, _)| *id == subscriber) {
                existing.1 = options;
                false
            } else {
                group.members.push((subscriber, options));
                true
            }
        } else {
            node.subscribers.insert(subscriber, options).is_none()
        };
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
        let removed = self.unsubscribe_one(filter, subscriber);
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
                let _ = self.unsubscribe_one(&filter, subscriber);
            }
        }
    }

    fn unsubscribe_one(&mut self, filter: &str, subscriber: SubscriberId) -> bool {
        let Ok(parsed) = parse_filter(filter) else {
            return false;
        };
        let (path, share) = match parsed {
            ParsedFilter::Normal(f) => (f, None),
            ParsedFilter::Shared {
                share_name,
                filter: f,
            } => (f, Some(share_name)),
        };
        let mut node = &mut self.root;
        for seg in path.split('/') {
            match node.children.get_mut(seg) {
                Some(child) => node = child,
                None => return false,
            }
        }
        if let Some(share_name) = share {
            let Some(group) = node.shared.get_mut(share_name) else {
                return false;
            };
            let before = group.members.len();
            group.members.retain(|(id, _)| *id != subscriber);
            let removed = group.members.len() != before;
            if group.members.is_empty() {
                node.shared.remove(share_name);
            }
            removed
        } else {
            node.subscribers.remove(&subscriber).is_some()
        }
    }

    /// Every (subscriber, match options) whose filter matches `topic`.
    ///
    /// Each matching share group contributes **exactly one** member
    /// (round-robin). Requires `&mut self` for the RR cursor.
    pub fn matching_subscribers(&mut self, topic: &str) -> Vec<(SubscriberId, MatchOptions)> {
        let mut out = Vec::new();
        let segments: Vec<&str> = topic.split('/').collect();
        collect(&mut self.root, &segments, true, &mut out);
        out
    }
}

fn collect(
    node: &mut TopicNode,
    segments: &[&str],
    is_root: bool,
    out: &mut Vec<(SubscriberId, MatchOptions)>,
) {
    if segments.is_empty() {
        out.extend(node.subscribers.iter().map(|(id, opt)| (*id, *opt)));
        for group in node.shared.values_mut() {
            if let Some(pick) = group.pick() {
                out.push(pick);
            }
        }
        if let Some(hash) = node.children.get_mut("#") {
            out.extend(hash.subscribers.iter().map(|(id, opt)| (*id, *opt)));
            for group in hash.shared.values_mut() {
                if let Some(pick) = group.pick() {
                    out.push(pick);
                }
            }
        }
        return;
    }
    let seg = segments[0];
    let rest = &segments[1..];
    let dollar_blocked = is_root && seg.starts_with('$');

    if let Some(child) = node.children.get_mut(seg) {
        collect(child, rest, false, out);
    }
    if !dollar_blocked {
        if let Some(plus) = node.children.get_mut("+") {
            collect(plus, rest, false, out);
        }
        if let Some(hash) = node.children.get_mut("#") {
            out.extend(hash.subscribers.iter().map(|(id, opt)| (*id, *opt)));
            for group in hash.shared.values_mut() {
                if let Some(pick) = group.pick() {
                    out.push(pick);
                }
            }
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
        tree.subscribe("a/b/c", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        assert_eq!(
            ids(tree.matching_subscribers("a/b/c")),
            vec![SubscriberId(1)]
        );
        assert!(tree.matching_subscribers("a/b").is_empty());
    }

    #[test]
    fn plus_matches_one_level() {
        let mut tree = TopicTree::new();
        tree.subscribe("sport/+/player1", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        assert_eq!(
            ids(tree.matching_subscribers("sport/tennis/player1")),
            vec![SubscriberId(1)]
        );
        assert!(tree
            .matching_subscribers("sport/tennis/player1/ranking")
            .is_empty());
    }

    #[test]
    fn hash_matches_trailing_levels_and_parent() {
        let mut tree = TopicTree::new();
        tree.subscribe("sport/tennis/#", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        assert_eq!(
            ids(tree.matching_subscribers("sport/tennis")),
            vec![SubscriberId(1)]
        );
        assert_eq!(
            ids(tree.matching_subscribers("sport/tennis/player1")),
            vec![SubscriberId(1)]
        );
        assert!(tree.matching_subscribers("sport/football").is_empty());
    }

    #[test]
    fn bare_wildcards_do_not_match_dollar_topics() {
        let mut tree = TopicTree::new();
        tree.subscribe("#", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        tree.subscribe("+/status", SubscriberId(2), opt(QoS::AtMostOnce))
            .unwrap();
        tree.subscribe("$SYS/#", SubscriberId(3), opt(QoS::AtMostOnce))
            .unwrap();

        assert!(tree
            .matching_subscribers("$SYS/broker/uptime")
            .iter()
            .all(|(id, _)| *id != SubscriberId(1)));
        assert!(tree
            .matching_subscribers("$SYS/status")
            .iter()
            .all(|(id, _)| *id != SubscriberId(2)));
        assert_eq!(
            ids(tree.matching_subscribers("$SYS/broker/uptime")),
            vec![SubscriberId(3)]
        );
        assert_eq!(
            ids(tree.matching_subscribers("plain/topic")),
            vec![SubscriberId(1)]
        );
    }

    #[test]
    fn unsubscribe_removes_entry() {
        let mut tree = TopicTree::new();
        tree.subscribe("a/b", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        assert!(tree.unsubscribe("a/b", SubscriberId(1)));
        assert!(tree.matching_subscribers("a/b").is_empty());
    }

    #[test]
    fn shared_subscription_delivers_to_one_member() {
        let mut tree = TopicTree::new();
        tree.subscribe("$share/g1/a/b", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        tree.subscribe("$share/g1/a/b", SubscriberId(2), opt(QoS::AtMostOnce))
            .unwrap();
        tree.subscribe("$share/g2/a/b", SubscriberId(3), opt(QoS::AtMostOnce))
            .unwrap();

        let first = ids(tree.matching_subscribers("a/b"));
        assert_eq!(first.len(), 2); // one from g1, one from g2
        assert!(first.contains(&SubscriberId(3)));

        let second = ids(tree.matching_subscribers("a/b"));
        assert_eq!(second.len(), 2);
        // g1 round-robins between 1 and 2
        let g1_picks: Vec<_> = [first.clone(), second]
            .into_iter()
            .flatten()
            .filter(|id| *id == SubscriberId(1) || *id == SubscriberId(2))
            .collect();
        assert_eq!(g1_picks.len(), 2);
        assert_ne!(g1_picks[0], g1_picks[1]);
    }

    #[test]
    fn shared_and_normal_both_match() {
        let mut tree = TopicTree::new();
        tree.subscribe("a/b", SubscriberId(1), opt(QoS::AtMostOnce))
            .unwrap();
        tree.subscribe("$share/g/a/b", SubscriberId(2), opt(QoS::AtMostOnce))
            .unwrap();
        let got = ids(tree.matching_subscribers("a/b"));
        assert_eq!(got, vec![SubscriberId(1), SubscriberId(2)]);
    }

    #[test]
    fn rejects_malformed_shared() {
        let mut tree = TopicTree::new();
        assert!(tree
            .subscribe("$share/", SubscriberId(1), opt(QoS::AtMostOnce))
            .is_err());
        assert!(tree
            .subscribe("$share/g", SubscriberId(1), opt(QoS::AtMostOnce))
            .is_err());
        assert!(tree
            .subscribe("$share/+/a", SubscriberId(1), opt(QoS::AtMostOnce))
            .is_err());
    }
}
