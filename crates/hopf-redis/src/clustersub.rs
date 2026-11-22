// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`RedisClusterSubscriber`]: publish/subscribe against a Redis Cluster or
//! Valkey Cluster.
//!
//! A [`RedisSubscriber`] is one connection to one node. In a cluster, which node
//! a subscription belongs on depends on what it is:
//!
//! - A **classic** channel or pattern (`SUBSCRIBE`, `PSUBSCRIBE`) is broadcast to
//!   every node, so one node is enough. The subscriber uses one master, and moves
//!   to another, subscribing to everything again, if that node's connection is lost
//!   or it leaves the cluster.
//! - A **shard** channel (`SSUBSCRIBE`) lives on the master that owns its slot, and
//!   only there. The subscriber has one connection per owning master, subscribes
//!   each channel on its owner, and follows the slot when it moves: on a `MOVED`
//!   reply, on the `sunsubscribe` push a server sends when it loses the slot, and
//!   whenever the layout changes.
//! - **Keyspace and keyevent notifications** are published by the master that owns
//!   the key, to that node alone, so they are subscribed (as patterns) on every
//!   master, and the set of masters is kept as the layout changes. The server must
//!   have `notify-keyspace-events` enabled; the client changes no configuration.
//!
//! The layout is the one a [`RedisCluster`] keeps: the subscriber is built on one,
//! and acts when it takes a new layout. Each node's connection is an ordinary
//! [`RedisSubscriber`], with its reconnection and keepalive, and its `HELLO`,
//! authentication, client name and TLS from the cluster's node configuration.
//!
//! # Handlers
//!
//! Each node's connection has a [`SubscriberHandler`] of its own, made by the
//! function given to [`RedisClusterSubscriber::connect`] when the connection is
//! first made, and given the node. So a handler hears one connection's messages
//! one at a time, as it does for a [`RedisSubscriber`], and several nodes' never
//! interleave in one. A message that has begun when a connection is replaced (the
//! classic node moved, a node left the cluster) is abandoned. What a message is
//! tagged with to tell the nodes apart is the handler: make one that knows its
//! node.
//!
//! # What is guaranteed
//!
//! Pub/sub in Redis is at-most-once, and this does not change that. What the
//! subscriber guarantees is its own part:
//!
//! - **No duplicates.** A shard message goes to one node, the owner of its slot; a
//!   classic message is taken from one node; a keyspace event from the master that
//!   owns the key. No message reaches a handler twice because of how the subscriber
//!   is arranged.
//! - **Subscribe before unsubscribe.** When a shard channel moves, the new owner is
//!   subscribed before the old one is released: with `SUNSUBSCRIBE` if the old
//!   owner has other subscriptions, or by closing its connection (which releases
//!   them) if it has none. So the subscriber never gives up a subscription before
//!   taking the replacement. A server will not take a shard subscription for a
//!   slot it does not own, so the replacement can be made only once the slot has
//!   moved, and a message published between the slot changing hands and the new
//!   owner acknowledging is not delivered. That window is as short as a reply from
//!   the server and a layout refresh can make it, and it is not hidden: the new
//!   owner's handler is told `Subscribed` when the channel is back, and a server
//!   that drops a subscription says so with a `sunsubscribe` its handler hears.
//! - **No silent drops.** A message dropped for the reasons a [`RedisSubscriber`]
//!   drops one (an over-long channel) is reported to the handler of its node.
//!
//! A message published while a classic node's connection is down, or while a node
//! is being failed over, is lost, as for a single [`RedisSubscriber`].

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use hopf_core::Bytes;

use crate::cluster::{ClusterConfig, RedisCluster};
use crate::error::RedisError;
use crate::keys::key_slot;
use crate::pubsub::{MessageHeader, RedisSubscriber, SubscriberHandler, SubscriptionChange, SubscriptionKind};
use crate::resp::{Flow, ReplySink, ServerError};
use crate::topology::{parse_redirect, NodeAddr};

/// Makes the handler for one node's connection.
type MakeHandler = dyn Fn(&NodeAddr) -> Box<dyn SubscriberHandler> + Send + Sync;

/// How often a subscriber looks again at a layout that has a connection down in it,
/// unless told otherwise: a node that is being failed over has no new layout to find
/// until the failover is done.
const DEFAULT_CHECK: Duration = Duration::from_secs(1);

/// What the application has asked to be subscribed to.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Want {
    channels: BTreeSet<Vec<u8>>,
    patterns: BTreeSet<Vec<u8>>,
    shards: BTreeSet<Vec<u8>>,
    keyspace: BTreeSet<Vec<u8>>,
}

/// What one node's connection is to be subscribed to.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Target {
    channels: BTreeSet<Vec<u8>>,
    patterns: BTreeSet<Vec<u8>>,
    shards: BTreeSet<Vec<u8>>,
}

impl Target {
    fn is_empty(&self) -> bool {
        self.channels.is_empty() && self.patterns.is_empty() && self.shards.is_empty()
    }
}

/// Where each thing wanted belongs, given the layout.
///
/// `classic` is the node that takes the classic channels and patterns (`None` while
/// there is no master to be one); `owner` says who serves a slot; `redirects` are
/// owners a server has named, which are fresher than the layout until it is taken
/// again.
fn plan(
    want: &Want,
    masters: &[NodeAddr],
    classic: Option<&NodeAddr>,
    owner: &dyn Fn(u16) -> Option<NodeAddr>,
    redirects: &HashMap<u16, NodeAddr>,
) -> HashMap<NodeAddr, Target> {
    let mut out: HashMap<NodeAddr, Target> = HashMap::new();
    // Keyspace notifications come from every master, to that master alone.
    if !want.keyspace.is_empty() {
        for m in masters {
            out.entry(m.clone()).or_default().patterns.extend(want.keyspace.iter().cloned());
        }
    }
    if let Some(node) = classic {
        if !want.channels.is_empty() || !want.patterns.is_empty() {
            let t = out.entry(node.clone()).or_default();
            t.channels.extend(want.channels.iter().cloned());
            t.patterns.extend(want.patterns.iter().cloned());
        }
    }
    for channel in &want.shards {
        let slot = key_slot(channel);
        let owner = redirects.get(&slot).cloned().or_else(|| owner(slot));
        if let Some(node) = owner {
            out.entry(node).or_default().shards.insert(channel.clone());
        }
    }
    out.retain(|_, t| !t.is_empty());
    out
}

/// The node to take classic subscriptions: the one in use if it is still a master,
/// otherwise the first master that is not `avoid` (one that has just failed), or
/// `avoid` itself if it is all there is.
fn choose_classic(current: Option<&NodeAddr>, masters: &[NodeAddr], avoid: Option<&NodeAddr>) -> Option<NodeAddr> {
    if let Some(c) = current {
        if masters.contains(c) {
            return Some(c.clone());
        }
    }
    masters
        .iter()
        .find(|m| Some(*m) != avoid)
        .or_else(|| masters.first())
        .cloned()
}

/// One node's connection.
struct Conn {
    sub: RedisSubscriber,
}

#[derive(Default)]
struct HubState {
    want: Want,
    conns: HashMap<NodeAddr, Conn>,
    classic: Option<NodeAddr>,
    /// A classic node that has just been lost: not chosen again while there is another.
    avoid: Option<NodeAddr>,
    /// Owners of slots that servers have named in `MOVED` replies, until a layout
    /// agrees with them. (A layout is not always as fresh as a server's answer: a
    /// slot that has just moved may not have reached the node that was asked.)
    redirects: HashMap<u16, NodeAddr>,
    /// What each node has acknowledged, so that a subscription is not released
    /// where it was until its replacement has been taken.
    acked: HashMap<NodeAddr, HashSet<(SubscriptionKind, Vec<u8>)>>,
    /// A timer to look again at the layout is set.
    watching: bool,
}

struct Hub {
    cluster: RedisCluster,
    make: Box<MakeHandler>,
    state: Mutex<HubState>,
    closed: AtomicBool,
    check_ms: AtomicU64,
    /// Close the cluster with the subscriber: it is the subscriber's own.
    owns_cluster: bool,
}

/// A subscriber for a cluster. See the module documentation.
///
/// Cheap to clone; clones share the connections.
#[derive(Clone)]
pub struct RedisClusterSubscriber {
    hub: Arc<Hub>,
}

impl RedisClusterSubscriber {
    /// A subscriber on the layout `cluster` keeps. `make` is called for each node's
    /// connection, when it is first made, and returns the handler for it; the
    /// handlers' methods run on the cluster's reactor. See the module
    /// documentation for what that means for a handler.
    pub fn connect(
        cluster: &RedisCluster,
        make: impl Fn(&NodeAddr) -> Box<dyn SubscriberHandler> + Send + Sync + 'static,
    ) -> Self {
        Self::build(cluster.clone(), Box::new(make), false)
    }

    /// A subscriber with a cluster of its own, made from `config` and bound to
    /// `reactor`, and closed with it.
    pub fn connect_config(
        reactor: &hopf_core::ReactorHandle,
        config: ClusterConfig,
        make: impl Fn(&NodeAddr) -> Box<dyn SubscriberHandler> + Send + Sync + 'static,
    ) -> Self {
        Self::build(RedisCluster::connect(reactor, config), Box::new(make), true)
    }

    fn build(cluster: RedisCluster, make: Box<MakeHandler>, owns_cluster: bool) -> Self {
        let hub = Arc::new(Hub {
            cluster,
            make,
            state: Mutex::new(HubState::default()),
            closed: AtomicBool::new(false),
            check_ms: AtomicU64::new(DEFAULT_CHECK.as_millis() as u64),
            owns_cluster,
        });
        let weak = Arc::downgrade(&hub);
        hub.cluster.on_layout(move || {
            if let Some(hub) = weak.upgrade() {
                hub.reconcile();
            }
        });
        Self { hub }
    }

    /// How often to look again at the layout while a connection is down. Default
    /// one second.
    pub fn check_interval(&self, interval: Duration) {
        self.hub.check_ms.store(interval.as_millis().max(1) as u64, Ordering::SeqCst);
    }

    /// Subscribe to channels by name, on one node (classic channels are broadcast
    /// to every node). Takes effect at once, and again on any node it moves to.
    pub fn subscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.change(|w| w.channels.extend(channels.iter().map(|c| c.as_ref().to_vec())));
    }

    /// Subscribe to patterns, on one node.
    pub fn psubscribe(&self, patterns: &[impl AsRef<[u8]>]) {
        self.change(|w| w.patterns.extend(patterns.iter().map(|c| c.as_ref().to_vec())));
    }

    /// Subscribe to shard channels, each on the master that owns its slot, and
    /// follow the slot if it moves.
    pub fn ssubscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.change(|w| w.shards.extend(channels.iter().map(|c| c.as_ref().to_vec())));
    }

    /// Subscribe to keyspace or keyevent notifications matching `patterns`
    /// (`__keyspace@0__:*`, `__keyevent@0__:expired`), on every master, and on
    /// each master that joins. The notifications are the server's to produce:
    /// enable `notify-keyspace-events` on every master. They arrive as pattern
    /// messages.
    pub fn subscribe_keyspace(&self, patterns: &[impl AsRef<[u8]>]) {
        self.change(|w| w.keyspace.extend(patterns.iter().map(|c| c.as_ref().to_vec())));
    }

    /// Unsubscribe from channels; with none named, from all of them.
    pub fn unsubscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.change(|w| remove(&mut w.channels, channels));
    }

    /// Unsubscribe from patterns; with none named, from all of them.
    pub fn punsubscribe(&self, patterns: &[impl AsRef<[u8]>]) {
        self.change(|w| remove(&mut w.patterns, patterns));
    }

    /// Unsubscribe from shard channels; with none named, from all of them.
    pub fn sunsubscribe(&self, channels: &[impl AsRef<[u8]>]) {
        self.change(|w| remove(&mut w.shards, channels));
    }

    /// Stop the keyspace subscriptions matching `patterns`; with none named, all.
    pub fn unsubscribe_keyspace(&self, patterns: &[impl AsRef<[u8]>]) {
        self.change(|w| remove(&mut w.keyspace, patterns));
    }

    fn change(&self, f: impl FnOnce(&mut Want)) {
        {
            let mut st = self.hub.state.lock().unwrap();
            f(&mut st.want);
        }
        self.hub.reconcile();
    }

    /// What is wanted, whatever the connections' state: classic channels, classic
    /// patterns, shard channels and keyspace patterns.
    pub fn subscriptions(&self) -> (Vec<Bytes>, Vec<Bytes>, Vec<Bytes>, Vec<Bytes>) {
        let st = self.hub.state.lock().unwrap();
        let v = |s: &BTreeSet<Vec<u8>>| s.iter().map(|b| Bytes::copy_from_slice(b)).collect();
        (v(&st.want.channels), v(&st.want.patterns), v(&st.want.shards), v(&st.want.keyspace))
    }

    /// The nodes there is a connection to now, and whether each is up.
    pub fn connections(&self) -> Vec<(NodeAddr, bool)> {
        let st = self.hub.state.lock().unwrap();
        st.conns.iter().map(|(n, c)| (n.clone(), c.sub.is_connected())).collect()
    }

    /// Close every connection and stop following the layout. If the subscriber
    /// made its own cluster ([`connect_config`](Self::connect_config)), that is
    /// closed too.
    pub fn close(&self) {
        self.hub.closed.store(true, Ordering::SeqCst);
        let conns = std::mem::take(&mut self.hub.state.lock().unwrap().conns);
        for (_, c) in conns {
            c.sub.close();
        }
        if self.hub.owns_cluster {
            self.hub.cluster.close();
        }
    }
}

fn remove(set: &mut BTreeSet<Vec<u8>>, names: &[impl AsRef<[u8]>]) {
    if names.is_empty() {
        set.clear();
    } else {
        for n in names {
            set.remove(n.as_ref());
        }
    }
}

impl Hub {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.cluster.is_closed()
    }

    /// Make the connections what the layout and what is wanted say they should be.
    /// Idempotent: called whenever either changes.
    fn reconcile(self: &Arc<Self>) {
        if self.is_closed() {
            return;
        }
        let (masters, slots): (Vec<NodeAddr>, Vec<Option<Arc<NodeAddr>>>) =
            self.cluster.with_layout(|slots, masters| (masters.iter().map(|m| (**m).clone()).collect(), slots.to_vec()));
        let mut st = self.state.lock().unwrap();
        if masters.is_empty() {
            // No layout yet: it will tell us when it comes.
            return;
        }
        // A redirect has done its work once the layout names the same owner.
        st.redirects.retain(|slot, node| slots.get(*slot as usize).and_then(|s| s.as_deref()) != Some(node));
        let classic = if st.want.channels.is_empty() && st.want.patterns.is_empty() {
            None
        } else {
            let c = choose_classic(st.classic.as_ref(), &masters, st.avoid.as_ref());
            st.classic = c.clone();
            c
        };
        let owner = |slot: u16| slots.get(slot as usize).and_then(|s| s.as_deref().cloned());
        let target = plan(&st.want, &masters, classic.as_ref(), &owner, &st.redirects);

        // Subscribe first, on every node that is to have more, and only then
        // release what is no longer wanted where it was.
        for (node, want) in &target {
            if !st.conns.contains_key(node) {
                let conn = self.open(node);
                st.conns.insert(node.clone(), conn);
            }
            let sub = &st.conns[node].sub;
            let (channels, patterns, shards) = held(sub);
            add(want.channels.difference(&channels), |n| sub.subscribe(&[n]));
            add(want.patterns.difference(&patterns), |n| sub.psubscribe(&[n]));
            add(want.shards.difference(&shards), |n| sub.ssubscribe(&[n]));
        }
        // A shard channel that is wanted on another node, and that node has not
        // yet acknowledged it, stays where it is until it has.
        let pending_elsewhere = |st: &HubState, from: &NodeAddr, channel: &Vec<u8>| {
            target.iter().any(|(to, t)| {
                to != from
                    && t.shards.contains(channel)
                    && !st.acked.get(to).is_some_and(|a| a.contains(&(SubscriptionKind::Shard, channel.clone())))
            })
        };
        let nodes: Vec<NodeAddr> = st.conns.keys().cloned().collect();
        for node in nodes {
            let (channels, patterns, shards) = held(&st.conns[&node].sub);
            let (want_channels, want_patterns, want_shards) = match target.get(&node) {
                Some(t) => (t.channels.clone(), t.patterns.clone(), t.shards.clone()),
                None => Default::default(),
            };
            let keep_shards: Vec<&Vec<u8>> = shards.difference(&want_shards).filter(|c| pending_elsewhere(&st, &node, c)).collect();
            let sub = &st.conns[&node].sub;
            let released_shards: Vec<&Vec<u8>> = shards.difference(&want_shards).filter(|c| !keep_shards.contains(c)).collect();
            if !target.contains_key(&node) && keep_shards.is_empty() {
                // Nothing left that is wanted here, and nothing held back: closing
                // the connection releases it all.
                if let Some(c) = st.conns.remove(&node) {
                    c.sub.close();
                }
                st.acked.remove(&node);
                continue;
            }
            add(channels.difference(&want_channels), |n| sub.unsubscribe(&[n]));
            add(patterns.difference(&want_patterns), |n| sub.punsubscribe(&[n]));
            add(released_shards.into_iter(), |n| sub.sunsubscribe(&[n]));
        }
        let down = st.conns.values().any(|c| !c.sub.is_connected());
        drop(st);
        if down {
            self.watch();
        }
    }

    /// A connection to `node`, with a handler for it that tells this hub what it
    /// needs to know.
    fn open(self: &Arc<Self>, node: &NodeAddr) -> Conn {
        let handler = Tap {
            inner: (self.make)(node),
            hub: Arc::downgrade(self),
            node: node.clone(),
        };
        let sub = RedisSubscriber::connect(self.cluster.reactor(), self.cluster.node_config(node), handler);
        Conn { sub }
    }

    /// Look again at the layout in a while, if a connection is down: a node that is
    /// failing over has no new layout to find until it is done.
    fn watch(self: &Arc<Self>) {
        {
            let mut st = self.state.lock().unwrap();
            if st.watching {
                return;
            }
            st.watching = true;
        }
        let weak = Arc::downgrade(self);
        let delay = Duration::from_millis(self.check_ms.load(Ordering::SeqCst));
        self.cluster.reactor().schedule_timer(
            delay,
            Box::new(move || {
                let Some(hub) = weak.upgrade() else {
                    return;
                };
                hub.state.lock().unwrap().watching = false;
                if hub.is_closed() {
                    return;
                }
                let down = hub.state.lock().unwrap().conns.values().any(|c| !c.sub.is_connected());
                if down {
                    hub.cluster.refresh();
                }
                // The layout may have changed without a listener having heard (a
                // refresh that found the same), and what a node has dropped is put
                // back.
                hub.reconcile();
            }),
        );
    }

    /// A node's connection has gone.
    fn node_down(self: &Arc<Self>, node: &NodeAddr) {
        {
            let mut st = self.state.lock().unwrap();
            // Whatever it had acknowledged is gone with the connection.
            st.acked.remove(node);
            if st.classic.as_ref() == Some(node) {
                // Classic messages are broadcast: another node will do, at once.
                st.classic = None;
                st.avoid = Some(node.clone());
            }
        }
        self.cluster.refresh();
        self.reconcile();
        self.watch();
    }

    /// A node has acknowledged a subscription, or released one.
    fn acknowledged(self: &Arc<Self>, node: &NodeAddr, kind: SubscriptionKind, name: &[u8], subscribed: bool) {
        {
            let mut st = self.state.lock().unwrap();
            let set = st.acked.entry(node.clone()).or_default();
            if subscribed {
                set.insert((kind, name.to_vec()));
            } else {
                set.remove(&(kind, name.to_vec()));
            }
        }
        if subscribed {
            // What was waiting for this can be let go of now.
            self.reconcile();
        }
    }

    /// A node has refused a subscription with `MOVED`: the slot is somewhere else.
    fn moved(self: &Arc<Self>, slot: u16, to: NodeAddr) {
        self.state.lock().unwrap().redirects.insert(slot, to);
        self.cluster.refresh();
        self.reconcile();
    }

    /// A node has said it no longer holds a shard subscription we want: its slot has
    /// gone elsewhere (or is going). Forget it there, so that it is subscribed afresh
    /// on whoever the layout says owns it, even if that is the same node.
    fn shard_lost(self: &Arc<Self>, node: &NodeAddr, channel: &[u8]) {
        {
            let st = self.state.lock().unwrap();
            let Some(conn) = st.conns.get(node) else {
                return;
            };
            if !st.want.shards.contains(channel) || !held(&conn.sub).2.contains(channel) {
                return;
            }
            conn.sub.sunsubscribe(&[channel]);
        }
        self.cluster.refresh();
        self.watch();
    }
}

/// What a node's subscriber has been told to be subscribed to.
fn held(sub: &RedisSubscriber) -> (BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>, BTreeSet<Vec<u8>>) {
    let (channels, patterns, shards) = sub.subscriptions();
    let set = |v: Vec<Bytes>| v.into_iter().map(|b| b.to_vec()).collect();
    (set(channels), set(patterns), set(shards))
}

fn add<'a>(names: impl Iterator<Item = &'a Vec<u8>>, mut f: impl FnMut(&Vec<u8>)) {
    for n in names {
        f(n);
    }
}

/// Stands in front of the application's handler for one node: it forwards
/// everything, and tells the hub what the hub has to act on.
struct Tap {
    inner: Box<dyn SubscriberHandler>,
    hub: Weak<Hub>,
    node: NodeAddr,
}

impl SubscriberHandler for Tap {
    fn message_begin(&mut self, header: &MessageHeader<'_>, len: Option<u64>) -> Flow {
        self.inner.message_begin(header, len)
    }

    fn message_chunk(&mut self, data: &[u8]) -> Flow {
        self.inner.message_chunk(data)
    }

    fn message_end(&mut self) {
        self.inner.message_end();
    }

    fn on_subscription(&mut self, change: SubscriptionChange) {
        if let Some(hub) = self.hub.upgrade() {
            match &change {
                SubscriptionChange::Subscribed { kind, name, .. } => hub.acknowledged(&self.node, *kind, name, true),
                SubscriptionChange::Unsubscribed { kind, name: Some(name), .. } => {
                    hub.acknowledged(&self.node, *kind, name, false);
                    if *kind == SubscriptionKind::Shard {
                        hub.shard_lost(&self.node, name);
                    }
                }
                SubscriptionChange::Unsubscribed { name: None, .. } => {}
            }
        }
        self.inner.on_subscription(change);
    }

    fn on_push(&mut self, kind: &str) -> Option<Box<dyn ReplySink + Send>> {
        self.inner.on_push(kind)
    }

    fn on_dropped(&mut self, why: &RedisError) {
        self.inner.on_dropped(why);
    }

    fn on_error(&mut self, error: ServerError) {
        if let Some(hub) = self.hub.upgrade() {
            match error.code.as_str() {
                "MOVED" => {
                    if let Some((slot, to)) = parse_redirect(&error.message) {
                        hub.moved(slot, to);
                    }
                }
                "CLUSTERDOWN" => hub.cluster.refresh(),
                _ => {}
            }
        }
        self.inner.on_error(error);
    }

    fn on_connected(&mut self, reconnect: bool) {
        self.inner.on_connected(reconnect);
    }

    fn on_disconnected(&mut self, reason: &RedisError) {
        if let Some(hub) = self.hub.upgrade() {
            hub.node_down(&self.node);
        }
        self.inner.on_disconnected(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(port: u16) -> NodeAddr {
        NodeAddr {
            host: "10.0.0.1".into(),
            port,
        }
    }

    fn set(names: &[&str]) -> BTreeSet<Vec<u8>> {
        names.iter().map(|n| n.as_bytes().to_vec()).collect()
    }

    /// A layout of masters on ports 1, 2 and 3, the first half of the slots to 1,
    /// then 2 up to 12000, then 3.
    fn owner(slot: u16) -> Option<NodeAddr> {
        Some(node(match slot {
            0..=5000 => 1,
            5001..=12000 => 2,
            _ => 3,
        }))
    }

    fn masters() -> Vec<NodeAddr> {
        vec![node(1), node(2), node(3)]
    }

    /// A channel in each of the three owners' ranges.
    fn channels() -> [String; 3] {
        let mut found: [Option<String>; 3] = [None, None, None];
        for i in 0..1000 {
            let name = format!("shard-{i}");
            let slot = key_slot(name.as_bytes());
            let at = match slot {
                0..=5000 => 0,
                5001..=12000 => 1,
                _ => 2,
            };
            found[at].get_or_insert(name);
        }
        found.map(|c| c.expect("a channel in every range"))
    }

    #[test]
    fn a_shard_channel_goes_to_the_master_that_owns_its_slot_and_nowhere_else() {
        let [a, b, c] = channels();
        let want = Want {
            shards: set(&[&a, &b, &c]),
            ..Want::default()
        };
        let got = plan(&want, &masters(), None, &owner, &HashMap::new());
        assert_eq!(got.len(), 3);
        for (n, ch) in [(1, &a), (2, &b), (3, &c)] {
            assert_eq!(got[&node(n)].shards, set(&[ch]), "node {n}");
            assert!(got[&node(n)].channels.is_empty() && got[&node(n)].patterns.is_empty());
        }
    }

    #[test]
    fn classic_channels_and_patterns_go_to_one_node_only() {
        let want = Want {
            channels: set(&["news"]),
            patterns: set(&["n*"]),
            ..Want::default()
        };
        let got = plan(&want, &masters(), Some(&node(2)), &owner, &HashMap::new());
        assert_eq!(got.len(), 1);
        assert_eq!(got[&node(2)].channels, set(&["news"]));
        assert_eq!(got[&node(2)].patterns, set(&["n*"]));
        // With no master to take them they wait.
        assert!(plan(&want, &[], None, &owner, &HashMap::new()).is_empty());
    }

    #[test]
    fn keyspace_patterns_go_to_every_master_beside_whatever_else_a_node_has() {
        let want = Want {
            channels: set(&["news"]),
            patterns: set(&["n*"]),
            keyspace: set(&["__keyspace@0__:*"]),
            ..Want::default()
        };
        let got = plan(&want, &masters(), Some(&node(1)), &owner, &HashMap::new());
        assert_eq!(got.len(), 3, "a connection to every master");
        assert_eq!(got[&node(1)].patterns, set(&["n*", "__keyspace@0__:*"]));
        assert_eq!(got[&node(1)].channels, set(&["news"]));
        assert_eq!(got[&node(2)].patterns, set(&["__keyspace@0__:*"]));
        assert!(got[&node(2)].channels.is_empty());
        // A master that leaves takes its keyspace subscription with it; one that joins gets one.
        let shrunk = plan(&want, &[node(1), node(3)], Some(&node(1)), &owner, &HashMap::new());
        assert!(!shrunk.contains_key(&node(2)));
        let grown = plan(&want, &[node(1), node(2), node(3), node(4)], Some(&node(1)), &owner, &HashMap::new());
        assert_eq!(grown[&node(4)].patterns, set(&["__keyspace@0__:*"]));
    }

    #[test]
    fn a_redirect_a_server_named_is_fresher_than_the_layout() {
        let [a, ..] = channels();
        let want = Want {
            shards: set(&[&a]),
            ..Want::default()
        };
        let slot = key_slot(a.as_bytes());
        let mut redirects = HashMap::new();
        redirects.insert(slot, node(3));
        let got = plan(&want, &masters(), None, &owner, &redirects);
        assert_eq!(got.keys().collect::<Vec<_>>(), vec![&node(3)]);
    }

    #[test]
    fn a_slot_nobody_serves_is_not_subscribed_anywhere_until_somebody_does() {
        let [a, ..] = channels();
        let want = Want {
            shards: set(&[&a]),
            ..Want::default()
        };
        assert!(plan(&want, &masters(), None, &|_| None, &HashMap::new()).is_empty());
    }

    #[test]
    fn the_classic_node_stays_while_it_is_a_master_and_moves_off_one_that_has_failed() {
        let m = masters();
        assert_eq!(choose_classic(Some(&node(2)), &m, None), Some(node(2)));
        // Lost: another is chosen, though the lost one is still in the layout.
        assert_eq!(choose_classic(None, &m, Some(&node(1))), Some(node(2)));
        // No longer a master: another is chosen.
        assert_eq!(choose_classic(Some(&node(9)), &m, None), Some(node(1)));
        // The only master is what there is.
        assert_eq!(choose_classic(None, &[node(1)], Some(&node(1))), Some(node(1)));
        assert_eq!(choose_classic(None, &[], None), None);
    }
}
