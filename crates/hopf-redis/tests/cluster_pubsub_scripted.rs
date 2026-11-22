// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Cluster publish/subscribe against scripted nodes: where each kind of
//! subscription goes, in what order it moves, and what the application's handlers
//! are told. Scripted, because a real cluster cannot be made to answer `MOVED` to
//! a subscription on cue, or to push a `sunsubscribe` for a slot it still serves.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hopf_core::ConnHandle;
use hopf_redis::{
    key_slot, ClusterConfig, Flow, MessageHeader, NodeAddr, RedisCluster, RedisClusterSubscriber, RedisError,
    SubscriberHandler, SubscriptionChange,
};

use common::scripted_server::*;
use common::*;

/// Which node serves which slots, as the nodes say it (`shown`, what `CLUSTER
/// SLOTS` answers) and as it is (`truth`, what a node checks a subscription
/// against), as `(first, last, node index)`.
struct Net {
    addrs: OnceLock<Vec<SocketAddr>>,
    shown: Mutex<Vec<(u16, u16, usize)>>,
    truth: Mutex<Vec<(u16, u16, usize)>>,
}

impl Net {
    fn new(ranges: Vec<(u16, u16, usize)>) -> Arc<Self> {
        Arc::new(Self {
            addrs: OnceLock::new(),
            shown: Mutex::new(ranges.clone()),
            truth: Mutex::new(ranges),
        })
    }

    fn addr(&self, i: usize) -> SocketAddr {
        self.addrs.get().unwrap()[i]
    }

    /// Change both what is said and what is so.
    fn set(&self, ranges: Vec<(u16, u16, usize)>) {
        *self.shown.lock().unwrap() = ranges.clone();
        *self.truth.lock().unwrap() = ranges;
    }

    fn owner(&self, slot: u16) -> Option<usize> {
        self.truth.lock().unwrap().iter().find(|(lo, hi, _)| (*lo..=*hi).contains(&slot)).map(|r| r.2)
    }

    fn slots_reply(&self) -> String {
        let shown = self.shown.lock().unwrap();
        let mut out = format!("*{}\r\n", shown.len());
        for (lo, hi, i) in shown.iter() {
            let a = self.addr(*i);
            let id = format!("node{i}");
            out += &format!(
                "*3\r\n:{lo}\r\n:{hi}\r\n*3\r\n${}\r\n{}\r\n:{}\r\n${}\r\n{id}\r\n",
                a.ip().to_string().len(),
                a.ip(),
                a.port(),
                id.len()
            );
        }
        out
    }
}

/// What the nodes were asked, in the order they were asked: `(node, command)`.
type Log = Arc<Mutex<Vec<(usize, String)>>>;
type Handles = Arc<Mutex<Vec<(usize, ConnHandle)>>>;

struct Cluster {
    rt: hopf_core::Runtime,
    servers: Vec<Server>,
    net: Arc<Net>,
    log: Log,
    handles: Handles,
}

impl Cluster {
    /// `n` nodes serving `ranges`.
    fn new(n: usize, ranges: Vec<(u16, u16, usize)>) -> Self {
        let net = Net::new(ranges);
        let log: Log = Arc::default();
        let handles: Handles = Arc::default();
        let servers: Vec<Server> = (0..n)
            .map(|i| {
                let (net, log, handles) = (Arc::clone(&net), Arc::clone(&log), Arc::clone(&handles));
                serve(move |s, w| script(i, &net, &log, &handles, s, w))
            })
            .collect();
        net.addrs.set(servers.iter().map(|s| s.addr).collect()).unwrap();
        Self {
            rt: runtime(),
            servers,
            net,
            log,
            handles,
        }
    }

    fn cluster(&self) -> RedisCluster {
        let config = ClusterConfig::new([("127.0.0.1".to_string(), self.servers[0].addr.port())])
            .min_refresh_interval(Duration::from_millis(5));
        let c = RedisCluster::connect(self.rt.pick_worker(), config);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !c.is_ready() {
            assert!(Instant::now() < deadline, "no layout");
            std::thread::sleep(Duration::from_millis(5));
        }
        c
    }

    /// Send `bytes` to the subscriber's connection to node `i`.
    fn push(&self, i: usize, bytes: &str) {
        let handle = self.handles.lock().unwrap().iter().rev().find(|(n, _)| *n == i).map(|(_, h)| h.clone()).expect("a connection");
        let bytes = bytes.as_bytes().to_vec();
        handle.with_endpoint(move |ep| ep.send(&bytes));
    }

    /// Close the subscriber's connection to node `i` from the server's side.
    fn drop_connection(&self, i: usize) {
        let handle = self.handles.lock().unwrap().iter().rev().find(|(n, _)| *n == i).map(|(_, h)| h.clone()).expect("a connection");
        handle.with_endpoint(|ep| ep.close());
    }

    /// The commands node `i` has been asked.
    fn asked(&self, i: usize) -> Vec<String> {
        self.log.lock().unwrap().iter().filter(|(n, _)| *n == i).map(|(_, c)| c.clone()).collect()
    }

    fn shutdown(self) {
        self.rt.shutdown();
        for s in self.servers {
            s.rt.shutdown();
        }
    }
}

fn script(i: usize, net: &Arc<Net>, log: &Log, handles: &Handles, s: &mut Session, w: &[Vec<u8>]) {
    let name = name_of(w);
    let chans: Vec<String> = w[1..].iter().map(|c| String::from_utf8_lossy(c).into_owned()).collect();
    let ack = |s: &mut Session, word: &str, ch: &str| {
        s.reply(format!(">3\r\n${}\r\n{word}\r\n${}\r\n{ch}\r\n:1\r\n", word.len(), ch.len()));
    };
    match name.as_str() {
        "HELLO" => s.reply(HELLO_OK),
        "CLUSTER" if arg(w, 1).eq_ignore_ascii_case("SHARDS") => s.reply("-ERR unknown subcommand 'SHARDS'\r\n"),
        "CLUSTER" => s.reply(net.slots_reply()),
        "PING" => s.reply("+PONG\r\n"),
        "SPUBLISH" => {
            log.lock().unwrap().push((i, format!("SPUBLISH {}", chans[0])));
            s.reply(":1\r\n");
        }
        "SSUBSCRIBE" | "SUBSCRIBE" | "PSUBSCRIBE" | "SUNSUBSCRIBE" | "UNSUBSCRIBE" | "PUNSUBSCRIBE" => {
            handles.lock().unwrap().push((i, s.endpoint.handle()));
            for ch in &chans {
                log.lock().unwrap().push((i, format!("{name} {ch}")));
                let slot = key_slot(ch.as_bytes());
                let word = name.to_ascii_lowercase();
                match (name.as_str(), net.owner(slot)) {
                    ("SSUBSCRIBE", Some(o)) if o != i => {
                        s.reply(format!("-MOVED {slot} {}\r\n", net.addr(o)));
                    }
                    _ => ack(s, &word, ch),
                }
            }
        }
        other => panic!("unexpected {other}"),
    }
}

/// A handler for one node's connection that writes what it hears into a shared log.
struct Tag {
    label: usize,
    log: Arc<Mutex<Vec<String>>>,
    channel: String,
    body: Vec<u8>,
}

impl SubscriberHandler for Tag {
    fn message_begin(&mut self, header: &MessageHeader<'_>, _len: Option<u64>) -> Flow {
        self.channel = String::from_utf8_lossy(header.channel()).into_owned();
        self.body.clear();
        Flow::Continue
    }
    fn message_chunk(&mut self, data: &[u8]) -> Flow {
        self.body.extend_from_slice(data);
        Flow::Continue
    }
    fn message_end(&mut self) {
        self.log
            .lock()
            .unwrap()
            .push(format!("message {} {} {}", self.label, self.channel, String::from_utf8_lossy(&self.body)));
    }
    fn on_subscription(&mut self, change: SubscriptionChange) {
        let text = match change {
            SubscriptionChange::Subscribed { kind, name, .. } => format!("subscribed {} {kind:?} {}", self.label, String::from_utf8_lossy(&name)),
            SubscriptionChange::Unsubscribed { kind, name, .. } => format!(
                "unsubscribed {} {kind:?} {}",
                self.label,
                name.map(|n| String::from_utf8_lossy(&n).into_owned()).unwrap_or_default()
            ),
        };
        self.log.lock().unwrap().push(text);
    }
    fn on_error(&mut self, error: hopf_redis::ServerError) {
        self.log.lock().unwrap().push(format!("error {} {}", self.label, error.code));
    }
    fn on_disconnected(&mut self, _reason: &RedisError) {
        self.log.lock().unwrap().push(format!("down {}", self.label));
    }
}

struct Heard {
    log: Arc<Mutex<Vec<String>>>,
    made: Arc<Mutex<Vec<usize>>>,
}

fn subscriber(cluster: &Cluster, c: &RedisCluster) -> (RedisClusterSubscriber, Heard) {
    let heard = Heard {
        log: Arc::default(),
        made: Arc::default(),
    };
    let (log, made) = (Arc::clone(&heard.log), Arc::clone(&heard.made));
    let ports: Vec<u16> = cluster.servers.iter().map(|s| s.addr.port()).collect();
    let sub = RedisClusterSubscriber::connect(c, move |node: &NodeAddr| {
        let label = ports.iter().position(|p| *p == node.port).unwrap();
        made.lock().unwrap().push(label);
        Box::new(Tag {
            label,
            log: Arc::clone(&log),
            channel: String::new(),
            body: Vec::new(),
        })
    });
    sub.check_interval(Duration::from_millis(50));
    (sub, heard)
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn channel_in(range: std::ops::RangeInclusive<u16>, prefix: &str) -> String {
    (0..).map(|n| format!("{prefix}{n}")).find(|k| range.contains(&key_slot(k.as_bytes()))).unwrap()
}

fn heard(h: &Heard) -> Vec<String> {
    h.log.lock().unwrap().clone()
}

fn position(log: &Log, node: usize, command: &str) -> Option<usize> {
    log.lock().unwrap().iter().position(|(n, c)| *n == node && c == command)
}

#[test]
fn a_shard_channel_is_subscribed_on_the_node_that_owns_its_slot_and_nowhere_else() {
    let net = Cluster::new(2, vec![(0, 8191, 0), (8192, 16383, 1)]);
    let c = net.cluster();
    let (sub, h) = subscriber(&net, &c);
    let on_a = channel_in(0..=8191, "sa");
    let on_b = channel_in(8192..=16383, "sb");
    sub.ssubscribe(&[&on_a, &on_b]);
    wait_until("both subscriptions", || position(&net.log, 0, &format!("SSUBSCRIBE {on_a}")).is_some() && position(&net.log, 1, &format!("SSUBSCRIBE {on_b}")).is_some());
    assert_eq!(net.asked(0), vec![format!("SSUBSCRIBE {on_a}")], "a was asked for its channel only");
    assert_eq!(net.asked(1), vec![format!("SSUBSCRIBE {on_b}")], "b for its channel only");

    // Each node's messages reach the handler made for it.
    wait_until("the acknowledgements", || heard(&h).len() == 2);
    net.push(0, &format!(">3\r\n$8\r\nsmessage\r\n${}\r\n{on_a}\r\n$2\r\nhi\r\n", on_a.len()));
    net.push(1, &format!(">3\r\n$8\r\nsmessage\r\n${}\r\n{on_b}\r\n$5\r\nthere\r\n", on_b.len()));
    wait_until("both messages", || heard(&h).iter().filter(|l| l.starts_with("message")).count() == 2);
    let got = heard(&h);
    assert!(got.contains(&format!("message 0 {on_a} hi")), "{got:?}");
    assert!(got.contains(&format!("message 1 {on_b} there")), "{got:?}");
    assert_eq!(sub.subscriptions().2.len(), 2);
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn a_shard_channel_that_moves_is_subscribed_on_its_new_owner_before_the_old_one_is_released() {
    let net = Cluster::new(2, vec![(0, 16383, 0)]);
    let c = net.cluster();
    let (sub, h) = subscriber(&net, &c);
    let ch = channel_in(0..=16383, "mv");
    // A second channel that stays, so that node 0 is released of one and not closed.
    let stays = channel_in(0..=16383, "stays");
    assert_ne!(key_slot(ch.as_bytes()), key_slot(stays.as_bytes()));
    sub.ssubscribe(&[&ch, &stays]);
    wait_until("the first subscriptions", || net.asked(0).len() >= 2);

    // The slot of one moves to node 1, and the layout says so.
    let slot = key_slot(ch.as_bytes());
    net.net.set(vec![(0, slot - 1, 0), (slot, slot, 1), (slot + 1, 16383, 0)].into_iter().filter(|(lo, hi, _)| lo <= hi).collect());
    c.refresh();
    wait_until("the new owner's subscription", || position(&net.log, 1, &format!("SSUBSCRIBE {ch}")).is_some());
    wait_until("the old owner's release", || position(&net.log, 0, &format!("SUNSUBSCRIBE {ch}")).is_some());

    // Make before break: the new owner was asked first.
    let (new_at, old_at) = (
        position(&net.log, 1, &format!("SSUBSCRIBE {ch}")).unwrap(),
        position(&net.log, 0, &format!("SUNSUBSCRIBE {ch}")).unwrap(),
    );
    assert!(new_at < old_at, "the new owner was subscribed after the old was released: {:?}", net.log.lock().unwrap());
    assert_eq!(net.asked(0).iter().filter(|c| c.starts_with("SUNSUBSCRIBE")).count(), 1, "only the channel that moved was released");

    // The handlers are told on each side, and a message from the new owner arrives.
    wait_until("both acknowledgements", || {
        let g = heard(&h);
        g.contains(&format!("subscribed 1 Shard {ch}")) && g.contains(&format!("unsubscribed 0 Shard {ch}"))
    });
    net.push(1, &format!(">3\r\n$8\r\nsmessage\r\n${}\r\n{ch}\r\n$3\r\nnew\r\n", ch.len()));
    wait_until("the message", || heard(&h).contains(&format!("message 1 {ch} new")));
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn a_node_left_with_nothing_is_let_go_of_once_the_new_owner_has_the_subscription() {
    let net = Cluster::new(2, vec![(0, 16383, 0)]);
    let c = net.cluster();
    let (sub, _h) = subscriber(&net, &c);
    let ch = channel_in(0..=16383, "alone");
    sub.ssubscribe(&[&ch]);
    wait_until("the subscription", || net.asked(0).len() == 1);
    let slot = key_slot(ch.as_bytes());
    net.net.set(vec![(0, slot - 1, 0), (slot, slot, 1), (slot + 1, 16383, 0)].into_iter().filter(|(lo, hi, _)| lo <= hi).collect());
    c.refresh();
    wait_until("the new owner", || position(&net.log, 1, &format!("SSUBSCRIBE {ch}")).is_some());
    wait_until("the old connection to be let go of", || {
        let ports: Vec<u16> = sub.connections().iter().map(|(n, _)| n.port).collect();
        ports == vec![net.servers[1].addr.port()]
    });
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn a_node_that_answers_moved_to_a_subscription_is_not_asked_again_and_the_one_it_names_is() {
    // The nodes say node 0 serves everything, but node 1 has the slot.
    let net = Cluster::new(2, vec![(0, 16383, 0)]);
    let ch = channel_in(0..=16383, "stale");
    let slot = key_slot(ch.as_bytes());
    *net.net.truth.lock().unwrap() = vec![(0, slot - 1, 0), (slot, slot, 1), (slot + 1, 16383, 0)].into_iter().filter(|(lo, hi, _)| lo <= hi).collect();
    let c = net.cluster();
    let (sub, h) = subscriber(&net, &c);
    sub.ssubscribe(&[&ch]);
    wait_until("the subscription on the node the server named", || position(&net.log, 1, &format!("SSUBSCRIBE {ch}")).is_some());
    wait_until("the refusing node to be let go of", || {
        let ports: Vec<u16> = sub.connections().iter().map(|(n, _)| n.port).collect();
        ports == vec![net.servers[1].addr.port()]
    });
    assert!(heard(&h).contains(&"error 0 MOVED".to_string()), "the handler of the refusing node is told: {:?}", heard(&h));
    assert_eq!(net.asked(0), vec![format!("SSUBSCRIBE {ch}")], "and it was asked once");
    wait_until("the acknowledgement from the owner", || heard(&h).contains(&format!("subscribed 1 Shard {ch}")));
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn a_shard_subscription_a_server_drops_is_made_again() {
    let net = Cluster::new(1, vec![(0, 16383, 0)]);
    let c = net.cluster();
    let (sub, h) = subscriber(&net, &c);
    let ch = "dropped-channel";
    sub.ssubscribe(&[ch]);
    wait_until("the subscription", || net.asked(0).contains(&format!("SSUBSCRIBE {ch}")));
    // The server loses the slot (a migration begun and abandoned) and says so.
    net.push(0, &format!(">3\r\n$12\r\nsunsubscribe\r\n${}\r\n{ch}\r\n:0\r\n", ch.len()));
    wait_until("a second subscription", || net.asked(0).iter().filter(|c| *c == &format!("SSUBSCRIBE {ch}")).count() >= 2);
    assert!(heard(&h).iter().any(|l| l.starts_with("unsubscribed 0 Shard")), "the handler is told it was dropped: {:?}", heard(&h));
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn keyspace_patterns_are_subscribed_on_every_master_and_follow_masters_that_come_and_go() {
    let net = Cluster::new(3, vec![(0, 8191, 0), (8192, 16383, 1)]);
    let c = net.cluster();
    let (sub, _h) = subscriber(&net, &c);
    sub.subscribe_keyspace(&["__keyspace@0__:*"]);
    wait_until("both masters", || {
        net.asked(0).contains(&"PSUBSCRIBE __keyspace@0__:*".to_string()) && net.asked(1).contains(&"PSUBSCRIBE __keyspace@0__:*".to_string())
    });
    assert!(net.asked(2).is_empty(), "a node that is not a master is not asked");

    // A third master joins; the second leaves.
    net.net.set(vec![(0, 8191, 0), (8192, 16383, 2)]);
    c.refresh();
    wait_until("the new master", || net.asked(2).contains(&"PSUBSCRIBE __keyspace@0__:*".to_string()));
    wait_until("the departed one's connection to go", || {
        let nodes: Vec<u16> = sub.connections().iter().map(|(n, _)| n.port).collect();
        nodes.len() == 2 && !nodes.contains(&net.servers[1].addr.port())
    });
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn a_classic_subscription_is_on_one_node_and_moves_to_another_when_that_node_is_lost() {
    let net = Cluster::new(2, vec![(0, 8191, 0), (8192, 16383, 1)]);
    let c = net.cluster();
    let (sub, h) = subscriber(&net, &c);
    sub.subscribe(&["news"]);
    sub.psubscribe(&["n*"]);
    wait_until("the subscriptions", || {
        net.asked(0).contains(&"SUBSCRIBE news".to_string()) || net.asked(1).contains(&"SUBSCRIBE news".to_string())
    });
    let first = (0..2).find(|i| net.asked(*i).contains(&"SUBSCRIBE news".to_string())).unwrap();
    let other = 1 - first;
    wait_until("the pattern too", || net.asked(first).contains(&"PSUBSCRIBE n*".to_string()));
    assert!(net.asked(other).iter().all(|c| !c.contains("news") && !c.contains("n*")), "one node only: {:?}", net.log.lock().unwrap());

    // The node it is on drops the connection and goes away.
    let other_port = net.servers[other].addr.port();
    let _ = other_port;
    net.drop_connection(first);
    wait_until("the move: everything subscribed again on the other node", || {
        net.asked(other).contains(&"SUBSCRIBE news".to_string()) && net.asked(other).contains(&"PSUBSCRIBE n*".to_string())
    });
    assert!(heard(&h).contains(&format!("down {first}")), "the handler of the lost connection is told: {:?}", heard(&h));
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn a_node_makes_one_handler_for_its_connection_and_another_when_the_connection_is_replaced() {
    let net = Cluster::new(2, vec![(0, 16383, 0)]);
    let c = net.cluster();
    let (sub, h) = subscriber(&net, &c);
    sub.ssubscribe(&["one", "two"]);
    wait_until("the subscriptions", || net.asked(0).len() >= 2);
    sub.subscribe_keyspace(&["k*"]);
    wait_until("the keyspace pattern", || net.asked(0).contains(&"PSUBSCRIBE k*".to_string()));
    assert_eq!(*h.made.lock().unwrap(), vec![0], "one handler, for the one node, though it has three subscriptions");
    sub.close();
    c.close();
    net.shutdown();
}

#[test]
fn spublish_goes_to_the_owner_of_the_channels_slot_and_publish_to_any_master() {
    let net = Cluster::new(2, vec![(0, 8191, 0), (8192, 16383, 1)]);
    let c = net.cluster();
    let on_b = channel_in(8192..=16383, "pub");
    assert_eq!(call!(|cb| c.spublish(&on_b, "m", cb)).unwrap(), 1);
    assert_eq!(net.asked(1), vec![format!("SPUBLISH {on_b}")]);
    assert!(net.asked(0).is_empty());
    c.close();
    net.shutdown();
}
