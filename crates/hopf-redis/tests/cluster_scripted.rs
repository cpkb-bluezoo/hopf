// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The cluster client against scripted nodes on loopback: what a real cluster
//! cannot be made to do on cue.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use hopf_core::Bytes;
use hopf_redis::{
    key_slot, ArgSource, ClusterConfig, Command, Deadline, NodeAddr, Push, RedisCluster, RedisError, SourceCtl, SourceRead,
    StreamArg,
};

use common::scripted_server::*;
use common::*;

/// `CLUSTER SLOTS` for one master serving every slot.
fn slots_of(addr: SocketAddr, id: &str) -> String {
    format!(
        "*1\r\n*3\r\n:0\r\n:16383\r\n*3\r\n${}\r\n{}\r\n:{}\r\n${}\r\n{}\r\n",
        addr.ip().to_string().len(),
        addr.ip(),
        addr.port(),
        id.len(),
        id
    )
}

fn b(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

/// A node that answers `HELLO`, refuses `CLUSTER SHARDS` as an old server
/// would, and leaves the rest to `rest`.
fn node(rest: impl Fn(&mut Session, &[Vec<u8>]) + Send + Sync + 'static) -> Server {
    serve(move |s, w| match name_of(w).as_str() {
        "HELLO" => s.reply(HELLO_OK),
        "CLUSTER" if arg(w, 1).eq_ignore_ascii_case("SHARDS") => s.reply("-ERR unknown subcommand 'SHARDS'\r\n"),
        _ => rest(s, w),
    })
}

#[test]
fn a_command_pipelined_behind_the_layout_survives_the_node_being_retired() {
    // `b` is the cluster's master from the second layout on.
    let new_master = node(|s, w| match name_of(w).as_str() {
        "GET" => s.reply("$3\r\nnew\r\n"),
        other => panic!("unexpected {other}"),
    });
    let new_addr = new_master.addr;

    // The old master answers the first layout at once, and sits on the second
    // until a command has been sent behind it, then answers both together: the
    // layout that retires it, and the reply of the command it was still owed.
    let layouts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&layouts);
    let old_addr: Arc<std::sync::OnceLock<SocketAddr>> = Arc::default();
    let own = Arc::clone(&old_addr);
    let old_master = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                s.reply(slots_of(*own.get().unwrap(), "old"));
            } else {
                s.held.push(w.to_vec());
            }
        }
        "GET" => {
            assert_eq!(s.held.len(), 1, "the layout request should be waiting");
            s.reply(slots_of(new_addr, "new"));
            s.reply("$3\r\nold\r\n");
        }
        other => panic!("unexpected {other}"),
    });
    old_addr.set(old_master.addr).unwrap();

    let rt = runtime();
    let config = ClusterConfig::new([("127.0.0.1".to_string(), old_master.addr.port())]).min_refresh_interval(Duration::from_millis(5));
    let c = RedisCluster::connect(rt.pick_worker(), config);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !c.is_ready() {
        assert!(std::time::Instant::now() < deadline, "no layout");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(c.masters(), vec![("127.0.0.1".to_string(), old_master.addr.port())]);

    // Ask for the layout again; wait until the old master holds the request.
    c.refresh();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while layouts.load(Ordering::SeqCst) < 2 {
        assert!(std::time::Instant::now() < deadline, "the layout was not requested");
        std::thread::sleep(Duration::from_millis(5));
    }
    // Still routed to the old master, behind the layout request.
    let got = call!(|cb| c.get("k", cb));
    assert_eq!(got.unwrap(), Some(b("old")), "the command was owed a reply by the node being retired");

    // The layout moved on, and the next command goes to the new master.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while c.masters() != vec![("127.0.0.1".to_string(), new_addr.port())] {
        assert!(std::time::Instant::now() < deadline, "the new layout was not taken");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(call!(|cb| c.get("k", cb)).unwrap(), Some(b("new")));
    c.close();
    rt.shutdown();
    old_master.rt.shutdown();
    new_master.rt.shutdown();
}

// ---- WAIT is bound to the connection of the write ----

type Log = Arc<Mutex<Vec<(usize, String)>>>;

/// `CLUSTER SLOTS` for two masters, `first` serving 0-8191 and `second` the rest.
fn slots_split(first: SocketAddr, second: SocketAddr) -> String {
    let range = |lo: u16, hi: u16, a: SocketAddr, id: &str| {
        format!(
            "*3\r\n:{lo}\r\n:{hi}\r\n*3\r\n${}\r\n{}\r\n:{}\r\n${}\r\n{id}\r\n",
            a.ip().to_string().len(),
            a.ip(),
            a.port(),
            id.len()
        )
    };
    format!("*2\r\n{}{}", range(0, 8191, first, "first"), range(8192, 16383, second, "second"))
}

fn key_with_slot(range: std::ops::RangeInclusive<u16>) -> String {
    (0..).map(|n| format!("k{n}")).find(|k| range.contains(&key_slot(k.as_bytes()))).unwrap()
}

fn one_node_cluster(server: &Server, tweak: impl FnOnce(ClusterConfig) -> ClusterConfig) -> (hopf_core::Runtime, RedisCluster) {
    let rt = runtime();
    let config = tweak(ClusterConfig::new([("127.0.0.1".to_string(), server.addr.port())]));
    let c = RedisCluster::connect(rt.pick_worker(), config);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !c.is_ready() {
        assert!(Instant::now() < deadline, "no layout");
        std::thread::sleep(Duration::from_millis(5));
    }
    (rt, c)
}

fn count(log: &Log, name: &str) -> usize {
    log.lock().unwrap().iter().filter(|(_, n)| n == name).count()
}

#[test]
fn a_wait_goes_on_the_connection_of_the_write_right_behind_it() {
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    // The write is held until the WAIT arrives, so it is certainly still in
    // flight when the WAIT is asked for; both are then answered together.
    let server = node(move |s, w| {
        let name = name_of(w);
        seen.lock().unwrap().push((s.conn, name.clone()));
        match name.as_str() {
            "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
            "SET" => s.held.push(w.to_vec()),
            "WAIT" => {
                assert_eq!(s.held.len(), 1, "the write is still unanswered");
                assert_eq!(arg(w, 1), "1");
                assert_eq!(arg(w, 2), "100");
                s.reply("+OK\r\n");
                s.reply(":1\r\n");
            }
            other => panic!("unexpected {other}"),
        }
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c);

    let (tx, rx) = std::sync::mpsc::channel();
    c.set("{user}k", "v", move |r| tx.send(r).unwrap());
    let replicas = call!(|cb| c.wait_replicas("{user}", 1, 100, cb)).unwrap();
    assert_eq!(replicas, 1);
    rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();

    let commands: Vec<(usize, String)> = log.lock().unwrap().iter().filter(|(_, n)| n == "SET" || n == "WAIT").cloned().collect();
    assert_eq!(commands.len(), 2, "{commands:?}");
    assert_eq!(commands[0].1, "SET");
    assert_eq!(commands[1].1, "WAIT");
    assert_eq!(commands[0].0, commands[1].0, "the same connection");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_wait_follows_its_write_when_the_write_is_redirected() {
    let slot = key_slot(b"{moved}k");
    // The node the slot moved to: it takes the write and the WAIT.
    let new_log: Log = Arc::default();
    let seen = Arc::clone(&new_log);
    let new_master = node(move |s, w| {
        seen.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "SET" => s.reply("+OK\r\n"),
            "WAIT" => s.reply(":2\r\n"),
            other => panic!("unexpected {other}"),
        }
    });
    let new_addr = new_master.addr;

    // The old one holds the write, then answers MOVED, and then, since the
    // WAIT is behind it on the connection, answers that too (0: nothing was
    // written here).
    let old_log: Log = Arc::default();
    let seen = Arc::clone(&old_log);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let old_master = node(move |s, w| {
        seen.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "old")),
            "SET" => s.held.push(w.to_vec()),
            "WAIT" => {
                s.reply(format!("-MOVED {slot} {new_addr}\r\n"));
                s.reply(":0\r\n");
            }
            other => panic!("unexpected {other}"),
        }
    });
    own.set(old_master.addr).unwrap();
    let (rt, c) = one_node_cluster(&old_master, |c| c);

    let (tx, rx) = std::sync::mpsc::channel();
    c.set("{moved}k", "v", move |r| tx.send(r).unwrap());
    let replicas = call!(|cb| c.wait_replicas("{moved}", 1, 100, cb)).unwrap();
    assert_eq!(replicas, 2, "the answer is the new node's, not the old node's 0");
    rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();

    let commands: Vec<(usize, String)> = new_log.lock().unwrap().iter().filter(|(_, n)| n != "CLUSTER").cloned().collect();
    assert_eq!(commands.len(), 2, "{commands:?}");
    assert_eq!((commands[0].1.as_str(), commands[1].1.as_str()), ("SET", "WAIT"));
    assert_eq!(commands[0].0, commands[1].0, "behind the write on its new connection");
    assert_eq!(count(&old_log, "WAIT"), 1, "the old node was asked once and its answer thrown away");
    c.close();
    rt.shutdown();
    old_master.rt.shutdown();
    new_master.rt.shutdown();
}

#[test]
fn a_wait_whose_connection_is_lost_fails_and_is_not_sent_again() {
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| {
        seen.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
            "SET" => s.held.push(w.to_vec()),
            // The primary dies between the write and the reply.
            "WAIT" => s.close(),
            other => panic!("unexpected {other}"),
        }
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c);

    let (tx, rx) = std::sync::mpsc::channel();
    c.set("{lost}k", "v", move |r| tx.send(r).unwrap());
    let err = call!(|cb| c.wait_replicas("{lost}", 1, 100, cb)).unwrap_err();
    assert!(matches!(err, RedisError::ConnectionLost(_)), "{err:?}");
    let err = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap_err();
    assert!(matches!(err, RedisError::ConnectionLost(_)), "{err:?}");
    // Nothing sends it again, here or anywhere.
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(count(&log, "WAIT"), 1);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn waits_for_different_slots_each_reach_their_own_master() {
    let low_log: Log = Arc::default();
    let high_log: Log = Arc::default();
    let (l, h) = (Arc::clone(&low_log), Arc::clone(&high_log));
    let low_addr: Arc<OnceLock<(SocketAddr, SocketAddr)>> = Arc::default();
    let (la, ha) = (Arc::clone(&low_addr), Arc::clone(&low_addr));
    let low = node(move |s, w| {
        l.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "CLUSTER" => {
                let (a, b) = *la.get().unwrap();
                s.reply(slots_split(a, b))
            }
            "WAIT" => s.reply(":1\r\n"),
            other => panic!("unexpected {other}"),
        }
    });
    let high = node(move |s, w| {
        h.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "CLUSTER" => {
                let (a, b) = *ha.get().unwrap();
                s.reply(slots_split(a, b))
            }
            "WAIT" => s.reply(":2\r\n"),
            other => panic!("unexpected {other}"),
        }
    });
    low_addr.set((low.addr, high.addr)).unwrap();
    let (rt, c) = one_node_cluster(&low, |c| c);
    let (k_low, k_high) = (key_with_slot(0..=8191), key_with_slot(8192..=16383));
    assert_eq!(call!(|cb| c.wait_replicas(&k_low, 1, 100, cb)).unwrap(), 1);
    assert_eq!(call!(|cb| c.wait_replicas(&k_high, 1, 100, cb)).unwrap(), 2);
    assert_eq!(count(&low_log, "WAIT"), 1);
    assert_eq!(count(&high_log, "WAIT"), 1);
    c.close();
    rt.shutdown();
    low.rt.shutdown();
    high.rt.shutdown();
}

#[test]
fn the_client_waits_the_server_timeout_on_top_of_its_own() {
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
        // The server never answers.
        "WAIT" => {}
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c.node_config(|n| n.command_timeout(Some(Duration::from_millis(100)))));
    let started = Instant::now();
    let err = call!(|cb| c.wait_replicas("k", 1, 300, cb)).unwrap_err();
    let took = started.elapsed();
    assert!(matches!(err, RedisError::Timeout), "{err:?}");
    assert!(took >= Duration::from_millis(380), "the 100 ms command timeout and the 300 ms the server holds it: {took:?}");
    assert!(took < Duration::from_secs(2), "{took:?}");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_keyless_wait_is_refused_and_one_routed_by_a_key_is_bound_like_wait_replicas() {
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| {
        seen.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
            "WAIT" => s.reply(":1\r\n"),
            "PING" => s.reply("+PONG\r\n"),
            other => panic!("unexpected {other}"),
        }
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c);

    // Any master would give it a count that means nothing.
    let err = call!(|cb| c.command(&[b"WAIT", b"1", b"10"], cb)).unwrap_err();
    assert!(matches!(err, RedisError::Unexpected(_)), "{err:?}");
    let err = call!(|cb| c.send(&Command::new("WAITAOF").arg("0").arg("1").arg("10"), cb)).unwrap_err();
    assert!(matches!(err, RedisError::Unexpected(_)), "{err:?}");
    assert_eq!(count(&log, "WAIT") + count(&log, "WAITAOF"), 0, "nothing was sent");

    let reply = call!(|cb| c.command_for_key("k", &Command::new("WAIT").arg("1").arg("10"), cb)).unwrap();
    assert_eq!(reply, hopf_redis::Value::Int(1));
    assert_eq!(count(&log, "WAIT"), 1);

    // An ordinary keyless command is routed by the key it is given.
    let reply = call!(|cb| c.command_for_key("k", &Command::new("PING"), cb)).unwrap();
    assert_eq!(reply, hopf_redis::Value::Simple("PONG".into()));
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn clusterdown_is_handed_to_the_wait_and_not_retried() {
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| {
        seen.lock().unwrap().push((s.conn, name_of(w)));
        match name_of(w).as_str() {
            "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
            "WAIT" => s.reply("-CLUSTERDOWN The cluster is down\r\n"),
            other => panic!("unexpected {other}"),
        }
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c);
    let err = call!(|cb| c.wait_replicas("k", 1, 100, cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("CLUSTERDOWN"), "{err:?}");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(count(&log, "WAIT"), 1);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

// ---- a slot nobody serves for a moment ----

/// `CLUSTER SLOTS` for one master serving only 0-8191, as a cluster does while
/// a failover is under way.
fn lower_half_of(addr: SocketAddr, id: &str) -> String {
    format!(
        "*1\r\n*3\r\n:0\r\n:8191\r\n*3\r\n${}\r\n{}\r\n:{}\r\n${}\r\n{}\r\n",
        addr.ip().to_string().len(),
        addr.ip(),
        addr.port(),
        id.len(),
        id
    )
}

#[test]
fn a_command_whose_slot_is_unserved_in_one_layout_waits_for_the_next() {
    let layouts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&layouts);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => {
            let me = *addr.get().unwrap();
            // The first layout is taken mid-failover: half the slots have no
            // master. The second has them again.
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                s.reply(lower_half_of(me, "only"))
            } else {
                s.reply(slots_of(me, "only"))
            }
        }
        "GET" => s.reply("$1\r\nv\r\n"),
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let rt = runtime();
    let config = ClusterConfig::new([("127.0.0.1".to_string(), server.addr.port())]).min_refresh_interval(Duration::from_millis(50));
    let c = RedisCluster::connect(rt.pick_worker(), config);
    // Asked before any layout is known, for a slot the first layout leaves out.
    let key = key_with_slot(8192..=16383);
    let got = call!(|cb| c.get(&key, cb));
    assert_eq!(got.unwrap(), Some(b("v")), "the layout that followed serves it");
    assert!(layouts.load(Ordering::SeqCst) >= 2);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_slot_that_stays_unserved_fails_with_clusterdown_after_the_retries_are_spent() {
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(lower_half_of(*addr.get().unwrap(), "only")),
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let rt = runtime();
    let config = ClusterConfig::new([("127.0.0.1".to_string(), server.addr.port())])
        .min_refresh_interval(Duration::from_millis(20))
        .max_redirects(3);
    let c = RedisCluster::connect(rt.pick_worker(), config);
    let key = key_with_slot(8192..=16383);
    let started = Instant::now();
    let err = call!(|cb| c.get(&key, cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("CLUSTERDOWN"), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn clusterdown_and_tryagain_are_retried_for_an_ordinary_command_since_nothing_ran() {
    let answers = Arc::new(AtomicUsize::new(0));
    let n = Arc::clone(&answers);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
        // A failover in progress: the node has no owner for the slot for a
        // moment, then asks to be tried again, then answers.
        "GET" => match n.fetch_add(1, Ordering::SeqCst) {
            0 => s.reply("-CLUSTERDOWN The cluster is down\r\n"),
            1 => s.reply("-TRYAGAIN Multiple keys request during rehashing of slot\r\n"),
            _ => s.reply("$1\r\nv\r\n"),
        },
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c.min_refresh_interval(Duration::from_millis(20)));
    assert_eq!(call!(|cb| c.get("k", cb)).unwrap(), Some(b("v")));
    assert_eq!(answers.load(Ordering::SeqCst), 3);
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn clusterdown_that_does_not_go_away_reaches_the_caller_once_the_retries_are_spent() {
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let gets = Arc::new(AtomicUsize::new(0));
    let g = Arc::clone(&gets);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
        "GET" => {
            g.fetch_add(1, Ordering::SeqCst);
            s.reply("-CLUSTERDOWN The cluster is down\r\n")
        }
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c.min_refresh_interval(Duration::from_millis(20)).max_redirects(3));
    let err = call!(|cb| c.get("k", cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("CLUSTERDOWN"), "{err:?}");
    assert_eq!(gets.load(Ordering::SeqCst), 4, "the first try and three retries");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

// ---- a node that stops answering ----

/// Two nodes. `a` is the cluster's master at first and then goes dark on its
/// first connection (no reply, no reset) and on every later one (not even the
/// handshake); `b` is the master from the second layout on, which is all `b`
/// ever shows. Returns the cluster once it has `a`'s layout.
fn dark_master_cluster(
    command_timeout: Duration,
    ping_interval: Duration,
) -> (hopf_core::Runtime, RedisCluster, Server, Server) {
    let b_addr: Arc<OnceLock<SocketAddr>> = Arc::default();
    let own_b = Arc::clone(&b_addr);
    let b = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*own_b.get().unwrap(), "b")),
        "GET" => s.reply("$1\r\nB\r\n"),
        other => panic!("unexpected {other}"),
    });
    b_addr.set(b.addr).unwrap();

    let a_addr: Arc<OnceLock<SocketAddr>> = Arc::default();
    let own_a = Arc::clone(&a_addr);
    let a = serve(move |s, w| {
        if s.conn != 0 {
            return; // black-holed from the second connection on
        }
        match name_of(w).as_str() {
            "HELLO" => s.reply(HELLO_OK),
            "CLUSTER" if arg(w, 1).eq_ignore_ascii_case("SHARDS") => s.reply("-ERR unknown subcommand 'SHARDS'\r\n"),
            "CLUSTER" => s.reply(slots_of(*own_a.get().unwrap(), "a")),
            _ => {} // a GET is swallowed
        }
    });
    a_addr.set(a.addr).unwrap();

    let rt = runtime();
    let config = ClusterConfig::new([("127.0.0.1".to_string(), a.addr.port()), ("127.0.0.1".to_string(), b.addr.port())])
        .min_refresh_interval(Duration::from_millis(5))
        .node_config(move |c| c.command_timeout(Some(command_timeout)).ping_interval(Some(ping_interval)));
    let c = RedisCluster::connect(rt.pick_worker(), config);
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.masters() != vec![("127.0.0.1".to_string(), a.addr.port())] {
        assert!(Instant::now() < deadline, "no layout from a");
        std::thread::sleep(Duration::from_millis(5));
    }
    (rt, c, a, b)
}

fn wait_for_master(c: &RedisCluster, b: &Server) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.masters() != vec![("127.0.0.1".to_string(), b.addr.port())] {
        assert!(Instant::now() < deadline, "the cluster never moved to the other node: {:?}", c.masters());
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_black_holed_master_is_dropped_its_commands_fail_and_the_layout_is_fetched_again() {
    let (rt, c, a, node_b) = dark_master_cluster(Duration::from_secs(30), Duration::from_millis(150));
    let refreshes = c.refresh_count();
    let started = Instant::now();
    let err = call!(|cb| c.get("k", cb)).unwrap_err();
    assert!(matches!(err, RedisError::ConnectionLost(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    wait_for_master(&c, &node_b);
    assert!(c.refresh_count() > refreshes, "the layout was fetched again");
    assert_eq!(call!(|cb| c.get("k", cb)).unwrap(), Some(b("B")), "new commands go to the new master");
    c.close();
    rt.shutdown();
    a.rt.shutdown();
    node_b.rt.shutdown();
}

#[test]
fn the_layout_is_fetched_again_even_when_every_command_had_already_timed_out() {
    // The command gives up at 100 ms, long before the connection is judged dead
    // at 400 ms; at that point nothing is waiting to hear that it was lost.
    let (rt, c, a, node_b) = dark_master_cluster(Duration::from_millis(100), Duration::from_millis(400));
    let err = call!(|cb| c.get("k", cb)).unwrap_err();
    assert_eq!(err, RedisError::Timeout);
    wait_for_master(&c, &node_b);
    assert_eq!(call!(|cb| c.get("k", cb)).unwrap(), Some(b("B")));
    c.close();
    rt.shutdown();
    a.rt.shutdown();
    node_b.rt.shutdown();
}

#[test]
fn a_command_that_merely_times_out_does_not_ask_for_a_new_layout() {
    // A slow node is not a moved one: with the health check off, a timeout alone
    // leaves the layout alone.
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
        "GET" => {} // never answered
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| {
        c.min_refresh_interval(Duration::from_millis(5))
            .node_config(|n| n.command_timeout(Some(Duration::from_millis(100))).ping_interval(None))
    });
    let before = c.refresh_count();
    for _ in 0..3 {
        assert_eq!(call!(|cb| c.get("k", cb)).unwrap_err(), RedisError::Timeout);
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(c.refresh_count(), before, "no refresh was asked for");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

#[test]
fn a_command_sent_through_the_cluster_can_have_a_deadline_of_its_own() {
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
        "GET" if arg(w, 1) == "never" => {}
        "GET" => s.reply_after(Duration::from_millis(400), "$4\r\nslow\r\n"),
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c.node_config(|n| n.command_timeout(Some(Duration::from_millis(150)))));
    let get = |key: &str| Command::new("GET").arg(key);

    // The node default gives up on the slow reply; a longer deadline of its own waits for it.
    assert_eq!(call!(|cb| c.send(&get("slow"), cb)).unwrap_err(), RedisError::Timeout);
    let slow = call!(|cb| c.send_with_deadline(&get("slow"), Deadline::After(Duration::from_secs(5)), cb));
    assert_eq!(slow.unwrap(), hopf_redis::Value::Bulk(b("slow")));
    assert_eq!(
        call!(|cb| c.send_with_deadline(&get("slow"), Deadline::Never, cb)).unwrap(),
        hopf_redis::Value::Bulk(b("slow"))
    );
    // And a shorter one fails sooner than the default.
    let started = Instant::now();
    let err = call!(|cb| c.send_with_deadline(&get("never"), Deadline::After(Duration::from_millis(40)), cb)).unwrap_err();
    assert_eq!(err, RedisError::Timeout);
    assert!(started.elapsed() < Duration::from_millis(130), "{:?}", started.elapsed());
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}

// ---- RESP3 pushes on node connections ----

/// `+OK`, then an `invalidate` push for `key`: what a node does on `CLIENT TRACKING on`.
fn tracked_reply(key: &str) -> String {
    format!("+OK\r\n>2\r\n$10\r\ninvalidate\r\n*1\r\n${}\r\n{key}\r\n", key.len())
}

/// Two masters, `a` serving 0-8191 and `b` the rest. A `CLIENT TRACKING` to
/// either is answered with `+OK` and an invalidation of the key `"<port>"`,
/// and a `GET` of `"moved"` to `a` is redirected to `b`.
fn two_masters() -> (hopf_core::Runtime, RedisCluster, Server, Server) {
    let pair: Arc<OnceLock<(SocketAddr, SocketAddr)>> = Arc::default();
    let script = |pair: Arc<OnceLock<(SocketAddr, SocketAddr)>>, me_is_a: bool| {
        move |s: &mut Session, w: &[Vec<u8>]| {
            let (a, b) = *pair.get().unwrap();
            let me = if me_is_a { a } else { b };
            match name_of(w).as_str() {
                "CLUSTER" => s.reply(slots_split(a, b)),
                "CLIENT" => s.reply(tracked_reply(&me.port().to_string())),
                "GET" if me_is_a && arg(w, 1) == "moved" => {
                    s.reply(format!("-MOVED {} {b}\r\n", key_slot(b"moved")));
                }
                "GET" => s.reply("$2\r\nok\r\n"),
                other => panic!("unexpected {other}"),
            }
        }
    };
    let a = node(script(Arc::clone(&pair), true));
    let b = node(script(Arc::clone(&pair), false));
    pair.set((a.addr, b.addr)).unwrap();
    let rt = runtime();
    let c = RedisCluster::connect(
        rt.pick_worker(),
        ClusterConfig::new([("127.0.0.1".to_string(), a.addr.port())]).min_refresh_interval(Duration::from_millis(5)),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !c.is_ready() {
        assert!(Instant::now() < deadline, "no layout");
        std::thread::sleep(Duration::from_millis(5));
    }
    (rt, c, a, b)
}

fn addr_of(server: &Server) -> NodeAddr {
    NodeAddr {
        host: "127.0.0.1".into(),
        port: server.addr.port(),
    }
}

fn tracking() -> Command {
    Command::new("CLIENT").arg("TRACKING").arg("on")
}

fn invalidated(push: &Push) -> String {
    match push.invalidation() {
        Some(hopf_redis::Invalidation::Keys(keys)) => String::from_utf8_lossy(&keys[0]).into_owned(),
        other => panic!("not a key invalidation: {other:?}"),
    }
}

#[test]
fn a_push_on_a_node_connection_reaches_the_handler_with_the_nodes_address() {
    let (rt, c, a, nb) = two_masters();
    let (tx, rx) = std::sync::mpsc::channel();
    c.set_push_handler(move |node, push| tx.send((node.clone(), push)).unwrap());

    // The connection to `a` was made before the handler was set.
    call!(|cb| c.send_to_node(&addr_of(&a), &tracking(), cb)).unwrap();
    let (from, push) = rx.recv_timeout(Duration::from_secs(5)).expect("a push from a");
    assert_eq!(from, addr_of(&a));
    assert_eq!(invalidated(&push), a.addr.port().to_string());

    // The connection to `b` is made now, after it.
    call!(|cb| c.send_to_node(&addr_of(&nb), &tracking(), cb)).unwrap();
    let (from, push) = rx.recv_timeout(Duration::from_secs(5)).expect("a push from b");
    assert_eq!(from, addr_of(&nb));
    assert_eq!(invalidated(&push), nb.addr.port().to_string());

    // Replies stay in step with their commands around the pushes.
    assert_eq!(call!(|cb| c.get("moved", cb)).unwrap(), Some(b("ok")));
    c.close();
    rt.shutdown();
    a.rt.shutdown();
    nb.rt.shutdown();
}

#[test]
fn pushes_still_arrive_from_a_node_first_reached_through_a_moved() {
    let (rt, c, a, nb) = two_masters();
    let (tx, rx) = std::sync::mpsc::channel();
    c.set_push_handler(move |node, push| tx.send((node.clone(), push)).unwrap());
    // `a` answers this with MOVED to `b`, which is where the connection to `b` comes from.
    assert_eq!(call!(|cb| c.get("moved", cb)).unwrap(), Some(b("ok")));
    call!(|cb| c.send_to_node(&addr_of(&nb), &tracking(), cb)).unwrap();
    let (from, _) = rx.recv_timeout(Duration::from_secs(5)).expect("a push");
    assert_eq!(from, addr_of(&nb));
    c.close();
    rt.shutdown();
    a.rt.shutdown();
    nb.rt.shutdown();
}

#[test]
fn pushes_are_dropped_without_a_handler_and_after_it_is_cleared() {
    let (rt, c, a, nb) = two_masters();
    // No handler: the push is dropped and the reply behind it is still the reply.
    call!(|cb| c.send_to_node(&addr_of(&a), &tracking(), cb)).unwrap();
    assert_eq!(call!(|cb| c.get("k", cb)).unwrap(), Some(b("ok")));

    let (tx, rx) = std::sync::mpsc::channel();
    c.set_push_handler(move |node, push| tx.send((node.clone(), push)).unwrap());
    call!(|cb| c.send_to_node(&addr_of(&a), &tracking(), cb)).unwrap();
    rx.recv_timeout(Duration::from_secs(5)).expect("delivered once a handler is set");

    c.clear_push_handler();
    call!(|cb| c.send_to_node(&addr_of(&a), &tracking(), cb)).unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "nothing after it is cleared");
    c.close();
    rt.shutdown();
    a.rt.shutdown();
    nb.rt.shutdown();
}

#[test]
fn a_node_that_replaces_another_in_a_new_layout_pushes_to_the_same_handler() {
    // `old` serves everything until it is asked for the layout a second time,
    // when it says `new` does; `old` is then let go of and `new` connected to.
    let new_addr: Arc<OnceLock<SocketAddr>> = Arc::default();
    let own_new = Arc::clone(&new_addr);
    let new = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*own_new.get().unwrap(), "new")),
        "CLIENT" => s.reply(tracked_reply("from-new")),
        other => panic!("unexpected {other}"),
    });
    new_addr.set(new.addr).unwrap();
    let layouts = Arc::new(AtomicUsize::new(0));
    let (seen, new_a) = (Arc::clone(&layouts), new.addr);
    let old_addr: Arc<OnceLock<SocketAddr>> = Arc::default();
    let own_old = Arc::clone(&old_addr);
    let old = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => {
            if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                s.reply(slots_of(*own_old.get().unwrap(), "old"));
            } else {
                s.reply(slots_of(new_a, "new"));
            }
        }
        other => panic!("unexpected {other}"),
    });
    old_addr.set(old.addr).unwrap();
    let (rt, c) = one_node_cluster(&old, |c| c.min_refresh_interval(Duration::from_millis(5)));
    let (tx, rx) = std::sync::mpsc::channel();
    c.set_push_handler(move |node, push| tx.send((node.clone(), push)).unwrap());

    c.refresh();
    let deadline = Instant::now() + Duration::from_secs(5);
    while c.masters() != vec![("127.0.0.1".to_string(), new.addr.port())] {
        assert!(Instant::now() < deadline, "the new layout was not taken");
        std::thread::sleep(Duration::from_millis(5));
    }
    call!(|cb| c.send_to_node(&addr_of(&new), &tracking(), cb)).unwrap();
    let (from, push) = rx.recv_timeout(Duration::from_secs(5)).expect("a push from the new node");
    assert_eq!(from, addr_of(&new));
    assert_eq!(invalidated(&push), "from-new");
    c.close();
    rt.shutdown();
    old.rt.shutdown();
    new.rt.shutdown();
}

#[test]
fn a_command_can_be_sent_to_a_given_master_or_to_every_one() {
    let (rt, c, a, nb) = two_masters();
    // Not a master in the layout: refused without being sent anywhere.
    let stranger = NodeAddr {
        host: "127.0.0.1".into(),
        port: 1,
    };
    let err = call!(|cb| c.send_to_node(&stranger, &tracking(), cb)).unwrap_err();
    assert!(matches!(err, RedisError::Unexpected(_)), "{err:?}");

    let (tx, rx) = std::sync::mpsc::channel();
    c.send_to_masters(&Command::new("GET").arg("k"), move |node, reply| tx.send((node, reply)).unwrap());
    let mut got: Vec<(NodeAddr, bool)> =
        (0..2).map(|_| rx.recv_timeout(Duration::from_secs(5)).expect("a reply per master")).map(|(n, r)| (n, r.is_ok())).collect();
    got.sort_by_key(|(n, _)| n.port);
    let mut want = vec![(addr_of(&a), true), (addr_of(&nb), true)];
    want.sort_by_key(|(n, _)| n.port);
    assert_eq!(got, want);
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "once each");
    c.close();
    rt.shutdown();
    a.rt.shutdown();
    nb.rt.shutdown();
}

// ---- streamed arguments ----

/// `left` bytes of `b`.
struct Fill {
    left: u64,
}

impl ArgSource for Fill {
    fn read(&mut self, out: &mut [u8], _ctl: &mut SourceCtl<'_>) -> SourceRead {
        let n = (self.left as usize).min(out.len());
        out[..n].fill(b'f');
        self.left -= n as u64;
        SourceRead::Data(n)
    }
}

#[test]
fn a_streamed_command_that_is_redirected_opens_a_fresh_source_and_a_one_shot_one_is_refused() {
    let len: u64 = 600_000;
    let seen: Log = Arc::default();
    let new_seen = Arc::clone(&seen);
    let new_master = node(move |s, w| match name_of(w).as_str() {
        "SET" => {
            new_seen.lock().unwrap().push((w[2].len(), "new".into()));
            s.reply("+OK\r\n");
        }
        other => panic!("unexpected {other}"),
    });
    let new_addr = new_master.addr;
    let slot = key_slot(b"k");
    let old_seen = Arc::clone(&seen);
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let old_master = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "old")),
        "SET" => {
            // The whole value arrived here; the slot has moved.
            old_seen.lock().unwrap().push((w[2].len(), "old".into()));
            s.reply(format!("-MOVED {slot} {new_addr}\r\n"));
        }
        other => panic!("unexpected {other}"),
    });
    own.set(old_master.addr).unwrap();
    let (rt, c) = one_node_cluster(&old_master, |c| c.min_refresh_interval(Duration::from_millis(5)));

    // Repeatable: the source is opened again for the node it moved to.
    let opens = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&opens);
    let arg = StreamArg::from_fn(len, move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Fill { left: len }))
    });
    let reply = call!(|cb| c.send(&Command::new("SET").arg("k").arg_stream(arg), cb));
    assert!(reply.is_ok(), "{reply:?}");
    assert_eq!(opens.load(Ordering::SeqCst), 2, "once for each node it was sent to");
    assert_eq!(*seen.lock().unwrap(), vec![(len as usize, "old".to_string()), (len as usize, "new".to_string())]);

    // One-shot: the redirection needs the value again, and it is gone.
    seen.lock().unwrap().clear();
    let once = StreamArg::once(len, Fill { left: len });
    let err = call!(|cb| c.send(&Command::new("SET").arg("k").arg_stream(once), cb)).unwrap_err();
    assert_eq!(err, RedisError::NotRepeatable);
    assert_eq!(seen.lock().unwrap().len(), 1, "it went to the old node and no further: {:?}", seen.lock().unwrap());
    c.close();
    rt.shutdown();
    old_master.rt.shutdown();
    new_master.rt.shutdown();
}

#[test]
fn a_streamed_argument_cannot_be_a_key_or_be_in_a_transaction() {
    let own: Arc<OnceLock<SocketAddr>> = Arc::default();
    let addr = Arc::clone(&own);
    let server = node(move |s, w| match name_of(w).as_str() {
        "CLUSTER" => s.reply(slots_of(*addr.get().unwrap(), "only")),
        other => panic!("unexpected {other}"),
    });
    own.set(server.addr).unwrap();
    let (rt, c) = one_node_cluster(&server, |c| c);
    let arg = || StreamArg::from_fn(4, || Ok(Box::new(Fill { left: 4 })));
    // The key is the first argument of SET, and it is streamed.
    let err = call!(|cb| c.send(&Command::new("SET").arg_stream(arg()).arg("v"), cb)).unwrap_err();
    assert!(matches!(err, RedisError::Unexpected(_)), "{err:?}");
    let err = call!(|cb| c.transaction(vec![Command::new("SET").arg("k").arg_stream(arg())], cb)).unwrap_err();
    assert!(matches!(err, RedisError::Unexpected(_)), "{err:?}");
    c.close();
    rt.shutdown();
    server.rt.shutdown();
}
