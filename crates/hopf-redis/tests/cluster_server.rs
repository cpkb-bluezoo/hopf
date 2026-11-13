// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The cluster client against a real Redis or Valkey cluster. Set
//! `HOPF_TEST_CLUSTER` to `host:port` of one node of a cluster of three
//! masters (slots split in the usual thirds, nodes announcing the addresses the
//! test reaches them on); a test whose cluster is not named is skipped.
//!
//! The tests that move slots about put them back when they finish. The one
//! that fails a master over to its replica runs only when
//! `HOPF_TEST_CLUSTER_FAILOVER` is also set, and needs a replica for every
//! master.
//!
//! ```text
//! podman run -d --name hopf-cluster -p 127.0.0.1:17000-17005:17000-17005 \
//!     -p 127.0.0.1:27000-27005:27000-27005 docker.io/library/redis:7 sleep infinity
//! # start six nodes on ports 17000-17005 with cluster-enabled yes and
//! # cluster-announce-ip 127.0.0.1, then redis-cli --cluster create ... --cluster-replicas 1
//! HOPF_TEST_CLUSTER=127.0.0.1:17000 cargo test -p hopf-redis --features integration --test cluster_server
//! ```

mod common;

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hopf_core::{Bytes, Runtime};
use hopf_redis::{ClusterConfig, Command, RedisClient, RedisCluster, RedisConfig, RedisError, Value};

use common::*;

/// Every test holds this shared while it runs; the one that fails a master over
/// holds it alone, because a manual failover pauses writes on the master and a
/// test running meanwhile would be measuring that instead of itself.
static CALM: std::sync::RwLock<()> = std::sync::RwLock::new(());

macro_rules! cluster_or_skip {
    () => {
        match parse_cluster_env("HOPF_TEST_CLUSTER") {
            Some(s) => (s, CALM.read().unwrap_or_else(|e| e.into_inner())),
            None => {
                eprintln!("skipped: no cluster named in the environment");
                return;
            }
        }
    };
    (alone) => {
        match parse_cluster_env("HOPF_TEST_CLUSTER") {
            Some(s) => (s, CALM.write().unwrap_or_else(|e| e.into_inner())),
            None => {
                eprintln!("skipped: no cluster named in the environment");
                return;
            }
        }
    };
}

fn parse_cluster_env(var: &str) -> Option<(String, u16)> {
    let v = std::env::var(var).ok()?;
    let (host, port) = v.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn b(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

/// Tests that move slots between nodes take turns.
fn exclusive() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn connect(rt: &Runtime, seed: &(String, u16)) -> RedisCluster {
    let c = RedisCluster::connect(rt.pick_worker(), ClusterConfig::new([(seed.0.clone(), seed.1)]));
    wait_until("the layout is known", || c.is_ready());
    c
}

fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("timed out waiting until {what}");
}

/// A key (with `label` in it) whose slot lies in `range`.
fn key_in(range: std::ops::RangeInclusive<u16>, label: &str) -> String {
    for n in 0.. {
        let k = format!("{}:{n}", unique(label));
        if range.contains(&hopf_redis::key_slot(k.as_bytes())) {
            return k;
        }
    }
    unreachable!()
}

/// A plain client on one node, for the administration the cluster client does
/// not do.
fn admin(rt: &Runtime, host: &str, port: u16) -> RedisClient {
    client(rt, host, port)
}

fn run(c: &RedisClient, words: &[&str]) -> Result<Value, RedisError> {
    let words: Vec<&[u8]> = words.iter().map(|w| w.as_bytes()).collect();
    call!(|cb| c.command(&words, cb))
}

fn node_id(c: &RedisClient) -> String {
    match run(c, &["CLUSTER", "MYID"]).unwrap() {
        Value::Bulk(id) => String::from_utf8(id.to_vec()).unwrap(),
        other => panic!("CLUSTER MYID answered {other:?}"),
    }
}

fn code(e: &RedisError) -> String {
    e.server_code().unwrap_or("").to_string()
}

#[test]
fn learns_the_layout_from_one_seed() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let masters = c.masters();
    assert_eq!(masters.len(), 3, "{masters:?}");
    assert!(c.owner_of(0).is_some());
    assert!(c.owner_of(16383).is_some());
    assert_ne!(c.owner_of(0), c.owner_of(16383));
    assert!(c.refresh_count() >= 1);
    rt.shutdown();
}

#[test]
fn routes_each_key_to_the_master_that_owns_it() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    // Enough keys to land on every master; each is written and read back
    // through the cluster client, so a wrong route would have shown as MOVED
    // retries (counted) or errors.
    let before = c.refresh_count();
    let keys: Vec<String> = (0..120).map(|n| format!("{}:{n}", unique("route"))).collect();
    for (n, k) in keys.iter().enumerate() {
        call!(|cb| c.set(k, format!("v{n}"), cb)).unwrap();
    }
    for (n, k) in keys.iter().enumerate() {
        assert_eq!(call!(|cb| c.get(k, cb)).unwrap(), Some(b(&format!("v{n}"))));
    }
    assert_eq!(c.refresh_count(), before, "a settled cluster needs no refresh");
    // The keys really are spread over the three masters.
    let owners: std::collections::HashSet<_> = keys.iter().map(|k| c.owner_of(c.slot_of(k)).unwrap()).collect();
    assert_eq!(owners.len(), 3);
    for k in &keys {
        call!(|cb| c.del(&[k], cb)).unwrap();
    }
    rt.shutdown();
}

#[test]
fn a_command_with_several_keys_works_when_they_share_a_hash_tag() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let tag = unique("tag");
    let (a, bk, ck) = (format!("{{{tag}}}a"), format!("{{{tag}}}b"), format!("{{{tag}}}c"));
    call!(|cb| c.mset(&[(&a, "1"), (&bk, "2"), (&ck, "3")], cb)).unwrap();
    let got = call!(|cb| c.mget(&[&a, &bk, &ck, &format!("{{{tag}}}missing")], cb)).unwrap();
    assert_eq!(got, vec![Some(b("1")), Some(b("2")), Some(b("3")), None]);
    assert_eq!(call!(|cb| c.del(&[&a, &bk, &ck], cb)).unwrap(), 3);
    rt.shutdown();
}

#[test]
fn keys_in_different_slots_fail_with_crossslot_and_never_touch_the_network() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k1 = key_in(0..=100, "cross1");
    let k2 = key_in(16000..=16383, "cross2");
    let err = call!(|cb| c.mget(&[&k1, &k2], cb)).unwrap_err();
    assert_eq!(code(&err), "CROSSSLOT", "{err:?}");
    let err = call!(|cb| c.transaction(
        vec![Command::new("SET").arg(&k1).arg("x"), Command::new("SET").arg(&k2).arg("y")],
        cb
    ))
    .unwrap_err();
    assert_eq!(code(&err), "CROSSSLOT", "{err:?}");
    // Neither reached a server, so neither wrote.
    assert_eq!(call!(|cb| c.get(&k1, cb)).unwrap(), None);
    assert_eq!(call!(|cb| c.get(&k2, cb)).unwrap(), None);
    rt.shutdown();
}

#[test]
fn a_script_runs_on_the_node_that_owns_its_keys() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let tag = unique("script");
    let (k1, k2) = (format!("{{{tag}}}1"), format!("{{{tag}}}2"));
    let script = "redis.call('SET', KEYS[1], ARGV[1]); redis.call('SET', KEYS[2], ARGV[2]); return redis.call('MGET', KEYS[1], KEYS[2])";
    let got = call!(|cb| c.eval(script, &[&k1, &k2], &["a", "b"], cb)).unwrap();
    assert_eq!(got, Value::Array(vec![Value::Bulk(b("a")), Value::Bulk(b("b"))]));
    // Keys in two slots: the script cannot be run at all.
    let (x, y) = (key_in(0..=100, "s1"), key_in(16000..=16383, "s2"));
    let err = call!(|cb| c.eval(script, &[&x, &y], &["a", "b"], cb)).unwrap_err();
    assert_eq!(code(&err), "CROSSSLOT", "{err:?}");
    call!(|cb| c.del(&[&k1, &k2], cb)).unwrap();
    rt.shutdown();
}

#[test]
fn a_transaction_runs_on_the_master_of_its_slot() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let tag = unique("tx");
    let (k1, k2) = (format!("{{{tag}}}1"), format!("{{{tag}}}2"));
    let out = call!(|cb| c.transaction(
        vec![
            Command::new("SET").arg(&k1).arg("one"),
            Command::new("INCR").arg(&k2),
            Command::new("GET").arg(&k1),
        ],
        cb
    ))
    .unwrap()
    .expect("EXEC was not aborted");
    assert_eq!(out, vec![Value::Simple("OK".into()), Value::Int(1), Value::Bulk(b("one"))]);
    call!(|cb| c.del(&[&k1, &k2], cb)).unwrap();
    rt.shutdown();
}

#[test]
fn a_keyless_command_goes_to_some_master() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    for _ in 0..6 {
        call!(|cb| c.ping(cb)).unwrap();
    }
    rt.shutdown();
}

#[test]
fn command_for_key_runs_a_keyless_command_where_the_key_lives() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(10923..=16383, "routed");
    let (host, port) = c.owner_of(c.slot_of(&k)).unwrap();
    // `CLUSTER MYID` has no key, so only the routing key says where it runs.
    let reply = call!(|cb| c.command_for_key(&k, &Command::new("CLUSTER").arg("MYID"), cb)).unwrap();
    let id = match reply {
        Value::Bulk(id) => String::from_utf8(id.to_vec()).unwrap(),
        other => panic!("{other:?}"),
    };
    let direct = admin(&rt, &host, port);
    assert_eq!(id, node_id(&direct));
    rt.shutdown();
}

/// Move `slot` (holding no keys) from the node `from` to the node `to`, the
/// way `redis-cli --cluster reshard` does: importing, migrating, then the
/// owner announced on both with an epoch bump.
fn move_empty_slot(from: &RedisClient, to: &RedisClient, slot: u16) {
    let (from_id, to_id) = (node_id(from), node_id(to));
    let s = slot.to_string();
    run(to, &["CLUSTER", "SETSLOT", &s, "IMPORTING", &from_id]).unwrap();
    run(from, &["CLUSTER", "SETSLOT", &s, "MIGRATING", &to_id]).unwrap();
    run(to, &["CLUSTER", "SETSLOT", &s, "NODE", &to_id]).unwrap();
    run(from, &["CLUSTER", "SETSLOT", &s, "NODE", &to_id]).unwrap();
}

#[test]
fn a_moved_reply_updates_the_layout_and_the_command_is_retried() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(0..=5460, "moved");
    let slot = c.slot_of(&k);
    let (a_host, a_port) = c.owner_of(slot).unwrap();
    let (b_host, b_port) = c.owner_of(10923).unwrap();
    assert_ne!((a_host.clone(), a_port), (b_host.clone(), b_port));
    let (a, bn) = (admin(&rt, &a_host, a_port), admin(&rt, &b_host, b_port));

    call!(|cb| c.set(&k, "before", cb)).unwrap();
    call!(|cb| c.del(&[&k], cb)).unwrap();
    let refreshes = c.refresh_count();

    move_empty_slot(&a, &bn, slot);
    // The client still believes `a` owns the slot: its first try meets MOVED,
    // and the command succeeds anyway.
    call!(|cb| c.set(&k, "after", cb)).unwrap();
    assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("after")));
    wait_until("the layout is fetched again", || c.refresh_count() > refreshes);
    wait_until("the client knows the new owner", || c.owner_of(slot) == Some((b_host.clone(), b_port)));

    // Put the slot back.
    call!(|cb| c.del(&[&k], cb)).unwrap();
    move_empty_slot(&bn, &a, slot);
    call!(|cb| c.set(&k, "home", cb)).unwrap();
    assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("home")));
    wait_until("the client knows the owner is back", || c.owner_of(slot) == Some((a_host.clone(), a_port)));
    call!(|cb| c.del(&[&k], cb)).unwrap();
    rt.shutdown();
}

#[test]
fn an_ask_reply_is_followed_for_that_command_only() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(0..=5460, "ask");
    let slot = c.slot_of(&k);
    let (a_host, a_port) = c.owner_of(slot).unwrap();
    let (b_host, b_port) = c.owner_of(10923).unwrap();
    let (a, bn) = (admin(&rt, &a_host, a_port), admin(&rt, &b_host, b_port));
    let (a_id, b_id) = (node_id(&a), node_id(&bn));
    let s = slot.to_string();

    // Half way through a migration: the slot is still `a`'s, and a key that is
    // not there is looked for on `b`.
    run(&bn, &["CLUSTER", "SETSLOT", &s, "IMPORTING", &a_id]).unwrap();
    run(&a, &["CLUSTER", "SETSLOT", &s, "MIGRATING", &b_id]).unwrap();
    let refreshes = c.refresh_count();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The key is on neither node. `a` answers ASK, and `b`, asked with
        // ASKING first, says it does not have it either.
        assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), None);
        // A write to a key `a` does not have is sent to `b`, where it lands.
        call!(|cb| c.set(&k, "asked", cb)).unwrap();
        assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("asked")));
        // ASK is not MOVED: the layout is not touched on its account.
        assert_eq!(c.owner_of(slot), Some((a_host.clone(), a_port)));
        assert_eq!(c.refresh_count(), refreshes);
    }));

    // Leave the cluster as it was, whatever happened. The key written to `b`
    // goes first, as a real migration would do.
    run(&bn, &["ASKING"]).ok();
    run(&bn, &["DEL", &k]).ok();
    run(&a, &["CLUSTER", "SETSLOT", &s, "STABLE"]).unwrap();
    run(&bn, &["CLUSTER", "SETSLOT", &s, "STABLE"]).unwrap();
    rt.shutdown();
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

#[test]
fn a_transaction_follows_an_ask_with_asking_in_the_same_batch() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(0..=5460, "askx");
    let slot = c.slot_of(&k);
    let (a_host, a_port) = c.owner_of(slot).unwrap();
    let (b_host, b_port) = c.owner_of(10923).unwrap();
    let (a, bn) = (admin(&rt, &a_host, a_port), admin(&rt, &b_host, b_port));
    let (a_id, b_id) = (node_id(&a), node_id(&bn));
    let s = slot.to_string();
    run(&bn, &["CLUSTER", "SETSLOT", &s, "IMPORTING", &a_id]).unwrap();
    run(&a, &["CLUSTER", "SETSLOT", &s, "MIGRATING", &b_id]).unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let out = call!(|cb| c.transaction(vec![Command::new("SET").arg(&k).arg("tx"), Command::new("GET").arg(&k)], cb))
            .unwrap()
            .expect("EXEC was not aborted");
        assert_eq!(out, vec![Value::Simple("OK".into()), Value::Bulk(b("tx"))]);
    }));

    run(&bn, &["ASKING"]).ok();
    run(&bn, &["DEL", &k]).ok();
    run(&a, &["CLUSTER", "SETSLOT", &s, "STABLE"]).unwrap();
    run(&bn, &["CLUSTER", "SETSLOT", &s, "STABLE"]).unwrap();
    rt.shutdown();
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

#[test]
fn the_layout_is_refreshed_at_most_once_in_the_minimum_interval() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let config = ClusterConfig::new([(seed.0.clone(), seed.1)]).min_refresh_interval(Duration::from_millis(400));
    let c = RedisCluster::connect(rt.pick_worker(), config);
    wait_until("the layout is known", || c.is_ready());
    let base = c.refresh_count();
    for _ in 0..50 {
        c.refresh();
    }
    std::thread::sleep(Duration::from_millis(150));
    let burst = c.refresh_count() - base;
    assert!(burst <= 1, "50 requests in a burst caused {burst} fetches");
    rt.shutdown();
}

#[test]
fn close_fails_what_is_asked_afterwards() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let c = connect(&rt, &seed);
    c.close();
    let err = call!(|cb| c.get("anything", cb)).unwrap_err();
    assert!(matches!(err, RedisError::Closed), "{err:?}");
    rt.shutdown();
}

#[test]
fn an_unreachable_seed_is_tried_after_a_dead_one() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    // Nothing listens on the first seed.
    let config = ClusterConfig::new([("127.0.0.1".to_string(), 1u16), (seed.0.clone(), seed.1)]);
    let c = RedisCluster::connect(rt.pick_worker(), config);
    wait_until("the layout is known", || c.is_ready());
    call!(|cb| c.ping(cb)).unwrap();
    rt.shutdown();
}

#[test]
fn a_node_config_is_applied_to_every_node_connection() {
    let (seed, _calm) = cluster_or_skip!();
    let rt = runtime();
    let config = ClusterConfig::new([(seed.0.clone(), seed.1)]).node_config(|c: RedisConfig| c.resp2_only());
    let c = RedisCluster::connect(rt.pick_worker(), config);
    wait_until("the layout is known", || c.is_ready());
    let k = unique("resp2");
    call!(|cb| c.set(&k, "v", cb)).unwrap();
    assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("v")));
    call!(|cb| c.del(&[&k], cb)).unwrap();
    rt.shutdown();
}

/// A cluster client whose connections are named, so a server's `CLIENT LIST`
/// says which connection is whose.
fn named(rt: &Runtime, seed: &(String, u16), name: &str) -> RedisCluster {
    let name = name.to_string();
    let config = ClusterConfig::new([(seed.0.clone(), seed.1)]).node_config(move |c: RedisConfig| c.client_name(name));
    let c = RedisCluster::connect(rt.pick_worker(), config);
    wait_until("the layout is known", || c.is_ready());
    c
}

/// What `CLIENT LIST` says of the connections named `name` on one node.
fn connections_named(node: &RedisClient, name: &str) -> Vec<String> {
    let listing = match run(node, &["CLIENT", "LIST"]).unwrap() {
        Value::Bulk(t) | Value::Verbatim { data: t, .. } => String::from_utf8(t.to_vec()).unwrap(),
        other => panic!("{other:?}"),
    };
    listing.lines().filter(|l| l.contains(&format!(" name={name} "))).map(str::to_string).collect()
}

#[test]
fn a_wait_runs_on_the_owner_of_the_slot_on_the_connection_that_wrote() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let name = unique("waiter").replace(':', "-");
    let c = named(&rt, &seed, &name);
    // One key for each master.
    let keys = [key_in(0..=5460, "w0"), key_in(5461..=10922, "w1"), key_in(10923..=16383, "w2")];
    for k in &keys {
        let owner = c.owner_of(c.slot_of(k)).unwrap();
        let before = c.refresh_count();
        call!(|cb| c.set(k, "v", cb)).unwrap();
        // Written and, at once, waited for: the replica of that master has it.
        let n = call!(|cb| c.wait_replicas(k, 1, 1000, cb)).unwrap();
        assert!(n >= 1, "{k} on {owner:?}: {n} replicas");
        assert_eq!(c.refresh_count(), before);
        // On the owner, the connection that wrote has the WAIT as its last
        // command. A master that does not own the slot has no connection that
        // ran one (it may have none yet at all).
        for (host, port) in c.masters() {
            let node = admin(&rt, &host, port);
            let ours = connections_named(&node, &name);
            assert!(ours.len() <= 1, "{host}:{port}: {ours:?}");
            let waited = ours.iter().any(|l| l.contains(" cmd=wait "));
            assert_eq!(waited, (host.clone(), port) == owner, "{host}:{port} vs owner {owner:?}: {ours:?}");
        }
        call!(|cb| c.del(&[k], cb)).unwrap();
        for _ in 0..3 {
            call!(|cb| c.ping(cb)).unwrap();
        }
    }
    rt.shutdown();
}

#[test]
fn a_wait_for_more_replicas_than_there_are_reports_how_many_there_were_after_its_timeout() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(0..=5460, "wmore");
    call!(|cb| c.set(&k, "v", cb)).unwrap();
    let started = Instant::now();
    // Each master has one replica; two is never reached.
    let n = call!(|cb| c.wait_replicas(&k, 2, 150, cb)).unwrap();
    let took = started.elapsed();
    assert_eq!(n, 1, "fewer than asked for is a count, not an error");
    assert!(took >= Duration::from_millis(140), "the server held it for its timeout: {took:?}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    call!(|cb| c.del(&[&k], cb)).unwrap();
    rt.shutdown();
}

#[test]
fn waitaof_reports_local_and_replica_acknowledgements() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(5461..=10922, "waof");
    call!(|cb| c.set(&k, "v", cb)).unwrap();
    // The servers here run without an append-only file, so nothing is ever
    // fsynced, and only the timeout ends the wait.
    let started = Instant::now();
    let (local, _replicas) = call!(|cb| c.wait_aof(&k, 0, 1, 150, cb)).unwrap();
    assert_eq!(local, 0);
    assert!(started.elapsed() >= Duration::from_millis(140));
    // Asking for the local file when there is none is the server's error.
    let err = call!(|cb| c.wait_aof(&k, 1, 0, 100, cb)).unwrap_err();
    assert!(matches!(err, RedisError::Server(_)), "{err:?}");
    call!(|cb| c.del(&[&k], cb)).unwrap();
    rt.shutdown();
}

#[test]
fn a_wait_for_a_write_that_was_redirected_is_answered_by_the_node_that_took_the_write() {
    let (seed, _calm) = cluster_or_skip!();
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(0..=5460, "wmoved");
    let slot = c.slot_of(&k);
    let (a_host, a_port) = c.owner_of(slot).unwrap();
    let (b_host, b_port) = c.owner_of(10923).unwrap();
    let (a, bn) = (admin(&rt, &a_host, a_port), admin(&rt, &b_host, b_port));
    move_empty_slot(&a, &bn, slot);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The map still says `a`: the write meets MOVED, and the WAIT goes
        // with it to `b`, where the write is.
        let (tx, rx) = std::sync::mpsc::channel();
        c.set(&k, "moved", move |r| tx.send(r).unwrap());
        let n = call!(|cb| c.wait_replicas(&k, 1, 1000, cb)).unwrap();
        assert!(n >= 1, "{n}");
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("moved")));
    }));

    let _ = call!(|cb| c.del(&[&k], cb));
    move_empty_slot(&bn, &a, slot);
    rt.shutdown();
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

/// Who `node` believes owns `slot`, from its own `CLUSTER SLOTS`.
fn owner_according_to(node: &RedisClient, slot: u16) -> Option<(String, u16)> {
    let Value::Array(ranges) = run(node, &["CLUSTER", "SLOTS"]).ok()? else {
        return None;
    };
    for r in ranges {
        let Value::Array(parts) = r else { continue };
        let (Some(Value::Int(lo)), Some(Value::Int(hi)), Some(Value::Array(master))) = (parts.first(), parts.get(1), parts.get(2)) else {
            continue;
        };
        if (*lo..=*hi).contains(&i64::from(slot)) {
            let host = match master.first() {
                Some(Value::Bulk(h)) => String::from_utf8(h.to_vec()).ok()?,
                _ => return None,
            };
            return match master.get(1) {
                Some(Value::Int(port)) => Some((host, *port as u16)),
                _ => None,
            };
        }
    }
    None
}

/// Whether `node`'s own `CLUSTER NODES` has `master` as a master and `replica`
/// as its replica.
fn roles_according_to(node: &RedisClient, master: &(String, u16), replica: &(String, u16)) -> bool {
    let Ok(Value::Bulk(text) | Value::Verbatim { data: text, .. }) = run(node, &["CLUSTER", "NODES"]) else {
        return false;
    };
    let text = String::from_utf8_lossy(&text).into_owned();
    let flags_of = |n: &(String, u16)| {
        let addr = format!("{}:{}@", n.0, n.1);
        text.lines().find(|l| l.split_whitespace().nth(1).is_some_and(|a| a.starts_with(&addr))).map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(2).copied().unwrap_or("").to_string(), f.get(7).copied().unwrap_or("").to_string())
        })
    };
    let m = flags_of(master);
    let r = flags_of(replica);
    m.is_some_and(|(flags, state)| flags.contains("master") && state == "connected")
        && r.is_some_and(|(flags, _)| flags.contains("slave") || flags.contains("replica"))
}

/// Wait until every node of the cluster says `owner` serves `slot` and that
/// `replica` is its replica: a change of roles spreads by gossip, and a test
/// that starts before it has finished reads a layout that is about to be wrong.
fn wait_converged(rt: &Runtime, nodes: &[(String, u16)], slot: u16, owner: &(String, u16), replica: &(String, u16)) {
    let admins: Vec<(RedisClient, (String, u16))> = nodes.iter().map(|(h, p)| (admin(rt, h, *p), (h.clone(), *p))).collect();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let stale: Vec<_> = admins
            .iter()
            .filter(|(a, _)| owner_according_to(a, slot).as_ref() != Some(owner) || !roles_according_to(a, owner, replica))
            .map(|(_, n)| n.clone())
            .collect();
        if stale.is_empty() {
            return;
        }
        assert!(Instant::now() < deadline, "nodes still disagree about {slot}'s owner: {stale:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A master failing over to its replica, by the graceful `CLUSTER FAILOVER`
/// the replica is asked for. The client has to follow the change of master
/// without its callers seeing an error, then follow the roles being put back.
#[test]
fn a_failover_is_followed() {
    if std::env::var("HOPF_TEST_CLUSTER_FAILOVER").is_err() {
        eprintln!("skipped: HOPF_TEST_CLUSTER_FAILOVER is not set");
        return;
    }
    let (seed, _calm) = cluster_or_skip!(alone);
    let _turn = exclusive();
    let rt = runtime();
    let c = connect(&rt, &seed);
    let k = key_in(10923..=16383, "failover");
    let slot = c.slot_of(&k);
    let (m_host, m_port) = c.owner_of(slot).unwrap();
    let master = admin(&rt, &m_host, m_port);
    let master_id = node_id(&master);

    // Find this master's replica from the master's own view.
    let nodes = match run(&master, &["CLUSTER", "NODES"]).unwrap() {
        Value::Bulk(t) | Value::Verbatim { data: t, .. } => String::from_utf8(t.to_vec()).unwrap(),
        other => panic!("{other:?}"),
    };
    let replica_addr = nodes
        .lines()
        .find(|l| l.contains(&format!("slave {master_id}")))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|a| a.split('@').next())
        .map(str::to_string)
        .expect("the master has a replica");
    let all_nodes: Vec<(String, u16)> = nodes
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|a| a.split('@').next())
        .filter_map(|a| a.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap())))
        .collect();
    let (r_host, r_port) = replica_addr.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap())).unwrap();
    let replica = admin(&rt, &r_host, r_port);

    call!(|cb| c.set(&k, "kept", cb)).unwrap();
    // Callers keep working through the change. Redis will not vote for a second
    // failover of the same master within twice its node timeout (30 s), so a
    // run soon after another has to ask again until the vote is granted.
    let deadline = Instant::now() + Duration::from_secs(75);
    let mut n = 0u32;
    'over: loop {
        assert!(Instant::now() < deadline, "the client never found the new master");
        let _ = run(&replica, &["CLUSTER", "FAILOVER"]);
        let settle = Instant::now() + Duration::from_secs(4);
        while Instant::now() < settle {
            match call!(|cb| c.get(&k, cb)) {
                Ok(v) => assert_eq!(v, Some(b("kept"))),
                Err(e) => panic!("a caller saw {e:?} during a failover"),
            }
            n += 1;
            if c.owner_of(slot) == Some((r_host.clone(), r_port)) {
                break 'over;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert!(n >= 1);

    // And back again. The old master has to be a replica with its link up
    // before it can take over, so the request is repeated until it does.
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        assert!(Instant::now() < deadline, "the original master never took over again");
        let _ = run(&master, &["CLUSTER", "FAILOVER"]);
        let settle = Instant::now() + Duration::from_secs(3);
        while Instant::now() < settle {
            // Keep the client busy so it meets the redirection.
            match call!(|cb| c.get(&k, cb)) {
                Ok(v) => assert_eq!(v, Some(b("kept"))),
                Err(e) => panic!("a caller saw {e:?} while the roles were put back"),
            }
            if c.owner_of(slot) == Some((m_host.clone(), m_port)) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if c.owner_of(slot) == Some((m_host.clone(), m_port)) {
            break;
        }
    }
    call!(|cb| c.del(&[&k], cb)).unwrap();
    // Leave nothing for the next test to find half way.
    wait_converged(&rt, &all_nodes, slot, &(m_host.clone(), m_port), &(r_host.clone(), r_port));
    rt.shutdown();
}
