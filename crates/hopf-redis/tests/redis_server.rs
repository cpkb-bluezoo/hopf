// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The client against a real Redis or Valkey. Set `HOPF_TEST_REDIS` to
//! `host:port` of a server (and `HOPF_TEST_REDIS_AUTH` to one started with
//! `--requirepass hunter2`); a test whose server is not named is skipped.
//!
//! ```text
//! podman run -d --rm -p 127.0.0.1:16379:6379 docker.io/library/redis:7
//! podman run -d --rm -p 127.0.0.1:16380:6379 docker.io/library/redis:7 redis-server --requirepass hunter2
//! HOPF_TEST_REDIS=127.0.0.1:16379 HOPF_TEST_REDIS_AUTH=127.0.0.1:16380 \
//!     cargo test -p hopf-redis --features integration
//! ```

mod common;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::Bytes;
use hopf_redis::{Command, RedisClient, RedisConfig, RedisError, SetOptions, Value};

use common::*;

macro_rules! server_or_skip {
    ($f:expr) => {
        match $f {
            Some(s) => s,
            None => {
                eprintln!("skipped: no server named in the environment");
                return;
            }
        }
    };
}

fn b(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

#[test]
fn negotiates_resp3_and_answers_a_ping() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    call!(|cb| c.ping(cb)).unwrap();
    assert!(c.is_ready());
    assert!(c.is_resp3(), "a Redis 6 or later server speaks RESP3");
    rt.shutdown();
}

#[test]
fn works_in_resp2_too() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new(host, port).resp2_only());
    let k = unique("resp2");
    call!(|cb| c.set(&k, "v", cb)).unwrap();
    assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("v")));
    assert!(!c.is_resp3());
    // Types whose reply shape differs between the protocols.
    let z = unique("resp2-z");
    call!(|cb| c.zadd(&z, &[(1.5, "a"), (2.0, "b")], cb)).unwrap();
    assert_eq!(call!(|cb| c.zrange_withscores(&z, 0, -1, cb)).unwrap(), vec![(b("a"), 1.5), (b("b"), 2.0)]);
    let h = unique("resp2-h");
    call!(|cb| c.hset(&h, &[("f", "v")], cb)).unwrap();
    assert_eq!(call!(|cb| c.hgetall(&h, cb)).unwrap(), vec![(b("f"), b("v"))]);
    let _ = call!(|cb| c.del(&[&k, &z, &h], cb));
    rt.shutdown();
}

#[test]
fn the_typed_helpers_round_trip() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let p = unique("typed");
    let key = |s: &str| format!("{p}:{s}");

    // Strings.
    assert_eq!(call!(|cb| c.get(key("missing"), cb)).unwrap(), None);
    call!(|cb| c.set(key("s"), "hello", cb)).unwrap();
    assert_eq!(call!(|cb| c.get(key("s"), cb)).unwrap(), Some(b("hello")));
    assert_eq!(call!(|cb| c.append(key("s"), " world", cb)).unwrap(), 11);
    assert_eq!(call!(|cb| c.strlen(key("s"), cb)).unwrap(), 11);
    assert!(call!(|cb| c.setnx(key("nx"), "1", cb)).unwrap());
    assert!(!call!(|cb| c.setnx(key("nx"), "2", cb)).unwrap());
    call!(|cb| c.mset(&[(key("m1"), "a"), (key("m2"), "b")], cb)).unwrap();
    assert_eq!(
        call!(|cb| c.mget(&[key("m1"), key("none"), key("m2")], cb)).unwrap(),
        vec![Some(b("a")), None, Some(b("b"))]
    );
    assert_eq!(call!(|cb| c.incr(key("n"), cb)).unwrap(), 1);
    assert_eq!(call!(|cb| c.incrby(key("n"), 9, cb)).unwrap(), 10);
    assert_eq!(call!(|cb| c.decr(key("n"), cb)).unwrap(), 9);
    assert_eq!(call!(|cb| c.decrby(key("n"), 4, cb)).unwrap(), 5);
    assert_eq!(call!(|cb| c.getdel(key("s"), cb)).unwrap(), Some(b("hello world")));
    assert_eq!(call!(|cb| c.get(key("s"), cb)).unwrap(), None);

    // Hashes.
    assert_eq!(call!(|cb| c.hset(key("h"), &[("a", "1"), ("b", "2")], cb)).unwrap(), 2);
    assert_eq!(call!(|cb| c.hget(key("h"), "a", cb)).unwrap(), Some(b("1")));
    assert_eq!(call!(|cb| c.hmget(key("h"), &["a", "zz"], cb)).unwrap(), vec![Some(b("1")), None]);
    let mut all = call!(|cb| c.hgetall(key("h"), cb)).unwrap();
    all.sort();
    assert_eq!(all, vec![(b("a"), b("1")), (b("b"), b("2"))]);
    assert!(call!(|cb| c.hexists(key("h"), "a", cb)).unwrap());
    assert_eq!(call!(|cb| c.hincrby(key("h"), "a", 5, cb)).unwrap(), 6);
    assert_eq!(call!(|cb| c.hlen(key("h"), cb)).unwrap(), 2);
    assert_eq!(call!(|cb| c.hdel(key("h"), &["a"], cb)).unwrap(), 1);

    // Lists.
    assert_eq!(call!(|cb| c.rpush(key("l"), &["a", "b", "c"], cb)).unwrap(), 3);
    assert_eq!(call!(|cb| c.lpush(key("l"), &["z"], cb)).unwrap(), 4);
    assert_eq!(call!(|cb| c.lrange(key("l"), 0, -1, cb)).unwrap(), vec![b("z"), b("a"), b("b"), b("c")]);
    assert_eq!(call!(|cb| c.lindex(key("l"), 1, cb)).unwrap(), Some(b("a")));
    assert_eq!(call!(|cb| c.lpop(key("l"), cb)).unwrap(), Some(b("z")));
    assert_eq!(call!(|cb| c.rpop(key("l"), cb)).unwrap(), Some(b("c")));
    assert_eq!(call!(|cb| c.llen(key("l"), cb)).unwrap(), 2);

    // Sets.
    assert_eq!(call!(|cb| c.sadd(key("set"), &["x", "y", "x"], cb)).unwrap(), 2);
    assert!(call!(|cb| c.sismember(key("set"), "x", cb)).unwrap());
    assert_eq!(call!(|cb| c.scard(key("set"), cb)).unwrap(), 2);
    let mut members = call!(|cb| c.smembers(key("set"), cb)).unwrap();
    members.sort();
    assert_eq!(members, vec![b("x"), b("y")]);
    assert_eq!(call!(|cb| c.srem(key("set"), &["x"], cb)).unwrap(), 1);

    // Sorted sets.
    assert_eq!(call!(|cb| c.zadd(key("z"), &[(1.0, "a"), (3.0, "c"), (2.0, "b")], cb)).unwrap(), 3);
    assert_eq!(call!(|cb| c.zrange(key("z"), 0, -1, cb)).unwrap(), vec![b("a"), b("b"), b("c")]);
    assert_eq!(
        call!(|cb| c.zrange_withscores(key("z"), 0, 1, cb)).unwrap(),
        vec![(b("a"), 1.0), (b("b"), 2.0)]
    );
    assert_eq!(call!(|cb| c.zscore(key("z"), "b", cb)).unwrap(), Some(2.0));
    assert_eq!(call!(|cb| c.zscore(key("z"), "none", cb)).unwrap(), None);
    assert_eq!(call!(|cb| c.zincrby(key("z"), 0.5, "a", cb)).unwrap(), 1.5);
    assert_eq!(call!(|cb| c.zcard(key("z"), cb)).unwrap(), 3);
    assert_eq!(call!(|cb| c.zrem(key("z"), &["a"], cb)).unwrap(), 1);

    // Keys.
    assert_eq!(call!(|cb| c.exists(&[key("s"), key("h"), key("l")], cb)).unwrap(), 2);
    assert!(call!(|cb| c.expire(key("h"), 100, cb)).unwrap());
    let ttl = call!(|cb| c.ttl(key("h"), cb)).unwrap();
    assert!((1..=100).contains(&ttl), "{ttl}");
    assert!(call!(|cb| c.pexpire(key("h"), 50_000, cb)).unwrap());
    assert!(call!(|cb| c.pttl(key("h"), cb)).unwrap() > 1000);
    assert!(call!(|cb| c.persist(key("h"), cb)).unwrap());
    assert_eq!(call!(|cb| c.ttl(key("h"), cb)).unwrap(), -1);
    assert_eq!(call!(|cb| c.ttl(key("gone"), cb)).unwrap(), -2);
    let all: Vec<String> = ["nx", "m1", "m2", "n", "h", "l", "set", "z"].iter().map(|s| key(s)).collect();
    assert!(call!(|cb| c.del(&all, cb)).unwrap() >= 7);
    rt.shutdown();
}

#[test]
fn set_with_options() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let k = unique("setwith");
    let nx = SetOptions {
        nx: true,
        ex: Some(100),
        ..Default::default()
    };
    assert!(call!(|cb| c.set_with(&k, "1", &nx, cb)).unwrap(), "set a missing key");
    assert!(!call!(|cb| c.set_with(&k, "2", &nx, cb)).unwrap(), "NX leaves an existing key alone");
    assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("1")));
    let ttl = call!(|cb| c.ttl(&k, cb)).unwrap();
    assert!((1..=100).contains(&ttl));
    let xx = SetOptions {
        xx: true,
        keepttl: true,
        ..Default::default()
    };
    assert!(call!(|cb| c.set_with(&k, "3", &xx, cb)).unwrap());
    assert!(call!(|cb| c.ttl(&k, cb)).unwrap() > 0, "KEEPTTL kept it");
    assert!(!call!(|cb| c.set_with(unique("nokey"), "x", &xx, cb)).unwrap(), "XX needs the key");
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn a_server_error_is_an_error_with_its_code() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let k = unique("wrongtype");
    call!(|cb| c.set(&k, "v", cb)).unwrap();
    let err = call!(|cb| c.lpush(&k, &["x"], cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("WRONGTYPE"), "{err}");
    // The connection is fine afterwards.
    call!(|cb| c.ping(cb)).unwrap();
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn commands_from_many_threads_are_pipelined_and_each_gets_its_own_reply() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let k = unique("pipeline");
    let (tx, rx) = mpsc::channel();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (c, tx, k) = (c.clone(), tx.clone(), k.clone());
            std::thread::spawn(move || {
                for _ in 0..250 {
                    let tx = tx.clone();
                    c.incr(&k, move |r| {
                        let _ = tx.send(r.unwrap());
                    });
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    drop(tx);
    let mut seen: Vec<i64> = rx.iter().take(2000).collect();
    seen.sort();
    assert_eq!(seen, (1..=2000).collect::<Vec<_>>(), "every INCR got its own reply: no loss, no duplicate");
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn replies_arrive_in_the_order_commands_were_issued() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let k = unique("order");
    let order = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel();
    for i in 0..200 {
        let (order, tx) = (Arc::clone(&order), tx.clone());
        c.set(&k, i.to_string(), move |r| {
            r.unwrap();
        });
        c.get(&k, move |r| {
            order.lock().unwrap().push(r.unwrap().unwrap());
            if i == 199 {
                let _ = tx.send(());
            }
        });
    }
    rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let got = order.lock().unwrap().clone();
    let want: Vec<Bytes> = (0..200).map(|i: i32| b(&i.to_string())).collect();
    assert_eq!(got, want, "each GET saw the SET issued just before it");
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn a_transaction_runs_together_and_reports_each_result() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let (a, bk) = (unique("tx-a"), unique("tx-b"));
    // Two threads run transactions at once; each one's commands stay together.
    let mut handles = Vec::new();
    for _ in 0..2 {
        let (c, a, bk) = (c.clone(), a.clone(), bk.clone());
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let r = call!(|cb| c.transaction(
                    vec![Command::new("INCR").arg(&a), Command::new("INCR").arg(&bk), Command::new("GET").arg(&a)],
                    cb
                ))
                .unwrap()
                .expect("not aborted");
                assert_eq!(r.len(), 3);
                // Both counters moved together: nothing came between.
                let (x, y) = (r[0].as_int().unwrap(), r[1].as_int().unwrap());
                assert_eq!(x, y);
                assert_eq!(r[2].as_int().unwrap(), x);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(call!(|cb| c.get(&a, cb)).unwrap(), Some(b("100")));
    // A command that fails when run is an error element, not a failed transaction.
    let r = call!(|cb| c.transaction(vec![Command::new("SET").arg(&a).arg("x"), Command::new("LPUSH").arg(&a).arg("y")], cb))
        .unwrap()
        .unwrap();
    assert_eq!(r[0], Value::Simple("OK".into()));
    assert!(matches!(&r[1], Value::Error(e) if e.code == "WRONGTYPE"), "{:?}", r[1]);
    // A command refused when queued fails the transaction with its own error.
    let err = call!(|cb| c.transaction(vec![Command::new("NOSUCHCOMMAND")], cb)).unwrap_err();
    assert!(matches!(&err, RedisError::Server(e) if e.code == "ERR"), "{err}");
    let _ = call!(|cb| c.del(&[&a, &bk], cb));
    rt.shutdown();
}

#[test]
fn watch_aborts_an_exec_when_the_key_changed() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    // A connection of its own: WATCH belongs to the connection.
    let c = client(&rt, &host, port);
    let other = client(&rt, &host, port);
    let k = unique("watch");
    call!(|cb| c.set(&k, "1", cb)).unwrap();
    call!(|cb| c.watch(&[&k], cb)).unwrap();
    call!(|cb| other.set(&k, "2", cb)).unwrap();
    call!(|cb| c.multi(cb)).unwrap();
    let _queued = call!(|cb| c.command(&[b"SET", k.as_bytes(), b"3"], cb)).unwrap();
    assert_eq!(call!(|cb| c.exec(cb)).unwrap(), None, "the watched key changed");
    assert_eq!(call!(|cb| c.get(&k, cb)).unwrap(), Some(b("2")));
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn scripts_run_and_are_cached_by_hash() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let k = unique("script");
    let script = "redis.call('SET', KEYS[1], ARGV[1]); return redis.call('GET', KEYS[1])";
    let v = call!(|cb| c.eval(script, &[&k], &["payload"], cb)).unwrap();
    assert_eq!(v.as_str(), Some("payload"));
    let sha = call!(|cb| c.script_load(script, cb)).unwrap();
    assert_eq!(sha.len(), 40);
    let v = call!(|cb| c.evalsha(&sha, &[&k], &["again"], cb)).unwrap();
    assert_eq!(v.as_str(), Some("again"));
    let err = call!(|cb| c.evalsha("0000000000000000000000000000000000000000", &[&k], &[] as &[&str], cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("NOSCRIPT"));
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn authentication_and_a_wrong_password() {
    let (host, port) = server_or_skip!(auth_server());
    let rt = runtime();
    // Without a password: refused.
    let c = client(&rt, &host, port);
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert!(matches!(err.server_code(), Some("NOAUTH") | Some("WRONGPASS")), "{err}");
    // A wrong one: refused, and not retried in RESP2.
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new(&host, port).password("nope"));
    let err = call!(|cb| c.ping(cb)).unwrap_err();
    assert_eq!(err.server_code(), Some("WRONGPASS"), "{err}");
    // The right one.
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new(&host, port).password("hunter2"));
    call!(|cb| c.ping(cb)).unwrap();
    // And over RESP2, with AUTH.
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new(&host, port).password("hunter2").resp2_only());
    call!(|cb| c.ping(cb)).unwrap();
    assert!(!c.is_resp3());
    rt.shutdown();
}

#[test]
fn a_database_is_selected_and_a_name_is_set() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let name = unique("named");
    let in_db2 = RedisClient::connect(
        rt.pick_worker(),
        RedisConfig::new(&host, port).database(2).client_name(name.replace(':', "-")),
    );
    let in_db0 = client(&rt, &host, port);
    let k = unique("db");
    call!(|cb| in_db2.set(&k, "here", cb)).unwrap();
    assert_eq!(call!(|cb| in_db2.get(&k, cb)).unwrap(), Some(b("here")));
    assert_eq!(call!(|cb| in_db0.get(&k, cb)).unwrap(), None, "database 0 does not have it");
    let list = call!(|cb| in_db0.command(&[b"CLIENT", b"LIST"], cb)).unwrap();
    let text = String::from_utf8_lossy(list.as_bytes().unwrap()).into_owned();
    assert!(text.contains(&name.replace(':', "-")), "the connection name is set: {text}");
    // The same under RESP2, which does the SELECT itself.
    let resp2 = RedisClient::connect(rt.pick_worker(), RedisConfig::new(&host, port).database(2).resp2_only());
    assert_eq!(call!(|cb| resp2.get(&k, cb)).unwrap(), Some(b("here")));
    let _ = call!(|cb| in_db2.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn a_host_name_is_resolved() {
    let (_, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new("localhost", port));
    call!(|cb| c.ping(cb)).unwrap();
    rt.shutdown();
}

#[test]
fn large_values_round_trip() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    let k = unique("large");
    let value: Vec<u8> = (0..3_000_000u32).map(|i| (i % 253) as u8).collect();
    call!(|cb| c.set(&k, &value, cb)).unwrap();
    let got = call!(|cb| c.get(&k, cb)).unwrap().unwrap();
    assert_eq!(got.len(), value.len());
    assert_eq!(&got[..], &value[..]);
    let _ = call!(|cb| c.del(&[&k], cb));
    rt.shutdown();
}

#[test]
fn a_blocking_command_times_out_and_its_late_reply_is_not_mistaken_for_the_next() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = RedisClient::connect(
        rt.pick_worker(),
        RedisConfig::new(&host, port).command_timeout(Some(Duration::from_millis(400))),
    );
    let other = client(&rt, &host, port);
    let list = unique("blpop");
    let started = Instant::now();
    let (tx, rx) = mpsc::channel();
    c.command(&[b"BLPOP", list.as_bytes(), b"0"], move |r| {
        let _ = tx.send(r);
    });
    // A command behind it, with its own reply to come.
    let ping = {
        let (tx, rx) = mpsc::channel();
        c.ping(move |r| {
            let _ = tx.send(r);
        });
        rx
    };
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap_err(), RedisError::Timeout);
    assert!(started.elapsed() >= Duration::from_millis(350));
    // The server is still blocked on BLPOP; unblock it from another connection.
    call!(|cb| other.rpush(&list, &["x"], cb)).unwrap();
    // The ping gets PONG, not the BLPOP's [list, x]: ordering survived the timeout.
    // (It timed out while blocked behind BLPOP; its reply is discarded in order.)
    let _ = ping.recv_timeout(Duration::from_secs(5)).unwrap();
    call!(|cb| c.ping(cb)).unwrap();
    assert_eq!(call!(|cb| other.llen(&list, cb)).unwrap(), 0, "the BLPOP did pop it");
    rt.shutdown();
}

#[test]
fn a_killed_connection_fails_what_was_in_flight_once_and_the_next_command_reconnects() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let name = unique("kill").replace(':', "-");
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new(&host, port).client_name(&name));
    let admin = client(&rt, &host, port);
    call!(|cb| c.ping(cb)).unwrap();

    // Something in flight that will not complete by itself.
    let list = unique("kill-blpop");
    let (tx, rx) = mpsc::channel();
    c.command(&[b"BLPOP", list.as_bytes(), b"0"], move |r| {
        let _ = tx.send(r);
    });
    std::thread::sleep(Duration::from_millis(200));

    // Find and kill the connection by its name.
    let listing = call!(|cb| admin.command(&[b"CLIENT", b"LIST"], cb)).unwrap();
    let text = String::from_utf8_lossy(listing.as_bytes().unwrap()).into_owned();
    let line = text.lines().find(|l| l.contains(&format!("name={name}"))).expect("the client is listed");
    let id = line.split_whitespace().find_map(|w| w.strip_prefix("id=")).unwrap().to_string();
    call!(|cb| admin.command(&[b"CLIENT", b"KILL", b"ID", id.as_bytes()], cb)).unwrap();

    let err = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap_err();
    assert!(matches!(err, RedisError::ConnectionLost(_)), "{err}");
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "the callback ran once");

    // The next command dials again.
    for _ in 0..100 {
        if !c.is_ready() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    call!(|cb| c.ping(cb)).unwrap();
    assert!(c.is_ready());
    rt.shutdown();
}

#[test]
fn close_fails_waiting_commands_and_later_ones() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = RedisClient::connect(rt.pick_worker(), RedisConfig::new(&host, port).command_timeout(None));
    let (tx, rx) = mpsc::channel();
    c.command(&[b"BLPOP", unique("close").as_bytes(), b"0"], move |r| {
        let _ = tx.send(r);
    });
    std::thread::sleep(Duration::from_millis(200));
    c.close();
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap_err(), RedisError::Closed);
    assert_eq!(call!(|cb| c.ping(cb)).unwrap_err(), RedisError::Closed);
    rt.shutdown();
}

#[test]
fn too_many_waiting_commands_are_refused() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = RedisClient::connect(
        rt.pick_worker(),
        RedisConfig::new(&host, port).max_pending(2).command_timeout(None),
    );
    let blocker = unique("max");
    let (tx, rx) = mpsc::channel();
    for _ in 0..2 {
        let tx = tx.clone();
        c.command(&[b"BLPOP", blocker.as_bytes(), b"0"], move |r| {
            let _ = tx.send(r);
        });
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(call!(|cb| c.ping(cb)).unwrap_err(), RedisError::Overloaded);
    c.close();
    drop(rx);
    rt.shutdown();
}
