// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Publish/subscribe and push messages against a real Redis or Valkey; see
//! `redis_server.rs` for how the server is named.

mod common;

use std::time::Duration;

use hopf_core::Bytes;
use hopf_redis::{InvalidationSink, RedisConfig, RedisError, RedisSubscriber, SubscriptionChange, SubscriptionKind};

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

fn channel_message(channel: &str, payload: &str) -> Event {
    Event::Message(Msg::channel(channel, payload))
}

/// Subscribe, publish and receive, in one protocol or the other.
fn subscribe_and_receive(resp2: bool) {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let rec = Recorder::default();
    let mut config = RedisConfig::new(&host, port);
    if resp2 {
        config = config.resp2_only();
    }
    let sub = RedisSubscriber::connect(rt.pick_worker(), config, rec.clone());
    let publisher = client(&rt, &host, port);
    let ch = unique("news");
    sub.subscribe(&[&ch]);
    rec.wait_for("the subscription", |e| e.iter().any(|x| matches!(x, Event::Change(SubscriptionChange::Subscribed { .. }))));

    let receivers = call!(|cb| publisher.publish(&ch, "hello", cb)).unwrap();
    assert_eq!(receivers, 1);
    rec.wait_for("the message", |e| e.contains(&channel_message(&ch, "hello")));

    let events = rec.events();
    assert_eq!(events[0], Event::Connected(false));
    assert_eq!(
        events[1],
        Event::Change(SubscriptionChange::Subscribed {
            kind: SubscriptionKind::Channel,
            name: b(&ch),
            count: 1
        })
    );
    sub.close();
    rt.shutdown();
}

#[test]
fn a_subscriber_receives_published_messages_over_resp3() {
    subscribe_and_receive(false);
}

#[test]
fn a_subscriber_receives_published_messages_over_resp2() {
    subscribe_and_receive(true);
}

#[test]
fn patterns_and_shard_channels_are_delivered_as_what_they_are() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let rec = Recorder::default();
    let sub = RedisSubscriber::connect(rt.pick_worker(), RedisConfig::new(&host, port), rec.clone());
    let publisher = client(&rt, &host, port);
    let prefix = unique("pat");
    let pattern = format!("{prefix}.*");
    let channel = format!("{prefix}.one");
    let shard = unique("shard");
    sub.psubscribe(&[&pattern]);
    sub.ssubscribe(&[&shard]);
    rec.wait_for("both subscriptions", |e| e.iter().filter(|x| matches!(x, Event::Change(_))).count() == 2);

    call!(|cb| publisher.publish(&channel, "p", cb)).unwrap();
    call!(|cb| publisher.spublish(&shard, "s", cb)).unwrap();
    rec.wait_for("both messages", |e| e.iter().filter(|x| matches!(x, Event::Message(_))).count() == 2);
    let msgs = rec.messages();
    assert!(msgs.contains(&Msg {
        kind: SubscriptionKind::Pattern,
        pattern: Some(pattern.as_bytes().to_vec()),
        channel: channel.as_bytes().to_vec(),
        payload: b"p".to_vec()
    }));
    assert!(msgs.contains(&Msg {
        kind: SubscriptionKind::Shard,
        pattern: None,
        channel: shard.as_bytes().to_vec(),
        payload: b"s".to_vec()
    }));
    sub.close();
    rt.shutdown();
}

#[test]
fn unsubscribing_stops_delivery_and_is_acknowledged() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let rec = Recorder::default();
    let sub = RedisSubscriber::connect(rt.pick_worker(), RedisConfig::new(&host, port), rec.clone());
    let publisher = client(&rt, &host, port);
    let (a, bch) = (unique("ua"), unique("ub"));
    sub.subscribe(&[&a, &bch]);
    rec.wait_for("two subscriptions", |e| e.iter().filter(|x| matches!(x, Event::Change(_))).count() == 2);
    assert_eq!(sub.subscriptions().0.len(), 2);

    sub.unsubscribe(&[&a]);
    rec.wait_for("the unsubscription", |e| {
        e.iter().any(|x| matches!(x, Event::Change(SubscriptionChange::Unsubscribed { name: Some(n), count: 1, .. }) if n == &b(&a)))
    });
    assert_eq!(call!(|cb| publisher.publish(&a, "gone", cb)).unwrap(), 0, "nobody is subscribed to it now");
    assert_eq!(call!(|cb| publisher.publish(&bch, "kept", cb)).unwrap(), 1);
    rec.wait_for("the message on the kept channel", |e| e.contains(&channel_message(&bch, "kept")));

    // No names: all of them.
    sub.unsubscribe(&[] as &[&str]);
    rec.wait_for("the last unsubscription", |e| {
        e.iter().any(|x| matches!(x, Event::Change(SubscriptionChange::Unsubscribed { name: Some(n), count: 0, .. }) if n == &b(&bch)))
    });
    assert!(sub.subscriptions().0.is_empty());
    sub.close();
    rt.shutdown();
}

#[test]
fn messages_arrive_in_the_order_they_were_published_and_a_large_one_whole() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let rec = Recorder::default();
    let sub = RedisSubscriber::connect(rt.pick_worker(), RedisConfig::new(&host, port), rec.clone());
    let publisher = client(&rt, &host, port);
    let ch = unique("order");
    sub.subscribe(&[&ch]);
    rec.wait_for("the subscription", |e| e.iter().any(|x| matches!(x, Event::Change(_))));
    for i in 0..500 {
        publisher.publish(&ch, i.to_string(), |r| {
            r.unwrap();
        });
    }
    let big = vec![b'z'; 2_000_000];
    publisher.publish(&ch, &big, |r| {
        r.unwrap();
    });
    rec.wait_for("all messages", |e| e.iter().filter(|x| matches!(x, Event::Message(_))).count() == 501);
    let msgs = rec.messages();
    for (i, m) in msgs[..500].iter().enumerate() {
        assert_eq!(m.payload, i.to_string().into_bytes(), "message {i}: {m:?}");
    }
    assert!(msgs[500].payload.len() == 2_000_000 && msgs[500].payload.iter().all(|&x| x == b'z'));
    sub.close();
    rt.shutdown();
}

#[test]
fn a_subscriber_reconnects_and_subscribes_again_on_its_own() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let rec = Recorder::default();
    let name = unique("resub").replace(':', "-");
    let sub = RedisSubscriber::connect(
        rt.pick_worker(),
        RedisConfig::new(&host, port).client_name(&name),
        rec.clone(),
    );
    let admin = client(&rt, &host, port);
    let ch = unique("resub-ch");
    let late = unique("resub-late");
    sub.subscribe(&[&ch]);
    rec.wait_for("the subscription", |e| e.iter().any(|x| matches!(x, Event::Change(_))));

    // Kill its connection from outside.
    let listing = collect::command(&admin, &[b"CLIENT", b"LIST"]).unwrap();
    let text = String::from_utf8_lossy(listing.as_bytes().unwrap()).into_owned();
    let line = text.lines().find(|l| l.contains(&format!("name={name}"))).expect("the subscriber is listed");
    let id = line.split_whitespace().find_map(|w| w.strip_prefix("id=")).unwrap().to_string();
    call!(|cb| admin.command(&[b"CLIENT", b"KILL", b"ID", id.as_bytes()], cb)).unwrap();

    rec.wait_for("the disconnect and the reconnect", |e| {
        e.contains(&Event::Disconnected) && e.contains(&Event::Connected(true))
    });
    // A subscription added while it was down or since is in place too.
    sub.subscribe(&[&late]);
    rec.wait_for("the subscriptions again", |e| {
        let subscribed = |name: &str| {
            e.iter()
                .rev()
                .take_while(|x| **x != Event::Disconnected)
                .any(|x| matches!(x, Event::Change(SubscriptionChange::Subscribed { name: n, .. }) if n == &b(name)))
        };
        subscribed(&ch) && subscribed(&late)
    });
    call!(|cb| admin.publish(&ch, "after", cb)).unwrap();
    rec.wait_for("a message on the new connection", |e| e.contains(&channel_message(&ch, "after")));
    sub.close();
    rt.shutdown();
}

#[test]
fn a_refused_subscription_is_reported_through_the_handler() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let admin = client(&rt, &host, port);
    let user = unique("acl").replace(':', "-");
    call!(|cb| admin.command(
        &[b"ACL", b"SETUSER", user.as_bytes(), b"on", b">pw", b"~*", b"&*", b"+@all", b"-subscribe"],
        cb
    ))
    .unwrap();
    let rec = Recorder::default();
    let sub = RedisSubscriber::connect(
        rt.pick_worker(),
        RedisConfig::new(&host, port).username(&user).password("pw"),
        rec.clone(),
    );
    sub.subscribe(&["anything"]);
    rec.wait_for("the refusal", |e| e.iter().any(|x| matches!(x, Event::Error(err) if err.code == "NOPERM")));
    sub.close();
    let _ = call!(|cb| admin.command(&[b"ACL", b"DELUSER", user.as_bytes()], cb));
    rt.shutdown();
}

#[test]
fn a_command_connection_receives_invalidation_pushes_for_tracked_keys() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let tracker = client(&rt, &host, port);
    let writer = client(&rt, &host, port);
    let seen = Invalidated::default();
    tracker.set_push_sink(InvalidationSink::new(seen.clone()));

    let key = unique("tracked");
    call!(|cb| tracker.command(&[b"CLIENT", b"TRACKING", b"on"], cb)).unwrap();
    call!(|cb| writer.set(&key, "1", cb)).unwrap();
    // Reading a key is what makes the server track it for this connection.
    assert_eq!(collect::get(&tracker, &key).unwrap(), Some(b("1")));
    call!(|cb| writer.set(&key, "2", cb)).unwrap();
    for _ in 0..500 {
        if !seen.seen().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(seen.seen(), vec![key.clone()]);
    // Replies are still matched to their commands around the push.
    assert_eq!(collect::get(&tracker, &key).unwrap(), Some(b("2")));
    let _ = call!(|cb| writer.del(&[&key], cb));
    rt.shutdown();
}

#[test]
fn a_command_connection_refuses_subscriptions_instead_of_losing_step() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let c = client(&rt, &host, port);
    for words in [&[&b"SUBSCRIBE"[..], b"x"][..], &[b"psubscribe", b"x*"], &[b"SSUBSCRIBE", b"x"], &[b"UNSUBSCRIBE"]] {
        let err = call!(|cb| c.command(words, cb)).unwrap_err();
        assert!(matches!(err, RedisError::Unexpected(_)), "{err}");
    }
    let err = call!(|cb| c.send(&hopf_redis::Command::new("SUBSCRIBE").arg("x"), cb)).unwrap_err();
    assert!(matches!(err, RedisError::Unexpected(_)));
    // Nothing was sent, so the connection is as it was.
    call!(|cb| c.ping(cb)).unwrap();
    rt.shutdown();
}

#[test]
fn a_handler_that_pauses_holds_a_real_server_back_and_nothing_is_lost() {
    use std::sync::atomic::Ordering::SeqCst;
    const SIZE: usize = 16_000_000;
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let counter = Counter::default();
    counter.pause_next.store(true, SeqCst);
    let sub = RedisSubscriber::connect(rt.pick_worker(), RedisConfig::new(&host, port), counter.clone());
    let publisher = client(&rt, &host, port);
    let ch = unique("pause");
    sub.subscribe(&[&ch]);
    for _ in 0..500 {
        if sub.is_connected() && !sub.subscriptions().0.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(200)); // the subscription is acknowledged
    publisher.publish(&ch, vec![b'q'; SIZE], |r| {
        r.unwrap();
    });
    publisher.publish(&ch, "end", |r| {
        r.unwrap();
    });
    for _ in 0..1000 {
        if counter.paused.load(SeqCst) == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(counter.paused.load(SeqCst), 1, "the handler paused");
    std::thread::sleep(Duration::from_millis(200));
    let held_at = counter.bytes.load(SeqCst);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(counter.bytes.load(SeqCst), held_at, "nothing is read while it is paused");
    assert!(held_at < SIZE);

    sub.resume();
    for _ in 0..1000 {
        if counter.messages.load(SeqCst) == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(counter.messages.load(SeqCst), 2);
    assert_eq!(counter.bytes.load(SeqCst), SIZE + 3);
    assert_eq!(counter.disconnects.load(SeqCst), 0);
    sub.close();
    rt.shutdown();
}

#[test]
fn a_real_servers_message_to_a_channel_over_the_limit_is_dropped_alone() {
    let (host, port) = server_or_skip!(real_server());
    let rt = runtime();
    let rec = Recorder::default();
    let sub = RedisSubscriber::connect(rt.pick_worker(), RedisConfig::new(&host, port).max_field(16), rec.clone());
    let publisher = client(&rt, &host, port);
    let short = format!("t{}", std::process::id());
    let long = unique("a-channel-name-longer-than-sixteen-bytes");
    assert!(short.len() <= 16 && long.len() > 16);
    sub.subscribe(&[&short, &long]);
    // Both are acknowledged by the server; only the short name is delivered whole.
    rec.wait_for("the short subscription", |e| {
        e.iter().any(|x| matches!(x, Event::Change(SubscriptionChange::Subscribed { name, .. }) if name == &b(&short)))
    });
    std::thread::sleep(Duration::from_millis(200));
    call!(|cb| publisher.publish(&long, "lost", cb)).unwrap();
    call!(|cb| publisher.publish(&short, "kept", cb)).unwrap();
    rec.wait_for("the message on the short channel", |e| e.contains(&channel_message(&short, "kept")));
    let events = rec.events();
    assert!(
        events.iter().any(|e| matches!(e, Event::Dropped(why) if why.contains("longer than 16 bytes"))),
        "the long one was dropped and reported: {events:?}"
    );
    assert!(!events.iter().any(|e| matches!(e, Event::Message(m) if m.payload == b"lost")));
    assert!(!events.contains(&Event::Disconnected), "and the connection went on");
    sub.close();
    rt.shutdown();
}
