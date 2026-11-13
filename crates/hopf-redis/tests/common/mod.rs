// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Helpers shared by the integration tests.

#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_redis::{RedisClient, RedisConfig};

/// Run an operation that takes a callback and wait for the one value it passes.
#[macro_export]
macro_rules! call {
    (|$cb:ident| $e:expr) => {{
        let (tx, rx) = std::sync::mpsc::channel();
        let $cb = move |v| {
            let _ = tx.send(v);
        };
        $e;
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the callback ran")
    }};
}

pub fn runtime() -> Runtime {
    Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap()
}

/// `host:port` of the real server for the tests that need one, from
/// `HOPF_TEST_REDIS`; `None` (and the test returns) when it is not set.
pub fn real_server() -> Option<(String, u16)> {
    parse_env("HOPF_TEST_REDIS")
}

/// A server started with `--requirepass hunter2`, from `HOPF_TEST_REDIS_AUTH`.
pub fn auth_server() -> Option<(String, u16)> {
    parse_env("HOPF_TEST_REDIS_AUTH")
}

fn parse_env(var: &str) -> Option<(String, u16)> {
    let v = std::env::var(var).ok()?;
    let (host, port) = v.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

/// A key prefix no other test shares.
pub fn unique(label: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!("hopf-test:{}:{}:{label}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

pub fn client(rt: &Runtime, host: &str, port: u16) -> RedisClient {
    RedisClient::connect(rt.pick_worker(), RedisConfig::new(host, port))
}

pub fn recv_within<T>(rx: &mpsc::Receiver<T>, secs: u64) -> Option<T> {
    rx.recv_timeout(Duration::from_secs(secs)).ok()
}

/// What a subscriber's handler saw, in order.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Message(hopf_redis::Message),
    Change(hopf_redis::SubscriptionChange),
    Push(hopf_redis::Push),
    Error(hopf_redis::ServerError),
    Connected(bool),
    Disconnected,
}

/// A handler that records what it is told.
#[derive(Clone, Default)]
pub struct Recorder(pub std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

impl Recorder {
    pub fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }

    pub fn messages(&self) -> Vec<hopf_redis::Message> {
        self.events()
            .into_iter()
            .filter_map(|e| if let Event::Message(m) = e { Some(m) } else { None })
            .collect()
    }

    /// Wait until `cond` holds of the events, or fail the test.
    pub fn wait_for(&self, what: &str, cond: impl Fn(&[Event]) -> bool) {
        for _ in 0..1000 {
            if cond(&self.events()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out waiting for {what}; saw {:?}", self.events());
    }
}

impl hopf_redis::SubscriberHandler for Recorder {
    fn on_message(&mut self, m: hopf_redis::Message) {
        self.0.lock().unwrap().push(Event::Message(m));
    }
    fn on_subscription(&mut self, c: hopf_redis::SubscriptionChange) {
        self.0.lock().unwrap().push(Event::Change(c));
    }
    fn on_push(&mut self, p: hopf_redis::Push) {
        self.0.lock().unwrap().push(Event::Push(p));
    }
    fn on_error(&mut self, e: hopf_redis::ServerError) {
        self.0.lock().unwrap().push(Event::Error(e));
    }
    fn on_connected(&mut self, reconnect: bool) {
        self.0.lock().unwrap().push(Event::Connected(reconnect));
    }
    fn on_disconnected(&mut self, _reason: &hopf_redis::RedisError) {
        self.0.lock().unwrap().push(Event::Disconnected);
    }
}
