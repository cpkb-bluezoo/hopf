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
