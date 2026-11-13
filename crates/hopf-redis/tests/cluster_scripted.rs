// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The cluster client against scripted nodes on loopback: what a real cluster
//! cannot be made to do on cue.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hopf_core::Bytes;
use hopf_redis::{ClusterConfig, RedisCluster};

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
