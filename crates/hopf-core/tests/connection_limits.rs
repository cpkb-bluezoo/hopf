// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The limits on a listener's connections (how many are open, in total and from
//! one address) and the idle timeout, which closes a connection with nothing
//! received or sent for the whole timeout. Real loopback sockets.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::{Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpConnectorConfig, TcpListenerConfig};

#[derive(Default)]
struct Seen {
    connected: AtomicUsize,
    disconnected: AtomicUsize,
    received: AtomicUsize,
    errors: Mutex<Vec<ErrorKind>>,
}

struct Probe(Arc<Seen>);

impl ProtocolHandler for Probe {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.0.connected.fetch_add(1, Ordering::SeqCst);
    }
    fn receive(&mut self, _endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let n = buf.len();
        buf.advance(n);
        self.0.received.fetch_add(n, Ordering::SeqCst);
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.0.disconnected.fetch_add(1, Ordering::SeqCst);
    }
    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        self.0.errors.lock().unwrap().push(err.kind());
    }
}

fn runtime() -> Runtime {
    Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap()
}

fn listen(rt: &Runtime, seen: &Arc<Seen>, tweak: impl FnOnce(TcpListenerConfig) -> TcpListenerConfig) -> SocketAddr {
    let seen = Arc::clone(seen);
    let config = tweak(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
        Box::new(Probe(Arc::clone(&seen))) as Box<dyn ProtocolHandler>
    }));
    rt.add_tcp_listener(config).unwrap().0
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

/// Whether the server has closed `stream`: a read says end of file. A connection
/// that is open and quiet times out instead.
fn closed_by_server(stream: &mut TcpStream, within: Duration) -> bool {
    stream.set_read_timeout(Some(within)).unwrap();
    let mut b = [0u8; 1];
    match stream.read(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => false,
        // A reset is a close too.
        Err(_) => true,
    }
}

#[test]
fn a_connection_over_the_limit_is_closed_at_once_and_its_place_is_given_back_by_a_close() {
    let rt = runtime();
    let seen = Arc::new(Seen::default());
    let addr = listen(&rt, &seen, |c| c.max_connections(Some(2)));
    let mut first = TcpStream::connect(addr).unwrap();
    let mut second = TcpStream::connect(addr).unwrap();
    wait_until("two connections", || seen.connected.load(Ordering::SeqCst) == 2);

    let mut third = TcpStream::connect(addr).unwrap();
    assert!(closed_by_server(&mut third, Duration::from_secs(5)), "the third was closed");
    assert!(!closed_by_server(&mut first, Duration::from_millis(200)), "and the first two were not");
    assert!(!closed_by_server(&mut second, Duration::from_millis(200)));
    assert_eq!(seen.connected.load(Ordering::SeqCst), 2, "the third never reached a handler");

    // A place is free again when a connection ends, whoever ends it.
    drop(first);
    wait_until("the first to be gone", || seen.disconnected.load(Ordering::SeqCst) == 1);
    let mut fourth = TcpStream::connect(addr).unwrap();
    wait_until("the fourth", || seen.connected.load(Ordering::SeqCst) == 3);
    assert!(!closed_by_server(&mut fourth, Duration::from_millis(300)));
    drop((second, fourth));
    rt.shutdown();
}

#[test]
fn an_address_is_held_to_its_own_limit() {
    let rt = runtime();
    let seen = Arc::new(Seen::default());
    let addr = listen(&rt, &seen, |c| c.max_connections_per_address(Some(1)));
    let mut first = TcpStream::connect(addr).unwrap();
    wait_until("the first", || seen.connected.load(Ordering::SeqCst) == 1);
    // The same address (loopback) again: refused.
    let mut second = TcpStream::connect(addr).unwrap();
    assert!(closed_by_server(&mut second, Duration::from_secs(5)));
    assert!(!closed_by_server(&mut first, Duration::from_millis(200)));
    assert_eq!(seen.connected.load(Ordering::SeqCst), 1);
    drop(first);
    wait_until("the first to be gone", || seen.disconnected.load(Ordering::SeqCst) == 1);
    let mut again = TcpStream::connect(addr).unwrap();
    wait_until("it to be accepted now", || seen.connected.load(Ordering::SeqCst) == 2);
    assert!(!closed_by_server(&mut again, Duration::from_millis(300)));
    rt.shutdown();
}

#[test]
fn with_no_limit_every_connection_is_accepted() {
    let rt = runtime();
    let seen = Arc::new(Seen::default());
    let addr = listen(&rt, &seen, |c| c);
    let held: Vec<TcpStream> = (0..30).map(|_| TcpStream::connect(addr).unwrap()).collect();
    wait_until("thirty connections", || seen.connected.load(Ordering::SeqCst) == 30);
    drop(held);
    rt.shutdown();
}

#[test]
fn a_connection_with_nothing_received_or_sent_is_closed_by_the_idle_timeout() {
    let rt = runtime();
    let seen = Arc::new(Seen::default());
    let addr = listen(&rt, &seen, |c| c.idle_timeout(Some(Duration::from_millis(300))));
    let mut quiet = TcpStream::connect(addr).unwrap();
    let started = Instant::now();
    assert!(closed_by_server(&mut quiet, Duration::from_secs(5)), "the idle connection was closed");
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(250), "not before the timeout: {took:?}");
    assert!(took < Duration::from_secs(2), "and not long after it: {took:?}");
    wait_until("the handler to hear of it", || seen.disconnected.load(Ordering::SeqCst) == 1);
    assert_eq!(*seen.errors.lock().unwrap(), vec![ErrorKind::TimedOut]);
    rt.shutdown();
}

#[test]
fn traffic_keeps_a_connection_from_being_idle_and_the_clock_starts_again_after_it() {
    let rt = runtime();
    let seen = Arc::new(Seen::default());
    let addr = listen(&rt, &seen, |c| c.idle_timeout(Some(Duration::from_millis(400))));
    let mut busy = TcpStream::connect(addr).unwrap();
    // Longer than the timeout in all, with a gap shorter than it between messages.
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1500) {
        busy.write_all(b"x").unwrap();
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(seen.disconnected.load(Ordering::SeqCst), 0, "it was never idle");
    assert!(seen.received.load(Ordering::SeqCst) >= 10);
    // And once it stops, the timeout runs from the last of it (which was up to a
    // gap before now), so it comes later than the gap's difference and before long.
    let stopped = Instant::now();
    assert!(closed_by_server(&mut busy, Duration::from_secs(5)));
    let after = stopped.elapsed();
    assert!(after >= Duration::from_millis(200) && after < Duration::from_secs(2), "{after:?}");
    rt.shutdown();
}

#[test]
fn a_connection_that_is_dialled_has_its_idle_timeout_too() {
    let rt = runtime();
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = silent.local_addr().unwrap();
    let keep = thread::spawn(move || silent.accept().map(|(s, _)| s));
    let seen = Arc::new(Seen::default());
    let handler_seen = Arc::clone(&seen);
    let config = TcpConnectorConfig::new(addr, move || Box::new(Probe(Arc::clone(&handler_seen))) as Box<dyn ProtocolHandler>)
        .idle_timeout(Some(Duration::from_millis(300)));
    rt.connect(config).unwrap();
    wait_until("the dial to connect", || seen.connected.load(Ordering::SeqCst) == 1);
    let started = Instant::now();
    wait_until("the idle timeout", || seen.disconnected.load(Ordering::SeqCst) == 1);
    assert!(started.elapsed() >= Duration::from_millis(200), "{:?}", started.elapsed());
    assert_eq!(*seen.errors.lock().unwrap(), vec![ErrorKind::TimedOut]);
    drop(keep.join());
    rt.shutdown();
}
