// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Readiness, draining and graceful shutdown (issue #530), over real loopback
//! sockets: the runtime stops accepting, tells open connections' handlers so
//! they can say goodbye, waits for them (no longer than the drain period) and
//! closes what is left by force.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{
    Endpoint, PeerAddr, ProtocolHandler, Runtime, RuntimeConfig, TcpConnectorConfig, TcpListenerConfig, TelemetryHook,
};

/// Echoes input. On drain it either says goodbye and closes, or ignores it.
struct Server {
    goodbye: bool,
    drained: Arc<AtomicUsize>,
}

impl ProtocolHandler for Server {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            endpoint.send(data);
            *data = &[];
        });
    }
    fn drain(&mut self, endpoint: &mut dyn Endpoint) {
        self.drained.fetch_add(1, Ordering::SeqCst);
        if self.goodbye {
            endpoint.send(b"421 going away\r\n");
            endpoint.close();
        }
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

/// Records what the runtime tells its telemetry hook.
#[derive(Default)]
struct Recorder {
    states: Mutex<Vec<(bool, bool)>>,
    bind_failures: Mutex<Vec<String>>,
    completed: Mutex<Vec<(usize, Duration)>>,
}

impl TelemetryHook for Recorder {
    fn on_accept(&self, _peer: PeerAddr) {}
    fn on_runtime_state(&self, ready: bool, draining: bool) {
        self.states.lock().unwrap().push((ready, draining));
    }
    fn on_bind_failure(&self, addr: &str, error: &str) {
        self.bind_failures.lock().unwrap().push(format!("{addr}: {error}"));
    }
    fn on_drain_complete(&self, forced: usize, elapsed: Duration) {
        self.completed.lock().unwrap().push((forced, elapsed));
    }
}

struct Fixture {
    rt: Runtime,
    addr: SocketAddr,
    drained: Arc<AtomicUsize>,
    telemetry: Arc<Recorder>,
}

fn start(goodbye: bool, drain_timeout: Duration) -> Fixture {
    let telemetry = Arc::new(Recorder::default());
    let rt = Runtime::start_with_telemetry(
        RuntimeConfig {
            worker_threads: 2,
            drain_timeout,
            ..Default::default()
        },
        Some(telemetry.clone() as Arc<dyn TelemetryHook>),
    )
    .unwrap();
    let drained = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&drained);
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(Server {
                goodbye,
                drained: Arc::clone(&d),
            }) as Box<dyn ProtocolHandler>
        }))
        .unwrap();
    Fixture {
        rt,
        addr,
        drained,
        telemetry,
    }
}

/// Connect and make sure the server has registered the connection.
fn connect(f: &Fixture) -> TcpStream {
    let mut s = TcpStream::connect(f.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(b"hi").unwrap();
    let mut buf = [0u8; 2];
    s.read_exact(&mut buf).unwrap();
    s
}

fn wait_for(mut cond: impl FnMut() -> bool) {
    for _ in 0..400 {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("condition not reached");
}

#[test]
fn a_new_runtime_is_ready_and_not_draining() {
    let f = start(true, Duration::from_secs(5));
    assert!(f.rt.is_ready());
    assert!(!f.rt.is_draining());
    assert_eq!(f.rt.bind_failures(), 0);
    assert_eq!(f.telemetry.states.lock().unwrap().as_slice(), [(true, false)]);
    f.rt.shutdown();
}

#[test]
fn draining_stops_accepting_flips_the_state_and_leaves_open_connections_open() {
    let f = start(false, Duration::from_secs(5)); // handlers ignore the drain
    let mut open = connect(&f);
    wait_for(|| f.rt.open_connections() == 1);

    f.rt.start_drain();
    assert!(f.rt.is_draining());
    assert!(!f.rt.is_ready());
    assert_eq!(
        f.telemetry.states.lock().unwrap().last(),
        Some(&(false, true)),
        "the hook is told readiness fell and a drain began"
    );
    wait_for(|| f.drained.load(Ordering::SeqCst) == 1);

    // Nothing new is accepted...
    assert!(TcpStream::connect(f.addr).is_err(), "the listener is closed");
    // ...but the open connection still works.
    open.write_all(b"ok").unwrap();
    let mut buf = [0u8; 2];
    open.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ok");

    // Draining again does nothing.
    f.rt.start_drain();
    assert_eq!(f.drained.load(Ordering::SeqCst), 1, "each handler is told once");
    f.rt.shutdown();
}

#[test]
fn handlers_say_goodbye_and_shutdown_returns_as_soon_as_they_are_gone() {
    let f = start(true, Duration::from_secs(20));
    let mut a = connect(&f);
    let mut b = connect(&f);
    wait_for(|| f.rt.open_connections() == 2);

    let started = Instant::now();
    let telemetry = Arc::clone(&f.telemetry);
    f.rt.shutdown_graceful();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "it did not wait out the 20 s drain period: {:?}",
        started.elapsed()
    );

    for c in [&mut a, &mut b] {
        let mut said = Vec::new();
        c.read_to_end(&mut said).unwrap();
        assert_eq!(said, b"421 going away\r\n");
    }
    let completed = telemetry.completed.lock().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].0, 0, "nothing had to be forced");
}

#[test]
fn a_connection_that_finishes_during_the_drain_is_waited_for() {
    let f = start(false, Duration::from_secs(20));
    let mut c = connect(&f);
    wait_for(|| f.rt.open_connections() == 1);
    let telemetry = Arc::clone(&f.telemetry);
    // The client finishes its business 300 ms into the drain.
    let closer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        c.write_all(b"done").unwrap();
        drop(c);
    });
    let started = Instant::now();
    f.rt.shutdown_graceful();
    let took = started.elapsed();
    closer.join().unwrap();
    assert!(took >= Duration::from_millis(250), "it waited for the client: {took:?}");
    assert!(took < Duration::from_secs(5), "and then no longer: {took:?}");
    assert_eq!(telemetry.completed.lock().unwrap()[0].0, 0);
}

#[test]
fn connections_still_open_when_the_drain_period_ends_are_closed_by_force() {
    let f = start(false, Duration::from_millis(300));
    let mut stubborn = connect(&f);
    wait_for(|| f.rt.open_connections() == 1);
    let telemetry = Arc::clone(&f.telemetry);
    let started = Instant::now();
    f.rt.shutdown_graceful();
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(300), "the whole drain period was given: {took:?}");
    assert!(took < Duration::from_secs(5));

    // The connection is gone: EOF or a reset, not a read that times out.
    let mut buf = [0u8; 8];
    match stubborn.read(&mut buf) {
        Ok(0) => {}
        Err(e) if !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
        other => panic!("expected the connection to have been closed, got {other:?}"),
    }
    let completed = telemetry.completed.lock().unwrap();
    assert_eq!(completed[0].0, 1, "one connection was forced");
    assert!(completed[0].1 >= Duration::from_millis(300));
}

#[test]
fn a_failed_bind_is_counted_and_makes_the_runtime_not_ready() {
    let f = start(true, Duration::from_secs(5));
    assert!(f.rt.is_ready());
    // The address the first listener already holds.
    let err = f
        .rt
        .add_tcp_listener(TcpListenerConfig::new(f.addr, || {
            Box::new(Server {
                goodbye: true,
                drained: Arc::new(AtomicUsize::new(0)),
            }) as Box<dyn ProtocolHandler>
        }))
        .err()
        .expect("the port is taken");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert_eq!(f.rt.bind_failures(), 1);
    assert!(!f.rt.is_ready());
    assert!(!f.rt.is_draining());
    assert_eq!(f.telemetry.bind_failures.lock().unwrap().len(), 1);
    assert_eq!(f.telemetry.states.lock().unwrap().last(), Some(&(false, false)));
    // The first listener is unaffected.
    let _ = connect(&f);
    f.rt.shutdown();
}

#[test]
fn a_connection_made_during_the_drain_is_told_at_once() {
    let f = start(false, Duration::from_secs(5));
    // Something for the runtime to dial.
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer_addr = peer.local_addr().unwrap();
    f.rt.start_drain();

    let drained = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&drained);
    f.rt.connect(TcpConnectorConfig::new(peer_addr, move || {
        Box::new(Server {
            goodbye: false,
            drained: Arc::clone(&d),
        }) as Box<dyn ProtocolHandler>
    }))
    .unwrap();
    let (_conn, _) = peer.accept().unwrap();
    wait_for(|| drained.load(Ordering::SeqCst) == 1);
    f.rt.shutdown();
}

#[test]
fn the_default_drain_period_is_thirty_seconds() {
    assert_eq!(RuntimeConfig::default().drain_timeout, Duration::from_secs(30));
}

#[test]
fn a_composition_drains_even_while_services_hold_the_runtime() {
    use hopf_core::Composition;

    let mut comp = Composition::new(RuntimeConfig {
        worker_threads: 1,
        drain_timeout: Duration::from_secs(20),
        ..Default::default()
    })
    .unwrap();
    let drained = Arc::new(AtomicUsize::new(0));
    let d = Arc::clone(&drained);
    comp.listen_tcp(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
        Box::new(Server {
            goodbye: true,
            drained: Arc::clone(&d),
        }) as Box<dyn ProtocolHandler>
    }))
    .unwrap();
    let addr = comp.listen_addrs[0];
    // A service holding a clone of the runtime, as the protocol services do.
    let held = Arc::clone(comp.runtime());

    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"hi").unwrap();
    let mut buf = [0u8; 2];
    c.read_exact(&mut buf).unwrap();
    wait_for(|| held.open_connections() == 1);

    let started = Instant::now();
    comp.shutdown_graceful();
    assert!(started.elapsed() < Duration::from_secs(5));
    let mut said = Vec::new();
    c.read_to_end(&mut said).unwrap();
    assert_eq!(said, b"421 going away\r\n");
    assert!(held.is_draining());
    assert_eq!(drained.load(Ordering::SeqCst), 1);
}
