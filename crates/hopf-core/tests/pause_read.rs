// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `Endpoint::pause_read` stops the connection being read, with whatever is
//! already in the ring left where it is: a peer that keeps sending meanwhile
//! fills the socket's buffers and is held back by TCP, and nothing fails. When
//! the handler resumes, it is given what was waiting and then the rest.

use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

#[derive(Default)]
struct Shared {
    /// Bytes the handler has taken.
    taken: AtomicUsize,
    /// While false the handler pauses on every read and takes nothing.
    released: AtomicBool,
    /// Calls to `receive` with the handler holding.
    held_reads: AtomicUsize,
    errors: Mutex<Vec<String>>,
    handle: Mutex<Option<ConnHandle>>,
}

struct Holder(Arc<Shared>);

impl ProtocolHandler for Holder {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        *self.0.handle.lock().unwrap() = Some(endpoint.handle());
    }
    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        if !self.0.released.load(Ordering::SeqCst) {
            // Not ready for this: stop reading, and take none of it.
            self.0.held_reads.fetch_add(1, Ordering::SeqCst);
            endpoint.pause_read();
            return;
        }
        let n = buf.len();
        buf.advance(n);
        self.0.taken.fetch_add(n, Ordering::SeqCst);
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, err: &std::io::Error) {
        self.0.errors.lock().unwrap().push(err.to_string());
    }
}

#[test]
fn a_paused_connection_is_held_by_tcp_and_loses_nothing_when_resumed() {
    const TOTAL: usize = 24 * 1024 * 1024; // far more than the ring and the socket buffers hold
    let shared = Arc::new(Shared::default());
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let state = Arc::clone(&shared);
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
            Box::new(Holder(Arc::clone(&state))) as Box<dyn ProtocolHandler>
        }))
        .unwrap();

    // A peer that sends as fast as it can.
    let sender = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        let block = vec![7u8; 64 * 1024];
        let mut left = TOTAL;
        while left > 0 {
            let n = left.min(block.len());
            if s.write_all(&block[..n]).is_err() {
                return false;
            }
            left -= n;
        }
        true
    });

    // The handler holds, and the peer keeps sending: the ring fills, the socket's
    // buffers fill, the peer's writes block. Nothing is an error.
    let start = Instant::now();
    while shared.held_reads.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(shared.held_reads.load(Ordering::SeqCst) > 0, "the handler was called and paused");
    assert_eq!(*shared.errors.lock().unwrap(), Vec::<String>::new(), "pausing is not an error");
    assert_eq!(shared.taken.load(Ordering::SeqCst), 0);

    // Resume: what waited is delivered, then the rest, all of it.
    shared.released.store(true, Ordering::SeqCst);
    let handle = shared.handle.lock().unwrap().clone().expect("connected");
    handle.with_endpoint(|ep| {
        ep.resume_read();
        ep.poke_handler();
    });
    let start = Instant::now();
    while shared.taken.load(Ordering::SeqCst) < TOTAL && start.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(shared.taken.load(Ordering::SeqCst), TOTAL, "everything the peer sent arrived");
    assert!(sender.join().unwrap(), "the peer's writes all completed");
    assert_eq!(*shared.errors.lock().unwrap(), Vec::<String>::new());
    rt.shutdown();
}
