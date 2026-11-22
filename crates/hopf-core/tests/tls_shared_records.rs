// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Application data a handler writes together shares TLS records: many small
//! `send`s in one callback go out as a few records, not one each, while writes
//! in separate events are never held waiting for more, and what is written
//! before a close, or before a large write, comes first.
//!
//! The connection runs through a relay that reads the TLS record headers of
//! what the server sends, so the records on the wire can be counted.
//!
//! Run with `cargo test -p hopf-core --features integration --test tls_shared_records`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{
    acceptor_from_pem_with_tcp_version_policy, connector_from_pem_with_tcp_version_policy, ConnHandle, Endpoint,
    ProtocolHandler, Runtime, RuntimeConfig, TcpConnectorConfig, TcpListenerConfig, TcpTlsVersionPolicy,
};

/// A TLS record as it was on the wire.
#[derive(Debug, Clone, Copy)]
struct Record {
    content_type: u8,
    len: usize,
}

type Records = Arc<Mutex<Vec<Record>>>;

/// Forwards a connection to `upstream`, noting the records of what the server
/// sends back. Returns the address to connect to.
fn relay(upstream: SocketAddr) -> (SocketAddr, Records) {
    let records: Records = Arc::default();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::clone(&records);
    std::thread::spawn(move || {
        let (client, _) = listener.accept().unwrap();
        let server = TcpStream::connect(upstream).unwrap();
        let (mut c_read, mut c_write) = (client.try_clone().unwrap(), client);
        let (mut s_read, mut s_write) = (server.try_clone().unwrap(), server);
        std::thread::spawn(move || {
            let mut buf = [0u8; 16384];
            while let Ok(n) = c_read.read(&mut buf) {
                if n == 0 || s_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            let _ = s_write.shutdown(std::net::Shutdown::Write);
        });
        let mut held: Vec<u8> = Vec::new();
        let mut buf = [0u8; 65536];
        while let Ok(n) = s_read.read(&mut buf) {
            if n == 0 {
                break;
            }
            if c_write.write_all(&buf[..n]).is_err() {
                break;
            }
            held.extend_from_slice(&buf[..n]);
            while held.len() >= 5 {
                let len = u16::from_be_bytes([held[3], held[4]]) as usize;
                if held.len() < 5 + len {
                    break;
                }
                seen.lock().unwrap().push(Record { content_type: held[0], len });
                held.drain(..5 + len);
            }
        }
        let _ = c_write.shutdown(std::net::Shutdown::Write);
    });
    (addr, records)
}

#[derive(Clone, Copy, Debug)]
enum Version {
    Tls13,
    Tls12,
}

struct Pki {
    _dir: tempfile::TempDir,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

fn pki() -> Pki {
    let dir = tempfile::tempdir().unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap().self_signed(&key).unwrap();
    let (cp, kp) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cp, cert.pem()).unwrap();
    std::fs::write(&kp, key.serialize_pem()).unwrap();
    Pki { _dir: dir, cert: cp, key: kp }
}

fn policy(v: Version) -> TcpTlsVersionPolicy {
    match v {
        Version::Tls13 => TcpTlsVersionPolicy::Tls13Only,
        Version::Tls12 => TcpTlsVersionPolicy::Tls12Only,
    }
}

/// What the server does on each byte the client sends.
struct Server {
    /// How many 20-byte writes `g` makes.
    small_writes: usize,
}

impl ProtocolHandler for Server {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {}

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let n = buf.len();
        let mut command = Vec::with_capacity(n);
        let (a, b) = buf.readable_spans();
        command.extend_from_slice(a);
        command.extend_from_slice(b);
        buf.advance(n);
        for c in command {
            match c {
                // Many small writes in one callback.
                b'g' => {
                    for _ in 0..self.small_writes {
                        endpoint.send(&[b'x'; 20]);
                    }
                }
                // One small write.
                b'a' => endpoint.send(b"answer"),
                // A write, then a close.
                b'c' => {
                    endpoint.send(b"goodbye");
                    endpoint.close();
                }
                // Small, large, small.
                b'l' => {
                    endpoint.send(b"<start>");
                    endpoint.send(&vec![b'L'; 1024 * 1024]);
                    endpoint.send(b"<end>");
                }
                _ => {}
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {}
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

#[derive(Default)]
struct Received {
    bytes: Mutex<Vec<u8>>,
    established: AtomicBool,
    disconnected: AtomicBool,
    handle: Mutex<Option<ConnHandle>>,
}

struct Client(Arc<Received>);

impl ProtocolHandler for Client {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        *self.0.handle.lock().unwrap() = Some(endpoint.handle());
    }
    fn security_established(&mut self, _endpoint: &mut dyn Endpoint, _info: &hopf_core::SecurityInfo) {
        self.0.established.store(true, Ordering::SeqCst);
    }
    fn receive(&mut self, _endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let n = buf.len();
        let (a, b) = buf.readable_spans();
        let mut bytes = self.0.bytes.lock().unwrap();
        bytes.extend_from_slice(a);
        bytes.extend_from_slice(b);
        drop(bytes);
        buf.advance(n);
    }
    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.0.disconnected.store(true, Ordering::SeqCst);
    }
    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

struct Setup {
    _rt: Runtime,
    records: Records,
    received: Arc<Received>,
    handle: ConnHandle,
}

fn wait_for(mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

fn setup(version: Version, small_writes: usize, listener_tweak: impl FnOnce(TcpListenerConfig) -> TcpListenerConfig) -> Setup {
    let pki = pki();
    let rt = Runtime::start(RuntimeConfig { worker_threads: 1, ..Default::default() }).unwrap();
    let acceptor = acceptor_from_pem_with_tcp_version_policy(&pki.cert, &pki.key, &[], policy(version)).unwrap();
    let cfg = TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
        Box::new(Server { small_writes }) as Box<dyn ProtocolHandler>
    })
    .with_tls(acceptor);
    let (server_addr, _) = rt.add_tcp_listener(listener_tweak(cfg)).unwrap();
    let (relay_addr, records) = relay(server_addr);
    let connector = connector_from_pem_with_tcp_version_policy(Path::new(&pki.cert), &[], policy(version)).unwrap();
    let received: Arc<Received> = Arc::default();
    let r = Arc::clone(&received);
    rt.connect(TcpConnectorConfig::new(relay_addr, move || Box::new(Client(Arc::clone(&r))) as Box<dyn ProtocolHandler>).with_tls(connector, "localhost"))
        .unwrap();
    assert!(wait_for(|| received.established.load(Ordering::SeqCst)), "no handshake");
    // Let the tickets and the rest of the handshake go by.
    std::thread::sleep(Duration::from_millis(300));
    let handle = received.handle.lock().unwrap().clone().unwrap();
    Setup { _rt: rt, records, received, handle }
}

impl Setup {
    fn send(&self, byte: u8) {
        self.handle.send(vec![byte]);
    }
    fn have(&self) -> usize {
        self.received.bytes.lock().unwrap().len()
    }
    /// Application-data records the server has sent since `mark`.
    fn data_records_since(&self, mark: usize) -> Vec<Record> {
        self.records.lock().unwrap()[mark..].iter().copied().filter(|r| r.content_type == 0x17).collect()
    }
    fn mark(&self) -> usize {
        self.records.lock().unwrap().len()
    }
}

const BOTH: [Version; 2] = [Version::Tls13, Version::Tls12];

#[test]
fn small_writes_made_together_share_records() {
    for version in BOTH {
        let s = setup(version, 1000, |c| c);
        let mark = s.mark();
        s.send(b'g');
        assert!(wait_for(|| s.have() >= 20_000), "{version:?}: got {} bytes", s.have());
        std::thread::sleep(Duration::from_millis(100));
        assert!(s.received.bytes.lock().unwrap().iter().all(|&b| b == b'x'));
        let records = s.data_records_since(mark);
        // 20,000 bytes in records of up to 16 KiB: two, with room for a stray
        // post-handshake record.
        assert!(records.len() <= 4, "{version:?}: {} records for 1000 writes: {records:?}", records.len());
        assert!(records.iter().any(|r| r.len > 8 * 1024), "{version:?}: {records:?}");
    }
}

#[test]
fn writes_in_separate_events_are_each_sent_at_once() {
    for version in BOTH {
        let s = setup(version, 0, |c| c);
        let mark = s.mark();
        for i in 1..=3 {
            s.send(b'a');
            assert!(wait_for(|| s.have() >= 6 * i), "{version:?}: write {i} was held back (got {})", s.have());
        }
        assert_eq!(&s.received.bytes.lock().unwrap()[..], "answer".repeat(3).as_bytes(), "{version:?}");
        // Each went in a record of its own, as it was written in an event of
        // its own.
        let records = s.data_records_since(mark);
        assert_eq!(records.len(), 3, "{version:?}: {records:?}");
    }
}

#[test]
fn what_is_written_before_a_close_arrives_before_it() {
    for version in BOTH {
        let s = setup(version, 0, |c| c);
        s.send(b'c');
        assert!(wait_for(|| s.received.disconnected.load(Ordering::SeqCst)), "{version:?}: never closed");
        assert_eq!(&s.received.bytes.lock().unwrap()[..], b"goodbye", "{version:?}");
    }
}

#[test]
fn a_large_write_between_small_ones_arrives_whole_and_in_order() {
    for version in BOTH {
        let s = setup(version, 0, |c| c);
        s.send(b'l');
        let total = "<start>".len() + 1024 * 1024 + "<end>".len();
        assert!(wait_for(|| s.have() >= total), "{version:?}: got {}", s.have());
        let bytes = s.received.bytes.lock().unwrap().clone();
        assert_eq!(bytes.len(), total);
        assert!(bytes.starts_with(b"<start>") && bytes.ends_with(b"<end>"), "{version:?}");
        assert!(bytes[7..7 + 1024 * 1024].iter().all(|&b| b == b'L'));
    }
}

#[test]
fn staged_plaintext_counts_against_the_outbound_limit() {
    for version in BOTH {
        // 1000 writes of 20 bytes is 20,000: over a limit of 8,000.
        let s = setup(version, 1000, |c| c.max_net_out(8000));
        s.send(b'g');
        // The server closes the connection: the client sees it end, and does
        // not get the whole 20,000.
        assert!(wait_for(|| s.received.disconnected.load(Ordering::SeqCst)), "{version:?}: not closed");
        assert!(s.have() < 20_000, "{version:?}: got {}", s.have());
    }
}

/// Many small writes, timed: `cargo test -p hopf-core --features integration
/// --test tls_shared_records --release -- --ignored --nocapture`.
#[test]
#[ignore]
fn bench_small_writes() {
    const WRITES: usize = 200_000;
    for version in BOTH {
        let s = setup(version, WRITES, |c| c.max_net_out(64 * 1024 * 1024));
        let mark = s.mark();
        let started = Instant::now();
        s.send(b'g');
        assert!(wait_for(|| s.have() >= WRITES * 20), "{version:?}: got {}", s.have());
        let elapsed = started.elapsed();
        std::thread::sleep(Duration::from_millis(200));
        let records = s.data_records_since(mark);
        let wire: usize = records.iter().map(|r| r.len + 5).sum();
        println!(
            "{version:?}: {WRITES} writes of 20 bytes: {} records, {} bytes on the wire for {} of data, {:.0} ms",
            records.len(),
            wire,
            WRITES * 20,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}
