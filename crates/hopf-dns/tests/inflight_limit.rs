// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The limit on queries outstanding on one TCP connection (issue #539): a client
//! that pipelines more than the limit has the rest held back by TCP rather than
//! refused, never has more outstanding than the limit, and has every query
//! answered. No external network.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::Runtime;
use hopf_dns::server::{
    listen_dns_tcp, listen_dns_tcp_with, DnsQueryCallback, DnsQueryHandler, DnsService, DnsServiceHandle, QueryContext,
};
use hopf_dns::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType};

/// Holds every callback until the test releases it, and counts how many are held
/// (started and not answered) at once.
#[derive(Default)]
struct Held {
    queue: Mutex<Vec<(DnsMessage, DnsQueryCallback)>>,
    started: AtomicUsize,
    outstanding: AtomicUsize,
    peak: AtomicUsize,
}

/// The handler, sharing `Held` with the test.
struct Handler(Arc<Held>);

impl DnsQueryHandler for Handler {
    fn handle_query(&self, q: &DnsMessage, _ctx: &QueryContext, callback: DnsQueryCallback) {
        let this = &self.0;
        match q.questions[0].name.as_str() {
            // Answered before this returns.
            "inline.test" => {
                let mut resp = q.response_template(0);
                resp.answers.push(DnsResourceRecord::a("inline.test", 60, Ipv4Addr::new(192, 0, 2, 1)));
                callback.respond(resp);
            }
            // A handler bug: the callback is let go of without an answer.
            "dropped.test" => drop(callback),
            _ => {
                let now = this.outstanding.fetch_add(1, Ordering::SeqCst) + 1;
                this.peak.fetch_max(now, Ordering::SeqCst);
                this.started.fetch_add(1, Ordering::SeqCst);
                let mut resp = q.response_template(0);
                resp.answers.push(DnsResourceRecord::a("held.test", 60, Ipv4Addr::new(192, 0, 2, 2)));
                this.queue.lock().unwrap().push((resp, callback));
            }
        }
    }
}

impl Held {
    /// Answer the oldest held query. Returns whether there was one.
    fn release_one(&self) -> bool {
        let next = {
            let mut q = self.queue.lock().unwrap();
            (!q.is_empty()).then(|| q.remove(0))
        };
        match next {
            Some((resp, callback)) => {
                self.outstanding.fetch_sub(1, Ordering::SeqCst);
                callback.respond(resp);
                true
            }
            None => false,
        }
    }
}

fn query(id: u16, name: &str) -> DnsMessage {
    DnsMessage::query(id, DnsQuestion::in_class(name, DnsType::A), false)
}

fn framed(msg: &DnsMessage) -> Vec<u8> {
    let bytes = msg.serialize().unwrap();
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&bytes);
    out
}

fn read_framed(stream: &mut TcpStream) -> DnsMessage {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut buf).unwrap();
    DnsMessage::parse(&buf).unwrap()
}

fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(5));
    }
}

struct Server {
    rt: Runtime,
    handle: DnsServiceHandle,
    held: Arc<Held>,
    stream: TcpStream,
}

fn server(limit: Option<usize>) -> Server {
    let rt = Runtime::start(Default::default()).unwrap();
    let held = Arc::new(Held::default());
    let mut service = DnsService::with_handler(Handler(Arc::clone(&held)));
    service.set_max_in_flight(limit);
    let handle = DnsServiceHandle::new(service);
    let addr = listen_dns_tcp(&rt, "127.0.0.1:0".parse().unwrap(), handle.clone()).unwrap();
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    Server { rt, handle, held, stream }
}

/// Every message of `ids` in one write: a client pipelining as fast as it can.
fn pipeline(stream: &mut TcpStream, ids: std::ops::RangeInclusive<u16>, name: &str) {
    let mut all = Vec::new();
    for id in ids {
        all.extend_from_slice(&framed(&query(id, name)));
    }
    stream.write_all(&all).unwrap();
}

#[test]
fn a_connection_never_has_more_than_the_limit_outstanding_and_every_query_is_answered() {
    let mut s = server(Some(4));
    pipeline(&mut s.stream, 1..=40, "held.test");

    // Four are started, and the others are not, however long they have had to be.
    wait_until("four queries to be started", || s.held.started.load(Ordering::SeqCst) == 4);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(s.held.started.load(Ordering::SeqCst), 4, "the limit held while nothing was answered");

    // Each answer lets one more start, and no more.
    let mut answered = Vec::new();
    for _ in 0..40 {
        wait_until("a held query", || !s.held.queue.lock().unwrap().is_empty());
        assert!(s.held.release_one());
        answered.push(read_framed(&mut s.stream).id);
        assert!(s.held.peak.load(Ordering::SeqCst) <= 4, "more than the limit were outstanding at once");
    }
    // They were started, and so answered, in the order they were sent.
    assert_eq!(answered, (1..=40).collect::<Vec<u16>>());
    assert_eq!(s.held.started.load(Ordering::SeqCst), 40);
    assert_eq!(s.held.peak.load(Ordering::SeqCst), 4);

    let m = s.handle.service().metrics();
    assert!(m.backpressure_events >= 1, "the connection was held back: {m:?}");
    assert_eq!(m.in_flight_peak, 4, "{m:?}");
    s.rt.shutdown();
}

#[test]
fn with_no_limit_every_query_is_started_at_once_as_before() {
    let mut s = server(None);
    pipeline(&mut s.stream, 1..=40, "held.test");
    wait_until("every query to be started", || s.held.started.load(Ordering::SeqCst) == 40);
    assert_eq!(s.held.peak.load(Ordering::SeqCst), 40);
    for _ in 0..40 {
        assert!(s.held.release_one());
    }
    let mut ids: Vec<u16> = (0..40).map(|_| read_framed(&mut s.stream).id).collect();
    ids.sort_unstable();
    assert_eq!(ids, (1..=40).collect::<Vec<u16>>());
    assert_eq!(s.handle.service().metrics().backpressure_events, 0);
    s.rt.shutdown();
}

#[test]
fn queries_answered_as_they_are_started_never_hold_the_connection_back() {
    let mut s = server(Some(2));
    pipeline(&mut s.stream, 1..=100, "inline.test");
    let mut ids: Vec<u16> = (0..100).map(|_| read_framed(&mut s.stream).id).collect();
    ids.sort_unstable();
    assert_eq!(ids, (1..=100).collect::<Vec<u16>>());
    assert_eq!(s.handle.service().metrics().backpressure_events, 0, "nothing was ever outstanding");
    s.rt.shutdown();
}

#[test]
fn a_query_whose_callback_is_let_go_of_does_not_hold_a_place_for_ever() {
    let mut s = server(Some(1));
    // The first is dropped without an answer; the second must still be started.
    let mut both = framed(&query(1, "dropped.test"));
    both.extend_from_slice(&framed(&query(2, "inline.test")));
    s.stream.write_all(&both).unwrap();
    // The first is answered SERVFAIL by the service, and frees its place for the second.
    let first = read_framed(&mut s.stream);
    assert_eq!((first.id, first.rcode()), (1, hopf_dns::wire::RCODE_SERVFAIL));
    assert_eq!(read_framed(&mut s.stream).id, 2);
    s.rt.shutdown();
}

#[test]
fn the_connection_is_read_again_after_it_was_held_and_takes_more_than_one_burst() {
    let mut s = server(Some(3));
    // Two bursts, the second written while the first is still held.
    pipeline(&mut s.stream, 1..=10, "held.test");
    wait_until("three started", || s.held.started.load(Ordering::SeqCst) == 3);
    pipeline(&mut s.stream, 11..=20, "held.test");
    thread::sleep(Duration::from_millis(100));
    assert_eq!(s.held.started.load(Ordering::SeqCst), 3);
    let mut ids = Vec::new();
    for _ in 0..20 {
        wait_until("a held query", || !s.held.queue.lock().unwrap().is_empty());
        s.held.release_one();
        ids.push(read_framed(&mut s.stream).id);
    }
    assert_eq!(ids, (1..=20).collect::<Vec<u16>>());
    assert!(s.held.peak.load(Ordering::SeqCst) <= 3);
    s.rt.shutdown();
}

#[test]
fn a_listener_takes_the_settings_of_a_tcp_listener() {
    let rt = Runtime::start(Default::default()).unwrap();
    let held = Arc::new(Held::default());
    let handle = DnsServiceHandle::new(DnsService::with_handler(Handler(held)));
    // Used by the listener: a small inbound buffer cap, which a long message would exceed.
    let addr = listen_dns_tcp_with(&rt, "127.0.0.1:0".parse().unwrap(), handle, |c| c.max_net_in(4096)).unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(&framed(&query(7, "inline.test"))).unwrap();
    assert_eq!(read_framed(&mut stream).id, 7);
    rt.shutdown();
}

/// Remembers the in-flight totals and backpressure events it is told of.
#[derive(Default)]
struct Hears {
    totals: Mutex<Vec<(String, i64)>>,
    backpressure: AtomicUsize,
}

impl hopf_dns::telemetry::DnsServerTelemetry for Hears {
    fn query_received(&self, _t: &str) {}
    fn response_sent(&self, _t: &str, _rcode: u16, _d: Duration) {}
    fn cache_hit(&self, _t: &str) {}
    fn upstream_query(&self, _t: &str) {}
    fn stale_served(&self, _t: &str) {}
    fn aggressive_nsec_hit(&self, _t: &str) {}
    fn error(&self, _t: &str) {}
    fn cookie_presented(&self, _t: &str) {}
    fn cookie_verified(&self, _t: &str) {}
    fn multi_qtype(&self, _t: &str, _n: u64) {}
    fn in_flight(&self, transport: &str, total: i64) {
        self.totals.lock().unwrap().push((transport.to_string(), total));
    }
    fn backpressure(&self, _transport: &str) {
        self.backpressure.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn telemetry_is_told_the_total_outstanding_and_each_time_a_connection_is_held_back() {
    let rt = Runtime::start(Default::default()).unwrap();
    let held = Arc::new(Held::default());
    let hears = Arc::new(Hears::default());
    let mut service = DnsService::with_handler(Handler(Arc::clone(&held)));
    service.set_max_in_flight(Some(2));
    service.set_telemetry(Arc::clone(&hears) as Arc<dyn hopf_dns::telemetry::DnsServerTelemetry>);
    let addr = listen_dns_tcp(&rt, "127.0.0.1:0".parse().unwrap(), DnsServiceHandle::new(service)).unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    pipeline(&mut stream, 1..=6, "held.test");
    for _ in 0..6 {
        wait_until("a held query", || !held.queue.lock().unwrap().is_empty());
        held.release_one();
        read_framed(&mut stream);
    }
    wait_until("the total to be back to none", || hears.totals.lock().unwrap().last().is_some_and(|(_, n)| *n == 0));
    let totals = hears.totals.lock().unwrap().clone();
    assert!(totals.iter().all(|(t, _)| t == "tcp"));
    assert!(totals.iter().map(|(_, n)| *n).max() == Some(2), "never more than the limit: {totals:?}");
    assert!(hears.backpressure.load(Ordering::SeqCst) >= 1);
    rt.shutdown();
}
