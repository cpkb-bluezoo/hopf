// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Callback-shaped `DnsQueryHandler`s (issue #525): a handler may complete its
//! `DnsQueryCallback` inline or later from any thread, and the listeners
//! deliver each answer on the right connection without holding the reactor.
//! No external network.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::server::{
    listen_dns_tcp, listen_dns_udp, ChainHandler, DnsQueryCallback, DnsQueryHandler, DnsService,
    DnsServiceHandle, DnsTransport, DnsUdpListenConfig, FnHandler, QueryContext,
    SyncDnsQueryHandler,
};
use hopf_dns::wire::{
    DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, RCODE_NXDOMAIN, RCODE_REFUSED,
    RCODE_SERVFAIL,
};

const DELAY: Duration = Duration::from_millis(400);

fn a(name: &str, last: u8) -> DnsResourceRecord {
    DnsResourceRecord::a(name, 60, Ipv4Addr::new(192, 0, 2, last))
}

fn query(id: u16, name: &str) -> DnsMessage {
    DnsMessage::query(id, DnsQuestion::in_class(name, DnsType::A), false)
}

fn answer_address(resp: &DnsMessage) -> Option<Ipv4Addr> {
    resp.answers.first().and_then(|rr| rr.as_a())
}

/// What the test handler does with a name.
///
/// * `slow.test`: answers 192.0.2.1 from another thread after `DELAY`.
/// * `fast.test`: answers 192.0.2.2 before `handle_query` returns.
/// * `dropped.test`: drops the callback, which is a handler bug.
/// * `refused.test`: `error(REFUSED)` from another thread.
struct Scripted;

impl DnsQueryHandler for Scripted {
    fn handle_query(&self, q: &DnsMessage, _ctx: &QueryContext<'_>, callback: DnsQueryCallback) {
        let mut resp = q.response_template(0);
        match q.questions[0].name.as_str() {
            "slow.test" => {
                resp.answers.push(a("slow.test", 1));
                thread::spawn(move || {
                    thread::sleep(DELAY);
                    callback.respond(resp);
                });
            }
            "fast.test" => {
                resp.answers.push(a("fast.test", 2));
                callback.respond(resp);
            }
            "refused.test" => {
                thread::spawn(move || callback.error(RCODE_REFUSED));
            }
            "dropped.test" => drop(callback),
            _ => callback.decline(),
        }
    }
}

fn write_framed(stream: &mut TcpStream, msg: &DnsMessage) {
    let bytes = msg.serialize().unwrap();
    stream.write_all(&(bytes.len() as u16).to_be_bytes()).unwrap();
    stream.write_all(&bytes).unwrap();
}

fn read_framed(stream: &mut TcpStream) -> DnsMessage {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut buf).unwrap();
    DnsMessage::parse(&buf).unwrap()
}

fn tcp_service(rt: &Runtime, handler: impl DnsQueryHandler + 'static) -> TcpStream {
    let addr = listen_dns_tcp(
        rt,
        "127.0.0.1:0".parse().unwrap(),
        DnsServiceHandle::new(DnsService::with_handler(handler)),
    )
    .unwrap();
    let stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
}

/// RFC 7766 §6.2.1.1: answers on one connection may come back in any order.
/// A query that is answered later must not hold up one that arrived after
/// it, and each answer reaches the connection it belongs to.
#[test]
fn tcp_late_answer_does_not_block_a_later_inline_answer() {
    let rt = Runtime::start(Default::default()).unwrap();
    let mut stream = tcp_service(&rt, Scripted);

    write_framed(&mut stream, &query(1, "slow.test"));
    write_framed(&mut stream, &query(2, "fast.test"));

    let first = read_framed(&mut stream);
    assert_eq!((first.id, answer_address(&first)), (2, Some(Ipv4Addr::new(192, 0, 2, 2))));
    let second = read_framed(&mut stream);
    assert_eq!((second.id, answer_address(&second)), (1, Some(Ipv4Addr::new(192, 0, 2, 1))));
    rt.shutdown();
}

/// The listener thread is free while a handler waits: a second client is
/// served while the first client's query is outstanding.
#[test]
fn tcp_connection_is_served_while_another_connections_query_is_outstanding() {
    let rt = Runtime::start(Default::default()).unwrap();
    let addr = listen_dns_tcp(
        &rt,
        "127.0.0.1:0".parse().unwrap(),
        DnsServiceHandle::new(DnsService::with_handler(Scripted)),
    )
    .unwrap();
    let connect = || {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s
    };
    let (mut slow, mut fast) = (connect(), connect());
    write_framed(&mut slow, &query(1, "slow.test"));
    write_framed(&mut fast, &query(2, "fast.test"));
    assert_eq!(read_framed(&mut fast).id, 2);
    assert_eq!(read_framed(&mut slow).id, 1);
    rt.shutdown();
}

#[test]
fn tcp_error_completed_from_another_thread_carries_that_rcode() {
    let rt = Runtime::start(Default::default()).unwrap();
    let mut stream = tcp_service(&rt, Scripted);
    write_framed(&mut stream, &query(3, "refused.test"));
    let resp = read_framed(&mut stream);
    assert_eq!((resp.id, resp.rcode()), (3, RCODE_REFUSED));
    assert!(resp.answers.is_empty());
    rt.shutdown();
}

/// A callback dropped without being completed is a handler bug, but the
/// client must still get an answer rather than wait for ever.
#[test]
fn dropped_callback_is_answered_servfail() {
    let rt = Runtime::start(Default::default()).unwrap();
    let mut stream = tcp_service(&rt, Scripted);
    write_framed(&mut stream, &query(4, "dropped.test"));
    let resp = read_framed(&mut stream);
    assert_eq!((resp.id, resp.rcode()), (4, RCODE_SERVFAIL));
    rt.shutdown();
}

#[test]
fn udp_answer_completed_from_another_thread_reaches_the_client() {
    let rt = Runtime::start(Default::default()).unwrap();
    let (addr, _) = listen_dns_udp(
        rt.pick_worker(),
        DnsUdpListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            service: DnsServiceHandle::new(DnsService::with_handler(Scripted)),
        },
    )
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.send_to(&query(5, "slow.test").serialize().unwrap(), addr).unwrap();
    let mut buf = [0u8; 512];
    let n = client.recv(&mut buf).unwrap();
    let resp = DnsMessage::parse(&buf[..n]).unwrap();
    assert_eq!((resp.id, answer_address(&resp)), (5, Some(Ipv4Addr::new(192, 0, 2, 1))));
    rt.shutdown();
}

/// `ChainHandler` hands the message to the next handler when an earlier one
/// declines, even when that decline comes late, from another thread.
struct DeclinesLater;

impl DnsQueryHandler for DeclinesLater {
    fn handle_query(&self, _q: &DnsMessage, _ctx: &QueryContext<'_>, callback: DnsQueryCallback) {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            callback.decline();
        });
    }
}

#[test]
fn chain_offers_the_message_onward_when_a_handler_declines_late() {
    let service = DnsService::with_handler(
        ChainHandler::new()
            .then(DeclinesLater)
            .then(FnHandler::new().on_query(|q| {
                let mut r = q.response_template(0);
                r.answers.push(a("x.test", 9));
                Some(r)
            })),
    );
    let resp = service.process_query_sync(&query(6, "x.test"), "127.0.0.1:5353".parse().unwrap());
    assert_eq!(answer_address(&resp), Some(Ipv4Addr::new(192, 0, 2, 9)));
}

#[test]
fn chain_that_runs_out_of_handlers_falls_back_to_empty_noerror() {
    let service = DnsService::with_handler(ChainHandler::new().then(DeclinesLater));
    let resp = service.process_query_sync(&query(7, "x.test"), "127.0.0.1:5353".parse().unwrap());
    assert_eq!(resp.rcode(), 0);
    assert!(resp.answers.is_empty());
}

#[test]
fn chain_stops_at_the_first_late_answer() {
    struct Late;
    impl DnsQueryHandler for Late {
        fn handle_query(&self, q: &DnsMessage, _ctx: &QueryContext<'_>, callback: DnsQueryCallback) {
            let resp = q.response_template(RCODE_NXDOMAIN);
            thread::spawn(move || callback.respond(resp));
        }
    }
    let service = DnsService::with_handler(
        ChainHandler::new().then(Late).then(FnHandler::new().on_query(|_| panic!("must not be reached"))),
    );
    let resp = service.process_query_sync(&query(8, "x.test"), "127.0.0.1:5353".parse().unwrap());
    assert_eq!(resp.rcode(), RCODE_NXDOMAIN);
}

/// Handlers that know their answer implement only `resolve`.
#[test]
fn a_sync_handler_is_adapted_without_writing_any_callback_code() {
    struct Fixed;
    impl SyncDnsQueryHandler for Fixed {
        fn resolve(&self, q: &DnsMessage, _ctx: &QueryContext<'_>) -> Option<DnsMessage> {
            (q.questions[0].name == "fixed.test").then(|| {
                let mut r = q.response_template(0);
                r.answers.push(a("fixed.test", 7));
                r
            })
        }
    }
    let service = DnsService::with_handler(ChainHandler::new().then(Fixed));
    let peer: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let hit = service.process_query_sync(&query(9, "fixed.test"), peer);
    assert_eq!(answer_address(&hit), Some(Ipv4Addr::new(192, 0, 2, 7)));
    let miss = service.process_query_sync(&query(10, "other.test"), peer);
    assert!(miss.answers.is_empty());
}

/// An answer that is ready is delivered before `dispatch_wire` returns (no
/// hop); one that is not is delivered later, exactly once, and `dispatch_wire`
/// does not wait for it.
#[test]
fn dispatch_wire_answers_inline_when_it_can_and_never_waits_when_it_cannot() {
    let service = DnsService::with_handler(Scripted);
    let peer: SocketAddr = "127.0.0.1:5353".parse().unwrap();

    let inline = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&inline);
    assert!(service.dispatch_wire(
        &query(11, "fast.test").serialize().unwrap(),
        peer,
        DnsTransport::Udp,
        Box::new(move |responses| {
            assert_eq!(responses.len(), 1);
            flag.store(true, Ordering::SeqCst);
        }),
    ));
    assert!(inline.load(Ordering::SeqCst), "an inline answer must not need a later turn");

    let (tx, rx) = mpsc::channel();
    let started = std::time::Instant::now();
    assert!(service.dispatch_wire(
        &query(12, "slow.test").serialize().unwrap(),
        peer,
        DnsTransport::Udp,
        Box::new(move |responses| tx.send(responses).unwrap()),
    ));
    assert!(started.elapsed() < DELAY / 2, "dispatch_wire must return without waiting");
    assert!(rx.try_recv().is_err(), "the answer is not ready yet");
    let responses = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(DnsMessage::parse(&responses[0]).unwrap().id, 12);
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "answered exactly once");
}

/// Bytes that are not a DNS message are rejected up front, so a DoQ listener
/// can treat them as a protocol error.
#[test]
fn dispatch_wire_rejects_bytes_that_are_not_dns() {
    let service = DnsService::with_handler(Scripted);
    let called = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&called);
    let accepted = service.dispatch_wire(
        &[0xde, 0xad],
        "127.0.0.1:5353".parse().unwrap(),
        DnsTransport::Udp,
        Box::new(move |_| flag.store(true, Ordering::SeqCst)),
    );
    assert!(!accepted);
    assert!(!called.load(Ordering::SeqCst));
}
