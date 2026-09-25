// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Forwarder policies against a live (local, scriptable) upstream: RFC 8767
//! Serve-Stale, RFC 8482 minimal ANY. No external network.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::Runtime;
use hopf_dns::server::{DnsService, ForwarderHandler, MinimalAnyDisabled, ServeStaleDisabled};
use hopf_dns::wire::{
    DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, FLAG_QR, FLAG_RA, RCODE_SERVFAIL,
};
use hopf_dns::{DnsCache, DnsResolver};

const ANSWER: u8 = 0;
const SILENT: u8 = 1;
const SERVFAIL: u8 = 2;
const SLOW: u8 = 3;

/// What the scripted upstream does with the next query.
struct Upstream {
    mode: Arc<AtomicU8>,
    queries: Arc<AtomicUsize>,
    addr: SocketAddr,
}

/// Answers `A` with `address` (TTL 1) and `ANY` with an A plus a TXT.
fn spawn_upstream(address: Ipv4Addr) -> Upstream {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    let mode = Arc::new(AtomicU8::new(ANSWER));
    let queries = Arc::new(AtomicUsize::new(0));
    let (m, n) = (Arc::clone(&mode), Arc::clone(&queries));
    thread::spawn(move || loop {
        let mut buf = [0u8; 512];
        let Ok((len, peer)) = sock.recv_from(&mut buf) else {
            return;
        };
        let Ok(q) = DnsMessage::parse(&buf[..len]) else {
            continue;
        };
        let Some(question) = q.questions.first() else {
            continue;
        };
        // Ignore the resolver's own DDR probe.
        if question.qtype == Some(DnsType::Svcb) {
            continue;
        }
        n.fetch_add(1, Ordering::SeqCst);
        let mode = m.load(Ordering::SeqCst);
        if mode == SILENT {
            continue;
        }
        let mut resp = q.response_template(if mode == SERVFAIL { RCODE_SERVFAIL } else { 0 });
        resp.flags |= FLAG_QR | FLAG_RA;
        if mode == ANSWER || mode == SLOW {
            resp.answers.push(DnsResourceRecord::a(&question.name, 1, address));
            if question.qtype == Some(DnsType::Any) {
                resp.answers.push(DnsResourceRecord::txt(&question.name, 1, "a needlessly large TXT").unwrap());
            }
        }
        let bytes = resp.serialize().unwrap();
        if mode == SLOW {
            let sock = sock.try_clone().unwrap();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(500));
                let _ = sock.send_to(&bytes, peer);
            });
        } else {
            let _ = sock.send_to(&bytes, peer);
        }
    });
    Upstream { mode, queries, addr }
}

fn resolver(rt: &Runtime, upstream: &Upstream) -> DnsResolver {
    let r = DnsResolver::new(rt.pick_worker().clone());
    // Keep the resolver's own retries out of the way of the forwarder's timers.
    r.set_timeout(Duration::from_millis(2500));
    r.add_server(upstream.addr);
    r.open().unwrap();
    r
}

fn ask(service: &DnsService, name: &str, qtype: DnsType) -> DnsMessage {
    service.process_query_sync(
        &DnsMessage::query(9, DnsQuestion::in_class(name, qtype), true),
        "127.0.0.1:5353".parse().unwrap(),
    )
}

fn address(resp: &DnsMessage) -> Option<Ipv4Addr> {
    resp.answers.first().and_then(|rr| rr.as_a())
}

#[test]
fn stale_answer_is_served_while_the_upstream_is_silent_and_the_cache_refreshes_afterwards() {
    let up = spawn_upstream(Ipv4Addr::new(203, 0, 113, 1));
    let rt = Runtime::start(Default::default()).unwrap();
    let forwarder = ForwarderHandler::new(Arc::new(DnsCache::default()))
        .with_upstream(resolver(&rt, &up))
        .with_client_response_timer(Duration::from_millis(250))
        .with_failure_recheck(Duration::from_millis(600));
    let service = DnsService::with_handler(forwarder);

    // Warm the cache: TTL 1.
    assert_eq!(address(&ask(&service, "svc.example", DnsType::A)), Some(Ipv4Addr::new(203, 0, 113, 1)));
    thread::sleep(Duration::from_millis(1300)); // now expired

    // The upstream goes silent: stale data, after about the client timer.
    up.mode.store(SILENT, Ordering::SeqCst);
    let started = Instant::now();
    let resp = ask(&service, "svc.example", DnsType::A);
    assert_eq!(resp.rcode(), 0, "stale data, not SERVFAIL");
    assert_eq!(address(&resp), Some(Ipv4Addr::new(203, 0, 113, 1)));
    assert_eq!(resp.answers[0].ttl, 30);
    assert!(started.elapsed() < Duration::from_millis(1500), "answered at the client timer, not the upstream timeout");
    assert_eq!(service.metrics().stale_served, 1);

    // Failure recheck: an immediate repeat is answered without asking again.
    let asked = up.queries.load(Ordering::SeqCst);
    let started = Instant::now();
    assert_eq!(ask(&service, "svc.example", DnsType::A).answers[0].ttl, 30);
    assert!(started.elapsed() < Duration::from_millis(150), "no waiting on an upstream that just failed");
    assert_eq!(up.queries.load(Ordering::SeqCst), asked, "and no new upstream query");
    assert_eq!(service.metrics().stale_served, 2);

    // Upstream recovers; once the recheck interval passes the next query
    // refreshes instead of serving stale.
    up.mode.store(ANSWER, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(700));
    let resp = ask(&service, "svc.example", DnsType::A);
    assert_eq!(address(&resp), Some(Ipv4Addr::new(203, 0, 113, 1)));
    assert!(resp.answers[0].ttl <= 1, "a fresh answer, not the 30 s stale TTL");
    assert_eq!(service.metrics().stale_served, 2, "no further stale serves");
    rt.shutdown();
}

#[test]
fn a_late_upstream_answer_still_refreshes_the_cache() {
    let up = spawn_upstream(Ipv4Addr::new(203, 0, 113, 99));
    let rt = Runtime::start(Default::default()).unwrap();
    let cache = Arc::new(DnsCache::default());
    // Seed an expired entry with a different address.
    cache.put_response(&{
        let mut m = DnsMessage::query(1, DnsQuestion::in_class("slow.example", DnsType::A), true).response_template(0);
        m.answers.push(DnsResourceRecord::a("slow.example", 1, Ipv4Addr::new(198, 51, 100, 1)));
        m
    });
    thread::sleep(Duration::from_millis(1300));
    up.mode.store(SLOW, Ordering::SeqCst);
    let service = DnsService::with_handler(
        ForwarderHandler::new(Arc::clone(&cache))
            .with_upstream(resolver(&rt, &up))
            .with_client_response_timer(Duration::from_millis(100)),
    );

    // The client gets the stale address at once...
    assert_eq!(address(&ask(&service, "slow.example", DnsType::A)), Some(Ipv4Addr::new(198, 51, 100, 1)));
    assert_eq!(service.metrics().stale_served, 1);
    // ...and the upstream's late reply lands in the cache anyway.
    thread::sleep(Duration::from_millis(800));
    let resp = ask(&service, "slow.example", DnsType::A);
    assert_eq!(address(&resp), Some(Ipv4Addr::new(203, 0, 113, 99)), "refreshed in the background");
    assert_eq!(service.metrics().stale_served, 1);
    rt.shutdown();
}

#[test]
fn an_upstream_servfail_counts_as_a_failed_refresh() {
    // RFC 8767 section 4: only NOERROR and NXDOMAIN refresh the data.
    let up = spawn_upstream(Ipv4Addr::new(203, 0, 113, 5));
    let rt = Runtime::start(Default::default()).unwrap();
    let service = DnsService::with_handler(
        ForwarderHandler::new(Arc::new(DnsCache::default())).with_upstream(resolver(&rt, &up)),
    );
    assert!(address(&ask(&service, "err.example", DnsType::A)).is_some());
    thread::sleep(Duration::from_millis(1300));
    up.mode.store(SERVFAIL, Ordering::SeqCst);
    let resp = ask(&service, "err.example", DnsType::A);
    assert_eq!(resp.rcode(), 0);
    assert_eq!(address(&resp), Some(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(service.metrics().stale_served, 1);
    rt.shutdown();
}

#[test]
fn without_serve_stale_the_same_failure_reaches_the_client() {
    let up = spawn_upstream(Ipv4Addr::new(203, 0, 113, 6));
    let rt = Runtime::start(Default::default()).unwrap();
    let service = DnsService::with_handler(
        ForwarderHandler::new(Arc::new(DnsCache::default()))
            .with_upstream(resolver(&rt, &up))
            .with_stale_policy(ServeStaleDisabled)
            .with_upstream_timeout(Duration::from_millis(300)),
    );
    assert!(address(&ask(&service, "off.example", DnsType::A)).is_some());
    thread::sleep(Duration::from_millis(1300));
    up.mode.store(SILENT, Ordering::SeqCst);
    assert_eq!(ask(&service, "off.example", DnsType::A).rcode(), RCODE_SERVFAIL);
    assert_eq!(service.metrics().stale_served, 0);
    rt.shutdown();
}

#[test]
fn any_queries_get_a_minimal_answer_unless_disabled_or_dnssec_aware() {
    let up = spawn_upstream(Ipv4Addr::new(203, 0, 113, 7));
    let rt = Runtime::start(Default::default()).unwrap();
    let make = |tune: fn(ForwarderHandler) -> ForwarderHandler| {
        DnsService::with_handler(tune(
            ForwarderHandler::new(Arc::new(DnsCache::default())).with_upstream(resolver(&rt, &up)),
        ))
    };

    // Default: one HINFO, and the repeat is answered from the cache.
    let service = make(|f| f);
    let resp = ask(&service, "any.example", DnsType::Any);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.answers[0].raw_type, 13, "HINFO");
    let asked = up.queries.load(Ordering::SeqCst);
    assert_eq!(ask(&service, "any.example", DnsType::Any).answers.len(), 1);
    assert_eq!(up.queries.load(Ordering::SeqCst), asked, "minimal answer is cached");

    // Disabled by policy: everything at the name.
    let service = make(|f| f.with_minimal_any_policy(MinimalAnyDisabled));
    assert_eq!(ask(&service, "any2.example", DnsType::Any).answers.len(), 2);

    // A DNSSEC-aware client (DO) cannot verify a synthesised record.
    let service = make(|f| f);
    let mut q = DnsMessage::query(9, DnsQuestion::in_class("any3.example", DnsType::Any), true);
    q.additionals.push(DnsResourceRecord::opt(1232, true, &[]));
    let resp = service.process_query_sync(&q, "127.0.0.1:5353".parse().unwrap());
    assert_eq!(resp.answers.len(), 2, "full answer for DO");
    rt.shutdown();
}
