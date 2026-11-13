// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Server-side RFC 10029 (issue #531): the resolver's `query_batch` against a
//! real UDP `DnsService`. Loopback only, no external network.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::server::{listen_dns_udp, DnsService, DnsServiceHandle, DnsUdpListenConfig, FnHandler};
use hopf_dns::wire::{DnsResourceRecord, DnsType};
use hopf_dns::{find_mqtype_option, DnsResolver, EDNS_OPTION_MQTYPE_QUERY};

/// What the handler saw: the questions that reached it from the wire.
#[derive(Default)]
struct Log {
    /// `(qtype, carried an MQTYPE-Query option)` for each wire query. Sub-
    /// queries the shell makes itself never carry the option.
    seen: Vec<(DnsType, bool)>,
}

fn zone(log: Arc<Mutex<Log>>) -> FnHandler {
    FnHandler::new().on_query(move |q| {
        let question = q.questions.first()?;
        let qtype = question.qtype?;
        let has_option = q
            .additionals
            .iter()
            .find(|rr| rr.rtype == Some(DnsType::Opt))
            .and_then(|o| find_mqtype_option(&o.rdata, EDNS_OPTION_MQTYPE_QUERY))
            .is_some();
        if question.name.starts_with("batch") {
            log.lock().unwrap().seen.push((qtype, has_option));
        }
        let mut r = q.response_template(0);
        match qtype {
            DnsType::A => r.answers.push(DnsResourceRecord::a(&question.name, 60, Ipv4Addr::new(203, 0, 113, 10))),
            DnsType::Aaaa => r.answers.push(DnsResourceRecord::aaaa(&question.name, 60, Ipv6Addr::LOCALHOST)),
            DnsType::Txt => r.answers.push(DnsResourceRecord::txt(&question.name, 60, "hi").unwrap()),
            _ => {}
        }
        Some(r)
    })
}

/// Start a UDP server with `cap` extra types allowed, and a resolver for it.
fn setup(cap: usize) -> (Runtime, DnsResolver, Arc<Mutex<Log>>, DnsServiceHandle) {
    let log = Arc::new(Mutex::new(Log::default()));
    let mut service = DnsService::with_handler(zone(Arc::clone(&log)));
    service.set_max_multi_qtypes(cap);
    let handle = DnsServiceHandle::new(service);
    let rt = Runtime::start(Default::default()).unwrap();
    let (addr, _) = listen_dns_udp(
        rt.pick_worker(),
        DnsUdpListenConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            service: handle.clone(),
        },
    )
    .unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    resolver.add_server(addr);
    resolver.open().unwrap();
    prime_cookie(&resolver);
    (rt, resolver, log, handle)
}

/// The server answers a client's first UDP query with just a DNS Cookie
/// (RFC 7873 section 5.2.3), before it has proved it can receive replies. Ask
/// something else first so the queries under test reach the handler.
fn prime_cookie(resolver: &DnsResolver) {
    let done = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&done);
    resolver.query_a("prime.example", Box::new(move |_| *flag.lock().unwrap() = true));
    for _ in 0..250 {
        if *done.lock().unwrap() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("the priming query never completed");
}

/// Resolve `types` for `name` and return what each came to.
fn batch(resolver: &DnsResolver, name: &str, types: &[DnsType]) -> Vec<(DnsType, usize)> {
    let results = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&results);
    let done = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&done);
    resolver.query_batch(
        name,
        types,
        Box::new(move |t, r| sink.lock().unwrap().push((t, r.expect("no error").len()))),
        Box::new(move || *flag.lock().unwrap() = true),
    );
    for _ in 0..250 {
        if *done.lock().unwrap() {
            let mut out = results.lock().unwrap().clone();
            out.sort_by_key(|(t, _)| t.value());
            return out;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("query_batch never completed");
}

#[test]
fn a_batch_is_answered_by_one_wire_query_when_the_server_allows_it() {
    let (rt, resolver, log, _) = setup(4);
    let got = batch(&resolver, "batch.example", &[DnsType::A, DnsType::Aaaa, DnsType::Txt]);
    assert_eq!(got, vec![(DnsType::A, 1), (DnsType::Txt, 1), (DnsType::Aaaa, 1)]);
    {
        let log = log.lock().unwrap();
        // One query carried the option; the other two types were asked by
        // the server itself, so nothing else came off the wire.
        let wire: Vec<_> = log.seen.iter().filter(|(_, option)| *option).collect();
        assert_eq!(wire.len(), 1, "{:?}", log.seen);
        assert_eq!(log.seen.len(), 3, "the handler answered three questions: {:?}", log.seen);
    }
    // The server is not written off: the option is attached again.
    batch(&resolver, "batch2.example", &[DnsType::A, DnsType::Aaaa]);
    let options = log.lock().unwrap().seen.iter().filter(|(_, o)| *o).count();
    assert_eq!(options, 2, "the second batch carried the option too");
    rt.shutdown();
}

#[test]
fn a_server_that_does_not_allow_it_is_remembered_and_every_type_is_still_answered() {
    let (rt, resolver, log, service) = setup(0);
    let got = batch(&resolver, "batch.example", &[DnsType::A, DnsType::Aaaa, DnsType::Txt]);
    assert_eq!(got, vec![(DnsType::A, 1), (DnsType::Txt, 1), (DnsType::Aaaa, 1)]);
    assert_eq!(service.service().metrics().mqtype_queries, 0);
    // The client then stops attaching the option to this server.
    batch(&resolver, "batch2.example", &[DnsType::A, DnsType::Aaaa]);
    let options = log.lock().unwrap().seen.iter().filter(|(_, o)| *o).count();
    assert_eq!(options, 1, "only the first batch tried the option");
    rt.shutdown();
}
