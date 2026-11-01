// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Tests of the responder's state machine without a socket: what it would
//! send is recorded in `Shared::outbox`, and datagrams are handed to the
//! same handler the reactor would call.
//!
//! Timers run on a real reactor, but every interval but the ones a test
//! wants is an hour long, so each test steps the machine itself.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig, UdpDatagramHandler};
use hopf_dns::wire::{
    DnsClass, DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, FLAG_AA, FLAG_QR,
};

use super::{
    add_dynamic_records, begin_probing, remove_dynamic_records, send_goodbye, send_next_probe,
    send_query, MdnsHandler, MdnsService, Shared, State, Timing,
};
use crate::bits::{cache_flush, with_unicast_response_requested};
use crate::dnssd::{BrowseEvent, ServiceRegistration};
use crate::socket::{MDNS_GROUP, MDNS_PORT};

const US: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn group() -> SocketAddr {
    SocketAddr::new(MDNS_GROUP.into(), MDNS_PORT)
}

fn other_host() -> SocketAddr {
    "192.0.2.9:5353".parse().unwrap()
}

fn timing() -> Timing {
    Timing {
        probe_initial_delay_max: Duration::ZERO,
        probe_interval: Duration::from_secs(3600),
        probe_count: 3,
        probe_conflict_wait: Duration::from_millis(40),
        announce_interval: Duration::from_secs(3600),
        announce_count: 2,
        record_ttl: 120,
        query_timeout: Duration::from_millis(50),
    }
}

struct Fixture {
    _rt: Arc<Runtime>,
    shared: Arc<Mutex<Shared>>,
    handler: MdnsHandler,
}

fn fixture(addresses: Vec<Ipv4Addr>) -> Fixture {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let shared = Arc::new(Mutex::new(Shared::new(
        rt.pick_worker().clone(),
        "host",
        addresses,
        timing(),
    )));
    let handler = MdnsHandler { shared: Arc::clone(&shared) };
    Fixture { _rt: rt, shared, handler }
}

impl Fixture {
    /// Skip probing: the responder is live under its first-choice name.
    fn announced(addresses: Vec<Ipv4Addr>) -> Self {
        let f = fixture(addresses);
        f.shared.lock().unwrap().state = State::Announced;
        f
    }

    fn state(&self) -> State {
        self.shared.lock().unwrap().state
    }

    fn name(&self) -> String {
        self.shared.lock().unwrap().current_name.clone()
    }

    fn feed(&mut self, from: SocketAddr, msg: &DnsMessage) {
        self.handler.on_datagram(from, &msg.serialize().unwrap());
    }

    fn sent(&self) -> Vec<(SocketAddr, DnsMessage)> {
        std::mem::take(&mut *self.shared.lock().unwrap().outbox.lock().unwrap())
    }

    /// Everything sent so far (without clearing), once there are at least `n` messages.
    fn wait_for_sent(&self, n: usize) -> Vec<(SocketAddr, DnsMessage)> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let g = self.shared.lock().unwrap();
            let out = g.outbox.lock().unwrap();
            if out.len() >= n {
                return out.clone();
            }
            drop(out);
            drop(g);
            assert!(Instant::now() < deadline, "timed out waiting for {n} messages");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn quiet_for(&self, d: Duration) -> usize {
        std::thread::sleep(d);
        self.shared.lock().unwrap().outbox.lock().unwrap().len()
    }
}

fn question(name: &str, qtype: DnsType) -> DnsQuestion {
    DnsQuestion::in_class(name, qtype)
}

fn query(q: DnsQuestion) -> DnsMessage {
    DnsMessage::query(0, q, false)
}

fn response(answers: Vec<DnsResourceRecord>) -> DnsMessage {
    DnsMessage::new(0, FLAG_QR | FLAG_AA, Vec::new(), answers, Vec::new(), Vec::new())
}

fn a(name: &str, ttl: u32, ip: [u8; 4]) -> DnsResourceRecord {
    DnsResourceRecord::a(name, ttl, Ipv4Addr::from(ip))
}

fn names(m: &DnsMessage) -> Vec<(String, u32)> {
    m.answers.iter().map(|r| (r.name.clone(), r.ttl)).collect()
}

// Probing -----------------------------------------------------------------

#[test]
fn probing_asks_for_the_name_and_proposes_our_record() {
    let f = fixture(vec![US]);
    begin_probing(&f.shared);
    assert_eq!(f.state(), State::Probing);
    let (dest, probe) = f.wait_for_sent(1).remove(0);
    assert_eq!(dest, group());
    assert_eq!(probe.flags & FLAG_QR, 0, "a probe is a query");
    assert_eq!(probe.questions.len(), 1);
    assert_eq!(probe.questions[0].name, "host.local");
    assert_eq!(probe.questions[0].qtype, Some(DnsType::A));
    assert_eq!(probe.authorities.len(), 1);
    assert_eq!(probe.authorities[0].rdata, US.octets());
}

#[test]
fn three_probes_then_the_name_is_announced() {
    let f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    send_next_probe(&f.shared);
    assert_eq!(f.state(), State::Probing);
    send_next_probe(&f.shared);
    assert_eq!(f.state(), State::Announced);

    let out = f.wait_for_sent(4);
    for (_, probe) in &out[..3] {
        assert_eq!(probe.flags & FLAG_QR, 0);
    }
    let (dest, announcement) = &out[3];
    assert_eq!(*dest, group());
    assert_eq!(announcement.flags & (FLAG_QR | FLAG_AA), FLAG_QR | FLAG_AA);
    assert_eq!(names(announcement), [("host.local".to_string(), 120)]);
    assert!(cache_flush(&announcement.answers[0]), "our own record replaces stale ones");
    assert_eq!(announcement.answers[0].rdata, US.octets());
}

#[test]
fn an_answer_to_a_probe_makes_us_pick_another_name() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    f.feed(other_host(), &response(vec![a("host.local", 120, [192, 0, 2, 9])]));
    assert_eq!(f.name(), "host-2.local");
    assert_eq!(f.state(), State::Probing);
    let out = f.wait_for_sent(2);
    assert_eq!(out[1].1.questions[0].name, "host-2.local", "probing starts again");
}

#[test]
fn each_further_conflict_takes_the_next_number() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    f.feed(other_host(), &response(vec![a("host.local", 120, [192, 0, 2, 9])]));
    f.wait_for_sent(2);
    f.feed(other_host(), &response(vec![a("host-2.local", 120, [192, 0, 2, 9])]));
    assert_eq!(f.name(), "host-3.local");
}

#[test]
fn an_answer_for_some_other_name_is_not_a_conflict() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    f.feed(other_host(), &response(vec![a("printer.local", 120, [192, 0, 2, 9])]));
    assert_eq!(f.name(), "host.local");
    assert_eq!(f.shared.lock().unwrap().name_conflict_suffix, 1);
}

#[test]
fn a_simultaneous_prober_with_the_greater_address_wins_and_we_try_again() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    let mut probe = query(question("host.local", DnsType::A));
    probe.authorities = vec![a("host.local", 120, [200, 0, 0, 1])];
    f.feed(other_host(), &probe);
    // After the conflict wait the same name is probed again from the start.
    let out = f.wait_for_sent(2);
    assert_eq!(out[1].1.questions[0].name, "host.local", "not renamed");
    assert_eq!(f.shared.lock().unwrap().name_conflict_suffix, 1);
    assert_eq!(f.state(), State::Probing);
}

#[test]
fn a_simultaneous_prober_with_the_lesser_address_loses_and_we_carry_on() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    let mut probe = query(question("host.local", DnsType::A));
    probe.authorities = vec![a("host.local", 120, [10, 0, 0, 1])];
    f.feed(other_host(), &probe);
    assert_eq!(f.quiet_for(Duration::from_millis(150)), 1, "no restart");
}

#[test]
fn hearing_our_own_probe_back_is_not_a_conflict() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    let (_, own) = f.wait_for_sent(1).remove(0);
    f.feed(other_host(), &own);
    assert_eq!(f.quiet_for(Duration::from_millis(150)), 1);
    assert_eq!(f.name(), "host.local");
}

#[test]
fn a_plain_query_for_our_name_while_probing_is_not_a_conflict() {
    let mut f = fixture(vec![US]);
    begin_probing(&f.shared);
    f.wait_for_sent(1);
    f.feed(other_host(), &query(question("host.local", DnsType::A)));
    assert_eq!(f.quiet_for(Duration::from_millis(150)), 1);
}

// Answering queries -------------------------------------------------------

#[test]
fn a_query_for_our_name_is_answered_to_the_group() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &query(question("host.local", DnsType::A)));
    let (dest, reply) = f.sent().remove(0);
    assert_eq!(dest, group());
    assert_eq!(reply.flags & (FLAG_QR | FLAG_AA), FLAG_QR | FLAG_AA);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].rdata, US.octets());
}

#[test]
fn the_name_is_matched_without_regard_to_case() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &query(question("HOST.Local", DnsType::A)));
    assert_eq!(f.sent().len(), 1);
}

#[test]
fn a_question_asking_for_a_unicast_reply_gets_one() {
    let mut f = Fixture::announced(vec![US]);
    let q = with_unicast_response_requested(question("host.local", DnsType::A), true);
    f.feed(other_host(), &query(q));
    let (dest, _) = f.sent().remove(0);
    assert_eq!(dest, other_host());
}

#[test]
fn queries_for_other_names_or_types_are_not_answered() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &query(question("printer.local", DnsType::A)));
    f.feed(other_host(), &query(question("host.local", DnsType::Aaaa)));
    assert!(f.sent().is_empty());
}

#[test]
fn an_any_query_gets_every_record() {
    let mut f = Fixture::announced(vec![US, Ipv4Addr::new(192, 0, 2, 2)]);
    f.feed(other_host(), &query(question("host.local", DnsType::Any)));
    assert_eq!(f.sent().remove(0).1.answers.len(), 2);
}

#[test]
fn a_known_answer_with_most_of_its_life_left_suppresses_the_reply() {
    let mut f = Fixture::announced(vec![US]);
    let mut q = query(question("host.local", DnsType::A));
    q.answers = vec![a("host.local", 100, US.octets())];
    f.feed(other_host(), &q);
    assert!(f.sent().is_empty());
}

#[test]
fn a_known_answer_close_to_expiry_does_not_suppress_it() {
    let mut f = Fixture::announced(vec![US]);
    let mut q = query(question("host.local", DnsType::A));
    q.answers = vec![a("host.local", 50, US.octets())];
    f.feed(other_host(), &q);
    assert_eq!(f.sent().len(), 1);
}

#[test]
fn a_known_answer_for_a_different_address_does_not_suppress_it() {
    let mut f = Fixture::announced(vec![US]);
    let mut q = query(question("host.local", DnsType::A));
    q.answers = vec![a("host.local", 120, [192, 0, 2, 77])];
    f.feed(other_host(), &q);
    assert_eq!(f.sent().len(), 1);
}

#[test]
fn nothing_is_answered_before_the_name_is_ours() {
    let mut f = fixture(vec![US]);
    f.feed(other_host(), &query(question("host.local", DnsType::A)));
    assert!(f.sent().is_empty(), "idle");
}

// What is heard -----------------------------------------------------------

#[test]
fn records_heard_are_cached() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &response(vec![a("printer.local", 120, [192, 0, 2, 9])]));
    let got = f.shared.lock().unwrap().cache_lookup("printer.local", DnsType::A);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].rdata, [192, 0, 2, 9]);
}

#[test]
fn a_goodbye_leaves_the_record_for_the_grace_period() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &response(vec![a("printer.local", 120, [192, 0, 2, 9])]));
    f.feed(other_host(), &response(vec![a("printer.local", 0, [192, 0, 2, 9])]));
    let got = f.shared.lock().unwrap().cache_lookup("printer.local", DnsType::A);
    assert_eq!(got.len(), 1, "removed a second later, not at once");
}

#[test]
fn a_goodbye_for_something_never_cached_is_harmless() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &response(vec![a("never.local", 0, [192, 0, 2, 9])]));
    assert!(f.shared.lock().unwrap().cache_lookup("never.local", DnsType::A).is_empty());
}

#[test]
fn garbage_is_ignored() {
    let mut f = Fixture::announced(vec![US]);
    f.handler.on_datagram(other_host(), &[1, 2, 3]);
    f.handler.on_datagram(other_host(), &[]);
    assert!(f.sent().is_empty());
}

// Goodbye and dynamic records ----------------------------------------------

#[test]
fn goodbye_withdraws_every_record_and_goes_idle() {
    let f = Fixture::announced(vec![US]);
    send_goodbye(&f.shared);
    let (dest, bye) = f.sent().remove(0);
    assert_eq!(dest, group());
    assert_eq!(names(&bye), [("host.local".to_string(), 0)]);
    assert_eq!(f.state(), State::Idle);
}

#[test]
fn dropping_the_service_says_goodbye_once() {
    let f = Fixture::announced(vec![US]);
    let service = MdnsService { shared: Arc::clone(&f.shared) };
    drop(service);
    let out = f.sent();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].1.answers[0].ttl, 0);
    // Already idle: a second handle going away says nothing.
    drop(MdnsService { shared: Arc::clone(&f.shared) });
    assert!(f.sent().is_empty());
}

#[test]
fn added_records_are_announced_with_the_hostname() {
    let f = Fixture::announced(vec![US]);
    let ptr = DnsResourceRecord::ptr("_x._tcp.local", 120, "i._x._tcp.local").unwrap();
    add_dynamic_records(&f.shared, vec![ptr]);
    let (_, msg) = f.wait_for_sent(1).remove(0);
    let owners: Vec<String> = msg.answers.iter().map(|r| r.name.clone()).collect();
    assert!(owners.contains(&"host.local".to_string()) && owners.contains(&"_x._tcp.local".to_string()), "{owners:?}");
}

#[test]
fn removing_records_withdraws_just_those_while_announced() {
    let f = Fixture::announced(vec![US]);
    f.shared.lock().unwrap().dynamic_records = vec![
        DnsResourceRecord::ptr("_x._tcp.local", 120, "i._x._tcp.local").unwrap(),
        DnsResourceRecord::ptr("_y._tcp.local", 120, "j._y._tcp.local").unwrap(),
    ];
    remove_dynamic_records(&f.shared, |rr| rr.name == "_x._tcp.local");
    let (_, bye) = f.sent().remove(0);
    assert_eq!(names(&bye), [("_x._tcp.local".to_string(), 0)]);
    assert_eq!(f.shared.lock().unwrap().dynamic_records.len(), 1);
}

#[test]
fn removing_records_when_not_announced_says_nothing() {
    let f = fixture(vec![US]);
    f.shared.lock().unwrap().dynamic_records =
        vec![DnsResourceRecord::ptr("_x._tcp.local", 120, "i._x._tcp.local").unwrap()];
    remove_dynamic_records(&f.shared, |_| true);
    assert!(f.sent().is_empty());
    assert!(f.shared.lock().unwrap().dynamic_records.is_empty());
}

// Queries we send ----------------------------------------------------------

#[test]
fn a_query_goes_to_the_group_and_answers_from_the_cache_after_the_timeout() {
    let mut f = Fixture::announced(vec![US]);
    f.feed(other_host(), &response(vec![a("printer.local", 120, [192, 0, 2, 9])]));
    let (tx, rx) = std::sync::mpsc::channel();
    send_query(&f.shared, "printer.local", DnsType::A, Box::new(move |r| tx.send(r).unwrap()));
    let (dest, q) = f.sent().remove(0);
    assert_eq!(dest, group());
    assert_eq!(q.questions[0].name, "printer.local");
    let got = rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert_eq!(got.len(), 1);
}

#[test]
fn a_query_nobody_answers_resolves_to_nothing() {
    let f = Fixture::announced(vec![US]);
    let (tx, rx) = std::sync::mpsc::channel();
    send_query(&f.shared, "nobody.local", DnsType::A, Box::new(move |r| tx.send(r).unwrap()));
    assert!(rx.recv_timeout(Duration::from_secs(3)).unwrap().is_empty());
}

// DNS-SD ------------------------------------------------------------------

fn registration() -> ServiceRegistration {
    ServiceRegistration {
        service_type: "_web._tcp".into(),
        instance_name: "Site".into(),
        port: 8080,
        txt: vec![("path".into(), "/".into())],
    }
}

#[test]
fn a_registered_service_is_announced_as_ptr_srv_and_txt() {
    let f = Fixture::announced(vec![US]);
    let service = MdnsService { shared: Arc::clone(&f.shared) };
    let handle = service.register_service(registration());
    let (_, msg) = f.wait_for_sent(1).remove(0);
    let find = |owner: &str, t: DnsType| msg.answers.iter().find(|r| r.name.eq_ignore_ascii_case(owner) && r.rtype == Some(t));
    let ptr = find("_web._tcp.local", DnsType::Ptr).expect("PTR");
    assert_eq!(ptr.as_domain_name().as_deref(), Some("Site._web._tcp.local"));
    let srv = find("Site._web._tcp.local", DnsType::Srv).expect("SRV");
    let (_, _, port, target) = srv.as_srv().unwrap();
    assert_eq!((port, target.as_str()), (8080, "host.local"));
    assert!(cache_flush(srv));
    let txt = find("Site._web._tcp.local", DnsType::Txt).expect("TXT");
    assert_eq!(txt.rdata, b"\x06path=/");
    assert!(find("_services._dns-sd._udp.local", DnsType::Ptr).is_some(), "the service-type enumeration record");
    assert!(find("host.local", DnsType::A).is_some());
    drop(handle);
}

#[test]
fn unregistering_withdraws_the_instance_but_not_the_host() {
    let f = Fixture::announced(vec![US]);
    let service = MdnsService { shared: Arc::clone(&f.shared) };
    let handle = service.register_service(registration());
    f.wait_for_sent(1);
    f.sent();
    handle.unregister();
    let (_, bye) = f.sent().remove(0);
    // Names come back lowercased from the wire parser.
    let owners: Vec<String> = bye.answers.iter().map(|r| r.name.to_ascii_lowercase()).collect();
    assert!(bye.answers.iter().all(|r| r.ttl == 0));
    assert!(owners.contains(&"_web._tcp.local".to_string()));
    assert!(owners.contains(&"site._web._tcp.local".to_string()));
    assert!(!owners.contains(&"host.local".to_string()));
}

#[test]
fn a_service_is_answered_when_asked_for() {
    let mut f = Fixture::announced(vec![US]);
    let service = MdnsService { shared: Arc::clone(&f.shared) };
    let _handle = service.register_service(registration());
    f.wait_for_sent(1);
    f.sent();
    f.feed(other_host(), &query(question("_web._tcp.local", DnsType::Ptr)));
    let (_, reply) = f.sent().remove(0);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].as_domain_name().as_deref(), Some("Site._web._tcp.local"));
}

#[test]
fn browsing_reports_a_service_found_in_the_cache() {
    let mut f = Fixture::announced(vec![US]);
    let service = MdnsService { shared: Arc::clone(&f.shared) };
    let srv = DnsResourceRecord::srv("Site._web._tcp.local", 120, 0, 0, 8080, "far.local").unwrap();
    let txt = DnsResourceRecord::new(
        "Site._web._tcp.local",
        DnsType::Txt,
        DnsClass::In,
        120,
        b"\x03a=b\x04flag".to_vec(),
    );
    let ptr = DnsResourceRecord::ptr("_web._tcp.local", 120, "Site._web._tcp.local").unwrap();
    // A pointer with nothing behind it is not reported.
    let dangling = DnsResourceRecord::ptr("_web._tcp.local", 120, "Ghost._web._tcp.local").unwrap();
    f.feed(other_host(), &response(vec![ptr, dangling, srv, txt]));

    let events = Arc::new(Mutex::new(Vec::new()));
    let e = Arc::clone(&events);
    let handle = service.browse("_web._tcp", move |ev| e.lock().unwrap().push(ev));
    let deadline = Instant::now() + Duration::from_secs(3);
    while events.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "no event");
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(handle);
    let got = events.lock().unwrap();
    assert_eq!(got.len(), 1, "{got:?}");
    match &got[0] {
        BrowseEvent::Found { instance, host, port, txt } => {
            assert_eq!(instance, "Site._web._tcp.local");
            assert_eq!((host.as_str(), *port), ("far.local", 8080));
            assert_eq!(txt, &[("a".to_string(), "b".to_string()), ("flag".to_string(), String::new())]);
        }
        other => panic!("{other:?}"),
    }
}
