// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Real loopback-multicast round-trips. mDNS's port (5353) and group
//! (224.0.0.251) are fixed by RFC 6762 — unlike this workspace's other
//! integration tests, there's no ephemeral-port trick available for
//! isolating concurrent tests from each other. Instead, every test uses a
//! randomly-generated, test-unique hostname/service label and filters
//! observed packets by name, so it's robust to other tests' (or another
//! process's) unrelated mDNS traffic on the same host rather than needing
//! `--test-threads=1`.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig, UdpDatagramHandler};
use hopf_dns::wire::{DnsMessage, DnsType, FLAG_QR};
use hopf_mdns::{BrowseEvent, MdnsService, ServiceRegistration, Timing};

/// Short, distinctive per-test label so concurrent tests (or unrelated
/// mDNS traffic on the host) can't be confused with this test's own.
fn unique_label(prefix: &str) -> String {
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    format!("{prefix}-{:08x}", u32::from_le_bytes(buf))
}

/// Not every host's default route is multicast-capable (some sandboxed/
/// firewalled dev environments in particular) — pin every test's mDNS
/// traffic to loopback explicitly rather than relying on the OS's default
/// outgoing interface.
fn start_test_service(rt: &Arc<Runtime>, label: &str, addresses: Vec<Ipv4Addr>) -> MdnsService {
    MdnsService::start_with_timing(rt, label, addresses, fast_timing(), Some(Ipv4Addr::LOCALHOST)).unwrap()
}

/// Timing shortened for fast tests: real probing/announcing still
/// happens, just in milliseconds instead of seconds.
fn fast_timing() -> Timing {
    Timing {
        probe_initial_delay_max: Duration::from_millis(5),
        probe_interval: Duration::from_millis(10),
        probe_count: 3,
        probe_conflict_wait: Duration::from_millis(30),
        announce_interval: Duration::from_millis(10),
        announce_count: 2,
        record_ttl: 120,
        query_timeout: Duration::from_millis(200),
    }
}

struct RecordingHandler {
    messages: Arc<Mutex<Vec<DnsMessage>>>,
}

impl UdpDatagramHandler for RecordingHandler {
    fn on_datagram(&mut self, _peer: std::net::SocketAddr, data: &[u8]) {
        if let Ok(msg) = DnsMessage::parse(data) {
            self.messages.lock().unwrap().push(msg);
        }
    }
}

/// Registers a second mDNS listener on the real port/group, recording
/// every parsed message it observes (including the multicast-looped-back
/// packets a responder in the same process sends).
fn start_observer(rt: &Arc<Runtime>) -> Arc<Mutex<Vec<DnsMessage>>> {
    let messages = Arc::new(Mutex::new(Vec::new()));
    let handler = Box::new(RecordingHandler { messages: Arc::clone(&messages) });
    hopf_mdns::socket::listen_mdns_udp(rt.pick_worker(), handler, Some(Ipv4Addr::LOCALHOST)).unwrap();
    messages
}

fn wait_for(mut pred: impl FnMut() -> bool, max: Duration) -> bool {
    let deadline = std::time::Instant::now() + max;
    loop {
        if pred() {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn messages_for(observed: &Arc<Mutex<Vec<DnsMessage>>>, name: &str) -> Vec<DnsMessage> {
    observed
        .lock()
        .unwrap()
        .iter()
        .filter(|m| {
            m.questions.iter().any(|q| q.name.eq_ignore_ascii_case(name))
                || m.answers.iter().any(|rr| rr.name.eq_ignore_ascii_case(name))
                || m.authorities.iter().any(|rr| rr.name.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

#[test]
fn probes_then_announces_with_the_right_record() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let observed = start_observer(&rt);

    let label = unique_label("probe-announce");
    let addr = Ipv4Addr::new(203, 0, 113, 42);
    let service = start_test_service(&rt, &label, vec![addr]);
    let name = format!("{label}.local");

    assert!(wait_for(|| service.is_announced(), Duration::from_secs(2)), "never finished announcing");
    // Give the (already-sent) final announcement a moment to be observed.
    std::thread::sleep(Duration::from_millis(50));

    let seen = messages_for(&observed, &name);
    let probes: Vec<_> = seen.iter().filter(|m| m.flags & FLAG_QR == 0).collect();
    let announces: Vec<_> = seen.iter().filter(|m| m.flags & FLAG_QR != 0).collect();

    assert_eq!(probes.len(), 3, "expected 3 probes, saw {}", probes.len());
    for probe in &probes {
        assert!(probe.questions.iter().any(|q| q.name.eq_ignore_ascii_case(&name)));
        assert!(probe.authorities.iter().any(|rr| rr.rtype == Some(DnsType::A)), "probe must propose the A record in Authority");
    }

    // At least `announce_count`: with multicast loopback enabled (needed
    // for this observer to work at all), the responder can legitimately
    // hear its own final, not-yet-known-answer-bearing probe echoed back
    // to itself just after transitioning to `Announced`, and reply to it
    // like it would to any other query -- a harmless, protocol-legal
    // duplicate this crate's design deliberately tolerates rather than
    // tries to filter out (see `responder.rs`'s module docs), so an exact
    // count isn't a safe invariant to assert on.
    assert!(announces.len() >= 2, "expected at least 2 announcements, saw {}", announces.len());
    for announce in &announces {
        let a = announce.answers.iter().find(|rr| rr.name.eq_ignore_ascii_case(&name) && rr.rtype == Some(DnsType::A));
        let a = a.expect("announcement must carry our A record");
        assert_eq!(a.as_a(), Some(addr));
        assert!(hopf_mdns::bits::cache_flush(a), "announced records must carry the cache-flush bit");
    }

    assert_eq!(service.current_name(), name, "no conflict expected -- name should be unsuffixed");
}

#[test]
fn a_name_conflict_renames_the_loser() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let label = unique_label("conflict");

    // First responder claims the name and finishes announcing.
    let first = start_test_service(&rt, &label, vec![Ipv4Addr::new(203, 0, 113, 1)]);
    assert!(wait_for(|| first.is_announced(), Duration::from_secs(2)));
    assert_eq!(first.current_name(), format!("{label}.local"));

    // Second responder probes for the *same* label -- the first, already
    // announced, will answer its probe (a real conflict, not the
    // simultaneous-probe tie-break case), forcing a rename.
    let second = start_test_service(&rt, &label, vec![Ipv4Addr::new(203, 0, 113, 2)]);
    assert!(wait_for(|| second.is_announced(), Duration::from_secs(2)), "second responder never resolved the conflict");

    assert_eq!(second.current_name(), format!("{label}-2.local"), "conflicting name must be suffixed");
    assert_eq!(first.current_name(), format!("{label}.local"), "the original owner keeps its name");
}

#[test]
fn known_answer_suppression_omits_already_known_records() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let observed = start_observer(&rt);

    let label = unique_label("kas");
    let addr = Ipv4Addr::new(203, 0, 113, 7);
    let service = start_test_service(&rt, &label, vec![addr]);
    let name = format!("{label}.local");
    assert!(wait_for(|| service.is_announced(), Duration::from_secs(2)));
    // Let any straggling self-loopback reply from the tail end of
    // announcing (see `probes_then_announces_with_the_right_record`'s
    // comment on this) land and get cleared, so it can't be mistaken
    // below for a reply to *our* query.
    std::thread::sleep(Duration::from_millis(100));
    observed.lock().unwrap().clear();

    // A query that already lists the exact answer, with the full TTL,
    // must be met with no response at all (nothing new to tell it).
    let known = hopf_dns::wire::DnsResourceRecord::a(&name, 120, addr);
    let mut query = DnsMessage::query(0, hopf_dns::wire::DnsQuestion::in_class(&name, DnsType::A), false);
    query.answers.push(known);
    hopf_mdns_test_send(&rt, &query);

    std::thread::sleep(Duration::from_millis(150));
    let responses = messages_for(&observed, &name).into_iter().filter(|m| m.flags & FLAG_QR != 0).count();
    assert_eq!(responses, 0, "a fully-known-answer query must get no reply");
}

#[test]
fn a_plain_query_without_known_answers_gets_a_reply() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let observed = start_observer(&rt);

    let label = unique_label("plain-query");
    let addr = Ipv4Addr::new(203, 0, 113, 8);
    let service = start_test_service(&rt, &label, vec![addr]);
    let name = format!("{label}.local");
    assert!(wait_for(|| service.is_announced(), Duration::from_secs(2)));
    observed.lock().unwrap().clear();

    let query = DnsMessage::query(0, hopf_dns::wire::DnsQuestion::in_class(&name, DnsType::A), false);
    hopf_mdns_test_send(&rt, &query);

    assert!(
        wait_for(
            || messages_for(&observed, &name).iter().any(|m| m.flags & FLAG_QR != 0),
            Duration::from_secs(1)
        ),
        "a query with no known answers must get a reply"
    );
}

/// Sends a raw mDNS message via a throwaway socket bound purely for this
/// one send (not registered with the reactor at all -- no response
/// handling needed here, only outbound).
fn hopf_mdns_test_send(_rt: &Arc<Runtime>, msg: &DnsMessage) {
    let sock2 = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)).unwrap();
    sock2.bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into()).unwrap();
    sock2.set_multicast_if_v4(&Ipv4Addr::LOCALHOST).unwrap();
    let sock: std::net::UdpSocket = sock2.into();
    sock.set_multicast_ttl_v4(255).unwrap();
    let bytes = msg.serialize().unwrap();
    sock.send_to(&bytes, (hopf_mdns::socket::MDNS_GROUP, hopf_mdns::socket::MDNS_PORT)).unwrap();
}

#[test]
fn dns_sd_register_and_browse_round_trip() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());

    let host_label = unique_label("dnssd-host");
    let service_type = format!("_test{}._tcp", unique_label(""));
    let instance_name = "My Test Service".to_string();

    let advertiser = start_test_service(&rt, &host_label, vec![Ipv4Addr::new(203, 0, 113, 20)]);
    assert!(wait_for(|| advertiser.is_announced(), Duration::from_secs(2)));

    let _handle = advertiser.register_service(ServiceRegistration {
        service_type: service_type.clone(),
        instance_name: instance_name.clone(),
        port: 8080,
        txt: vec![("path".to_string(), "/api".to_string())],
    });

    // Browse from a *separate* responder instance -- a realistic
    // discovery scenario, not just self-observation.
    let browser_label = unique_label("dnssd-browser");
    let browser = start_test_service(&rt, &browser_label, vec![Ipv4Addr::new(203, 0, 113, 21)]);
    assert!(wait_for(|| browser.is_announced(), Duration::from_secs(2)));

    let found: Arc<Mutex<Vec<BrowseEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let found2 = Arc::clone(&found);
    let _browse = browser.browse(&service_type, move |event| {
        found2.lock().unwrap().push(event);
    });

    assert!(
        wait_for(
            || found.lock().unwrap().iter().any(|e| matches!(e, BrowseEvent::Found { instance, .. } if instance.to_lowercase().starts_with(&instance_name.to_lowercase()))),
            Duration::from_secs(3)
        ),
        "browse never found the registered service"
    );

    let events = found.lock().unwrap();
    let BrowseEvent::Found { host, port, txt, .. } =
        events.iter().find(|e| matches!(e, BrowseEvent::Found { .. })).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(*port, 8080);
    assert!(host.to_lowercase().starts_with(&host_label.to_lowercase()));
    assert_eq!(txt, &vec![("path".to_string(), "/api".to_string())]);
}

#[test]
fn dropping_the_service_sends_goodbye() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let observed = start_observer(&rt);

    let label = unique_label("goodbye");
    let addr = Ipv4Addr::new(203, 0, 113, 30);
    let service = start_test_service(&rt, &label, vec![addr]);
    let name = format!("{label}.local");
    assert!(wait_for(|| service.is_announced(), Duration::from_secs(2)));
    observed.lock().unwrap().clear();

    drop(service);

    assert!(
        wait_for(
            || messages_for(&observed, &name).iter().any(|m| {
                m.flags & FLAG_QR != 0 && m.answers.iter().any(|rr| rr.name.eq_ignore_ascii_case(&name) && rr.ttl == 0)
            }),
            Duration::from_secs(1)
        ),
        "dropping the service must send a TTL-0 goodbye"
    );
}
