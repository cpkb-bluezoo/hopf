// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Authoritative serving over real sockets: a primary and a secondary on
//! loopback exercising UPDATE, NOTIFY, AXFR/IXFR and SOA-timer refresh.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hopf_core::Runtime;
use hopf_dns::server::zone::client::{build_update, Transfer, ZoneClient};
use hopf_dns::server::zone::{Acl, AuthoritativeZoneHandler, Zone, ZoneFileMode, ZoneOptions};
use hopf_dns::tsig::{TsigAlgorithm, TsigKey, TsigKeyring};
use hopf_dns::server::{
    listen_dns_tcp, listen_dns_udp, DnsService, DnsServiceHandle, DnsUdpListenConfig,
};
use hopf_dns::wire::{
    DnsMessage, DnsQuestion, DnsResourceRecord, DnsType, FLAG_AA, RCODE_NOERROR, RCODE_NXDOMAIN,
    RCODE_REFUSED, RCODE_SERVFAIL,
};

const LOOPBACK: &str = "127.0.0.1";

fn zone_text(serial: u32, refresh: u32, expire: u32) -> String {
    format!(
        "$TTL 60\n@ SOA ns1 hostmaster {serial} {refresh} 1 {expire} 60\n NS ns1\nns1 A 192.0.2.1\nwww A 192.0.2.80\n"
    )
}

/// A UDP+TCP port pair that is free at the moment of asking, and that no
/// other test in this process has been handed (tests run in parallel).
fn free_port() -> u16 {
    static HANDED_OUT: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let tcp = TcpListener::bind((LOOPBACK, 0)).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let mut used = HANDED_OUT.lock().unwrap();
        if !used.contains(&port) && UdpSocket::bind((LOOPBACK, port)).is_ok() {
            used.push(port);
            return port;
        }
    }
}

struct Node {
    addr: SocketAddr,
    handle: DnsServiceHandle,
}

impl Node {
    fn start(rt: &Runtime, port: u16, handler: AuthoritativeZoneHandler) -> Node {
        Self::start_with(rt, port, handler, None)
    }

    fn start_with(
        rt: &Runtime,
        port: u16,
        handler: AuthoritativeZoneHandler,
        keyring: Option<TsigKeyring>,
    ) -> Node {
        let mut service = DnsService::with_handler(handler);
        if let Some(ring) = keyring {
            service.set_tsig_keyring(ring);
        }
        service.start(rt).unwrap();
        let handle = DnsServiceHandle::new(service);
        let addr: SocketAddr = format!("{LOOPBACK}:{port}").parse().unwrap();
        listen_dns_udp(rt.pick_worker(), DnsUdpListenConfig { addr, service: handle.clone() }).unwrap();
        listen_dns_tcp(rt, addr, handle.clone()).unwrap();
        Node { addr, handle }
    }

    fn stop(&self) {
        self.handle.service().stop();
    }
}

fn udp_query(server: SocketAddr, name: &str, ty: DnsType) -> DnsMessage {
    let sock = UdpSocket::bind((LOOPBACK, 0)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let q = DnsMessage::query(0x4242, DnsQuestion::in_class(name, ty), false);
    sock.send_to(&q.serialize().unwrap(), server).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    DnsMessage::parse(&buf[..n]).unwrap()
}

fn tcp_exchange(server: SocketAddr, q: &DnsMessage, expect: usize) -> Vec<DnsMessage> {
    let mut s = TcpStream::connect(server).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let bytes = q.serialize().unwrap();
    s.write_all(&(bytes.len() as u16).to_be_bytes()).unwrap();
    s.write_all(&bytes).unwrap();
    (0..expect)
        .map(|_| {
            let mut len = [0u8; 2];
            s.read_exact(&mut len).unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut buf).unwrap();
            DnsMessage::parse(&buf).unwrap()
        })
        .collect()
}

fn eventually<T>(what: &str, secs: u64, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = probe() {
            return v;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn www_addr(server: SocketAddr) -> Option<Ipv4Addr> {
    let r = udp_query(server, "www.example.org", DnsType::A);
    (r.rcode() == RCODE_NOERROR).then(|| r.answers.first().and_then(|a| a.as_a())).flatten()
}

fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hopf-authns-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn primary_options() -> ZoneOptions {
    ZoneOptions::new()
        .allow_transfer(Acl::any())
        .allow_update(Acl::from_cidrs([LOOPBACK]).unwrap())
        .notify_ns_records(false)
}

fn set_www(new: [u8; 4]) -> DnsMessage {
    build_update(
        "example.org",
        vec![],
        vec![
            DnsResourceRecord::opaque("www.example.org", 1, 255, 0, vec![]),
            DnsResourceRecord::a("www.example.org", 60, Ipv4Addr::from(new)),
        ],
    )
}

#[test]
fn serves_a_zone_file_authoritatively_over_udp_and_gates_transfers() {
    let dir = temp_dir("serve");
    let path = dir.join("example.org.zone");
    std::fs::write(&path, zone_text(7, 3600, 86400)).unwrap();
    let rt = Runtime::start(Default::default()).unwrap();
    let closed = AuthoritativeZoneHandler::builder()
        .zone_file(&path, Some("example.org"), ZoneFileMode::ReadOnly, ZoneOptions::new())
        .unwrap()
        .build()
        .unwrap();
    let node = Node::start(&rt, free_port(), closed);

    let soa = udp_query(node.addr, "example.org", DnsType::Soa);
    assert!(soa.flags & FLAG_AA != 0);
    assert_eq!(soa.answers[0].as_soa().unwrap().serial, 7);
    assert_eq!(www_addr(node.addr), Some(Ipv4Addr::new(192, 0, 2, 80)));
    assert_eq!(udp_query(node.addr, "nope.example.org", DnsType::A).rcode(), RCODE_NXDOMAIN);
    assert_eq!(udp_query(node.addr, "example.net", DnsType::A).rcode(), RCODE_REFUSED);

    // Default options are closed: no transfer for anyone.
    let axfr = DnsMessage::new(1, 0, vec![DnsQuestion::opaque("example.org", 252, 1)], vec![], vec![], vec![]);
    assert_eq!(tcp_exchange(node.addr, &axfr, 1)[0].rcode(), RCODE_REFUSED);
    // And no update either.
    let resp = ZoneClient::new().update(node.addr, &set_www([1, 1, 1, 1])).unwrap();
    assert_eq!(resp.rcode(), RCODE_REFUSED);
    assert_eq!(www_addr(node.addr), Some(Ipv4Addr::new(192, 0, 2, 80)));
    // AXFR over UDP is never answered in full.
    let r = udp_query(node.addr, "example.org", DnsType::Any);
    assert_eq!(r.answers.len(), 1, "minimal ANY");
    node.stop();
    rt.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn update_notifies_the_secondary_which_converges_without_waiting_for_its_timer() {
    let dir = temp_dir("notify");
    let rt = Runtime::start(Default::default()).unwrap();
    let (pport, sport) = (free_port(), free_port());
    let paddr: SocketAddr = format!("{LOOPBACK}:{pport}").parse().unwrap();
    let saddr: SocketAddr = format!("{LOOPBACK}:{sport}").parse().unwrap();
    let ppath = dir.join("primary.zone");
    let spath = dir.join("secondary.zone");

    // REFRESH is an hour: only NOTIFY can make the secondary catch up in time.
    let zone = Zone::from_zone_text(&zone_text(1, 3600, 86400), Some("example.org")).unwrap();
    let primary = Node::start(
        &rt,
        pport,
        AuthoritativeZoneHandler::builder()
            .zone_with(zone, primary_options().also_notify(saddr).persist(&ppath, ZoneFileMode::ReadWrite))
            .build()
            .unwrap(),
    );
    let secondary = Node::start(
        &rt,
        sport,
        AuthoritativeZoneHandler::builder()
            .secondary("example.org", paddr, ZoneOptions::new().persist(&spath, ZoneFileMode::ReadWrite))
            .build()
            .unwrap(),
    );

    // Until the first transfer completes the secondary cannot answer.
    // (It may already have transferred by the time we ask, so just require
    // convergence.)
    eventually("initial transfer", 10, || {
        (www_addr(secondary.addr) == Some(Ipv4Addr::new(192, 0, 2, 80))).then_some(())
    });

    // Update the primary.
    let resp = ZoneClient::new().update(primary.addr, &set_www([203, 0, 113, 7])).unwrap();
    assert_eq!(resp.rcode(), RCODE_NOERROR);
    assert_eq!(www_addr(primary.addr), Some(Ipv4Addr::new(203, 0, 113, 7)));
    eventually("NOTIFY-driven refresh", 8, || {
        (www_addr(secondary.addr) == Some(Ipv4Addr::new(203, 0, 113, 7))).then_some(())
    });

    // The secondary refuses updates.
    let resp = ZoneClient::new().update(secondary.addr, &set_www([9, 9, 9, 9])).unwrap();
    assert_eq!(resp.rcode(), RCODE_REFUSED);
    assert_eq!(www_addr(secondary.addr), Some(Ipv4Addr::new(203, 0, 113, 7)));

    // Both wrote their own zone file.
    eventually("primary zone file", 5, || {
        let z = Zone::from_zone_file(&ppath, Some("example.org")).ok()?;
        (z.serial() == 2).then_some(())
    });
    eventually("secondary zone file", 5, || {
        let z = Zone::from_zone_file(&spath, Some("example.org")).ok()?;
        (z.serial() == 2).then_some(())
    });

    // IXFR from the primary now yields just the difference.
    match ZoneClient::new().transfer(primary.addr, "example.org", Some(1)).unwrap() {
        Transfer::Incremental(diffs) => assert_eq!(diffs.len(), 1),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        ZoneClient::new().transfer(primary.addr, "example.org", Some(2)).unwrap(),
        Transfer::UpToDate
    );
    match ZoneClient::new().transfer(primary.addr, "example.org", None).unwrap() {
        Transfer::Full(rrs) => assert_eq!(rrs.first().unwrap().as_soa().unwrap().serial, 2),
        other => panic!("{other:?}"),
    }

    primary.stop();
    secondary.stop();
    rt.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_secondary_converges_on_the_soa_refresh_timer_with_no_notify_at_all() {
    let rt = Runtime::start(Default::default()).unwrap();
    let (pport, sport) = (free_port(), free_port());
    let paddr: SocketAddr = format!("{LOOPBACK}:{pport}").parse().unwrap();

    // No also_notify and no NS notification: nothing tells the secondary.
    let zone = Zone::from_zone_text(&zone_text(1, 1, 86400), Some("example.org")).unwrap();
    let primary = Node::start(
        &rt,
        pport,
        AuthoritativeZoneHandler::builder().zone_with(zone, primary_options()).build().unwrap(),
    );
    let secondary = Node::start(
        &rt,
        sport,
        AuthoritativeZoneHandler::builder()
            .secondary("example.org", paddr, ZoneOptions::new())
            .build()
            .unwrap(),
    );
    eventually("initial transfer", 10, || {
        (www_addr(secondary.addr) == Some(Ipv4Addr::new(192, 0, 2, 80))).then_some(())
    });
    assert_eq!(
        ZoneClient::new().update(primary.addr, &set_www([198, 51, 100, 1])).unwrap().rcode(),
        RCODE_NOERROR
    );
    eventually("timer-driven refresh", 10, || {
        (www_addr(secondary.addr) == Some(Ipv4Addr::new(198, 51, 100, 1))).then_some(())
    });
    primary.stop();
    secondary.stop();
    rt.shutdown();
}

#[test]
fn a_secondary_serves_its_persisted_copy_then_expires_when_the_primary_stays_away() {
    let dir = temp_dir("expire");
    let path = dir.join("secondary.zone");
    // EXPIRE of 2 seconds, RETRY of 1.
    std::fs::write(&path, zone_text(5, 3600, 2)).unwrap();
    let rt = Runtime::start(Default::default()).unwrap();
    let dead: SocketAddr = format!("{LOOPBACK}:{}", free_port()).parse().unwrap();
    let secondary = Node::start(
        &rt,
        free_port(),
        AuthoritativeZoneHandler::builder()
            .secondary("example.org", dead, ZoneOptions::new().persist(&path, ZoneFileMode::ReadOnly))
            .build()
            .unwrap(),
    );
    assert_eq!(
        www_addr(secondary.addr),
        Some(Ipv4Addr::new(192, 0, 2, 80)),
        "served from the persisted file while the primary is unreachable"
    );
    eventually("EXPIRE", 15, || {
        (udp_query(secondary.addr, "www.example.org", DnsType::A).rcode() == RCODE_SERVFAIL).then_some(())
    });
    secondary.stop();
    rt.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn notify_from_anyone_but_the_primary_is_refused_and_unknown_zones_are_notauth() {
    let rt = Runtime::start(Default::default()).unwrap();
    let primary_elsewhere: SocketAddr = "192.0.2.99:53".parse().unwrap();
    let secondary = Node::start(
        &rt,
        free_port(),
        AuthoritativeZoneHandler::builder()
            .secondary("example.org", primary_elsewhere, ZoneOptions::new())
            .build()
            .unwrap(),
    );
    let client = ZoneClient::new();
    let err = client.notify(secondary.addr, "example.org").unwrap_err();
    assert!(err.to_string().contains("rcode 5"), "REFUSED: {err}");
    let err = client.notify(secondary.addr, "unknown.example").unwrap_err();
    assert!(err.to_string().contains("rcode 9"), "NOTAUTH: {err}");
    secondary.stop();
    rt.shutdown();
}

fn tsig_key(secret: u8) -> TsigKey {
    TsigKey::new("xfer-key", TsigAlgorithm::HmacSha256, vec![secret; 32])
}

#[test]
fn tsig_gates_transfers_and_updates_and_a_secondary_signs_its_requests() {
    let rt = Runtime::start(Default::default()).unwrap();
    let (pport, sport) = (free_port(), free_port());
    let paddr: SocketAddr = format!("{LOOPBACK}:{pport}").parse().unwrap();
    let saddr: SocketAddr = format!("{LOOPBACK}:{sport}").parse().unwrap();

    // Only the key opens transfers and updates: not the source address.
    let zone = Zone::from_zone_text(&zone_text(1, 3600, 86400), Some("example.org")).unwrap();
    let opts = ZoneOptions::new()
        .allow_transfer(Acl::tsig_key("xfer-key"))
        .allow_update(Acl::tsig_key("xfer-key"))
        .also_notify(saddr)
        .notify_ns_records(false)
        .tsig_key(tsig_key(1));
    let primary = Node::start_with(
        &rt,
        pport,
        AuthoritativeZoneHandler::builder().zone_with(zone, opts).build().unwrap(),
        Some(TsigKeyring::new().with_key(tsig_key(1))),
    );
    // The secondary knows the same key (to sign, and to verify the NOTIFY).
    let secondary = Node::start_with(
        &rt,
        sport,
        AuthoritativeZoneHandler::builder()
            .secondary("example.org", paddr, ZoneOptions::new().tsig_key(tsig_key(1)))
            .build()
            .unwrap(),
        Some(TsigKeyring::new().with_key(tsig_key(1))),
    );

    eventually("signed initial transfer", 10, || {
        (www_addr(secondary.addr) == Some(Ipv4Addr::new(192, 0, 2, 80))).then_some(())
    });

    // Unsigned and wrongly signed clients are refused, for transfers...
    let unsigned = ZoneClient::new();
    assert!(unsigned.transfer(primary.addr, "example.org", None).is_err());
    let wrong = ZoneClient::new().with_tsig(tsig_key(2));
    assert!(wrong.transfer(primary.addr, "example.org", None).is_err());
    // ...and for updates.
    assert_eq!(unsigned.update(primary.addr, &set_www([6, 6, 6, 6])).unwrap().rcode(), RCODE_REFUSED);
    let bad = wrong.update(primary.addr, &set_www([6, 6, 6, 6]));
    assert!(bad.is_err(), "a response signed under another key cannot be trusted: {bad:?}");
    assert_eq!(www_addr(primary.addr), Some(Ipv4Addr::new(192, 0, 2, 80)));

    // The right key does both, and the responses verify.
    let good = ZoneClient::new().with_tsig(tsig_key(1));
    assert_eq!(good.update(primary.addr, &set_www([203, 0, 113, 8])).unwrap().rcode(), RCODE_NOERROR);
    match good.transfer(primary.addr, "example.org", None).unwrap() {
        Transfer::Full(rrs) => assert_eq!(rrs[0].as_soa().unwrap().serial, 2),
        other => panic!("{other:?}"),
    }
    // A signed NOTIFY reaches the secondary, which pulls the change with its own signature.
    eventually("signed NOTIFY-driven refresh", 8, || {
        (www_addr(secondary.addr) == Some(Ipv4Addr::new(203, 0, 113, 8))).then_some(())
    });

    primary.stop();
    secondary.stop();
    rt.shutdown();
}
