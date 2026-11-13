// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The DNS server's counters exported through a real `hopf-otel` pipeline
//! (issue #529): what a collector would receive for queries over different
//! transports, handler counters, cookies and multiple-QTYPE queries.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hopf_dns::server::{DnsService, DnsTransport, FnHandler, QueryContext};
use hopf_dns::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType};
use hopf_otel::{OtelConfig, TelemetryPipeline};

/// A pipeline writing metrics to a fresh JSONL file, and that file's path.
fn pipeline(label: &str) -> (TelemetryPipeline, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("hopf-dns-telemetry-{}-{label}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let p = TelemetryPipeline::start(OtelConfig::new(label).with_jsonl_metrics(&path)).unwrap();
    (p, path)
}

/// Everything exported so far.
fn exported(p: &TelemetryPipeline, path: &std::path::Path) -> String {
    p.export_handle().flush().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    std::fs::read_to_string(path).unwrap_or_default()
}

fn query(id: u16, name: &str, t: DnsType) -> DnsMessage {
    DnsMessage::query(id, DnsQuestion::in_class(name, t), true)
}

const PEER: &str = "198.51.100.7:5353";

#[test]
fn queries_and_responses_are_exported_with_their_transport_and_response_code() {
    let (p, path) = pipeline("basic");
    let mut service = DnsService::with_handler(FnHandler::new().on_query(|q| {
        let mut r = q.response_template(if q.questions[0].name == "gone.test" { 3 } else { 0 });
        if r.rcode() == 0 {
            r.answers.push(DnsResourceRecord::a(&q.questions[0].name, 60, Ipv4Addr::LOCALHOST));
        }
        Some(r)
    }));
    service.set_telemetry(p.dns_metrics());
    let peer: SocketAddr = PEER.parse().unwrap();

    service.process_on(&query(1, "ok.test", DnsType::A), peer, DnsTransport::Udp);
    service.process_on(&query(2, "gone.test", DnsType::A), peer, DnsTransport::Tcp);
    let body = exported(&p, &path);

    for needle in [
        "dns.server.queries",
        "dns.server.responses",
        "dns.server.query.duration",
        "NOERROR",
        "NXDOMAIN",
        "\"udp\"",
        "\"tcp\"",
        "dns.transport",
        "dns.response.code",
    ] {
        assert!(body.contains(needle), "missing {needle} in:\n{body}");
    }
    // The snapshot counters are untouched.
    assert_eq!(service.metrics().queries, 2);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn handler_counters_and_cookies_are_exported_too() {
    use hopf_dns::server::{DnsQueryCallback, DnsQueryHandler};

    struct Counting;
    impl DnsQueryHandler for Counting {
        fn handle_query(&self, q: &DnsMessage, ctx: &QueryContext, callback: DnsQueryCallback) {
            ctx.metrics().cache_hit();
            ctx.metrics().upstream();
            ctx.metrics().stale_served();
            ctx.metrics().aggressive_nsec();
            ctx.metrics().error();
            callback.respond(q.response_template(0));
        }
    }

    let (p, path) = pipeline("handler");
    let mut service = DnsService::with_handler(Counting);
    service.set_telemetry(p.dns_metrics());
    let peer: SocketAddr = PEER.parse().unwrap();

    // A client cookie with a server cookie we issued: verified.
    let client_cookie = [5u8; 8];
    let ip = match peer.ip() {
        std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
        std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let server_cookie = service.cookies().generate_server_cookie(&client_cookie, &ip);
    let mut data = Vec::new();
    data.extend_from_slice(&10u16.to_be_bytes());
    data.extend_from_slice(&((client_cookie.len() + server_cookie.len()) as u16).to_be_bytes());
    data.extend_from_slice(&client_cookie);
    data.extend_from_slice(&server_cookie);
    let mut q = query(1, "c.test", DnsType::A);
    q.additionals.push(DnsResourceRecord::opt(1232, false, &data));
    service.process_on(&q, peer, DnsTransport::Dot);

    let body = exported(&p, &path);
    for needle in [
        "dns.server.cache.hits",
        "dns.server.upstream.queries",
        "dns.server.stale_served",
        "dns.server.aggressive_nsec_hits",
        "dns.server.errors",
        "dns.server.cookies.presented",
        "dns.server.cookies.verified",
        "\"dot\"",
    ] {
        assert!(body.contains(needle), "missing {needle} in:\n{body}");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn multiple_qtype_expansion_is_exported() {
    use hopf_dns::multi_qtype::encode_mqtype_query_option;

    let (p, path) = pipeline("mqtype");
    let mut service = DnsService::with_handler(FnHandler::new().on_query(|q| Some(q.response_template(0))));
    service.set_max_multi_qtypes(4);
    service.set_telemetry(p.dns_metrics());
    let mut q = query(1, "m.test", DnsType::A);
    q.additionals
        .push(DnsResourceRecord::opt(1232, false, &encode_mqtype_query_option(&[DnsType::Aaaa, DnsType::Txt])));
    service.process_on(&q, PEER.parse().unwrap(), DnsTransport::Udp);
    let body = exported(&p, &path);
    for needle in ["dns.server.mqtype.queries", "dns.server.mqtype.subqueries"] {
        assert!(body.contains(needle), "missing {needle} in:\n{body}");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn nothing_is_exported_until_a_sink_is_attached() {
    // The default: no telemetry, counters still work.
    let service = DnsService::with_handler(FnHandler::new().on_query(|q| Some(q.response_template(0))));
    service.process_on(&query(1, "x.test", DnsType::A), PEER.parse().unwrap(), DnsTransport::Udp);
    assert_eq!(service.metrics().queries, 1);
    let _ = Arc::new(());
}
