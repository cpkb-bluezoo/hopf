// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `UpstreamClient` (issue #526) against real loopback TLS (and QUIC) servers
//! that misbehave on cue: queries pipelined and answered out of order, a
//! connection killed under a query, an idle close, a query that is never
//! answered. Every callback must run exactly once.

use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hopf_core::{Bytes, Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_dns::client::{UpstreamClient, UpstreamConfig, UpstreamError, UpstreamResult, UpstreamTls};
use hopf_dns::wire::{DnsMessage, DnsQuestion, DnsResourceRecord, DnsType};

const SLOW: Duration = Duration::from_millis(500);

fn query(id: u16, name: &str) -> DnsMessage {
    DnsMessage::query(id, DnsQuestion::in_class(name, DnsType::A), true)
}

fn answer_to(q: &DnsMessage) -> DnsMessage {
    let mut r = q.response_template(0);
    let name = q.questions[0].name.clone();
    r.answers.push(DnsResourceRecord::a(&name, 60, Ipv4Addr::new(192, 0, 2, 7)));
    r
}

/// What the test server has seen.
#[derive(Default)]
struct Stats {
    connections: AtomicUsize,
    queries: AtomicUsize,
    closed: AtomicUsize,
    /// Names already dropped once, for `dropfirst-*`.
    dropped: Mutex<Vec<String>>,
}

/// A DoT server whose behaviour is chosen by the first label of the name:
///
/// * `fast-*`: answered at once.
/// * `slow-*`: answered after `SLOW`, from another thread.
/// * `late-*`: answered after 1.5 s.
/// * `hang-*`: never answered.
/// * `drop-*`: the connection is closed instead of answering.
/// * `dropfirst-*`: the connection is closed the first time the name is seen,
///   answered after that.
struct TestDot {
    stats: Arc<Stats>,
    buf: Vec<u8>,
}

fn frame(m: &DnsMessage) -> Vec<u8> {
    let b = m.serialize().unwrap();
    let mut out = (b.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&b);
    out
}

impl ProtocolHandler for TestDot {
    fn connected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.stats.connections.fetch_add(1, Ordering::SeqCst);
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        let mut queries = Vec::new();
        hopf_core::with_slice(buf, |data| {
            self.buf.extend_from_slice(data);
            *data = &[];
            while self.buf.len() >= 2 {
                let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
                if self.buf.len() < 2 + len {
                    break;
                }
                queries.push(DnsMessage::parse(&self.buf[2..2 + len]).unwrap());
                self.buf.drain(..2 + len);
            }
        });
        for q in queries {
            self.stats.queries.fetch_add(1, Ordering::SeqCst);
            let name = q.questions[0].name.clone();
            let kind = name.split('-').next().unwrap_or("").to_string();
            let reply = frame(&answer_to(&q));
            let delayed = |wait: Duration, endpoint: &mut dyn Endpoint, reply: Vec<u8>| {
                let handle = endpoint.handle();
                thread::spawn(move || {
                    thread::sleep(wait);
                    handle.with_endpoint(move |ep| ep.send(&reply));
                });
            };
            match kind.as_str() {
                "fast" => endpoint.send(&reply),
                "slow" => delayed(SLOW, endpoint, reply),
                "late" => delayed(Duration::from_millis(1500), endpoint, reply),
                "hang" => {}
                "drop" => endpoint.close(),
                "dropfirst" => {
                    let mut seen = self.stats.dropped.lock().unwrap();
                    if seen.contains(&name) {
                        drop(seen);
                        endpoint.send(&reply);
                    } else {
                        seen.push(name);
                        drop(seen);
                        endpoint.close();
                    }
                }
                other => panic!("unexpected test name kind {other}"),
            }
        }
    }

    fn disconnected(&mut self, _endpoint: &mut dyn Endpoint) {
        self.stats.closed.fetch_add(1, Ordering::SeqCst);
    }

    fn error(&mut self, _endpoint: &mut dyn Endpoint, _err: &std::io::Error) {}
}

struct Identity {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Identity {
    fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Self { cert, key }
    }

    fn der(&self) -> Bytes {
        Bytes::copy_from_slice(self.cert.der())
    }

    fn credentials(&self) -> hopf_core::ServerCredentials {
        hopf_core::server_credentials_from_pem_bytes(self.cert.pem().as_bytes(), self.key.serialize_pem().as_bytes())
            .unwrap()
    }

    fn pem_files(&self, label: &str) -> (PathBuf, PathBuf) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "hopf-dns-upstream-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (c, k) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&c, self.cert.pem()).unwrap();
        std::fs::write(&k, self.key.serialize_pem()).unwrap();
        (c, k)
    }
}

struct Server {
    rt: Runtime,
    addr: SocketAddr,
    stats: Arc<Stats>,
}

impl Server {
    fn start(acceptor: hopf_core::SharedTlsAcceptor) -> Self {
        let stats = Arc::new(Stats::default());
        let s = Arc::clone(&stats);
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let (addr, _) = rt
            .add_tcp_listener(
                TcpListenerConfig::new("127.0.0.1:0".parse().unwrap(), move || {
                    Box::new(TestDot {
                        stats: Arc::clone(&s),
                        buf: Vec::new(),
                    }) as Box<dyn ProtocolHandler>
                })
                .with_tls(acceptor),
            )
            .unwrap();
        Self { rt, addr, stats }
    }

    /// A server with a fresh self-signed identity, and the TLS settings that
    /// trust it.
    fn plain() -> (Self, Identity, UpstreamTls) {
        let id = Identity::new("localhost");
        let (c, k) = id.pem_files("server");
        let acceptor = hopf_core::acceptor_from_pem(&c, &k, &[b"dot"]).unwrap();
        let tls = UpstreamTls::builder("localhost").trust_anchors([id.der()]).build().unwrap();
        (Self::start(acceptor), id, tls)
    }

    fn connections(&self) -> usize {
        self.stats.connections.load(Ordering::SeqCst)
    }
}

fn client(server: &Server, tls: UpstreamTls, config: UpstreamConfig) -> UpstreamClient {
    UpstreamClient::dot(server.rt.pick_worker().clone(), server.addr, tls, config)
}

/// A client on its own runtime, for tests where the server is elsewhere.
fn quick() -> UpstreamConfig {
    UpstreamConfig {
        timeout: Duration::from_secs(5),
        ..Default::default()
    }
}

/// Send `message` and return a receiver for the one result.
fn ask(c: &UpstreamClient, message: DnsMessage) -> Receiver<(UpstreamResult, Instant)> {
    let (tx, rx) = mpsc::channel();
    c.query(message, move |r| {
        let _ = tx.send((r, Instant::now()));
    });
    rx
}

fn await_result(rx: &Receiver<(UpstreamResult, Instant)>) -> (UpstreamResult, Instant) {
    rx.recv_timeout(Duration::from_secs(10)).expect("the callback ran")
}

/// No second result ever arrives on `rx`.
fn assert_exactly_once(rx: &Receiver<(UpstreamResult, Instant)>, wait: Duration) {
    assert!(rx.recv_timeout(wait).is_err(), "the callback ran twice");
}

#[test]
fn queries_are_pipelined_and_a_fast_answer_does_not_wait_for_a_slow_one() {
    let (server, _id, tls) = Server::plain();
    let c = client(&server, tls, quick());

    let started = Instant::now();
    let slow = ask(&c, query(7, "slow-1.test"));
    let fast = ask(&c, query(7, "fast-1.test")); // the same caller ID, on purpose
    let (fast_result, fast_at) = await_result(&fast);
    let (slow_result, slow_at) = await_result(&slow);

    let fast_answer = fast_result.expect("fast answered");
    let slow_answer = slow_result.expect("slow answered");
    assert_eq!(fast_answer.questions[0].name, "fast-1.test");
    assert_eq!(slow_answer.questions[0].name, "slow-1.test");
    assert_eq!((fast_answer.id, slow_answer.id), (7, 7), "each caller's own ID comes back");
    assert!(fast_at < slow_at, "the fast answer overtook the slow one");
    assert!(fast_at - started < SLOW / 2, "the fast query was not held up by the slow one");
    assert!(slow_at - started >= SLOW);
    assert_eq!(server.connections(), 1, "both rode one connection");

    let m = c.metrics();
    assert_eq!((m.queries, m.responses, m.connects, m.connections, m.in_flight), (2, 2, 1, 1, 0));
    assert!(m.latency_micros_max >= SLOW.as_micros() as u64);
    c.close();
}

#[test]
fn a_hundred_concurrent_queries_each_get_their_own_answer_once() {
    let (server, _id, tls) = Server::plain();
    let c = client(&server, tls, quick());
    let receivers: Vec<_> = (0..100)
        .map(|i| {
            let kind = if i % 3 == 0 { "slow" } else { "fast" };
            // Many callers using the same few IDs.
            (i, ask(&c, query((i % 4) as u16, &format!("{kind}-{i}.test"))))
        })
        .collect();
    for (i, rx) in &receivers {
        let (result, _) = await_result(rx);
        let answer = result.unwrap_or_else(|e| panic!("query {i}: {e}"));
        assert!(answer.questions[0].name.ends_with(&format!("-{i}.test")), "query {i} got another's answer");
        assert_eq!(answer.id, (*i % 4) as u16);
    }
    for (_, rx) in &receivers {
        assert_exactly_once(rx, Duration::from_millis(1));
    }
    assert_eq!(server.connections(), 1);
    assert_eq!(c.metrics().responses, 100);
    c.close();
}

#[test]
fn an_unanswered_query_times_out_once_and_a_late_answer_is_discarded() {
    let (server, _id, tls) = Server::plain();
    let c = client(
        &server,
        tls,
        UpstreamConfig {
            timeout: Duration::from_millis(400),
            ..Default::default()
        },
    );
    let started = Instant::now();
    let hang = ask(&c, query(1, "hang-1.test"));
    let late = ask(&c, query(2, "late-1.test"));
    let (r, at) = await_result(&hang);
    assert_eq!(r.unwrap_err(), UpstreamError::Timeout);
    assert!(at - started >= Duration::from_millis(400) && at - started < Duration::from_millis(1200));
    assert_eq!(await_result(&late).0.unwrap_err(), UpstreamError::Timeout);

    // The server answers `late` after 1.5 s: nothing more reaches the callback.
    assert_exactly_once(&late, Duration::from_millis(1400));
    assert_exactly_once(&hang, Duration::from_millis(1));
    let m = c.metrics();
    assert_eq!((m.timeouts, m.responses, m.in_flight), (2, 0, 0));

    // The connection is still good for the next query.
    assert!(await_result(&ask(&c, query(3, "fast-1.test"))).0.is_ok());
    assert_eq!(server.connections(), 1);
    c.close();
}

#[test]
fn a_query_on_a_connection_that_is_killed_is_sent_again_and_runs_its_callback_once() {
    let (server, _id, tls) = Server::plain();
    let c = client(&server, tls, quick());
    // The server closes the connection the first time it sees the name.
    let rx = ask(&c, query(1, "dropfirst-1.test"));
    let (result, _) = await_result(&rx);
    assert_eq!(result.expect("answered after the retry").questions[0].name, "dropfirst-1.test");
    assert_exactly_once(&rx, Duration::from_millis(300));
    assert_eq!(server.connections(), 2, "a second connection carried the retry");
    let m = c.metrics();
    assert_eq!((m.retries, m.reconnects, m.responses, m.failures), (1, 1, 1, 0));
    c.close();
}

#[test]
fn a_query_that_keeps_losing_its_connection_fails_once_after_its_retries() {
    let (server, _id, tls) = Server::plain();
    let c = client(&server, tls, quick());
    let rx = ask(&c, query(1, "drop-1.test"));
    let (result, _) = await_result(&rx);
    assert!(matches!(result, Err(UpstreamError::ConnectionLost(_))), "{result:?}");
    assert_exactly_once(&rx, Duration::from_millis(300));
    assert_eq!(server.connections(), 2, "the original attempt and one retry");

    // Reconnects lazily for the next query.
    assert!(await_result(&ask(&c, query(2, "fast-1.test"))).0.is_ok());
    assert_eq!(server.connections(), 3);
    c.close();
}

#[test]
fn a_connection_lost_under_several_queries_completes_each_exactly_once() {
    let (server, _id, tls) = Server::plain();
    let c = client(&server, tls, quick());
    let mut all = Vec::new();
    for i in 0..10 {
        all.push(ask(&c, query(i, &format!("hang-{i}.test"))));
    }
    // Everything is outstanding on one connection; this query closes it, and
    // closes the connection its retry opens too.
    all.push(ask(&c, query(99, "drop-1.test")));
    for rx in &all {
        // The hung queries were sent again on the second connection, which
        // the retry of `drop` then killed: out of retries, each one fails.
        let (result, _) = await_result(rx);
        assert!(matches!(result, Err(UpstreamError::ConnectionLost(_))), "{result:?}");
    }
    for rx in &all {
        assert_exactly_once(rx, Duration::from_millis(1));
    }
    let m = c.metrics();
    assert_eq!((m.queries, m.failures, m.responses, m.in_flight), (11, 11, 0, 0));
    c.close();
}

#[test]
fn closing_the_client_fails_every_waiting_query_once_and_later_ones_too() {
    let (server, _id, tls) = Server::plain();
    let c = client(&server, tls, quick());
    let waiting: Vec<_> = (0..5).map(|i| ask(&c, query(i, &format!("hang-{i}.test")))).collect();
    // Let them reach the server.
    for _ in 0..100 {
        if server.stats.queries.load(Ordering::SeqCst) == 5 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    c.close();
    for rx in &waiting {
        assert_eq!(await_result(rx).0.unwrap_err(), UpstreamError::Closed);
        assert_exactly_once(rx, Duration::from_millis(1));
    }
    let after = server.connections();
    assert_eq!(await_result(&ask(&c, query(5, "fast-1.test"))).0.unwrap_err(), UpstreamError::Closed);
    assert_eq!(server.connections(), after, "no connection for a closed client");
}

#[test]
fn an_idle_connection_is_closed_and_reopened_by_the_next_query() {
    let (server, _id, tls) = Server::plain();
    let c = client(
        &server,
        tls,
        UpstreamConfig {
            timeout: Duration::from_millis(300),
            idle_timeout: Duration::from_millis(300),
            ..Default::default()
        },
    );
    assert!(await_result(&ask(&c, query(1, "fast-1.test"))).0.is_ok());
    assert_eq!(c.metrics().connections, 1);

    // Idle long enough for the client to hang up.
    for _ in 0..100 {
        if server.stats.closed.load(Ordering::SeqCst) == 1 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(server.stats.closed.load(Ordering::SeqCst), 1, "the idle connection was closed");
    assert_eq!(c.metrics().connections, 0);

    assert!(await_result(&ask(&c, query(2, "fast-2.test"))).0.is_ok());
    assert_eq!(server.connections(), 2);
    assert_eq!(c.metrics().reconnects, 1);
    c.close();
}

#[test]
fn a_busy_pool_opens_another_connection_up_to_its_limit() {
    let (server, _id, tls) = Server::plain();
    let c = client(
        &server,
        tls,
        UpstreamConfig {
            max_connections: 2,
            ..quick()
        },
    );
    let a = ask(&c, query(1, "slow-1.test"));
    let b = ask(&c, query(2, "slow-2.test")); // the first is still outstanding
    let d = ask(&c, query(3, "slow-3.test")); // the pool is full: shares
    for rx in [&a, &b, &d] {
        assert!(await_result(rx).0.is_ok());
    }
    assert_eq!(server.connections(), 2);
    assert_eq!(c.metrics().connections, 2, "the pool size");
    c.close();
}

#[test]
fn a_refused_connection_fails_its_queries_once_with_connect_and_never_inline() {
    // A port nobody listens on.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let id = Identity::new("localhost");
    let tls = UpstreamTls::builder("localhost").trust_anchors([id.der()]).build().unwrap();
    let c = UpstreamClient::dot(rt.pick_worker().clone(), dead, tls, quick());

    // Hold a lock across `query`: a callback that ran inline would deadlock on it.
    let gate = Arc::new(Mutex::new(()));
    let (tx, rx) = mpsc::channel();
    {
        let _held = gate.lock().unwrap();
        let g = Arc::clone(&gate);
        c.query(query(1, "fast-1.test"), move |r| {
            let _wait = g.lock().unwrap();
            let _ = tx.send(r);
        });
    }
    let result = rx.recv_timeout(Duration::from_secs(10)).expect("the callback ran");
    assert!(matches!(result, Err(UpstreamError::Connect(_))), "{result:?}");
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    let m = c.metrics();
    assert_eq!((m.failures, m.connect_failures, m.connects), (1, 1, 0));
    c.close();
    rt.shutdown();
}

#[test]
fn certificate_pins_decide_the_connection() {
    let id = Identity::new("localhost");
    let (cert, key) = id.pem_files("pin");
    let acceptor = hopf_core::acceptor_from_pem(&cert, &key, &[b"dot"]).unwrap();
    let server = Server::start(acceptor);
    let pin: [u8; 32] = hopf_core::crypto::spki_sha256(&id.der()).unwrap().as_ref().try_into().unwrap();

    let ok = |tls: UpstreamTls| await_result(&ask(&client(&server, tls, quick()), query(1, "fast-1.test"))).0;

    // The right pin, and the chain check passes.
    let right = UpstreamTls::builder("localhost").trust_anchors([id.der()]).pin_spki_sha256(pin).build().unwrap();
    assert!(ok(right).is_ok());
    // A rolled pin set: any one match is enough.
    let rolled = UpstreamTls::builder("localhost")
        .trust_anchors([id.der()])
        .pin_spki_sha256([0u8; 32])
        .pin_spki_sha256(pin)
        .build()
        .unwrap();
    assert!(ok(rolled).is_ok());
    // A wrong pin fails even though the chain is trusted.
    let wrong = UpstreamTls::builder("localhost").trust_anchors([id.der()]).pin_spki_sha256([1u8; 32]).build().unwrap();
    assert!(matches!(ok(wrong), Err(UpstreamError::Connect(_))));
    // Pin only: no anchors, no chain validation, the pin is the whole decision.
    let pin_only = UpstreamTls::builder("localhost").pin_spki_sha256(pin).pins_only().build().unwrap();
    assert!(ok(pin_only).is_ok());
    // The default trust is the public WebPKI, which does not know this server.
    let public = UpstreamTls::builder("localhost").build().unwrap();
    assert!(matches!(ok(public), Err(UpstreamError::Connect(_))));
    // pins_only without a pin would verify nothing.
    assert!(UpstreamTls::builder("localhost").pins_only().build().is_err());
}

#[test]
fn a_client_certificate_is_presented_for_mutual_tls() {
    use hopf_core::{ClientAuthPolicy, ClientVerifyOverride, ServerTlsBuilder};

    let server_id = Identity::new("localhost");
    let client_id = Identity::new("client.example");
    let allowed = client_id.der();
    let acceptor = ServerTlsBuilder::new()
        .credentials(server_id.credentials())
        .alpn(&[b"dot"])
        .client_auth(ClientAuthPolicy::Require)
        .client_verify(ClientVerifyOverride::new(move |chain| chain.first() == Some(&allowed)))
        .build()
        .unwrap();
    let server = Server::start(acceptor);

    let with_cert = UpstreamTls::builder("localhost")
        .trust_anchors([server_id.der()])
        .client_credentials(client_id.credentials())
        .build()
        .unwrap();
    let c = client(&server, with_cert, quick());
    assert!(await_result(&ask(&c, query(1, "fast-1.test"))).0.is_ok());
    c.close();

    // Without one the server hangs up: the TLS 1.3 client completes its
    // handshake first, so the refusal shows as a lost connection.
    let without = UpstreamTls::builder("localhost").trust_anchors([server_id.der()]).build().unwrap();
    let c = client(&server, without, quick());
    let r = await_result(&ask(&c, query(2, "fast-2.test"))).0;
    assert!(r.is_err(), "{r:?}");
    c.close();
}

/// The client's events reach a `hopf-otel` pipeline: queries, answers and
/// their latency, a timeout, the connection and the in-flight gauge, each
/// labelled with the upstream and transport.
#[test]
fn upstream_events_are_exported_through_a_telemetry_pipeline() {
    use hopf_otel::{OtelConfig, TelemetryPipeline};

    let path = std::env::temp_dir().join(format!("hopf-dns-upstream-telemetry-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let pipeline = TelemetryPipeline::start(OtelConfig::new("upstream-test").with_jsonl_metrics(&path)).unwrap();

    let (server, _id, tls) = Server::plain();
    let c = client(
        &server,
        tls,
        UpstreamConfig {
            timeout: Duration::from_millis(300),
            ..Default::default()
        },
    );
    c.set_telemetry(pipeline.dns_upstream_metrics());
    assert!(await_result(&ask(&c, query(1, "fast-1.test"))).0.is_ok());
    assert_eq!(await_result(&ask(&c, query(2, "hang-1.test"))).0.unwrap_err(), UpstreamError::Timeout);

    pipeline.export_handle().flush().unwrap();
    thread::sleep(Duration::from_millis(100));
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    for needle in [
        "dns.upstream.queries",
        "dns.upstream.responses",
        "dns.upstream.query.duration",
        "dns.upstream.timeouts",
        "dns.upstream.connects",
        "dns.upstream.connections",
        "dns.upstream.in_flight",
        "\"dot\"",
        &server.addr.to_string(),
    ] {
        assert!(body.contains(needle), "missing {needle} in:\n{body}");
    }
    c.close();
    let _ = std::fs::remove_file(&path);
}

/// The forwarder, over a resolver whose upstream is DoT, answers a quick query
/// while a slow one is still outstanding at the same upstream: the listener
/// thread is never held, and the two share one pipelined connection.
#[test]
fn a_forwarder_over_dot_is_not_held_up_by_a_slow_upstream_query() {
    use hopf_dns::server::{DnsService, DnsTransport, ForwarderHandler};
    use hopf_dns::{DnsCache, DnsResolver};

    let (server, id, _tls) = Server::plain();
    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let resolver = DnsResolver::new(rt.pick_worker().clone());
    let connector = hopf_core::ClientTlsBuilder::new().trust_anchors([id.der()]).alpn(&[b"dot"]).build();
    resolver.add_server_dot(server.addr, "localhost", connector);
    resolver.open().unwrap();
    let service = DnsService::with_handler(ForwarderHandler::new(Arc::new(DnsCache::default())).with_upstream(resolver.clone()));

    let dispatch = |id: u16, name: &str| {
        let (tx, rx) = mpsc::channel();
        let wire = query(id, name).serialize().unwrap();
        assert!(service.dispatch_wire(
            &wire,
            "127.0.0.1:5353".parse().unwrap(),
            DnsTransport::Udp,
            Box::new(move |responses| {
                let _ = tx.send((responses, Instant::now()));
            }),
        ));
        rx
    };
    let started = Instant::now();
    let slow = dispatch(1, "slow-9.test");
    let fast = dispatch(2, "fast-9.test");
    let (fast_resp, fast_at) = fast.recv_timeout(Duration::from_secs(5)).expect("fast answered");
    let (slow_resp, slow_at) = slow.recv_timeout(Duration::from_secs(5)).expect("slow answered");

    assert_eq!(DnsMessage::parse(&fast_resp[0]).unwrap().answers.len(), 1);
    assert_eq!(DnsMessage::parse(&slow_resp[0]).unwrap().answers.len(), 1);
    assert!(fast_at - started < SLOW / 2, "the quick query waited for the slow one");
    assert!(slow_at - started >= SLOW);
    assert_eq!(server.connections(), 1, "both queries shared one DoT connection");
    let metrics = resolver.dot_upstream_metrics();
    assert_eq!(metrics.len(), 1);
    assert_eq!((metrics[0].1.queries, metrics[0].1.responses), (2, 2));
    rt.shutdown();
}

/// A DoQ server whose answers are scripted by the first label of the name,
/// and the client settings that trust it.
#[cfg(feature = "doq")]
fn doq_server() -> (hopf_quic::QuicDriverHandle, Arc<hopf_quic::QuicClientConfig>) {
    use hopf_core::{HandshakeConfig, HandshakeMode, HandshakeRole};
    use hopf_dns::server::{
        listen_dns_doq, DnsQueryCallback, DnsQueryHandler, DnsService, DnsServiceHandle, QueryContext,
    };
    use hopf_quic::QuicClientConfig;

    struct Scripted;
    impl DnsQueryHandler for Scripted {
        fn handle_query(&self, q: &DnsMessage, _ctx: &QueryContext, callback: DnsQueryCallback) {
            let reply = answer_to(q);
            match q.questions[0].name.split('-').next() {
                Some("slow") => {
                    thread::spawn(move || {
                        thread::sleep(SLOW);
                        callback.respond(reply);
                    });
                }
                Some("hang") => {
                    // Hold the callback, and complete nothing, for a while.
                    thread::spawn(move || {
                        thread::sleep(Duration::from_secs(3));
                        drop(callback);
                    });
                }
                _ => callback.respond(reply),
            }
        }
    }

    let server_id = Identity::new("localhost");
    let server_config = hopf_quic::server_config_from_tls_builder(
        &hopf_core::ServerTlsBuilder::new()
            .credentials(server_id.credentials())
            .alpn(&[b"doq"]),
    )
    .unwrap();
    let handle = DnsServiceHandle::new(DnsService::with_handler(Scripted));
    let driver = listen_dns_doq("127.0.0.1:0".parse().unwrap(), server_config, handle).unwrap();
    let mut trust = hopf_core::crypto::TrustStore::new();
    trust.add_anchor(server_id.der());
    let client_config = Arc::new(QuicClientConfig::from_handshake(HandshakeConfig {
        role: HandshakeRole::Client,
        mode: HandshakeMode::Quic,
        alpn: vec![Bytes::from_static(b"doq")],
        trust_store: Some(trust),
        ..Default::default()
    }));
    (driver, client_config)
}

/// DoQ: each query is its own stream, so once the connection is up a slow
/// answer does not hold up a quick one; an unanswered query times out once.
#[cfg(feature = "doq")]
#[test]
fn doq_upstream_answers_out_of_order_and_times_out_once() {
    let (driver, client_config) = doq_server();
    let rt = Runtime::start(Default::default()).unwrap();
    let c = UpstreamClient::doq(rt.pick_worker().clone(), driver.local_addr, "localhost", client_config, quick());

    // The first query proves the new connection (see the module docs).
    assert!(await_result(&ask(&c, query(1, "fast-0.test"))).0.is_ok());

    let started = Instant::now();
    let slow = ask(&c, query(5, "slow-1.test"));
    let fast = ask(&c, query(5, "fast-1.test"));
    let hang = {
        let (tx, rx) = mpsc::channel();
        c.query_within(query(6, "hang-1.test"), Duration::from_millis(800), move |r| {
            let _ = tx.send((r, Instant::now()));
        });
        rx
    };
    let (fast_result, fast_at) = await_result(&fast);
    let (slow_result, slow_at) = await_result(&slow);
    assert_eq!(fast_result.unwrap().id, 5, "the caller's ID is restored over DoQ");
    assert_eq!(slow_result.unwrap().questions[0].name, "slow-1.test");
    assert!(fast_at < slow_at && fast_at - started < SLOW / 2);
    assert_eq!(await_result(&hang).0.unwrap_err(), UpstreamError::Timeout);
    assert_exactly_once(&hang, Duration::from_millis(500));
    let m = c.metrics();
    assert_eq!((m.queries, m.responses, m.timeouts, m.in_flight), (4, 3, 1, 0));
    c.close();
    rt.shutdown();
    driver.shutdown();
}

/// Queries that all arrive before the first connection is up used to leave it
/// unable to carry any of them (and still looking alive). The client sends one
/// as a probe, then the rest together, so in practice every one is answered.
///
/// The fault is in the QUIC transport, and a burst of new streams can still
/// wedge a connection that looks alive. The client must then recover: a query
/// that times out on a connection that has answered nothing in the latter half
/// of its wait gets the connection discarded, and the next query is answered on a new one.
/// So the test requires either success, or a timeout followed by a successful
/// query.
#[cfg(feature = "doq")]
#[test]
fn doq_queries_that_race_the_handshake_are_answered_or_recover() {
    let config = UpstreamConfig {
        timeout: Duration::from_millis(1500),
        ..Default::default()
    };
    let mut wedged = 0;
    for round in 0..8 {
        let (driver, client_config) = doq_server();
        let rt = Runtime::start(Default::default()).unwrap();
        let c = UpstreamClient::doq(rt.pick_worker().clone(), driver.local_addr, "localhost", client_config, config.clone());
        let all: Vec<_> = (0..4).map(|i| ask(&c, query(i, &format!("fast-{i}.test")))).collect();
        let mut timed_out = false;
        for (i, rx) in all.iter().enumerate() {
            match await_result(rx).0 {
                Ok(_) => {}
                Err(UpstreamError::Timeout) => timed_out = true,
                Err(e) => panic!("round {round}, query {i}: {e}"),
            }
            assert_exactly_once(rx, Duration::from_millis(1));
        }
        if timed_out {
            wedged += 1;
            let again = await_result(&ask(&c, query(9, "fast-9.test"))).0;
            assert!(again.is_ok(), "round {round}: the client did not recover from a wedged connection: {again:?}");
        }
        c.close();
        rt.shutdown();
        driver.shutdown();
    }
    assert!(wedged <= 2, "{wedged} of 8 fresh connections wedged");
}

#[allow(dead_code)]
fn unused(_: UdpSocket) {}
