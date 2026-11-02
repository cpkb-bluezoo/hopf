// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-process tests of the SOCKS server handler and the SOCKS client
//! handler: the test plays the other end over a [`Peer`], writing bytes and
//! checking the replies. The relaying itself, which needs real sockets, is
//! covered by the `integration` feature's tests.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
#[cfg(feature = "integration")]
use std::time::Duration;

use hopf_core::testing::Peer;
use hopf_core::{Endpoint, LoopBuf, ProtocolHandler, Runtime, RuntimeConfig};
use hopf_dns::DnsResolver;

use crate::client::{SocksClientConfig, SocksClientVersion, SocksConnectHandler};
use crate::handler::SocksConnectionHandlerFactory;
use crate::metrics::SocksServerMetrics;
use crate::wire::{self, Socks5Reply};
use crate::{SocksAuthenticator, SocksPolicy};

/// `Peer` takes a concrete handler; this lets it drive a boxed one.
struct Boxed(Box<dyn ProtocolHandler>);

impl ProtocolHandler for Boxed {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        self.0.connected(ep);
    }
    fn receive(&mut self, ep: &mut dyn Endpoint, buf: &mut LoopBuf) {
        self.0.receive(ep, buf);
    }
    fn disconnected(&mut self, ep: &mut dyn Endpoint) {
        self.0.disconnected(ep);
    }
    fn error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.0.error(ep, err);
    }
}

struct Policy(bool);

impl SocksPolicy for Policy {
    fn is_target_allowed(&self, _addr: IpAddr, _port: u16) -> bool {
        self.0
    }
}

struct Users;

impl SocksAuthenticator for Users {
    fn verify(&self, username: &str, password: &str) -> bool {
        username == "alice" && password == "secret"
    }
}

struct Server {
    peer: Peer<Boxed>,
    metrics: Arc<SocksServerMetrics>,
    _rt: Arc<Runtime>,
}

fn server(allow: bool, auth: bool) -> Server {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    let mut factory = SocksConnectionHandlerFactory::new(dns, Arc::clone(&rt), Arc::new(Policy(allow)));
    if auth {
        factory = factory.with_authenticator(Arc::new(Users));
    }
    let metrics = factory.metrics();
    let mut peer = Peer::connect(Boxed(factory.create_handler()), |_| false);
    peer.take_bytes();
    Server { peer, metrics, _rt: rt }
}

fn count(c: &std::sync::atomic::AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

const ZERO: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

fn socks5_reply(reply: Socks5Reply) -> Vec<u8> {
    wire::encode_socks5_reply(reply, ZERO)
}

/// A SOCKS5 CONNECT request for an IPv4 target.
fn connect5(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut r = vec![5, 1, 0, 1];
    r.extend_from_slice(&ip);
    r.extend_from_slice(&port.to_be_bytes());
    r
}

#[cfg(feature = "integration")]
/// A port nothing is listening on.
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[cfg(feature = "integration")]
/// Waits for the reply to something that completes on another thread.
fn wait_bytes(p: &mut Peer<Boxed>) -> Vec<u8> {
    for _ in 0..250 {
        p.pump();
        let b = p.take_bytes();
        if !b.is_empty() {
            return b;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("no reply");
}

// SOCKS5 greeting and authentication -------------------------------------------

#[test]
fn a_socks5_greeting_with_no_authentication_is_answered_with_that_method() {
    let mut s = server(true, false);
    assert_eq!(s.peer.run_bytes(&[5, 1, 0]), [5, 0]);
    assert_eq!(count(&s.metrics.connections), 1);
}

#[test]
fn the_server_picks_no_authentication_out_of_several_offers() {
    let mut s = server(true, false);
    assert_eq!(s.peer.run_bytes(&[5, 3, 2, 1, 0]), [5, 0]);
}

#[test]
fn a_greeting_with_no_acceptable_method_is_refused_and_the_connection_closed() {
    let mut s = server(true, false);
    assert_eq!(s.peer.run_bytes(&[5, 1, 2]), [5, 0xff]);
    assert!(s.peer.is_closed());
}

#[test]
fn a_server_with_users_wants_username_and_password_and_will_not_do_without() {
    let mut s = server(true, true);
    assert_eq!(s.peer.run_bytes(&[5, 2, 0, 2]), [5, 2]);
    let mut s = server(true, true);
    assert_eq!(s.peer.run_bytes(&[5, 1, 0]), [5, 0xff]);
    assert!(s.peer.is_closed());
}

fn user_pass(user: &str, pass: &str) -> Vec<u8> {
    let mut r = vec![1, user.len() as u8];
    r.extend_from_slice(user.as_bytes());
    r.push(pass.len() as u8);
    r.extend_from_slice(pass.as_bytes());
    r
}

#[test]
fn good_credentials_open_the_way_to_a_request() {
    let mut s = server(true, true);
    s.peer.run_bytes(&[5, 1, 2]);
    assert_eq!(s.peer.run_bytes(&user_pass("alice", "secret")), [1, 0]);
    assert!(!s.peer.is_closed());
    assert_eq!(count(&s.metrics.auth_ok), 1);
    // A request is now accepted; this one is not allowed.
    let mut s2 = server(false, true);
    s2.peer.run_bytes(&[5, 1, 2]);
    s2.peer.run_bytes(&user_pass("alice", "secret"));
    assert_eq!(s2.peer.run_bytes(&connect5([192, 0, 2, 9], 80)), socks5_reply(Socks5Reply::NotAllowed));
}

#[test]
fn bad_credentials_are_refused_and_the_connection_closed() {
    let mut s = server(true, true);
    s.peer.run_bytes(&[5, 1, 2]);
    assert_eq!(s.peer.run_bytes(&user_pass("alice", "wrong")), [1, 1]);
    assert!(s.peer.is_closed());
    assert_eq!(count(&s.metrics.auth_fail), 1);
    assert_eq!(count(&s.metrics.auth_ok), 0);
}

#[test]
fn a_malformed_credentials_message_closes_the_connection() {
    let mut s = server(true, true);
    s.peer.run_bytes(&[5, 1, 2]);
    s.peer.run_bytes(&[9, 1, b'a', 1, b'b']); // wrong sub-negotiation version
    assert!(s.peer.is_closed());
}

// SOCKS5 requests -----------------------------------------------------------------

#[test]
fn a_connect_to_a_target_the_policy_forbids_is_refused() {
    let mut s = server(false, false);
    s.peer.run_bytes(&[5, 1, 0]);
    assert_eq!(s.peer.run_bytes(&connect5([10, 0, 0, 1], 80)), socks5_reply(Socks5Reply::NotAllowed));
    assert!(s.peer.is_closed());
    assert_eq!(count(&s.metrics.connect_requests), 1);
}

#[cfg(feature = "integration")]
#[test]
fn a_connect_to_a_port_nothing_listens_on_is_reported_as_refused() {
    let mut s = server(true, false);
    s.peer.run_bytes(&[5, 1, 0]);
    s.peer.run_bytes(&connect5([127, 0, 0, 1], closed_port()));
    assert_eq!(wait_bytes(&mut s.peer), socks5_reply(Socks5Reply::ConnectionRefused));
    assert!(s.peer.is_closed());
}

#[test]
fn a_request_with_an_unknown_address_type_gets_the_matching_reply() {
    let mut s = server(true, false);
    s.peer.run_bytes(&[5, 1, 0]);
    assert_eq!(
        s.peer.run_bytes(&[5, 1, 0, 9, 1, 2, 3, 4, 0, 80]),
        socks5_reply(Socks5Reply::AddressTypeNotSupported)
    );
    assert!(s.peer.is_closed());
}

#[test]
fn the_relay_limit_refuses_a_connect_that_would_exceed_it() {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let dns = Arc::new(DnsResolver::new(rt.pick_worker().clone()));
    let factory = SocksConnectionHandlerFactory::new(dns, Arc::clone(&rt), Arc::new(Policy(true))).with_max_relays(1);
    factory.metrics().active_relays.store(1, Ordering::Relaxed);
    let mut peer = Peer::connect(Boxed(factory.create_handler()), |_| false);
    peer.take_bytes();
    peer.run_bytes(&[5, 1, 0]);
    assert_eq!(peer.run_bytes(&connect5([127, 0, 0, 1], 80)), socks5_reply(Socks5Reply::GeneralFailure));
    assert!(peer.is_closed());
}

#[test]
fn a_whole_socks5_exchange_is_the_same_whatever_the_chunking() {
    let mut wire = vec![5, 1, 0];
    wire.extend(connect5([10, 0, 0, 1], 80));
    let run = |chunk: usize| {
        let mut s = server(false, false);
        (s.peer.run_chunked_bytes(&wire, chunk), s.peer.is_closed())
    };
    let whole = run(wire.len());
    let mut expect = vec![5, 0];
    expect.extend(socks5_reply(Socks5Reply::NotAllowed));
    assert_eq!(whole, (expect, true));
    for chunk in [1, 2, 3, 5] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn a_first_byte_that_is_neither_socks4_nor_socks5_closes_the_connection() {
    let mut s = server(true, false);
    s.peer.run_bytes(b"GET / HTTP/1.1\r\n");
    assert!(s.peer.is_closed());
}

#[test]
fn a_malformed_greeting_closes_the_connection() {
    let mut s = server(true, false);
    s.peer.run_bytes(&[5, 0]); // claims no methods at all
    assert!(s.peer.is_closed());
}

#[test]
fn an_error_closes_the_connection() {
    let mut s = server(true, false);
    s.peer.fail(&io::Error::other("boom"));
    assert!(s.peer.is_closed());
}

// SOCKS4 ---------------------------------------------------------------------------

fn socks4_connect(ip: [u8; 4], port: u16, user: &[u8]) -> Vec<u8> {
    let mut r = vec![4, 1];
    r.extend_from_slice(&port.to_be_bytes());
    r.extend_from_slice(&ip);
    r.extend_from_slice(user);
    r.push(0);
    r
}

const SOCKS4_REJECTED: [u8; 8] = [0, 0x5b, 0, 0, 0, 0, 0, 0];

#[test]
fn a_socks4_connect_to_a_forbidden_target_is_rejected() {
    let mut s = server(false, false);
    assert_eq!(s.peer.run_bytes(&socks4_connect([10, 0, 0, 1], 80, b"bob")), SOCKS4_REJECTED);
    assert!(s.peer.is_closed());
}

#[cfg(feature = "integration")]
#[test]
fn a_socks4_connect_to_a_port_nothing_listens_on_is_rejected() {
    let mut s = server(true, false);
    s.peer.run_bytes(&socks4_connect([127, 0, 0, 1], closed_port(), b""));
    assert_eq!(wait_bytes(&mut s.peer), SOCKS4_REJECTED);
}

#[test]
fn socks4_cannot_carry_credentials_so_a_server_with_users_refuses_it() {
    let mut s = server(true, true);
    assert_eq!(s.peer.run_bytes(&socks4_connect([127, 0, 0, 1], 80, b"alice")), SOCKS4_REJECTED);
    assert!(s.peer.is_closed());
}

#[test]
fn a_socks4_request_for_udp_is_refused() {
    let mut s = server(true, false);
    let mut r = socks4_connect([127, 0, 0, 1], 80, b"");
    r[1] = 3;
    s.peer.run_bytes(&r);
    // Not a command SOCKS4 has: either refused or the connection dropped.
    assert!(s.peer.is_closed());
}

#[test]
fn a_socks4_request_arriving_a_byte_at_a_time_is_the_same() {
    let wire = socks4_connect([10, 0, 0, 1], 80, b"bob");
    let run = |chunk: usize| {
        let mut s = server(false, false);
        s.peer.run_chunked_bytes(&wire, chunk)
    };
    let whole = run(wire.len());
    assert_eq!(whole, SOCKS4_REJECTED);
    for chunk in [1, 2, 4] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

// The client ---------------------------------------------------------------------------

#[derive(Default)]
struct Seen {
    connected: bool,
    received: Vec<u8>,
    disconnected: bool,
    errors: Vec<String>,
}

struct Inner(Arc<Mutex<Seen>>);

impl ProtocolHandler for Inner {
    fn connected(&mut self, _ep: &mut dyn Endpoint) {
        self.0.lock().unwrap().connected = true;
    }
    fn receive(&mut self, _ep: &mut dyn Endpoint, buf: &mut LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            self.0.lock().unwrap().received.extend_from_slice(data);
            *data = &[];
        });
    }
    fn disconnected(&mut self, _ep: &mut dyn Endpoint) {
        self.0.lock().unwrap().disconnected = true;
    }
    fn error(&mut self, _ep: &mut dyn Endpoint, err: &io::Error) {
        self.0.lock().unwrap().errors.push(err.to_string());
    }
}

fn client(config: SocksClientConfig, host: &str, port: u16) -> (Peer<SocksConnectHandler>, Arc<Mutex<Seen>>) {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let handler = SocksConnectHandler::new(config, host, port, Box::new(Inner(Arc::clone(&seen))));
    (Peer::connect(handler, |_| false), seen)
}

fn v5() -> SocksClientConfig {
    SocksClientConfig::new(SocksClientVersion::Socks5)
}

fn v4() -> SocksClientConfig {
    SocksClientConfig::new(SocksClientVersion::Socks4)
}

fn success5() -> Vec<u8> {
    socks5_reply(Socks5Reply::Succeeded)
}

#[test]
fn a_socks5_client_greets_asks_to_connect_and_then_hands_over_the_tunnel() {
    let (mut c, seen) = client(v5(), "192.0.2.9", 8080);
    assert_eq!(c.take_bytes(), [5, 1, 0], "greeting with no authentication");
    assert_eq!(c.run_bytes(&[5, 0]), [5, 1, 0, 1, 192, 0, 2, 9, 0x1f, 0x90]);
    assert!(!seen.lock().unwrap().connected, "not before the proxy has said yes");
    let mut reply = success5();
    reply.extend_from_slice(b"hello from the target");
    c.run_bytes(&reply);
    let s = seen.lock().unwrap();
    assert!(s.connected);
    assert_eq!(s.received, b"hello from the target", "what follows the reply belongs to the tunnel");
}

#[test]
fn a_hostname_is_sent_as_a_name_for_the_proxy_to_resolve() {
    let (mut c, _seen) = client(v5(), "example.com", 443);
    c.take_bytes();
    let sent = c.run_bytes(&[5, 0]);
    let mut expect = vec![5, 1, 0, 3, 11];
    expect.extend_from_slice(b"example.com");
    expect.extend_from_slice(&443u16.to_be_bytes());
    assert_eq!(sent, expect);
}

#[test]
fn an_ipv6_target_is_sent_as_an_ipv6_address() {
    let (mut c, _seen) = client(v5(), "::1", 25);
    c.take_bytes();
    let sent = c.run_bytes(&[5, 0]);
    assert_eq!(sent[..4], [5, 1, 0, 4]);
    assert_eq!(sent.len(), 4 + 16 + 2);
}

#[test]
fn a_hostname_too_long_for_socks5_fails_before_it_is_sent() {
    let (mut c, seen) = client(v5(), &"a".repeat(300), 80);
    c.take_bytes();
    assert!(c.run_bytes(&[5, 0]).is_empty());
    assert!(seen.lock().unwrap().errors[0].contains("too long"), "{:?}", seen.lock().unwrap().errors);
    assert!(c.is_closed());
}

#[test]
fn with_credentials_the_client_offers_both_methods_and_signs_in() {
    let (mut c, seen) = client(v5().with_credentials("alice", "secret"), "192.0.2.9", 80);
    assert_eq!(c.take_bytes(), [5, 2, 0, 2]);
    assert_eq!(c.run_bytes(&[5, 2]), user_pass("alice", "secret"));
    assert_eq!(c.run_bytes(&[1, 0]), [5, 1, 0, 1, 192, 0, 2, 9, 0, 80]);
    c.run_bytes(&success5());
    assert!(seen.lock().unwrap().connected);
}

#[test]
fn refused_credentials_are_a_failure() {
    let (mut c, seen) = client(v5().with_credentials("alice", "wrong"), "192.0.2.9", 80);
    c.take_bytes();
    c.run_bytes(&[5, 2]);
    c.run_bytes(&[1, 1]);
    assert!(seen.lock().unwrap().errors[0].contains("credentials"), "{:?}", seen.lock().unwrap().errors);
    assert!(!seen.lock().unwrap().connected);
    assert!(c.is_closed());
}

#[test]
fn a_proxy_that_accepts_none_of_the_methods_is_a_failure() {
    let (mut c, seen) = client(v5(), "192.0.2.9", 80);
    c.take_bytes();
    c.run_bytes(&[5, 0xff]);
    assert!(seen.lock().unwrap().errors[0].contains("every offered"), "{:?}", seen.lock().unwrap().errors);
    assert!(c.is_closed());
}

#[test]
fn a_proxy_that_picks_a_method_the_client_did_not_offer_is_a_failure() {
    for method in [1u8, 2] {
        // 2 is not offered when there are no credentials.
        let (mut c, seen) = client(v5(), "192.0.2.9", 80);
        c.take_bytes();
        c.run_bytes(&[5, method]);
        assert!(seen.lock().unwrap().errors[0].contains("unsupported"), "{method}: {:?}", seen.lock().unwrap().errors);
    }
}

#[test]
fn a_proxy_refusing_the_connect_is_a_failure_with_its_reply_code() {
    let (mut c, seen) = client(v5(), "192.0.2.9", 80);
    c.take_bytes();
    c.run_bytes(&[5, 0]);
    c.run_bytes(&socks5_reply(Socks5Reply::HostUnreachable));
    assert!(seen.lock().unwrap().errors[0].contains("0x04"), "{:?}", seen.lock().unwrap().errors);
    assert!(c.is_closed());
}

#[test]
fn a_reply_that_is_not_socks_is_a_failure() {
    let (mut c, seen) = client(v5(), "192.0.2.9", 80);
    c.take_bytes();
    c.run_bytes(b"HTTP/1.1 400 Bad Request\r\n");
    assert!(seen.lock().unwrap().errors[0].contains("malformed"), "{:?}", seen.lock().unwrap().errors);
    assert!(c.is_closed());
}

#[test]
fn the_client_handshake_is_the_same_whatever_the_chunking() {
    let mut wire = vec![5, 0];
    wire.extend(success5());
    wire.extend_from_slice(b"tunnel data");
    let run = |chunk: usize| {
        let (mut c, seen) = client(v5(), "192.0.2.9", 80);
        let sent = c.take_bytes();
        let more = c.run_chunked_bytes(&wire, chunk);
        let s = seen.lock().unwrap();
        (sent, more, s.connected, s.received.clone())
    };
    let whole = run(wire.len());
    assert_eq!(whole.3, b"tunnel data");
    assert!(whole.2);
    for chunk in [1, 2, 3, 7] {
        assert_eq!(run(chunk), whole, "chunk {chunk}");
    }
}

#[test]
fn a_socks4_client_sends_one_request_and_waits_for_the_grant() {
    let (mut c, seen) = client(v4(), "192.0.2.9", 80);
    assert_eq!(c.take_bytes(), [4, 1, 0, 80, 192, 0, 2, 9, 0]);
    c.run_bytes(&[0, 0x5a, 0, 0, 0, 0, 0, 0]);
    assert!(seen.lock().unwrap().connected);
}

#[test]
fn a_socks4_client_asks_the_proxy_to_resolve_a_hostname_using_socks4a() {
    let (mut c, _seen) = client(v4(), "example.com", 80);
    let sent = c.take_bytes();
    assert_eq!(sent[..8], [4, 1, 0, 80, 0, 0, 0, 1], "an address of 0.0.0.x marks SOCKS4a");
    assert!(sent.ends_with(b"example.com\0"), "{sent:?}");
}

#[test]
fn a_socks4_client_cannot_reach_an_ipv6_target() {
    let (mut c, seen) = client(v4(), "::1", 80);
    assert!(c.take_bytes().is_empty());
    assert!(seen.lock().unwrap().errors[0].contains("IPv6"), "{:?}", seen.lock().unwrap().errors);
    assert!(c.is_closed());
}

#[test]
fn a_socks4_rejection_is_a_failure() {
    let (mut c, seen) = client(v4(), "192.0.2.9", 80);
    c.take_bytes();
    c.run_bytes(&[0, 0x5b, 0, 0, 0, 0, 0, 0]);
    assert!(seen.lock().unwrap().errors[0].contains("rejected"), "{:?}", seen.lock().unwrap().errors);
    assert!(!seen.lock().unwrap().connected);
}

#[test]
fn the_tunnel_is_told_when_the_connection_ends_but_only_if_it_was_ever_established() {
    let (mut c, seen) = client(v5(), "192.0.2.9", 80);
    c.take_bytes();
    c.run_bytes(&[5, 0]);
    c.run_bytes(&success5());
    c.disconnect();
    assert!(seen.lock().unwrap().disconnected);

    let (mut c, seen) = client(v5(), "192.0.2.9", 80);
    c.take_bytes();
    c.disconnect();
    assert!(!seen.lock().unwrap().disconnected, "the tunnel never opened, so it never closes");
}

#[test]
fn a_connection_error_reaches_the_tunnel_and_closes() {
    let (mut c, seen) = client(v5(), "192.0.2.9", 80);
    c.take_bytes();
    c.fail(&io::Error::new(io::ErrorKind::ConnectionReset, "reset"));
    assert_eq!(seen.lock().unwrap().errors, ["reset"]);
    assert!(c.is_closed());
}
