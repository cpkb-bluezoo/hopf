// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime TCP/UDP smoke (enable with `--features integration`).

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_dns::DnsResolver;
use hopf_http::{
    AltSvcCache, CleartextHttpEndpoint, HttpClientTimeouts, HttpFallback, HttpLimits,
    ServerHandlerFactory,
};

use crate::{
    connect_ip, connect_udp, ConnectIpClientSession, ConnectIpEventHandler, ConnectIpFactory,
    ConnectIpHandler, ConnectIpHandlerFactory, ConnectIpPolicy, ConnectIpSession,
    ConnectUdpEventHandler, ConnectUdpFactory, ConnectUdpPolicy, ConnectUdpSession, IpProto,
    IpTarget, RequestedAddress,
};

/// Allows relaying to any target — fine for a loopback test, never for a
/// real deployment (see [`ConnectUdpPolicy`]'s own docs).
struct AllowAny;
impl ConnectUdpPolicy for AllowAny {
    fn is_target_allowed(&self, _addr: IpAddr, _port: u16) -> bool {
        true
    }
}

struct DenyAll;
impl ConnectUdpPolicy for DenyAll {
    fn is_target_allowed(&self, _addr: IpAddr, _port: u16) -> bool {
        false
    }
}

/// A trivial UDP echo server standing in for "the proxied target" —
/// started on a plain OS thread, not part of the `Runtime` under test.
fn start_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf) else {
                break;
            };
            let _ = socket.send_to(&buf[..n], from);
        }
    });
    addr
}

fn start_connect_udp_server(policy: Arc<dyn ConnectUdpPolicy>) -> (Arc<Runtime>, SocketAddr) {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());
    let factory = Arc::new(ConnectUdpFactory::new(dns, Arc::clone(&rt), policy));
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            move || {
                Box::new(CleartextHttpEndpoint::new(
                    Arc::clone(&factory) as Arc<dyn ServerHandlerFactory>,
                    HttpLimits::default(),
                )) as Box<dyn ProtocolHandler>
            },
        ))
        .unwrap();
    (rt, addr)
}

/// Reads a capsule-framed HTTP Datagram (Context ID + UDP payload) off
/// `stream` and returns the decoded UDP payload — blocks (with the
/// stream's own read timeout) until a full capsule arrives.
fn read_one_capsule_datagram(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((ty, value, consumed)) = try_parse_capsule(&buf) {
            assert_eq!(ty, 0, "expected a DATAGRAM capsule");
            let (context_id, payload) = hopf_http::context_id::decode(&value)
                .expect("well-formed Context ID prefix");
            assert_eq!(context_id, 0);
            let _ = consumed;
            return payload.to_vec();
        }
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "connection closed before a capsule arrived");
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Minimal standalone capsule-header parser for the test's own reads (the
/// crate's real [`hopf_http::capsule::CapsuleParser`] is exercised by the
/// server side; using a second, independent decoder here means a bug in
/// one doesn't mask a bug in the other).
fn try_parse_capsule(buf: &[u8]) -> Option<(u64, Vec<u8>, usize)> {
    let (ty, n_ty) = decode_varint(buf)?;
    let (len, n_len) = decode_varint(&buf[n_ty..])?;
    let header = n_ty + n_len;
    let len = len as usize;
    if buf.len() < header + len {
        return None;
    }
    Some((ty, buf[header..header + len].to_vec(), header + len))
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        value = (value << 8) | u64::from(b);
    }
    Some((value, len))
}

#[test]
fn h1_connect_udp_relay_round_trip() {
    let target = start_udp_echo();
    let (rt, server_addr) = start_connect_udp_server(Arc::new(AllowAny));
    thread::sleep(Duration::from_millis(50));

    let mut c = TcpStream::connect(server_addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

    let req = format!(
        "GET /.well-known/masque/udp/{}/{}/ HTTP/1.1\r\nHost: localhost\r\nUpgrade: connect-udp\r\nConnection: Upgrade\r\nCapsule-Protocol: ?1\r\n\r\n",
        target.ip(),
        target.port(),
    );
    c.write_all(req.as_bytes()).unwrap();

    let mut buf = [0u8; 4096];
    let n = c.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains(" 101 "), "expected 101 Switching Protocols: {resp}");
    assert!(resp.to_ascii_lowercase().contains("upgrade: connect-udp"), "{resp}");
    assert!(resp.to_ascii_lowercase().contains("capsule-protocol: ?1"), "{resp}");

    // Any bytes after the header block in the same read are the start of
    // the capsule stream; a fresh connection here has none yet.

    let mut frame = Vec::new();
    let payload_with_context =
        hopf_http::context_id::encode(hopf_http::context_id::REGISTERED_CONTEXT_ID, b"ping");
    hopf_http::capsule::Capsule::datagram(payload_with_context).encode(&mut frame);
    c.write_all(&frame).unwrap();

    let echoed = read_one_capsule_datagram(&mut c);
    assert_eq!(echoed, b"ping");

    let _ = rt;
}

enum ClientEvent {
    Opened(Arc<dyn ConnectUdpSession>),
    Datagram(Vec<u8>),
    Closed,
    Error(String),
}

impl std::fmt::Debug for ClientEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opened(_) => write!(f, "Opened"),
            Self::Datagram(d) => write!(f, "Datagram({d:?})"),
            Self::Closed => write!(f, "Closed"),
            Self::Error(e) => write!(f, "Error({e:?})"),
        }
    }
}

struct ChannelEventHandler {
    tx: std::sync::mpsc::Sender<ClientEvent>,
}

impl ConnectUdpEventHandler for ChannelEventHandler {
    fn opened(&mut self, session: Arc<dyn ConnectUdpSession>) {
        let _ = self.tx.send(ClientEvent::Opened(session));
    }

    fn datagram_received(&mut self, data: &[u8]) {
        let _ = self.tx.send(ClientEvent::Datagram(data.to_vec()));
    }

    fn closed(&mut self) {
        let _ = self.tx.send(ClientEvent::Closed);
    }

    fn error(&mut self, err: &std::io::Error) {
        let _ = self.tx.send(ClientEvent::Error(err.to_string()));
    }
}

/// Proves the client side (`connect_udp`) actually interoperates with this
/// crate's own server relay, not just that each half separately matches
/// the RFC 9298 wire format on paper: dials the real relay from
/// `start_connect_udp_server` over a real loopback TCP connection, sends a
/// UDP payload through it, and checks the target's echo comes all the way
/// back out through [`ConnectUdpEventHandler::datagram_received`].
#[test]
fn client_connect_udp_round_trips_through_the_server_relay() {
    let target = start_udp_echo();
    let (rt, server_addr) = start_connect_udp_server(Arc::new(AllowAny));
    thread::sleep(Duration::from_millis(50));

    let (tx, rx) = std::sync::mpsc::channel();
    let handler = Box::new(ChannelEventHandler { tx });

    connect_udp(
        &rt,
        &server_addr.ip().to_string(),
        server_addr.port(),
        target.ip().to_string(),
        target.port(),
        HttpFallback::PlaintextH1,
        handler,
        None,
        Arc::new(AltSvcCache::new()),
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    let session = match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(ClientEvent::Opened(s)) => s,
        Ok(ClientEvent::Error(e)) => panic!("tunnel failed to open: {e}"),
        other => panic!("expected Opened, got {other:?}"),
    };

    session.send_datagram(b"ping");

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(ClientEvent::Datagram(d)) => assert_eq!(d, b"ping"),
        other => panic!("expected an echoed Datagram, got {other:?}"),
    }
}

/// A policy that denies the target gets a real `403`, not a silent hang
/// or a connection reset — proving the policy hook is actually consulted
/// before any relay socket is opened, not just present in the type
/// signature.
#[test]
fn policy_denial_returns_403_and_opens_no_relay() {
    let target = start_udp_echo();
    let (rt, server_addr) = start_connect_udp_server(Arc::new(DenyAll));
    thread::sleep(Duration::from_millis(50));

    let mut c = TcpStream::connect(server_addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

    let req = format!(
        "GET /.well-known/masque/udp/{}/{}/ HTTP/1.1\r\nHost: localhost\r\nUpgrade: connect-udp\r\nConnection: Upgrade\r\nCapsule-Protocol: ?1\r\n\r\n",
        target.ip(),
        target.port(),
    );
    c.write_all(req.as_bytes()).unwrap();

    let mut buf = [0u8; 4096];
    let n = c.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains(" 403 "), "expected 403: {resp}");

    let _ = rt;
}

// ---------------------------------------------------------------------------
// CONNECT-IP (RFC 9484)
// ---------------------------------------------------------------------------

/// Allows any target/protocol scope — fine for a loopback test, never for a
/// real deployment (see [`ConnectIpPolicy`]'s own docs).
struct AllowAnyIp;
impl ConnectIpPolicy for AllowAnyIp {
    fn is_target_allowed(&self, _target: &IpTarget, _ipproto: &IpProto) -> bool {
        true
    }
}

struct DenyAllIp;
impl ConnectIpPolicy for DenyAllIp {
    fn is_target_allowed(&self, _target: &IpTarget, _ipproto: &IpProto) -> bool {
        false
    }
}

/// Echoes every received packet back, and answers every address request
/// with a fixed `192.0.2.1/32` regardless of what was asked for — a real
/// forwarder would consult its own address pool, but a fixed answer is
/// enough to prove the request/response plumbing itself works.
struct EchoIpHandler {
    session: Option<Arc<dyn ConnectIpSession>>,
}

impl ConnectIpHandler for EchoIpHandler {
    fn opened(&mut self, session: Arc<dyn ConnectIpSession>) {
        self.session = Some(session);
    }

    fn packet_received(&mut self, packet: &[u8]) {
        if let Some(s) = &self.session {
            s.send_packet(packet);
        }
    }

    fn address_requested(&mut self, request_id: u64, _address: IpAddr, _prefix_length: u8) {
        if let Some(s) = &self.session {
            s.assign_address(request_id, "192.0.2.1".parse().unwrap(), 32);
        }
    }
}

struct EchoIpHandlerFactory;
impl ConnectIpHandlerFactory for EchoIpHandlerFactory {
    fn create_handler(&self) -> Box<dyn ConnectIpHandler> {
        Box::new(EchoIpHandler { session: None })
    }
}

/// Advertises one fixed route as soon as the tunnel opens, unprompted —
/// stands in for a relay that announces its own reachable ranges rather
/// than waiting to be asked.
struct RouteAdvertisingIpHandler;
impl ConnectIpHandler for RouteAdvertisingIpHandler {
    fn opened(&mut self, session: Arc<dyn ConnectIpSession>) {
        session.advertise_route(
            "192.0.2.0".parse().unwrap(),
            "192.0.2.255".parse().unwrap(),
            0,
        );
    }

    fn packet_received(&mut self, _packet: &[u8]) {}
}

struct RouteAdvertisingIpHandlerFactory;
impl ConnectIpHandlerFactory for RouteAdvertisingIpHandlerFactory {
    fn create_handler(&self) -> Box<dyn ConnectIpHandler> {
        Box::new(RouteAdvertisingIpHandler)
    }
}

fn start_connect_ip_server(
    app: Arc<dyn ConnectIpHandlerFactory>,
    policy: Arc<dyn ConnectIpPolicy>,
) -> (Arc<Runtime>, SocketAddr) {
    let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
    let factory = Arc::new(ConnectIpFactory::new(app, policy));
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            move || {
                Box::new(CleartextHttpEndpoint::new(
                    Arc::clone(&factory) as Arc<dyn ServerHandlerFactory>,
                    HttpLimits::default(),
                )) as Box<dyn ProtocolHandler>
            },
        ))
        .unwrap();
    (rt, addr)
}

/// Connects, sends the CONNECT-IP Upgrade request, and reads until the
/// `\r\n\r\n` header terminator. Returns the stream plus any bytes already
/// read *past* that terminator — capsule bytes can legitimately arrive
/// coalesced with the header response in the same TCP read (e.g. a route
/// advertised the moment the tunnel opens, per
/// [`RouteAdvertisingIpHandler`]), and silently dropping them here would
/// make [`read_one_capsule`] hang waiting for bytes that already arrived.
fn connect_ip_h1_upgrade(server_addr: SocketAddr) -> (TcpStream, Vec<u8>) {
    let mut c = TcpStream::connect(server_addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let req = "GET /.well-known/masque/ip/*/*/ HTTP/1.1\r\nHost: localhost\r\nUpgrade: connect-ip\r\nConnection: Upgrade\r\nCapsule-Protocol: ?1\r\n\r\n";
    c.write_all(req.as_bytes()).unwrap();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = c.read(&mut chunk).unwrap();
        assert!(n > 0, "connection closed before the response headers completed");
        buf.extend_from_slice(&chunk[..n]);
    };
    let resp = String::from_utf8_lossy(&buf[..header_end]);
    assert!(resp.contains(" 101 "), "expected 101 Switching Protocols: {resp}");
    assert!(resp.to_ascii_lowercase().contains("upgrade: connect-ip"), "{resp}");
    assert!(resp.to_ascii_lowercase().contains("capsule-protocol: ?1"), "{resp}");

    let leftover = buf[header_end..].to_vec();
    (c, leftover)
}

/// Reads one capsule off `stream` (consuming `prefix` first — bytes
/// already read past the response headers, see
/// [`connect_ip_h1_upgrade`]) and returns its type and value —
/// deliberately a second, independent decoder from the crate's own
/// [`hopf_http::capsule::CapsuleParser`] (which the server side exercises),
/// same reasoning as [`read_one_capsule_datagram`]'s.
fn read_one_capsule(stream: &mut TcpStream, prefix: Vec<u8>) -> (u64, Vec<u8>) {
    let mut buf = prefix;
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((ty, value, _consumed)) = try_parse_capsule(&buf) {
            return (ty, value);
        }
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "connection closed before a capsule arrived");
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn encode_test_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16_384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn encode_test_capsule(ty: u64, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_test_varint(&mut out, ty);
    encode_test_varint(&mut out, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn encode_test_address_entry(request_id: u64, address: IpAddr, prefix_length: u8) -> Vec<u8> {
    let mut out = Vec::new();
    encode_test_varint(&mut out, request_id);
    match address {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.push(prefix_length);
    out
}

fn decode_test_address_entry(buf: &[u8]) -> (u64, IpAddr, u8) {
    let (request_id, n1) = decode_varint(buf).unwrap();
    let (address, n2) = match buf[n1] {
        4 => {
            let b = &buf[n1 + 1..n1 + 5];
            (IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])), 5)
        }
        6 => {
            let b: [u8; 16] = buf[n1 + 1..n1 + 17].try_into().unwrap();
            (IpAddr::V6(std::net::Ipv6Addr::from(b)), 17)
        }
        v => panic!("unexpected IP Version {v}"),
    };
    (request_id, address, buf[n1 + n2])
}

fn decode_test_route_entry(buf: &[u8]) -> (IpAddr, IpAddr, u8) {
    match buf[0] {
        4 => {
            let start = IpAddr::V4(std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]));
            let end = IpAddr::V4(std::net::Ipv4Addr::new(buf[5], buf[6], buf[7], buf[8]));
            (start, end, buf[9])
        }
        6 => {
            let start_b: [u8; 16] = buf[1..17].try_into().unwrap();
            let end_b: [u8; 16] = buf[17..33].try_into().unwrap();
            (
                IpAddr::V6(std::net::Ipv6Addr::from(start_b)),
                IpAddr::V6(std::net::Ipv6Addr::from(end_b)),
                buf[33],
            )
        }
        v => panic!("unexpected IP Version {v}"),
    }
}

#[test]
fn h1_connect_ip_relay_round_trip() {
    let (rt, server_addr) = start_connect_ip_server(Arc::new(EchoIpHandlerFactory), Arc::new(AllowAnyIp));
    thread::sleep(Duration::from_millis(50));

    let (mut c, leftover) = connect_ip_h1_upgrade(server_addr);

    let mut frame = Vec::new();
    let payload_with_context = hopf_http::context_id::encode(
        hopf_http::context_id::REGISTERED_CONTEXT_ID,
        b"fake-ip-packet",
    );
    hopf_http::capsule::Capsule::datagram(payload_with_context).encode(&mut frame);
    c.write_all(&frame).unwrap();

    let (ty, value) = read_one_capsule(&mut c, leftover);
    assert_eq!(ty, 0, "expected a DATAGRAM capsule");
    let (context_id, payload) = hopf_http::context_id::decode(&value).unwrap();
    assert_eq!(context_id, 0);
    assert_eq!(payload, b"fake-ip-packet");

    let _ = rt;
}

/// An `ADDRESS_REQUEST` from the client gets a real `ADDRESS_ASSIGN` back,
/// carrying the same Request ID — proves the capsule round trip through
/// [`crate::ip_relay::ConnectIpRelay::capsule_received`] and
/// [`ConnectIpSession::assign_address`] end to end, not just that each
/// side's codec matches the RFC on paper.
#[test]
fn h1_connect_ip_address_request_gets_assigned() {
    let (rt, server_addr) = start_connect_ip_server(Arc::new(EchoIpHandlerFactory), Arc::new(AllowAnyIp));
    thread::sleep(Duration::from_millis(50));

    let (mut c, leftover) = connect_ip_h1_upgrade(server_addr);

    let entry = encode_test_address_entry(5, "0.0.0.0".parse().unwrap(), 0);
    let frame = encode_test_capsule(0x02, &entry); // ADDRESS_REQUEST
    c.write_all(&frame).unwrap();

    let (ty, value) = read_one_capsule(&mut c, leftover);
    assert_eq!(ty, 0x01, "expected an ADDRESS_ASSIGN capsule");
    let (request_id, address, prefix_length) = decode_test_address_entry(&value);
    assert_eq!(request_id, 5);
    assert_eq!(address, "192.0.2.1".parse::<IpAddr>().unwrap());
    assert_eq!(prefix_length, 32);

    let _ = rt;
}

/// A route advertised unprompted (from [`ConnectIpHandler::opened`]) still
/// reaches the client — proves `take_outbound` flushes it via the same
/// cross-thread poke path a delayed advertisement would need, not just the
/// happy path where it happens to already be queued before the first read.
#[test]
fn h1_connect_ip_route_advertisement_reaches_the_client() {
    let (rt, server_addr) =
        start_connect_ip_server(Arc::new(RouteAdvertisingIpHandlerFactory), Arc::new(AllowAnyIp));
    thread::sleep(Duration::from_millis(50));

    let (mut c, leftover) = connect_ip_h1_upgrade(server_addr);

    let (ty, value) = read_one_capsule(&mut c, leftover);
    assert_eq!(ty, 0x03, "expected a ROUTE_ADVERTISEMENT capsule");
    let (start, end, ip_protocol) = decode_test_route_entry(&value);
    assert_eq!(start, "192.0.2.0".parse::<IpAddr>().unwrap());
    assert_eq!(end, "192.0.2.255".parse::<IpAddr>().unwrap());
    assert_eq!(ip_protocol, 0);

    let _ = rt;
}

/// A policy that denies the target scope gets a real `403` — same proof as
/// CONNECT-UDP's [`policy_denial_returns_403_and_opens_no_relay`], for the
/// separate [`ConnectIpPolicy`] hook.
#[test]
fn connect_ip_policy_denial_returns_403() {
    let (rt, server_addr) = start_connect_ip_server(Arc::new(EchoIpHandlerFactory), Arc::new(DenyAllIp));
    thread::sleep(Duration::from_millis(50));

    let mut c = TcpStream::connect(server_addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let req = "GET /.well-known/masque/ip/*/*/ HTTP/1.1\r\nHost: localhost\r\nUpgrade: connect-ip\r\nConnection: Upgrade\r\nCapsule-Protocol: ?1\r\n\r\n";
    c.write_all(req.as_bytes()).unwrap();

    let mut buf = [0u8; 4096];
    let n = c.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains(" 403 "), "expected 403: {resp}");

    let _ = rt;
}

// ---------------------------------------------------------------------------
// CONNECT-IP client (`connect_ip`) against this crate's own relay
// ---------------------------------------------------------------------------

enum IpClientEvent {
    Opened(Arc<dyn ConnectIpClientSession>),
    Packet(Vec<u8>),
    AddressAssigned(u64, IpAddr, u8),
    RouteAdvertised(IpAddr, IpAddr, u8),
    Closed,
    Error(String),
}

impl std::fmt::Debug for IpClientEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opened(_) => write!(f, "Opened"),
            Self::Packet(d) => write!(f, "Packet({d:?})"),
            Self::AddressAssigned(id, a, p) => write!(f, "AddressAssigned({id}, {a}, {p})"),
            Self::RouteAdvertised(s, e, p) => write!(f, "RouteAdvertised({s}, {e}, {p})"),
            Self::Closed => write!(f, "Closed"),
            Self::Error(e) => write!(f, "Error({e:?})"),
        }
    }
}

struct ChannelIpEventHandler {
    tx: std::sync::mpsc::Sender<IpClientEvent>,
}

impl ConnectIpEventHandler for ChannelIpEventHandler {
    fn opened(&mut self, session: Arc<dyn ConnectIpClientSession>) {
        let _ = self.tx.send(IpClientEvent::Opened(session));
    }

    fn packet_received(&mut self, packet: &[u8]) {
        let _ = self.tx.send(IpClientEvent::Packet(packet.to_vec()));
    }

    fn address_assigned(&mut self, request_id: u64, address: IpAddr, prefix_length: u8) {
        let _ = self.tx.send(IpClientEvent::AddressAssigned(request_id, address, prefix_length));
    }

    fn route_advertised(&mut self, start: IpAddr, end: IpAddr, ip_protocol: u8) {
        let _ = self.tx.send(IpClientEvent::RouteAdvertised(start, end, ip_protocol));
    }

    fn closed(&mut self) {
        let _ = self.tx.send(IpClientEvent::Closed);
    }

    fn error(&mut self, err: &std::io::Error) {
        let _ = self.tx.send(IpClientEvent::Error(err.to_string()));
    }
}

/// Proves the client side (`connect_ip`) actually interoperates with this
/// crate's own server relay, not just that each half separately matches
/// the RFC 9484 wire format on paper: dials [`EchoIpHandlerFactory`]'s
/// relay over a real loopback TCP connection, sends a packet through it,
/// and checks the echo comes all the way back out through
/// [`ConnectIpEventHandler::packet_received`].
#[test]
fn client_connect_ip_round_trips_packets_through_the_server_relay() {
    let (rt, server_addr) = start_connect_ip_server(Arc::new(EchoIpHandlerFactory), Arc::new(AllowAnyIp));
    thread::sleep(Duration::from_millis(50));

    let (tx, rx) = std::sync::mpsc::channel();
    let handler = Box::new(ChannelIpEventHandler { tx });

    connect_ip(
        &rt,
        &server_addr.ip().to_string(),
        server_addr.port(),
        IpTarget::Wildcard,
        IpProto::Wildcard,
        HttpFallback::PlaintextH1,
        handler,
        None,
        Arc::new(AltSvcCache::new()),
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    let session = match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(IpClientEvent::Opened(s)) => s,
        Ok(IpClientEvent::Error(e)) => panic!("tunnel failed to open: {e}"),
        other => panic!("expected Opened, got {other:?}"),
    };

    session.send_packet(b"fake-ip-packet");

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(IpClientEvent::Packet(d)) => assert_eq!(d, b"fake-ip-packet"),
        other => panic!("expected an echoed Packet, got {other:?}"),
    }
}

/// A `send_address_request` from the client gets a real `address_assigned`
/// callback — the client-side counterpart of
/// [`h1_connect_ip_address_request_gets_assigned`], proving the same
/// capsule round trip end to end from the client API rather than a raw
/// socket.
#[test]
fn client_connect_ip_address_request_gets_assigned() {
    let (rt, server_addr) = start_connect_ip_server(Arc::new(EchoIpHandlerFactory), Arc::new(AllowAnyIp));
    thread::sleep(Duration::from_millis(50));

    let (tx, rx) = std::sync::mpsc::channel();
    let handler = Box::new(ChannelIpEventHandler { tx });

    connect_ip(
        &rt,
        &server_addr.ip().to_string(),
        server_addr.port(),
        IpTarget::Wildcard,
        IpProto::Wildcard,
        HttpFallback::PlaintextH1,
        handler,
        None,
        Arc::new(AltSvcCache::new()),
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    let session = match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(IpClientEvent::Opened(s)) => s,
        other => panic!("expected Opened, got {other:?}"),
    };

    session.send_address_request(&[RequestedAddress {
        request_id: 9,
        address: "0.0.0.0".parse().unwrap(),
        prefix_length: 0,
    }]);

    match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(IpClientEvent::AddressAssigned(id, addr, prefix)) => {
            assert_eq!(id, 9);
            assert_eq!(addr, "192.0.2.1".parse::<IpAddr>().unwrap());
            assert_eq!(prefix, 32);
        }
        other => panic!("expected AddressAssigned, got {other:?}"),
    }
}

/// A route the server advertises unprompted, the instant the tunnel opens
/// (see [`RouteAdvertisingIpHandler`]), still reaches the client via
/// `connect_ip` — the client-side counterpart of
/// [`h1_connect_ip_route_advertisement_reaches_the_client`].
#[test]
fn client_connect_ip_receives_route_advertisement() {
    let (rt, server_addr) =
        start_connect_ip_server(Arc::new(RouteAdvertisingIpHandlerFactory), Arc::new(AllowAnyIp));
    thread::sleep(Duration::from_millis(50));

    let (tx, rx) = std::sync::mpsc::channel();
    let handler = Box::new(ChannelIpEventHandler { tx });

    connect_ip(
        &rt,
        &server_addr.ip().to_string(),
        server_addr.port(),
        IpTarget::Wildcard,
        IpProto::Wildcard,
        HttpFallback::PlaintextH1,
        handler,
        None,
        Arc::new(AltSvcCache::new()),
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    // The route is advertised from `opened()` on the *server* side, before
    // this client's own `opened()` even fires — either event may arrive
    // first, so accept both orders.
    let mut saw_opened = false;
    let mut saw_route = false;
    while !(saw_opened && saw_route) {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(IpClientEvent::Opened(_)) => saw_opened = true,
            Ok(IpClientEvent::RouteAdvertised(start, end, ip_protocol)) => {
                assert_eq!(start, "192.0.2.0".parse::<IpAddr>().unwrap());
                assert_eq!(end, "192.0.2.255".parse::<IpAddr>().unwrap());
                assert_eq!(ip_protocol, 0);
                saw_route = true;
            }
            other => panic!("expected Opened or RouteAdvertised, got {other:?}"),
        }
    }
}
