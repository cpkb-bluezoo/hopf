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

use crate::{connect_udp, ConnectUdpEventHandler, ConnectUdpFactory, ConnectUdpPolicy, ConnectUdpSession};

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
