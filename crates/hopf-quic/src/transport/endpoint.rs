// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC endpoint: CID demux, connect, accept, Retry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use hopf_core::tls::HandshakeConfig;

use crate::transport::cid::CidMap;
use crate::transport::connection::Connection;
use crate::transport::packet::long_header::{self, TYPE_INITIAL, TYPE_RETRY};
use crate::transport::packet::retry;
use crate::transport::packet::version_negotiation as vn;
use crate::transport::quic_lb::{ConnectionIdGenerator, RandomConnectionIdGenerator};
use crate::transport::types::{
    ConnectionEvent, ConnectionHandle, ConnectionId, DatagramEvent, EndpointConfig, Incoming,
    Transmit, VERSION_V1,
};

/// Server crypto + transport settings.
#[derive(Clone)]
pub struct ServerConfig {
    /// TLS handshake config.
    pub handshake: HandshakeConfig,
    /// Transport options (idle timeout etc. — applied as defaults for now).
    pub transport: Arc<()>,
    /// AES-256 key for sealing Retry Tokens.
    pub retry_token_key: [u8; 32],
    /// Maximum age of a Retry Token.
    pub retry_token_lifetime: Duration,
    /// Local `max_datagram_frame_size` (`None` = DATAGRAM disabled).
    pub max_datagram_frame_size: Option<u64>,
    /// Local `max_idle_timeout` override (`None` = transport default).
    pub max_idle_timeout: Option<Duration>,
    /// Local `initial_max_streams_bidi` override.
    pub initial_max_streams_bidi: Option<u64>,
    /// Local `initial_max_streams_uni` override.
    pub initial_max_streams_uni: Option<u64>,
    /// Keep-alive PING interval (`None` = disabled).
    pub keep_alive_interval: Option<Duration>,
    /// Where server-issued connection IDs come from. `None` = 8 random
    /// octets; set it to issue QUIC-LB IDs (see [`crate::transport::quic_lb`]).
    pub cid_generator: Option<Arc<dyn ConnectionIdGenerator>>,
}

impl ServerConfig {
    /// Build with handshake config (fresh random Retry key, 10s lifetime).
    pub fn new(handshake: HandshakeConfig) -> Self {
        Self {
            handshake,
            transport: Arc::new(()),
            retry_token_key: retry::generate_token_key(),
            retry_token_lifetime: Duration::from_secs(10),
            max_datagram_frame_size: Some(1452),
            max_idle_timeout: None,
            initial_max_streams_bidi: None,
            initial_max_streams_uni: None,
            keep_alive_interval: None,
            cid_generator: None,
        }
    }
}

/// Client crypto + transport settings.
#[derive(Clone)]
pub struct ClientConfig {
    /// TLS handshake config.
    pub handshake: HandshakeConfig,
    /// QUIC version.
    pub version: u32,
    /// Transport placeholder.
    pub transport: Arc<()>,
    /// Local `max_datagram_frame_size` (`None` = DATAGRAM disabled).
    pub max_datagram_frame_size: Option<u64>,
    /// Local `max_idle_timeout` override (`None` = transport default).
    pub max_idle_timeout: Option<Duration>,
    /// Local `initial_max_streams_bidi` override.
    pub initial_max_streams_bidi: Option<u64>,
    /// Local `initial_max_streams_uni` override.
    pub initial_max_streams_uni: Option<u64>,
    /// Keep-alive PING interval (`None` = disabled).
    pub keep_alive_interval: Option<Duration>,
}

impl ClientConfig {
    /// Build with handshake config.
    pub fn new(handshake: HandshakeConfig) -> Self {
        Self {
            handshake,
            version: VERSION_V1,
            transport: Arc::new(()),
            max_datagram_frame_size: Some(1452),
            max_idle_timeout: None,
            initial_max_streams_bidi: None,
            initial_max_streams_uni: None,
            keep_alive_interval: None,
        }
    }
}

/// QUIC endpoint multiplexer.
pub struct Endpoint {
    config: EndpointConfig,
    server: Option<ServerConfig>,
    /// Source of every connection ID this endpoint issues.
    cid_generator: Arc<dyn ConnectionIdGenerator>,
    cids: CidMap,
    connections: HashMap<ConnectionHandle, Connection>,
    next_handle: usize,
    /// Client-only: the single outbound connection handle.
    client_handle: Option<ConnectionHandle>,
}

impl Endpoint {
    /// Create an endpoint. `server` is `Some` for listeners.
    pub fn new(
        config: EndpointConfig,
        server: Option<ServerConfig>,
        _enable_client: bool,
        _reset_token_key: Option<()>,
    ) -> Self {
        // A configured generator (QUIC-LB) fixes the CID length, which the
        // short-header demux below depends on; otherwise 8 random octets.
        let cid_generator = server
            .as_ref()
            .and_then(|s| s.cid_generator.clone())
            .unwrap_or_else(|| Arc::new(RandomConnectionIdGenerator::new(if config.cid_len == 0 { 8 } else { config.cid_len })));
        Self {
            config: EndpointConfig { cid_len: cid_generator.cid_len() },
            cid_generator,
            server,
            cids: CidMap::default(),
            connections: HashMap::new(),
            next_handle: 0,
            client_handle: None,
        }
    }

    /// A new local connection ID from the generator that no live connection
    /// already uses. Collisions are only possible for a generator with a
    /// random component (e.g. QUIC-LB's plaintext nonce), and are rare, so a
    /// few retries suffice.
    fn new_local_cid(&self) -> ConnectionId {
        let mut cid = self.cid_generator.generate();
        for _ in 0..16 {
            if self.cids.get(&cid).is_none() {
                break;
            }
            cid = self.cid_generator.generate();
        }
        cid
    }

    fn alloc_handle(&mut self) -> ConnectionHandle {
        let h = ConnectionHandle(self.next_handle);
        self.next_handle += 1;
        h
    }

    /// Client connect.
    pub fn connect(
        &mut self,
        now: Instant,
        config: ClientConfig,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<(ConnectionHandle, Connection), ConnectError> {
        let local_cid = self.new_local_cid();
        let initial_dcid = ConnectionId::random(8);
        let conn = Connection::new_client(
            now,
            remote,
            server_name,
            config.handshake,
            local_cid.clone(),
            initial_dcid,
            config.max_datagram_frame_size,
            config.max_idle_timeout,
            config.initial_max_streams_bidi,
            config.initial_max_streams_uni,
            config.keep_alive_interval,
        );
        let handle = self.alloc_handle();
        self.cids.insert(local_cid, handle);
        self.client_handle = Some(handle);
        let _ = now;
        Ok((handle, conn))
    }

    /// Handle an inbound datagram.
    pub fn handle(
        &mut self,
        _now: Instant,
        remote: SocketAddr,
        _local: Option<std::net::IpAddr>,
        _ecn: Option<u8>,
        data: Bytes,
        send_buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        if data.is_empty() {
            return None;
        }
        if data[0] & 0x80 != 0 {
            // Anything but version 1 can't be parsed past the RFC 8999
            // invariants, so it never reaches the v1 header parser below.
            if let Some((version, dcid, scid)) = vn::parse_invariants(&data) {
                if version != VERSION_V1 {
                    return self.unsupported_version(version, dcid, scid, &data, remote, send_buf);
                }
            }
            let first_type = (data[0] >> 4) & 0x03;
            // Retry has no Length; demux by DCID only.
            if first_type == TYPE_RETRY {
                let parsed = retry::parse(&data)?;
                let handle = self.cids.get(&parsed.dst_cid)?;
                return Some(DatagramEvent::ConnectionEvent(
                    handle,
                    ConnectionEvent { datagram: data },
                ));
            }
            let prefix = long_header::parse_prefix(&data)?;
            if let Some(handle) = self.cids.get(&prefix.dst_cid) {
                return Some(DatagramEvent::ConnectionEvent(
                    handle,
                    ConnectionEvent { datagram: data },
                ));
            }
            if prefix.packet_type == TYPE_INITIAL && prefix.version == VERSION_V1 {
                if self.server.is_none() {
                    return None;
                }
                let (address_validated, orig_dst_cid, retry_local_cid) =
                    self.validate_initial_token(&prefix.token, remote, &prefix.dst_cid);
                return Some(DatagramEvent::NewConnection(Incoming {
                    remote,
                    dst_cid: prefix.dst_cid.clone(),
                    src_cid: prefix.src_cid,
                    orig_dst_cid,
                    packet: data,
                    address_validated,
                    retry_local_cid,
                }));
            }
            return None;
        }
        let cid_len = self.config.cid_len;
        if data.len() > 1 + cid_len {
            let cid = ConnectionId::from_slice(&data[1..1 + cid_len]);
            if let Some(handle) = self.cids.get(&cid) {
                return Some(DatagramEvent::ConnectionEvent(
                    handle,
                    ConnectionEvent { datagram: data },
                ));
            }
        }
        None
    }

    /// A long-header packet in a version other than 1 (RFC 9000 section
    /// 5.2.2): a Version Negotiation packet is handed to the outbound
    /// connection it echoes (and never answered, section 6), a big-enough
    /// datagram to a server gets a Version Negotiation packet, and anything
    /// else - too small, for a connection we already have, or arriving at a
    /// client-only endpoint - is dropped.
    fn unsupported_version(
        &mut self,
        version: u32,
        dcid: &[u8],
        scid: &[u8],
        data: &Bytes,
        remote: SocketAddr,
        send_buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        if version == 0 {
            // A Version Negotiation packet: only ever for one of our own
            // outbound connections, demultiplexed on its DCID (our SCID).
            let handle = self.cids.get(&ConnectionId::from_slice(dcid))?;
            return Some(DatagramEvent::ConnectionEvent(handle, ConnectionEvent { datagram: data.clone() }));
        }
        if self.server.is_none()
            || data.len() < vn::MIN_INITIAL_DATAGRAM_LEN
            || self.cids.get(&ConnectionId::from_slice(dcid)).is_some()
        {
            return None;
        }
        let packet = vn::build(scid, dcid);
        send_buf.clear();
        send_buf.extend_from_slice(&packet);
        Some(DatagramEvent::Response(Transmit {
            destination: remote,
            ecn: None,
            size: packet.len(),
            segment_size: None,
            src_ip: None,
        }))
    }

    fn validate_initial_token(
        &self,
        token: &[u8],
        remote: SocketAddr,
        packet_dst_cid: &ConnectionId,
    ) -> (bool, ConnectionId, Option<ConnectionId>) {
        if token.is_empty() {
            return (false, packet_dst_cid.clone(), None);
        }
        let Some(server) = self.server.as_ref() else {
            return (false, packet_dst_cid.clone(), None);
        };
        match retry::unseal_token(
            &server.retry_token_key,
            token,
            remote.ip(),
            server.retry_token_lifetime,
        ) {
            Some(odcid) => (
                true,
                ConnectionId::from_slice(&odcid),
                Some(packet_dst_cid.clone()),
            ),
            None => (false, packet_dst_cid.clone(), None),
        }
    }

    /// Accept an Incoming connection.
    pub fn accept(
        &mut self,
        incoming: Incoming,
        now: Instant,
        _send_buf: &mut Vec<u8>,
        _server_config: Option<Arc<ServerConfig>>,
    ) -> Result<(ConnectionHandle, Connection), AcceptError> {
        let server = self.server.clone().ok_or(AcceptError::NoServerConfig)?;
        let via_retry = incoming.retry_local_cid.is_some();
        // The Retry source CID was chosen statelessly, before this connection
        // existed; if a live connection has since been given the same one,
        // taking it would overwrite that connection's routing entry.
        if let Some(cid) = &incoming.retry_local_cid {
            if self.cids.get(cid).is_some() {
                return Err(AcceptError::CidInUse);
            }
        }
        let local_cid = incoming
            .retry_local_cid
            .clone()
            .unwrap_or_else(|| self.new_local_cid());
        // Initial keys use the DCID the client addressed (post-Retry: Retry SCID).
        let initial_dcid = if via_retry {
            incoming.dst_cid.clone()
        } else {
            incoming.orig_dst_cid.clone()
        };
        let mut conn = Connection::new_server(
            now,
            incoming.remote,
            server.handshake,
            local_cid.clone(),
            initial_dcid,
            incoming.src_cid,
            incoming.orig_dst_cid,
            incoming.retry_local_cid.clone(),
            server.max_datagram_frame_size,
            server.max_idle_timeout,
            server.initial_max_streams_bidi,
            server.initial_max_streams_uni,
            server.keep_alive_interval,
        );
        let handle = self.alloc_handle();
        self.cids.insert(local_cid, handle);
        conn.handle_packet(now, &incoming.packet);
        Ok((handle, conn))
    }

    /// Build a stateless Retry packet (RFC 9000 §8.1.2).
    pub fn retry(
        &mut self,
        incoming: Incoming,
        send_buf: &mut Vec<u8>,
    ) -> Result<Transmit, ()> {
        let server = self.server.as_ref().ok_or(())?;
        let retry_scid = self.new_local_cid();
        let token = retry::seal_token(
            &server.retry_token_key,
            incoming.orig_dst_cid.as_slice(),
            incoming.remote.ip(),
            SystemTime::now(),
        );
        let packet = retry::build_packet(
            &incoming.src_cid,
            &retry_scid,
            incoming.orig_dst_cid.as_slice(),
            &token,
        );
        send_buf.clear();
        send_buf.extend_from_slice(&packet);
        Ok(Transmit {
            destination: incoming.remote,
            ecn: None,
            size: packet.len(),
            segment_size: None,
            src_ip: None,
        })
    }

    /// Refuse an Incoming.
    pub fn refuse(&mut self, _incoming: Incoming, _send_buf: &mut Vec<u8>) {}

    /// Handle endpoint event from a connection (no-op).
    pub fn handle_event(
        &mut self,
        _ch: ConnectionHandle,
        _ev: ConnectionEvent,
    ) -> Option<ConnectionEvent> {
        None
    }

    /// Register an additional CID for an existing handle.
    pub fn register_cid(&mut self, cid: ConnectionId, handle: ConnectionHandle) {
        self.cids.insert(cid, handle);
    }

    /// Forget a connection's CIDs.
    pub fn forget(&mut self, handle: ConnectionHandle) {
        self.cids.remove_handle(handle);
    }
}

/// Connect error.
#[derive(Debug)]
pub enum ConnectError {
    /// Invalid server name.
    InvalidServerName(String),
    /// Unsupported version.
    UnsupportedVersion,
    /// Invalid remote address.
    InvalidRemoteAddress(SocketAddr),
    /// CIDs exhausted.
    CidsExhausted,
}

/// Accept error.
#[derive(Debug)]
pub enum AcceptError {
    /// No server config.
    NoServerConfig,
    /// The post-Retry local connection ID (fixed by the Retry already sent)
    /// is already held by a live connection.
    CidInUse,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::packet::long_header;
    use hopf_core::tls::{HandshakeMode, HandshakeRole};

    const UNKNOWN_VERSION: u32 = 0xbabababa;
    const MIN_INITIAL_DATAGRAM: usize = 1200;

    fn endpoint(server: bool) -> Endpoint {
        let server = server.then(|| {
            ServerConfig::new(HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Quic,
                ..Default::default()
            })
        });
        Endpoint::new(EndpointConfig::default(), server, false, None)
    }

    /// A long-header datagram of `total` bytes in a version-invariant shape
    /// (RFC 8999): first byte, version, DCID, SCID, then filler.
    fn long_header_datagram(version: u32, dcid: &[u8], scid: &[u8], total: usize) -> Bytes {
        let mut d = vec![0xc0u8];
        d.extend_from_slice(&version.to_be_bytes());
        d.push(dcid.len() as u8);
        d.extend_from_slice(dcid);
        d.push(scid.len() as u8);
        d.extend_from_slice(scid);
        d.resize(total, 0x55);
        Bytes::from(d)
    }

    fn remote() -> SocketAddr {
        "192.0.2.7:4433".parse().unwrap()
    }

    /// Feed a datagram; return the Version Negotiation bytes if the
    /// endpoint answered with one.
    fn response_to(ep: &mut Endpoint, datagram: Bytes) -> Option<Vec<u8>> {
        let mut send_buf = Vec::new();
        match ep.handle(Instant::now(), remote(), None, None, datagram, &mut send_buf) {
            Some(DatagramEvent::Response(tx)) => {
                assert_eq!(tx.destination, remote());
                assert_eq!(tx.size, send_buf.len());
                Some(send_buf)
            }
            _ => None,
        }
    }

    /// Split a Version Negotiation packet (RFC 9000 section 17.2.1) into
    /// (first byte, version, DCID, SCID, supported versions).
    fn split_vn(p: &[u8]) -> (u8, u32, Vec<u8>, Vec<u8>, Vec<u32>) {
        let version = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
        let dl = p[5] as usize;
        let dcid = p[6..6 + dl].to_vec();
        let sl = p[6 + dl] as usize;
        let scid = p[7 + dl..7 + dl + sl].to_vec();
        let list = &p[7 + dl + sl..];
        assert_eq!(list.len() % 4, 0, "version list is whole 32-bit values");
        let versions = list.chunks(4).map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]])).collect();
        (p[0], version, dcid, scid, versions)
    }

    /// RFC 9000 section 5.2.2: an unsupported version in a datagram big
    /// enough to be an Initial gets a Version Negotiation packet echoing the
    /// client's connection IDs (swapped) and listing what we support.
    #[test]
    fn server_answers_an_unsupported_version_with_version_negotiation() {
        let mut ep = endpoint(true);
        let dcid = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let scid = [9u8, 10, 11, 12, 13];
        let vn = response_to(&mut ep, long_header_datagram(UNKNOWN_VERSION, &dcid, &scid, MIN_INITIAL_DATAGRAM))
            .expect("Version Negotiation response");
        let (first, version, vn_dcid, vn_scid, versions) = split_vn(&vn);
        assert_eq!(first & 0x80, 0x80, "long header form bit");
        assert_eq!(version, 0);
        assert_eq!(vn_dcid, scid, "DCID is the client's SCID");
        assert_eq!(vn_scid, dcid, "SCID is the client's DCID");
        assert!(versions.contains(&VERSION_V1), "{versions:x?}");
        assert!(!versions.contains(&UNKNOWN_VERSION));
        assert!(vn.len() < MIN_INITIAL_DATAGRAM, "must not amplify");
    }

    /// Connection IDs of an unknown version may be up to 255 bytes long
    /// (RFC 8999); they are echoed verbatim, not truncated to v1's 20.
    #[test]
    fn version_negotiation_echoes_long_connection_ids_verbatim() {
        let mut ep = endpoint(true);
        let dcid: Vec<u8> = (0..30u8).collect();
        let scid: Vec<u8> = (100..125u8).collect();
        let vn = response_to(&mut ep, long_header_datagram(UNKNOWN_VERSION, &dcid, &scid, 1350)).unwrap();
        let (_, _, vn_dcid, vn_scid, _) = split_vn(&vn);
        assert_eq!(vn_dcid, scid);
        assert_eq!(vn_scid, dcid);
    }

    /// Below the smallest possible Initial the datagram can't start a
    /// connection in any supported version, so no reply (RFC 9000 5.2.2).
    #[test]
    fn undersized_unsupported_version_datagram_is_dropped_without_a_reply() {
        let mut ep = endpoint(true);
        let d = long_header_datagram(UNKNOWN_VERSION, &[1; 8], &[2; 8], MIN_INITIAL_DATAGRAM - 1);
        assert!(response_to(&mut ep, d).is_none());
    }

    /// RFC 9000 section 6: never answer a Version Negotiation packet
    /// (version 0) with another - that could loop between two endpoints.
    #[test]
    fn a_version_negotiation_packet_is_never_answered() {
        let mut ep = endpoint(true);
        let d = long_header_datagram(0, &[1; 8], &[2; 8], MIN_INITIAL_DATAGRAM);
        assert!(response_to(&mut ep, d).is_none());
    }

    #[test]
    fn a_client_only_endpoint_never_sends_version_negotiation() {
        let mut ep = endpoint(false);
        let d = long_header_datagram(UNKNOWN_VERSION, &[1; 8], &[2; 8], MIN_INITIAL_DATAGRAM);
        assert!(response_to(&mut ep, d).is_none());
    }

    /// Regression: a version 1 Initial still becomes a new connection.
    #[test]
    fn a_version_1_initial_still_starts_a_connection() {
        let mut ep = endpoint(true);
        let dcid = ConnectionId::from_slice(&[7u8; 8]);
        let scid = ConnectionId::from_slice(&[8u8; 8]);
        let mut d = long_header::build(TYPE_INITIAL, VERSION_V1, &dcid, &scid, &[], 0, 1, 1180);
        d.resize(MIN_INITIAL_DATAGRAM, 0);
        let mut send_buf = Vec::new();
        let ev = ep.handle(Instant::now(), remote(), None, None, Bytes::from(d), &mut send_buf);
        assert!(matches!(ev, Some(DatagramEvent::NewConnection(_))), "{ev:?}");
    }

    // ---- QUIC-LB server-issued connection IDs (issue 413) ----

    use crate::transport::quic_lb::{ConnectionIdGenerator, QuicLbConfig};

    /// Two backends of one deployment: same config ID, key and nonce length,
    /// distinct server IDs; the load balancer's config is the same again
    /// without any server ID of its own (it only decodes).
    fn lb_config(server_id: &[u8]) -> QuicLbConfig {
        QuicLbConfig::new(1, server_id, 6).unwrap().with_key([0x42; 16]).unwrap()
    }

    fn lb_endpoint(cfg: &QuicLbConfig) -> Endpoint {
        let mut server = ServerConfig::new(HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Quic,
            ..Default::default()
        });
        server.cid_generator = Some(cfg.generator());
        Endpoint::new(EndpointConfig::default(), Some(server), false, None)
    }

    fn incoming(validated: bool, retry_local_cid: Option<ConnectionId>) -> Incoming {
        Incoming {
            remote: remote(),
            dst_cid: ConnectionId::from_slice(&[7u8; 8]),
            src_cid: ConnectionId::from_slice(&[8u8; 8]),
            orig_dst_cid: ConnectionId::from_slice(&[7u8; 8]),
            packet: Bytes::new(),
            address_validated: validated,
            retry_local_cid,
        }
    }

    fn accept(ep: &mut Endpoint) -> (ConnectionHandle, ConnectionId) {
        let (h, conn) = ep.accept(incoming(true, None), Instant::now(), &mut Vec::new(), None).unwrap();
        (h, conn.local_cid().clone())
    }

    /// The Initial-response source CID is a QUIC-LB CID naming this backend.
    #[test]
    fn accepted_connections_get_lb_connection_ids_that_decode_to_the_server_id() {
        let cfg = lb_config(&[0xa1, 0x01]);
        let mut ep = lb_endpoint(&cfg);
        for _ in 0..5 {
            let (_, cid) = accept(&mut ep);
            assert_eq!(cid.len(), cfg.cid_len());
            assert_eq!(cfg.decode_server_id(cid.as_slice()), Some(vec![0xa1, 0x01]));
        }
    }

    /// A Retry's source CID becomes the connection's CID after the client
    /// returns with the token, so it must be routable too.
    #[test]
    fn retry_source_connection_ids_decode_to_the_server_id() {
        let cfg = lb_config(&[0xa1, 0x01]);
        let mut ep = lb_endpoint(&cfg);
        let mut buf = Vec::new();
        ep.retry(incoming(false, None), &mut buf).unwrap();
        let retry_scid = retry::parse(&buf).expect("a Retry packet").src_cid;
        assert_eq!(cfg.decode_server_id(retry_scid.as_slice()), Some(vec![0xa1, 0x01]));
    }

    /// The migration scenario the issue asks for. The client's address
    /// changes (NAT rebinding) but its DCID does not: a stateless load
    /// balancer decodes the same server ID from the datagram and picks the
    /// same backend, whose own table then finds the connection. Without
    /// QUIC-LB the other backend would get it and drop it.
    #[test]
    fn a_datagram_keeps_reaching_the_same_backend_after_the_client_address_changes() {
        let (id_a, id_b) = ([0xa1u8, 0x01], [0xb2u8, 0x02]);
        let (mut a, mut b) = (lb_endpoint(&lb_config(&id_a)), lb_endpoint(&lb_config(&id_b)));
        let lb = lb_config(&[0, 0]); // the balancer only decodes; its own server ID is unused
        let route = |dcid: &[u8]| match lb.decode_server_id(dcid).as_deref() {
            Some(x) if x == id_a => "a",
            Some(x) if x == id_b => "b",
            _ => "unroutable",
        };

        let (handle, cid) = accept(&mut a);
        let mut short = vec![0x41u8];
        short.extend_from_slice(cid.as_slice());
        short.extend_from_slice(&[0x99; 40]);

        for new_addr in ["192.0.2.7:4433", "198.51.100.9:61000", "203.0.113.5:1024"] {
            assert_eq!(route(&short[1..1 + cid.len()]), "a", "balancer picks the issuing backend");
            let mut buf = Vec::new();
            let ev = a.handle(Instant::now(), new_addr.parse().unwrap(), None, None, Bytes::from(short.clone()), &mut buf);
            match ev {
                Some(DatagramEvent::ConnectionEvent(h, _)) => assert_eq!(h, handle),
                other => panic!("backend a lost the connection: {other:?}"),
            }
        }
        // The other backend has no such connection - which is exactly why the
        // balancer must not send it there.
        let mut buf = Vec::new();
        assert!(b.handle(Instant::now(), remote(), None, None, Bytes::from(short), &mut buf).is_none());

        // And backend b's own CIDs route to b.
        let (_, cid_b) = accept(&mut b);
        assert_eq!(route(cid_b.as_slice()), "b");
    }

    /// The endpoint's short-header demux length follows the generator.
    #[test]
    fn the_endpoint_demultiplexes_short_headers_at_the_generators_length() {
        for (sid_len, nonce_len) in [(1usize, 4usize), (2, 6), (4, 12), (1, 18)] {
            let cfg = QuicLbConfig::new(0, &vec![0x5a; sid_len], nonce_len).unwrap().with_key([1; 16]).unwrap();
            let mut ep = lb_endpoint(&cfg);
            let (handle, cid) = accept(&mut ep);
            assert_eq!(cid.len(), 1 + sid_len + nonce_len);
            let mut d = vec![0x40u8];
            d.extend_from_slice(cid.as_slice());
            d.extend_from_slice(&[1; 30]);
            let ev = ep.handle(Instant::now(), remote(), None, None, Bytes::from(d), &mut Vec::new());
            assert!(matches!(ev, Some(DatagramEvent::ConnectionEvent(h, _)) if h == handle), "{sid_len}/{nonce_len}");
        }
    }

    /// Without QUIC-LB, connection IDs stay 8 random octets.
    #[test]
    fn random_connection_ids_remain_the_default() {
        let mut ep = endpoint(true);
        let (_, a) = accept(&mut ep);
        let (_, b) = accept(&mut ep);
        assert_eq!(a.len(), 8);
        assert_ne!(a, b);
    }

    /// A plaintext-mode QUIC-LB nonce is random, so two CIDs can collide; the
    /// endpoint must never register one CID for two connections.
    #[test]
    fn a_colliding_generated_connection_id_is_never_reused() {
        #[derive(Debug)]
        struct Colliding(Arc<std::sync::atomic::AtomicUsize>);
        impl ConnectionIdGenerator for Colliding {
            fn cid_len(&self) -> usize {
                8
            }
            fn generate(&self) -> ConnectionId {
                // The same ID for the first four calls, then fresh ones.
                let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < 4 {
                    ConnectionId::from_slice(&[0xcc; 8])
                } else {
                    ConnectionId::from_slice(&[n as u8; 8])
                }
            }
        }
        let mut server = ServerConfig::new(HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Quic,
            ..Default::default()
        });
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        server.cid_generator = Some(Arc::new(Colliding(Arc::clone(&calls))));
        let mut ep = Endpoint::new(EndpointConfig::default(), Some(server), false, None);
        let (h1, c1) = accept(&mut ep);
        let (h2, c2) = accept(&mut ep);
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 2, "the endpoint should have drawn again after the clash");
        assert_ne!(c1, c2, "two connections must not share a connection ID");
        assert_ne!(h1, h2);
    }

    /// After a Retry the server must keep the Retry source CID as its own; if
    /// a live connection has meanwhile taken the same CID, accepting would
    /// silently steal that connection's traffic, so the accept is refused.
    #[test]
    fn accept_after_retry_refuses_a_connection_id_a_live_connection_holds() {
        let cfg = lb_config(&[0xa1, 0x01]);
        let mut ep = lb_endpoint(&cfg);
        let (_, live_cid) = accept(&mut ep);
        let clash = incoming(true, Some(live_cid.clone()));
        let refused = ep.accept(clash, Instant::now(), &mut Vec::new(), None);
        assert!(matches!(refused, Err(AcceptError::CidInUse)), "{:?}", refused.map(|_| ()));
        // The live connection still owns its CID.
        let mut d = vec![0x40u8];
        d.extend_from_slice(live_cid.as_slice());
        d.extend_from_slice(&[1; 30]);
        assert!(matches!(
            ep.handle(Instant::now(), remote(), None, None, Bytes::from(d), &mut Vec::new()),
            Some(DatagramEvent::ConnectionEvent(..))
        ));
    }
}
