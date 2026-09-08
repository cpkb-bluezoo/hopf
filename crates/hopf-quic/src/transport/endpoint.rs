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
        Self {
            config: EndpointConfig {
                cid_len: if config.cid_len == 0 { 8 } else { config.cid_len },
            },
            server,
            cids: CidMap::default(),
            connections: HashMap::new(),
            next_handle: 0,
            client_handle: None,
        }
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
        let local_cid = ConnectionId::random(self.config.cid_len);
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
        _send_buf: &mut Vec<u8>,
    ) -> Option<DatagramEvent> {
        if data.is_empty() {
            return None;
        }
        if data[0] & 0x80 != 0 {
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
        let local_cid = incoming
            .retry_local_cid
            .clone()
            .unwrap_or_else(|| ConnectionId::random(self.config.cid_len));
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
        let retry_scid = ConnectionId::random(self.config.cid_len);
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
}
