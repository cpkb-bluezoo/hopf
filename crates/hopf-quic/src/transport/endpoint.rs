// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC endpoint: CID demux, connect, accept.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use hopf_core::tls::HandshakeConfig;

use crate::transport::cid::CidMap;
use crate::transport::connection::Connection;
use crate::transport::packet::long_header::{self, TYPE_INITIAL};
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
}

impl ServerConfig {
    /// Build with handshake config.
    pub fn new(handshake: HandshakeConfig) -> Self {
        Self {
            handshake,
            transport: Arc::new(()),
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
}

impl ClientConfig {
    /// Build with handshake config.
    pub fn new(handshake: HandshakeConfig) -> Self {
        Self {
            handshake,
            version: VERSION_V1,
            transport: Arc::new(()),
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
        let mut conn = Connection::new_client(
            now,
            remote,
            server_name,
            config.handshake,
            local_cid.clone(),
            initial_dcid,
        );
        let handle = self.alloc_handle();
        self.cids.insert(local_cid, handle);
        // Leave Initial ClientHello queued on `conn` — the driver owns the
        // Connection and will `poll_transmit` after insert.
        self.client_handle = Some(handle);
        let _ = now;
        Ok((handle, conn))
    }

    /// Handle an inbound datagram. Returns events; connection events are for handles the driver owns.
    ///
    /// For server NewConnection, the driver calls `accept`. For ConnectionEvent, the driver
    /// forwards to its Connection. This endpoint only demuxes and creates Incoming.
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
        // Long header: parse DCID for demux / new connection.
        if data[0] & 0x80 != 0 {
            let prefix = long_header::parse_prefix(&data)?;
            if let Some(handle) = self.cids.get(&prefix.dst_cid) {
                return Some(DatagramEvent::ConnectionEvent(
                    handle,
                    ConnectionEvent { datagram: data },
                ));
            }
            // Unknown DCID — maybe new Initial.
            if prefix.packet_type == TYPE_INITIAL && prefix.version == VERSION_V1 {
                if self.server.is_none() {
                    return None;
                }
                return Some(DatagramEvent::NewConnection(Incoming {
                    remote,
                    dst_cid: prefix.dst_cid.clone(),
                    src_cid: prefix.src_cid,
                    orig_dst_cid: prefix.dst_cid,
                    packet: data,
                    address_validated: true, // permissive for echo
                }));
            }
            return None;
        }
        // Short header: try all CID lengths we know (use configured len).
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

    /// Accept an Incoming connection.
    pub fn accept(
        &mut self,
        incoming: Incoming,
        now: Instant,
        _send_buf: &mut Vec<u8>,
        _server_config: Option<Arc<ServerConfig>>,
    ) -> Result<(ConnectionHandle, Connection), AcceptError> {
        let server = self
            .server
            .clone()
            .ok_or(AcceptError::NoServerConfig)?;
        let local_cid = ConnectionId::random(self.config.cid_len);
        let mut conn = Connection::new_server(
            now,
            incoming.remote,
            server.handshake,
            local_cid.clone(),
            incoming.dst_cid,
            incoming.src_cid,
        );
        let handle = self.alloc_handle();
        self.cids.insert(local_cid, handle);
        // Process the Initial packet that created this Incoming.
        conn.handle_packet(now, &incoming.packet);
        Ok((handle, conn))
    }

    /// Retry (not implemented for echo — refuse path unused).
    pub fn retry(
        &mut self,
        _incoming: Incoming,
        _send_buf: &mut Vec<u8>,
    ) -> Result<Transmit, ()> {
        Err(())
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

    /// Register an additional CID for an existing handle (driver calls after accept/connect).
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
