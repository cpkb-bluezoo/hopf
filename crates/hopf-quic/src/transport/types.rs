// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Core transport types (replacing quinn-proto handles / events).

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;

/// Opaque connection key used by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionHandle(pub usize);

/// Opaque QUIC stream identifier (RFC 9000 §2.1).
///
/// Constructed by the transport (or decoded from the wire via
/// [`Self::from_wire`]). Not interchangeable with [`crate::StreamKey`]
/// handles returned by [`crate::QuicConnApi::open_uni`] /
/// [`crate::QuicConnApi::open_bi`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamId({})", self.0)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<VarInt> for StreamId {
    fn from(v: VarInt) -> Self {
        Self(v.0)
    }
}

impl StreamId {
    /// Client-initiated bidirectional stream 0.
    pub const CLIENT_BI_0: Self = Self(0);
    /// Server-initiated bidirectional stream 1.
    pub const SERVER_BI_0: Self = Self(1);

    /// Decode a stream id from a QUIC / HTTP varint on the wire.
    ///
    /// Prefer values handed out by [`crate::QuicConnection::accept_bi`] /
    /// [`crate::QuicConnection::accept_uni`] when referring to live streams;
    /// use this only when parsing an id carried in application framing
    /// (QPACK, HTTP Datagrams, GOAWAY, …).
    pub const fn from_wire(raw: u64) -> Self {
        Self(raw)
    }

    /// Encode for QUIC / HTTP varint framing.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// `true` when this is a client-initiated bidirectional stream
    /// (`id % 4 == 0`) — the request streams HTTP/3 keys on.
    pub const fn is_client_bidi(self) -> bool {
        self.0 % 4 == 0
    }

    /// Stream initiator side.
    pub fn initiator(self) -> Side {
        if self.0 & 0x01 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }

    /// Bidirectional vs unidirectional.
    pub fn dir(self) -> Dir {
        if self.0 & 0x02 == 0 {
            Dir::Bi
        } else {
            Dir::Uni
        }
    }

    /// Index among streams of the same type.
    pub fn index(self) -> u64 {
        self.0 >> 2
    }

    /// Build from side + direction + index.
    pub fn new(side: Side, dir: Dir, index: u64) -> Self {
        let mut id = index << 2;
        if side == Side::Server {
            id |= 0x01;
        }
        if dir == Dir::Uni {
            id |= 0x02;
        }
        Self(id)
    }
}

/// Client or server role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Client.
    Client,
    /// Server.
    Server,
}

/// Stream direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Bidirectional.
    Bi,
    /// Unidirectional.
    Uni,
}

/// Variable-length integer wrapper for close codes etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(pub u64);

impl VarInt {
    /// Construct from `u32`.
    pub fn from_u32(v: u32) -> Self {
        Self(v as u64)
    }

    /// Construct from `u64` (must fit QUIC varint).
    pub fn from_u64(v: u64) -> Result<Self, ()> {
        if v > crate::transport::varint::MAX_VALUE {
            Err(())
        } else {
            Ok(Self(v))
        }
    }

    /// Into raw `u64`.
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

impl From<u32> for VarInt {
    fn from(v: u32) -> Self {
        Self::from_u32(v)
    }
}

/// Encryption / packet number space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SpaceId {
    /// Initial packets.
    #[default]
    Initial,
    /// Handshake packets.
    Handshake,
    /// 1-RTT (and 0-RTT receive) data space.
    Data,
}

/// Outbound UDP datagram descriptor.
#[derive(Debug, Clone)]
pub struct Transmit {
    /// Peer address.
    pub destination: SocketAddr,
    /// Optional ECN codepoint bits.
    pub ecn: Option<u8>,
    /// Bytes of `contents` to send.
    pub size: usize,
    /// Optional GSO segment size.
    pub segment_size: Option<usize>,
    /// Source IP hint (unused for echo).
    pub src_ip: Option<std::net::IpAddr>,
}

/// Application-facing connection events.
#[derive(Debug)]
pub enum Event {
    /// Handshake data (ALPN/SNI) available — no-op for hopf path today.
    HandshakeDataReady,
    /// TLS + transport handshake complete; streams may open.
    Connected,
    /// Connection closed or timed out.
    ConnectionLost { reason: ConnectionError },
    /// Stream lifecycle.
    Stream(StreamEvent),
    /// DATAGRAM received (Phase 3b).
    DatagramReceived,
    /// DATAGRAM send unblocked (Phase 3b).
    DatagramsUnblocked,
}

/// Stream lifecycle events.
#[derive(Debug)]
pub enum StreamEvent {
    /// Peer opened a stream of `dir`.
    Opened { dir: Dir },
    /// Stream has readable data.
    Readable { id: StreamId },
    /// Send half fully acknowledged / finished.
    Finished { id: StreamId },
    /// Peer STOP_SENDING.
    Stopped { id: StreamId, error_code: VarInt },
    /// New stream credit available.
    Available { dir: Dir },
}

/// Connection teardown reason.
#[derive(Debug, Clone)]
pub enum ConnectionError {
    /// Local close.
    LocallyClosed,
    /// Application CONNECTION_CLOSE (0x1d).
    ApplicationClosed {
        error_code: VarInt,
        reason: Bytes,
    },
    /// Transport CONNECTION_CLOSE (0x1c).
    ConnectionClosed {
        error_code: VarInt,
        reason: Bytes,
    },
    /// Transport protocol error.
    TransportError {
        code: u64,
        reason: String,
    },
    /// Idle timeout.
    TimedOut,
    /// Stateless reset.
    Reset,
    /// Version mismatch.
    VersionMismatch,
    /// Connection IDs exhausted.
    CidsExhausted,
}

/// DATAGRAM send failure.
#[derive(Debug, Clone)]
pub enum SendDatagramError {
    /// Not supported / disabled.
    UnsupportedByPeer,
    /// Disabled locally.
    Disabled,
    /// Too large.
    TooLarge,
    /// Blocked on buffer.
    Blocked(Bytes),
}

/// Result of feeding a datagram to the endpoint.
#[derive(Debug)]
pub enum DatagramEvent {
    /// New server connection pending accept.
    NewConnection(Incoming),
    /// Event for an existing connection.
    ConnectionEvent(ConnectionHandle, ConnectionEvent),
    /// Immediate response datagram (Retry / Version Negotiation / refuse).
    Response(Transmit),
}

/// Event from endpoint → connection (inbound datagram bytes).
#[derive(Debug)]
pub struct ConnectionEvent {
    /// Raw UDP payload for this connection.
    pub datagram: Bytes,
}

/// Pending server connection before accept/retry.
#[derive(Debug)]
pub struct Incoming {
    /// Remote address.
    pub remote: SocketAddr,
    /// Destination CID from the client's Initial.
    pub dst_cid: ConnectionId,
    /// Source CID from the client's Initial.
    pub src_cid: ConnectionId,
    /// Original Destination CID (for Retry).
    pub orig_dst_cid: ConnectionId,
    /// Raw Initial packet bytes (for accept).
    pub(crate) packet: Bytes,
    /// Whether the address was already validated (Retry/NEW_TOKEN).
    pub address_validated: bool,
    /// When set, accept must use this as the server's local CID (Retry SCID).
    pub retry_local_cid: Option<ConnectionId>,
}

impl Incoming {
    /// True if Retry / NEW_TOKEN already validated the path.
    pub fn remote_address_validated(&self) -> bool {
        self.address_validated
    }
}

/// Connection ID bytes (0–20).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    bytes: [u8; 20],
    len: u8,
}

impl ConnectionId {
    /// Empty CID.
    pub fn empty() -> Self {
        Self {
            bytes: [0; 20],
            len: 0,
        }
    }

    /// From a byte slice (truncated to 20).
    pub fn from_slice(s: &[u8]) -> Self {
        let len = s.len().min(20) as u8;
        let mut bytes = [0u8; 20];
        bytes[..len as usize].copy_from_slice(&s[..len as usize]);
        Self { bytes, len }
    }

    /// Random CID of `len` bytes (1–20).
    pub fn random(len: usize) -> Self {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let len = len.clamp(1, 20);
        let mut bytes = [0u8; 20];
        let _ = SystemRandom::new().fill(&mut bytes[..len]);
        Self {
            bytes,
            len: len as u8,
        }
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// As byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::ops::Deref for ConnectionId {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Endpoint configuration.
#[derive(Debug, Clone, Default)]
pub struct EndpointConfig {
    /// Local CID length for newly issued CIDs.
    pub cid_len: usize,
}

impl EndpointConfig {
    /// Default: 8-byte CIDs.
    pub fn new() -> Self {
        Self { cid_len: 8 }
    }
}

/// Idle / handshake timeout hint for `poll_timeout`.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutHint {
    /// When the next timer should fire.
    pub at: std::time::Instant,
    /// Kind (informational).
    pub kind: TimeoutKind,
}

/// Timer kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutKind {
    /// Idle timeout.
    Idle,
    /// Handshake overall timeout.
    Handshake,
    /// Loss / PTO (Phase 3b).
    LossDetection,
}

/// Default idle timeout used when none is configured.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// QUIC version 1.
pub const VERSION_V1: u32 = 0x0000_0001;
