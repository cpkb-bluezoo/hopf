// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC connection state machine (minimal echo subset).


use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hopf_core::security::SecurityInfo;
use hopf_core::tls::{HandshakeConfig, Tls13Aead};

use crate::transport::varint;
use crate::transport::frame::{parse_all, writer, Frame};
use crate::transport::packet::long_header::{self, TYPE_0RTT, TYPE_HANDSHAKE, TYPE_INITIAL};
use crate::transport::packet::pn;
use crate::transport::packet::protection::{KeyPair, PacketKeys, TAG_LEN};
use crate::transport::packet::retry;
use crate::transport::packet::short_header;
use crate::transport::packet::version_negotiation;
use crate::transport::version::{self, QuicVersion};
use crate::transport::packet::transport_params::VersionInformation;
use crate::transport::packet::TransportParameters;
use crate::transport::recovery::{LossDetector, RecoverableFrame};
use crate::transport::stream::{RecvStream, SendStream, StreamReassembler};
use crate::transport::tls_bridge::{self, OutboundCrypto, TlsBridge, TlsBridgeEvents};
use crate::transport::types::{
    ConnectionError, ConnectionId, Dir, Event, Side, SpaceId, StreamEvent, StreamId, Transmit,
    VarInt,
};

/// Maximum datagram size we send until the path is shown to support more
/// (RFC 9000 §14). The single source of truth for stream chunking,
/// congestion gating and GSO padding.
const MAX_DATAGRAM_SIZE: usize = 1200;

/// Minimum size of a datagram carrying an Initial packet (RFC 9000 §14.1).
const MIN_INITIAL_DATAGRAM_SIZE: usize = 1200;
/// TRANSPORT_PARAMETER_ERROR (RFC 9000 section 20.1).
const TRANSPORT_PARAMETER_ERROR: u64 = 0x08;
/// VERSION_NEGOTIATION_ERROR (RFC 9368 section 10.2).
const VERSION_NEGOTIATION_ERROR: u64 = 0x11;

/// Per-PN-space state.
struct Space {
    /// Client and server traffic secrets (when installed).
    secrets: Option<([u8; 32], [u8; 32])>,
    /// AEAD paired with `secrets` — always AES-128-GCM for Initial (RFC 9001
    /// §5.2 fixes it regardless of the handshake's own negotiated suite);
    /// for Handshake/1-RTT this is set alongside `secrets` from the
    /// handshake's actual negotiation (see `TlsBridgeEvents::aead`). The
    /// default matches Initial's fixed requirement, so Initial's own
    /// `secrets` assignment never needs to touch this field.
    aead: Tls13Aead,
    next_pn: u64,
    largest_received: Option<u64>,
    largest_acked: Option<u64>,
    crypto_recv: StreamReassembler,
    crypto_send_offset: u64,
    crypto_pending: VecDeque<Bytes>,
    /// Lost CRYPTO chunks to resend at their original offsets (before new data).
    crypto_retransmit: VecDeque<(u64, Bytes)>,
    pending_ack: HashSet<u64>,
}

impl Space {
    fn new() -> Self {
        Self {
            secrets: None,
            aead: Tls13Aead::Aes128GcmSha256,
            next_pn: 0,
            largest_received: None,
            largest_acked: None,
            crypto_recv: StreamReassembler::new(1 << 20),
            crypto_send_offset: 0,
            crypto_pending: VecDeque::new(),
            crypto_retransmit: VecDeque::new(),
            pending_ack: HashSet::new(),
        }
    }

    fn keys(&self, side: Side, version: QuicVersion) -> Option<KeyPair> {
        let (c, s) = self.secrets?;
        Some(KeyPair::from_traffic_secrets(version, side, self.aead, c, s))
    }
}

/// The client-side constructor arguments a version restart replays.
#[derive(Clone)]
struct ClientRestart {
    server_name: String,
    handshake: HandshakeConfig,
    max_datagram_frame_size: Option<u64>,
    max_idle_timeout: Option<Duration>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,
    keep_alive_interval: Option<Duration>,
}

/// In-tree QUIC connection.
pub struct Connection {
    side: Side,
    /// The QUIC version in use (RFC 9000/9369): selects Initial salt, key
    /// derivation labels, long-header type bits and Retry integrity keys.
    version: QuicVersion,
    /// Client: the versions this connection may speak, most preferred first
    /// (empty for a server). A Version Negotiation packet restarts the
    /// attempt in the first of these the server offers.
    client_versions: Vec<QuicVersion>,
    /// Client: what a restart needs to rebuild the connection from scratch.
    client_restart: Option<ClientRestart>,
    /// Client: this attempt began by reacting to a Version Negotiation packet
    /// (RFC 9368 section 4: further ones are ignored, and the server's
    /// `version_information` must then be present and consistent).
    reacted_to_version_negotiation: bool,
    remote: SocketAddr,
    /// Our local CID (SCID we advertise).
    local_cid: ConnectionId,
    /// Peer's CID (DCID we send to).
    rem_cid: ConnectionId,
    /// Original DCID from client's first Initial (Initial keying).
    initial_dcid: ConnectionId,
    spaces: [Space; 3],
    tls: TlsBridge,
    local_tp: TransportParameters,
    peer_tp: Option<TransportParameters>,
    events: VecDeque<Event>,
    transmits: VecDeque<(Transmit, Vec<u8>)>,
    established: bool,
    handshake_done: bool,
    handshake_done_pending: bool,
    closed: bool,
    idle_timeout: Duration,
    /// Local advertised idle timeout in ms (0 = infinite).
    local_idle_timeout_ms: u64,
    last_activity: Instant,
    security_info: Option<SecurityInfo>,
    streams: HashMap<StreamId, StreamState>,
    next_local_bi: u64,
    next_local_uni: u64,
    next_remote_bi_expected: u64,
    next_remote_uni_expected: u64,
    peer_max_streams_bidi: u64,
    peer_max_streams_uni: u64,
    /// Cumulative bi stream limit we have advertised to the peer.
    local_max_streams_bidi: u64,
    /// Pending MAX_STREAMS_BIDI to send on next flush.
    pending_max_streams_bidi: Option<u64>,
    conn_max_data: u64,
    /// Token for Initial (usually empty; set after Retry).
    token: Vec<u8>,
    /// Short-header CID length (peer's CID length we send to).
    short_cid_len: usize,
    /// Client: already processed one Retry.
    retry_processed: bool,
    /// A server packet has been decrypted and processed (RFC 9000 section
    /// 6.2: from then on Version Negotiation packets are ignored).
    server_packet_processed: bool,
    /// Client: Retry SCID that must match peer `retry_source_connection_id`.
    expected_retry_scid: Option<ConnectionId>,
    /// Client: Initial CRYPTO chunks for requeue after Retry.
    initial_crypto_chunks: Vec<Bytes>,
    /// Inbound DATAGRAM payloads.
    datagram_rx: VecDeque<Bytes>,
    /// Outbound DATAGRAM payloads.
    datagram_tx: VecDeque<Bytes>,
    /// Peer's max_datagram_frame_size (0 = unsupported).
    peer_max_datagram: u64,
    /// RFC 9002 loss recovery / congestion control.
    loss: LossDetector,
    /// Spaces that need a PTO probe PING on the next flush.
    pto_ping_pending: [bool; 3],
    /// When set, pad each built packet (PADDING frames before AEAD) so the
    /// final UDP payload length equals this size — required for Linux UDP GSO.
    gso_pad_to: Option<usize>,
    /// Client early traffic secret for 0-RTT (client write / server read).
    early_secret: Option<[u8; 32]>,
    /// AEAD paired with `early_secret` — see `Space::aead`'s doc comment;
    /// same default-matches-fixed-Initial reasoning (0-RTT never installs
    /// before `early_secret` is `Some`, so the default is never actually used).
    early_aead: Tls13Aead,
    /// Client: EE early_data acceptance (`None` until EncryptedExtensions).
    early_data_accepted: Option<bool>,
    /// STREAM chunks sent under 0-RTT keys; requeued on reject for 1-RTT.
    pending_0rtt_retransmit: Vec<(StreamId, u64, Bytes, bool)>,
    /// Remembered peer stream limit for 0-RTT sends (client bidi remote).
    remembered_0rtt_stream_max: Option<u64>,
    /// Optional keep-alive PING interval.
    keep_alive_interval: Option<Duration>,
    /// Last time a keep-alive PING was sent (or connection start).
    last_keep_alive: Instant,
}

struct StreamState {
    send: SendStream,
    recv: RecvStream,
    opened_event: bool,
    /// Peer bi stream: already raised local MAX_STREAMS for this id.
    bidi_credit_granted: bool,
}

impl Connection {
    fn space_mut(&mut self, id: SpaceId) -> &mut Space {
        &mut self.spaces[space_index(id)]
    }

    fn space(&self, id: SpaceId) -> &Space {
        &self.spaces[space_index(id)]
    }

    /// Client connection after `Endpoint::connect`.
    pub fn new_client(
        now: Instant,
        remote: SocketAddr,
        server_name: &str,
        handshake: HandshakeConfig,
        local_cid: ConnectionId,
        initial_dcid: ConnectionId,
        // Versions this client speaks, most preferred first (kept for
        // Version Negotiation and its downgrade check), and the one this
        // attempt opens with.
        preference: &[QuicVersion],
        version: QuicVersion,
        max_datagram_frame_size: Option<u64>,
        max_idle_timeout: Option<Duration>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
        keep_alive_interval: Option<Duration>,
    ) -> Self {
        let restart = ClientRestart {
            server_name: server_name.to_string(),
            handshake: handshake.clone(),
            max_datagram_frame_size,
            max_idle_timeout,
            initial_max_streams_bidi,
            initial_max_streams_uni,
            keep_alive_interval,
        };
        let mut local_tp = TransportParameters::default();
        local_tp.initial_src_cid = Some(local_cid.clone());
        local_tp.max_datagram_frame_size = max_datagram_frame_size;
        // RFC 9369 section 4 / RFC 9368: send version_information. Only the
        // chosen version is listed as available, which disables compatible
        // version negotiation (RFC 9368 section 3) - this client does not
        // switch versions mid-handshake.
        local_tp.version_information = Some(VersionInformation { chosen: version.wire(), available: vec![version.wire()] });
        if let Some(d) = max_idle_timeout {
            local_tp.max_idle_timeout = d.as_millis() as u64;
        }
        if let Some(n) = initial_max_streams_bidi {
            local_tp.initial_max_streams_bidi = n;
        }
        if let Some(n) = initial_max_streams_uni {
            local_tp.initial_max_streams_uni = n;
        }
        let local_idle_timeout_ms = local_tp.max_idle_timeout;
        let idle_timeout = idle_timeout_from_ms(local_idle_timeout_ms);
        let local_max_streams_bidi = local_tp.initial_max_streams_bidi;
        let mut hs = handshake;
        // Dial-time SNI always wins over any name baked into the client
        // config (shared configs / PEM helpers must not pin "localhost").
        hs.server_name = Some(server_name.to_string());
        // RFC 9369 section 5: never present a ticket another version issued.
        hs.ticket_namespace = version.ticket_namespace();
        let (tls, events) = TlsBridge::start_client(hs, &local_tp);
        let mut conn = Self {
            side: Side::Client,
            version,
            client_versions: preference.to_vec(),
            client_restart: Some(restart),
            reacted_to_version_negotiation: false,
            remote,
            local_cid,
            rem_cid: initial_dcid.clone(),
            initial_dcid: initial_dcid.clone(),
            spaces: [Space::new(), Space::new(), Space::new()],
            tls,
            local_tp,
            peer_tp: None,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
            established: false,
            handshake_done: false,
            handshake_done_pending: false,
            closed: false,
            idle_timeout,
            local_idle_timeout_ms,
            last_activity: now,
            security_info: None,
            streams: HashMap::new(),
            next_local_bi: 0,
            next_local_uni: 0,
            next_remote_bi_expected: 0,
            next_remote_uni_expected: 0,
            peer_max_streams_bidi: 100,
            peer_max_streams_uni: 100,
            local_max_streams_bidi,
            pending_max_streams_bidi: None,
            conn_max_data: 10 * 1024 * 1024,
            token: Vec::new(),
            short_cid_len: initial_dcid.len(),
            retry_processed: false,
            server_packet_processed: false,
            expected_retry_scid: None,
            initial_crypto_chunks: Vec::new(),
            datagram_rx: VecDeque::new(),
            datagram_tx: VecDeque::new(),
            peer_max_datagram: 0,
            loss: LossDetector::new(MAX_DATAGRAM_SIZE),
            pto_ping_pending: [false; 3],
            gso_pad_to: None,
            early_secret: None,
            early_aead: Tls13Aead::Aes128GcmSha256,
            early_data_accepted: None,
            pending_0rtt_retransmit: Vec::new(),
            remembered_0rtt_stream_max: None,
            keep_alive_interval,
            last_keep_alive: now,
        };
        conn.spaces[0].secrets = Some(crate::transport::packet::protection::initial_secrets(
            version,
            initial_dcid.as_slice(),
        ));
        conn.apply_tls_events(events);
        conn
    }

    /// Server connection after accept.
    pub fn new_server(
        now: Instant,
        remote: SocketAddr,
        handshake: HandshakeConfig,
        local_cid: ConnectionId,
        // DCID the client used on this Initial (Initial keying material).
        initial_dcid: ConnectionId,
        // Version of the client's Initial, which this connection speaks, and
        // every version this listener offers.
        version: QuicVersion,
        server_versions: &[QuicVersion],
        client_src_cid: ConnectionId,
        // original_destination_connection_id transport parameter.
        original_dst_cid: ConnectionId,
        // Present when this accept followed a Retry.
        retry_src_cid: Option<ConnectionId>,
        max_datagram_frame_size: Option<u64>,
        max_idle_timeout: Option<Duration>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
        keep_alive_interval: Option<Duration>,
    ) -> Self {
        let mut local_tp = TransportParameters::default();
        local_tp.initial_src_cid = Some(local_cid.clone());
        local_tp.original_dst_cid = Some(original_dst_cid);
        local_tp.retry_src_cid = retry_src_cid;
        // RFC 9368 section 3: the server's Available Versions are its
        // deployment's versions; the Chosen Version is the one in use.
        local_tp.version_information = Some(VersionInformation {
            chosen: version.wire(),
            available: server_versions.iter().map(|v| v.wire()).collect(),
        });
        local_tp.max_datagram_frame_size = max_datagram_frame_size;
        if let Some(d) = max_idle_timeout {
            local_tp.max_idle_timeout = d.as_millis() as u64;
        }
        if let Some(n) = initial_max_streams_bidi {
            local_tp.initial_max_streams_bidi = n;
        }
        if let Some(n) = initial_max_streams_uni {
            local_tp.initial_max_streams_uni = n;
        }
        let local_idle_timeout_ms = local_tp.max_idle_timeout;
        let idle_timeout = idle_timeout_from_ms(local_idle_timeout_ms);
        let local_max_streams_bidi = local_tp.initial_max_streams_bidi;
        // RFC 9369 section 5: only accept tickets this version issued.
        let mut handshake = handshake;
        handshake.ticket_key = handshake.ticket_key.map(|k| version.ticket_keys(k));
        let tls = TlsBridge::start_server(handshake, &local_tp);
        let mut conn = Self {
            side: Side::Server,
            version,
            client_versions: Vec::new(),
            client_restart: None,
            reacted_to_version_negotiation: false,
            remote,
            local_cid,
            rem_cid: client_src_cid,
            initial_dcid: initial_dcid.clone(),
            spaces: [Space::new(), Space::new(), Space::new()],
            tls,
            local_tp,
            peer_tp: None,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
            established: false,
            handshake_done: false,
            handshake_done_pending: false,
            closed: false,
            idle_timeout,
            local_idle_timeout_ms,
            last_activity: now,
            security_info: None,
            streams: HashMap::new(),
            next_local_bi: 0,
            next_local_uni: 0,
            next_remote_bi_expected: 0,
            next_remote_uni_expected: 0,
            peer_max_streams_bidi: 100,
            peer_max_streams_uni: 100,
            local_max_streams_bidi,
            pending_max_streams_bidi: None,
            conn_max_data: 10 * 1024 * 1024,
            token: Vec::new(),
            short_cid_len: 0,
            retry_processed: false,
            server_packet_processed: false,
            expected_retry_scid: None,
            initial_crypto_chunks: Vec::new(),
            datagram_rx: VecDeque::new(),
            datagram_tx: VecDeque::new(),
            peer_max_datagram: 0,
            loss: LossDetector::new(MAX_DATAGRAM_SIZE),
            pto_ping_pending: [false; 3],
            gso_pad_to: None,
            early_secret: None,
            early_aead: Tls13Aead::Aes128GcmSha256,
            early_data_accepted: None,
            pending_0rtt_retransmit: Vec::new(),
            remembered_0rtt_stream_max: None,
            keep_alive_interval,
            last_keep_alive: now,
        };
        conn.short_cid_len = conn.rem_cid.len();
        conn.spaces[0].secrets = Some(crate::transport::packet::protection::initial_secrets(
            version,
            initial_dcid.as_slice(),
        ));
        conn
    }

    /// Peer address.
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }

    /// Local CID.
    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Security info after handshake.
    pub fn security_info(&self) -> Option<&SecurityInfo> {
        self.security_info.as_ref()
    }

    /// Whether 0-RTT keys are installed (early STREAM may be sent).
    pub fn has_0rtt(&self) -> bool {
        self.early_secret.is_some()
    }

    /// Poll application events.
    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Poll outbound datagram.
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut Vec<u8>) -> Option<Transmit> {
        self.flush_pending_packets(now);
        let (tx, data) = self.transmits.pop_front()?;
        buf.clear();
        buf.extend_from_slice(&data);
        Some(Transmit {
            destination: tx.destination,
            ecn: tx.ecn,
            size: data.len(),
            segment_size: None,
            src_ip: None,
        })
    }

    /// Next timeout (idle, keep-alive, or loss detection).
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        let idle = self.last_activity + self.idle_timeout;
        let mut next = idle;
        if let Some(interval) = self.keep_alive_interval {
            if self.established && self.spaces[2].secrets.is_some() {
                next = next.min(self.last_keep_alive + interval);
            }
        }
        let loss = self.loss.loss_detection_timeout(
            false,
            self.peer_address_validated(),
            self.spaces[1].secrets.is_some(),
            self.peer_max_ack_delay(),
            Instant::now(),
        );
        Some(match loss {
            Some(t) => next.min(t),
            None => next,
        })
    }

    /// Handle timeout.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.closed {
            return;
        }

        if let Some(interval) = self.keep_alive_interval {
            if self.established
                && self.spaces[2].secrets.is_some()
                && now >= self.last_keep_alive + interval
            {
                self.last_keep_alive = now;
                self.pto_ping_pending[space_index(SpaceId::Data)] = true;
                self.flush_pending_packets(now);
            }
        }

        let loss_due = self
            .loss
            .loss_detection_timeout(
                false,
                self.peer_address_validated(),
                self.spaces[1].secrets.is_some(),
                self.peer_max_ack_delay(),
                now,
            )
            .map(|t| now >= t)
            .unwrap_or(false);

        if loss_due {
            let result = self.loss.on_loss_detection_timeout(
                self.peer_address_validated(),
                self.spaces[1].secrets.is_some(),
                self.peer_max_ack_delay(),
                now,
            );
            if let Some(space) = result.loss_space {
                for lost in result.newly_lost {
                    self.requeue_lost_packet(space, &lost);
                }
            } else if let Some(probe) = result.probe_space {
                if self.space(probe).secrets.is_some() {
                    self.pto_ping_pending[space_index(probe)] = true;
                }
            }
            self.flush_pending_packets(now);
        }

        if now >= self.last_activity + self.idle_timeout {
            self.closed = true;
            self.events.push_back(Event::ConnectionLost {
                reason: ConnectionError::TimedOut,
            });
        }
    }

    /// Close the connection with an application CONNECTION_CLOSE (0x1d).
    pub fn close(&mut self, now: Instant, error_code: VarInt, reason: Bytes) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut payload = Vec::new();
        writer::connection_close_app(&mut payload, error_code.0, reason.as_ref());
        self.queue_packet(SpaceId::Data, payload, Vec::new(), true, false, now);
        self.flush_pending_packets(now);
    }

    /// Handle endpoint→connection event (inbound datagram).
    pub fn handle_event(&mut self, now: Instant, ev: crate::transport::types::ConnectionEvent) {
        self.handle_packet(now, &ev.datagram);
    }

    /// Poll endpoint events (none for echo).
    pub fn poll_endpoint_events(&mut self) -> Option<crate::transport::types::ConnectionEvent> {
        None
    }

    /// Receive a decrypted-path datagram (may contain coalesced packets).
    pub fn handle_packet(&mut self, now: Instant, data: &[u8]) {
        if self.closed {
            return;
        }
        self.last_activity = now;
        let mut rest = data;
        while !rest.is_empty() {
            let consumed = self.handle_one_packet(rest, now);
            if consumed == 0 {
                break;
            }
            rest = &rest[consumed..];
        }
        self.flush_pending_packets(now);
    }

    fn handle_one_packet(&mut self, data: &[u8], now: Instant) -> usize {
        if data.is_empty() {
            return 0;
        }
        if data[0] & 0x80 != 0 {
            self.handle_long_packet(data, now)
        } else {
            self.handle_short_packet(data, now)
        }
    }

    fn handle_long_packet(&mut self, data: &[u8], now: Instant) -> usize {
        // Version Negotiation (version 0) and versions we don't speak can't go
        // through the header parsers: only the RFC 8999 invariants are readable.
        if let Some((version, _, _)) = version_negotiation::parse_invariants(data) {
            if version == 0 {
                return self.handle_version_negotiation(data, now);
            }
            // A connection speaks one version (RFC 9369 section 4.1: an endpoint
            // drops packets in any other), and a Retry's type bits depend on it.
            if version != self.version.wire() {
                return data.len();
            }
        }
        if long_header::is_retry(data) {
            return self.handle_retry_packet(data);
        }
        let Some(prefix) = long_header::parse_prefix(data) else {
            return data.len();
        };
        if prefix.version != self.version {
            return data.len();
        }
        let space = match prefix.packet_type {
            TYPE_INITIAL => SpaceId::Initial,
            TYPE_HANDSHAKE => SpaceId::Handshake,
            TYPE_0RTT => SpaceId::Data,
            _ => return data.len(),
        };
        let packet_len = prefix.pn_offset + prefix.length as usize;
        if data.len() < packet_len {
            return data.len();
        }
        let mut packet = data[..packet_len].to_vec();
        // 0-RTT uses client early secret (server decrypts with remote = early).
        let (remote_keys, is_0rtt) = if prefix.packet_type == TYPE_0RTT {
            let Some(early) = self.early_secret else {
                return packet_len;
            };
            (PacketKeys::from_secret(self.version, self.early_aead, &early), true)
        } else {
            match self.space(space).keys(self.side, self.version) {
                Some(k) => (k.remote, false),
                None => return packet_len,
            }
        };
        remote_keys.protect_header(prefix.pn_offset, &mut packet, false);
        let pn_len = (packet[0] & 0x03) as usize + 1;
        if prefix.pn_offset + pn_len > packet.len() {
            return packet_len;
        }
        let truncated = pn::read_truncated(&packet[prefix.pn_offset..prefix.pn_offset + pn_len]);
        let full_pn = pn::decode(self.space(space).largest_received, truncated, pn_len);
        let header_len = prefix.pn_offset + pn_len;
        let mut payload = packet[header_len..].to_vec();
        let header = &packet[..header_len];
        let Ok(plain_len) = remote_keys.decrypt(full_pn, header, &mut payload) else {
            return packet_len;
        };
        payload.truncate(plain_len);
        // Learn peer CID before queuing ACKs so outbound DCID is correct.
        if self.side == Side::Client && !prefix.src_cid.is_empty() {
            self.rem_cid = prefix.src_cid;
            self.short_cid_len = self.rem_cid.len();
        }
        let _ = is_0rtt;
        if self.side == Side::Client {
            self.server_packet_processed = true;
        }
        self.on_decrypted(space, full_pn, &payload, now);
        packet_len
    }

    /// RFC 9000 section 6.2 and RFC 9368 section 2.1: a valid Version
    /// Negotiation packet that offers a version this client speaks restarts
    /// the attempt in the first such version (a new first flight, with a new
    /// destination CID); one that offers none abandons it.
    ///
    /// Ignored when it lists the version the client already used (bogus), when
    /// it doesn't echo our connection IDs (an off-path forgery), when the
    /// client has already processed any other server packet, and when this
    /// attempt is itself the result of a Version Negotiation packet (RFC 9368
    /// section 4).
    fn handle_version_negotiation(&mut self, data: &[u8], now: Instant) -> usize {
        if self.side != Side::Client
            || self.established
            || self.retry_processed
            || self.server_packet_processed
            || self.reacted_to_version_negotiation
        {
            return data.len();
        }
        let Some(pkt) = version_negotiation::parse(data) else {
            return data.len();
        };
        if pkt.dst_cid != self.local_cid.as_slice() || pkt.src_cid != self.initial_dcid.as_slice() {
            return data.len();
        }
        if pkt.versions.contains(&self.version.wire()) {
            return data.len();
        }
        let Some(next) = self.client_versions.iter().copied().find(|v| pkt.versions.contains(&v.wire())) else {
            self.closed = true;
            self.events.push_back(Event::ConnectionLost { reason: ConnectionError::VersionMismatch });
            return data.len();
        };
        self.restart_client(now, next);
        data.len()
    }

    /// Start the client attempt over in `version`: a new first flight, keyed
    /// from a fresh destination CID, as if it were a new connection (RFC 9368
    /// section 2.4). Our own connection ID is kept, so the endpoint's routing
    /// entry still reaches this connection.
    fn restart_client(&mut self, now: Instant, version: QuicVersion) {
        let Some(ctx) = self.client_restart.clone() else {
            return;
        };
        let preference = self.client_versions.clone();
        let mut fresh = Connection::new_client(
            now,
            self.remote,
            &ctx.server_name,
            ctx.handshake,
            self.local_cid.clone(),
            ConnectionId::random(8),
            &preference,
            version,
            ctx.max_datagram_frame_size,
            ctx.max_idle_timeout,
            ctx.initial_max_streams_bidi,
            ctx.initial_max_streams_uni,
            ctx.keep_alive_interval,
        );
        fresh.reacted_to_version_negotiation = true;
        *self = fresh;
    }

    fn handle_retry_packet(&mut self, data: &[u8]) -> usize {
        if self.side != Side::Client || self.retry_processed || self.established {
            return data.len();
        }
        let Some(retry_pkt) = retry::parse(data) else {
            return data.len();
        };
        // Retry DCID must echo our SCID.
        if retry_pkt.dst_cid.as_slice() != self.local_cid.as_slice() {
            return data.len();
        }
        if !retry::verify_integrity(
            self.version,
            self.initial_dcid.as_slice(),
            &retry_pkt.without_tag,
            &retry_pkt.tag,
        ) {
            return data.len();
        }

        self.retry_processed = true;
        self.token = retry_pkt.token;
        self.expected_retry_scid = Some(retry_pkt.src_cid.clone());
        self.rem_cid = retry_pkt.src_cid.clone();
        self.short_cid_len = self.rem_cid.len();

        // RFC 9001 §5.2: after Retry, Initial secrets use the new DCID
        // (Retry SCID).
        self.spaces[0].secrets = Some(crate::transport::packet::protection::initial_secrets(
            self.version,
            self.rem_cid.as_slice(),
        ));
        self.spaces[0].pending_ack.clear();
        self.transmits.clear();

        // Requeue Initial CRYPTO (TLS transcript unchanged).
        let chunks = self.initial_crypto_chunks.clone();
        {
            let sp = self.space_mut(SpaceId::Initial);
            sp.crypto_pending.clear();
            sp.crypto_send_offset = 0;
            for chunk in chunks {
                sp.crypto_pending.push_back(chunk);
            }
        }
        data.len()
    }

    fn handle_short_packet(&mut self, data: &[u8], now: Instant) -> usize {
        let cid_len = self.local_cid.len();
        let Some(prefix) = short_header::parse_prefix(data, cid_len) else {
            return data.len();
        };
        let keys = match self.space(SpaceId::Data).keys(self.side, self.version) {
            Some(k) => k,
            None => return data.len(),
        };
        let mut packet = data.to_vec();
        keys.remote.protect_header(prefix.pn_offset, &mut packet, false);
        let pn_len = (packet[0] & 0x03) as usize + 1;
        if prefix.pn_offset + pn_len > packet.len() {
            return data.len();
        }
        let truncated = pn::read_truncated(&packet[prefix.pn_offset..prefix.pn_offset + pn_len]);
        let full_pn = pn::decode(self.space(SpaceId::Data).largest_received, truncated, pn_len);
        let header_len = prefix.pn_offset + pn_len;
        let mut payload = packet[header_len..].to_vec();
        let header = &packet[..header_len];
        let Ok(plain_len) = keys.remote.decrypt(full_pn, header, &mut payload) else {
            return data.len();
        };
        payload.truncate(plain_len);
        self.on_decrypted(SpaceId::Data, full_pn, &payload, now);
        data.len()
    }

    fn on_decrypted(&mut self, space: SpaceId, pn: u64, payload: &[u8], now: Instant) {
        {
            let sp = self.space_mut(space);
            sp.largest_received = Some(
                sp.largest_received
                    .map(|l| l.max(pn))
                    .unwrap_or(pn),
            );
        }
        let Ok(frames) = parse_all(payload) else {
            return;
        };
        // RFC 9000 §13.2.1: ACK/PADDING-only packets are not ack-eliciting —
        // ACKing them creates an infinite ACK loop.
        let ack_eliciting = frames.iter().any(|f| {
            !matches!(f, Frame::Ack { .. } | Frame::Padding { .. })
        });
        if ack_eliciting {
            self.space_mut(space).pending_ack.insert(pn);
        }
        for frame in frames {
            self.handle_frame(space, frame, now);
        }
        if ack_eliciting {
            self.queue_acks(space, now);
        }
    }

    fn handle_frame(&mut self, space: SpaceId, frame: Frame, now: Instant) {
        match frame {
            Frame::Padding { .. } | Frame::Ping => {}
            Frame::Ack {
                largest,
                delay,
                ranges,
            } => {
                {
                    let sp = self.space_mut(space);
                    sp.largest_acked =
                        Some(sp.largest_acked.map(|a| a.max(largest)).unwrap_or(largest));
                }
                // ACK Delay is in microseconds × 2^ack_delay_exponent (default 3).
                let ack_delay = Duration::from_micros(delay.saturating_mul(8));
                let peer_validated = self.peer_address_validated();
                let max_ack_delay = self.peer_max_ack_delay();
                let result = self.loss.on_ack_received(
                    space,
                    largest,
                    ack_delay,
                    &ranges,
                    max_ack_delay,
                    now,
                    peer_validated,
                );
                for lost in result.newly_lost {
                    self.requeue_lost_packet(space, &lost);
                }
            }
            Frame::Crypto { offset, data } => {
                let contiguous = {
                    let sp = self.space_mut(space);
                    sp.crypto_recv.receive(offset, data).unwrap_or_default()
                };
                if !contiguous.is_empty() {
                    let events = self.tls.feed_crypto(space, &contiguous);
                    self.apply_tls_events(events);
                }
            }
            Frame::Stream {
                id,
                offset,
                data,
                fin,
            } => {
                self.ensure_recv_stream(id);
                let mut grant_credit = false;
                if let Some(st) = self.streams.get_mut(&id) {
                    if let Ok(readable) = st.recv.ingest(offset, data, fin) {
                        if !st.opened_event && id.initiator() != self.side {
                            st.opened_event = true;
                            self.events
                                .push_back(Event::Stream(StreamEvent::Opened { dir: id.dir() }));
                        }
                        if readable || fin {
                            // Peer FIN is surfaced via `read_stream`'s fin flag,
                            // not `StreamEvent::Finished` (that means local send done).
                            self.events
                                .push_back(Event::Stream(StreamEvent::Readable { id }));
                        }
                        grant_credit = fin;
                    }
                }
                if grant_credit {
                    self.maybe_grant_bidi_credit(id);
                }
            }
            Frame::MaxData { max } => {
                self.conn_max_data = self.conn_max_data.max(max);
            }
            Frame::MaxStreamData { id, max } => {
                if let Some(st) = self.streams.get_mut(&id) {
                    st.send.max_data = st.send.max_data.max(max);
                }
            }
            Frame::MaxStreamsBidi { max } => {
                if max > self.peer_max_streams_bidi {
                    self.peer_max_streams_bidi = max;
                    self.events
                        .push_back(Event::Stream(StreamEvent::Available { dir: Dir::Bi }));
                }
            }
            Frame::HandshakeDone => {
                if self.side == Side::Client {
                    self.handshake_done = true;
                    self.loss.set_handshake_confirmed(true);
                    self.maybe_establish();
                }
            }
            Frame::ConnectionClose {
                application,
                error_code,
                reason,
                ..
            } => {
                self.closed = true;
                let reason_err = if application {
                    ConnectionError::ApplicationClosed {
                        error_code: VarInt(error_code),
                        reason,
                    }
                } else {
                    ConnectionError::ConnectionClosed {
                        error_code: VarInt(error_code),
                        reason,
                    }
                };
                self.events
                    .push_back(Event::ConnectionLost { reason: reason_err });
            }
            Frame::ResetStream { id, error_code, .. } => {
                self.events.push_back(Event::Stream(StreamEvent::Stopped {
                    id,
                    error_code: VarInt(error_code),
                }));
            }
            Frame::StopSending { id, error_code } => {
                self.events.push_back(Event::Stream(StreamEvent::Stopped {
                    id,
                    error_code: VarInt(error_code),
                }));
            }
            Frame::Datagram { data } => {
                if self.local_tp.max_datagram_frame_size.is_none() {
                    // Peer sent DATAGRAM but we didn't advertise support — ignore
                    // for the echo milestone (or could close).
                    return;
                }
                self.datagram_rx.push_back(data);
                self.events.push_back(Event::DatagramReceived);
            }
        }
    }

    fn apply_tls_events(&mut self, events: TlsBridgeEvents) {
        if let Some(msg) = events.failed {
            self.closed = true;
            self.events.push_back(Event::ConnectionLost {
                reason: ConnectionError::TransportError {
                    code: 0x100,
                    reason: msg,
                },
            });
            return;
        }
        if let Some((c, s)) = events.handshake_keys {
            self.spaces[1].secrets = Some((c, s));
            self.spaces[1].aead = events.aead.unwrap_or(Tls13Aead::Aes128GcmSha256);
        }
        if let Some(early) = events.early_keys {
            self.early_secret = Some(early);
            self.early_aead = events.aead.unwrap_or(Tls13Aead::Aes128GcmSha256);
        }
        if let Some(limits) = events.remembered_0rtt_limits {
            self.apply_remembered_peer_limits(limits);
        }
        if let Some(accepted) = events.early_data_accepted {
            self.early_data_accepted = Some(accepted);
            if !accepted {
                // Server rejected 0-RTT: stop sending under early keys and
                // retransmit any STREAM data already queued as 0-RTT under 1-RTT.
                self.early_secret = None;
                for (id, offset, data, fin) in self.pending_0rtt_retransmit.drain(..) {
                    if let Some(st) = self.streams.get_mut(&id) {
                        st.send.requeue(offset, data, fin);
                    }
                }
            } else {
                self.pending_0rtt_retransmit.clear();
            }
        }
        if let Some((c, s)) = events.app_keys {
            self.spaces[2].secrets = Some((c, s));
            self.spaces[2].aead = events.aead.unwrap_or(Tls13Aead::Aes128GcmSha256);
        }
        if let Some(raw) = events.peer_tp {
            if let Some(tp) = TransportParameters::decode(&raw) {
                if let Some((code, reason)) = self.check_version_information(&tp) {
                    self.fail_transport(code, reason);
                    return;
                }
                self.peer_max_streams_bidi = tp.initial_max_streams_bidi;
                self.peer_max_streams_uni = tp.initial_max_streams_uni;
                self.conn_max_data = tp.initial_max_data;
                self.idle_timeout =
                    negotiate_idle_timeout(self.local_idle_timeout_ms, tp.max_idle_timeout);
                self.peer_max_datagram = tp.max_datagram_frame_size.unwrap_or(0);
                self.peer_tp = Some(tp);
            }
        }
        // Queue outbound CRYPTO. ServerHello stays on Initial; after handshake
        // keys are installed every subsequent server flight goes Handshake.
        // Client post-SH messages similarly move to Handshake.
        for OutboundCrypto { space, data } in events.outbound {
            let space = if data.first() == Some(&0x04) && self.spaces[2].secrets.is_some() {
                // NewSessionTicket on 1-RTT.
                SpaceId::Data
            } else if self.side == Side::Server && self.spaces[1].secrets.is_some() {
                if data.first() == Some(&0x02) {
                    if let Some((sh, rest)) = tls_bridge::split_server_hello(&data) {
                        self.queue_crypto(SpaceId::Initial, sh);
                        if !rest.is_empty() {
                            self.queue_crypto(SpaceId::Handshake, rest);
                        }
                        continue;
                    }
                    SpaceId::Initial
                } else if self.spaces[2].secrets.is_some() {
                    SpaceId::Data
                } else {
                    SpaceId::Handshake
                }
            } else if self.side == Side::Client
                && self.spaces[1].secrets.is_some()
                && space == SpaceId::Initial
            {
                SpaceId::Handshake
            } else {
                space
            };
            self.queue_crypto(space, data);
        }
        if let Some(info) = events.complete {
            self.security_info = Some(info);
            if self.side == Side::Server {
                self.handshake_done_pending = true;
                self.maybe_establish();
            } else {
                // Client waits for HANDSHAKE_DONE, but can establish for streams after TLS done
                // once we have 1-RTT keys — still wait for HANDSHAKE_DONE per RFC.
                // For echo, establish when we have app keys + peer TP.
                if self.spaces[2].secrets.is_some() {
                    // Will establish on HANDSHAKE_DONE; also allow early establish if server
                    // already sent it in same flight (handled in frame).
                }
            }
        }
    }

    /// Validate the peer's `version_information` (RFC 9368 section 4), which
    /// every endpoint supporting version 2 must process (RFC 9369 section 4).
    /// Returns the transport error to close the connection with, if any.
    fn check_version_information(&self, tp: &TransportParameters) -> Option<(u64, &'static str)> {
        if tp.version_information_invalid {
            return Some((TRANSPORT_PARAMETER_ERROR, "malformed version_information"));
        }
        let in_use = self.version.wire();
        match (self.side, &tp.version_information) {
            // A server may complete the handshake without it.
            (Side::Server, None) => None,
            (Side::Server, Some(vi)) => {
                if !vi.available.contains(&vi.chosen) {
                    Some((TRANSPORT_PARAMETER_ERROR, "chosen version missing from available versions"))
                } else if vi.chosen != in_use {
                    Some((VERSION_NEGOTIATION_ERROR, "client chosen version differs from the version in use"))
                } else {
                    None
                }
            }
            // A client may too, unless it is reacting to Version Negotiation.
            (Side::Client, None) if self.reacted_to_version_negotiation => {
                Some((VERSION_NEGOTIATION_ERROR, "server sent no version_information after version negotiation"))
            }
            (Side::Client, None) => None,
            (Side::Client, Some(vi)) => {
                if vi.chosen != in_use {
                    Some((VERSION_NEGOTIATION_ERROR, "server chosen version differs from the version in use"))
                } else if self.reacted_to_version_negotiation
                    && !version::validates_negotiation(&self.client_versions, &vi.available, self.version)
                {
                    Some((VERSION_NEGOTIATION_ERROR, "version negotiation was not genuine"))
                } else {
                    None
                }
            }
        }
    }

    /// Close the connection with a transport error: tell the peer with a
    /// CONNECTION_CLOSE (type 0x1c) in the highest packet space we have keys
    /// for, and report it locally.
    fn fail_transport(&mut self, code: u64, reason: &'static str) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut payload = Vec::new();
        writer::connection_close(&mut payload, code, reason.as_bytes());
        let now = self.last_activity;
        for space in [SpaceId::Data, SpaceId::Handshake, SpaceId::Initial] {
            if self.space(space).secrets.is_some() && self.queue_packet(space, payload.clone(), Vec::new(), false, false, now) {
                break;
            }
        }
        self.events.push_back(Event::ConnectionLost {
            reason: ConnectionError::TransportError { code, reason: reason.to_string() },
        });
    }

    fn maybe_establish(&mut self) {
        if self.established {
            return;
        }
        let ready = self.spaces[2].secrets.is_some()
            && self.security_info.is_some()
            && (self.side == Side::Server
                || self.handshake_done
                || self.peer_tp.is_some());
        // Client: establish after HANDSHAKE_DONE; if peer_tp present and app keys, wait for HD.
        if self.side == Side::Client && !self.handshake_done {
            return;
        }
        if ready || (self.side == Side::Server && self.spaces[2].secrets.is_some()) {
            self.established = true;
            self.events.push_back(Event::Connected);
        }
    }

    fn queue_crypto(&mut self, space: SpaceId, data: Bytes) {
        if space == SpaceId::Initial {
            self.initial_crypto_chunks.push(data.clone());
        }
        let sp = self.space_mut(space);
        sp.crypto_pending.push_back(data);
    }

    fn queue_acks(&mut self, space: SpaceId, now: Instant) {
        let pns: Vec<u64> = self.space(space).pending_ack.iter().copied().collect();
        if pns.is_empty() {
            return;
        }
        self.space_mut(space).pending_ack.clear();
        // One ACK per largest PN (sufficient for echo).
        let largest = pns.into_iter().max().unwrap();
        let mut payload = Vec::new();
        writer::ack_single(&mut payload, largest);
        // ACK-only: not ack-eliciting, not in flight.
        self.queue_packet(space, payload, Vec::new(), false, false, now);
    }

    fn flush_pending_packets(&mut self, now: Instant) {
        if self.handshake_done_pending && self.spaces[2].secrets.is_some() {
            self.handshake_done_pending = false;
            let mut payload = Vec::new();
            writer::handshake_done(&mut payload);
            self.queue_packet(
                SpaceId::Data,
                payload,
                Vec::new(),
                true,
                true,
                now,
            );
            self.handshake_done = true;
            self.loss.set_handshake_confirmed(true);
            self.maybe_establish();
        }

        if let Some(max) = self.pending_max_streams_bidi.take() {
            if self.spaces[2].secrets.is_some() {
                let mut payload = Vec::new();
                writer::max_streams_bidi(&mut payload, max);
                self.queue_packet(SpaceId::Data, payload, Vec::new(), true, true, now);
            } else {
                self.pending_max_streams_bidi = Some(max);
            }
        }

        // PTO probe PINGs.
        for space in [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data] {
            let idx = space_index(space);
            if !self.pto_ping_pending[idx] {
                continue;
            }
            self.pto_ping_pending[idx] = false;
            if self.space(space).secrets.is_none() {
                continue;
            }
            let mut payload = Vec::new();
            writer::ping(&mut payload);
            self.queue_packet(
                space,
                payload,
                vec![RecoverableFrame::Ping],
                true,
                true,
                now,
            );
        }

        // CRYPTO frames (retransmits first, at stored offsets).
        for space in [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data] {
            loop {
                let retransmit = {
                    let sp = self.space_mut(space);
                    sp.crypto_retransmit.pop_front()
                };
                let Some((offset, chunk)) = retransmit else {
                    break;
                };
                if space == SpaceId::Data && !self.loss.congestion().can_send(MAX_DATAGRAM_SIZE) {
                    self.space_mut(space)
                        .crypto_retransmit
                        .push_front((offset, chunk));
                    break;
                }
                let mut payload = Vec::new();
                writer::crypto(&mut payload, offset, &chunk);
                let frames = vec![RecoverableFrame::Crypto {
                    offset,
                    data: chunk.clone(),
                }];
                if space == SpaceId::Initial {
                    self.queue_packet_pad_initial(payload, frames, now);
                } else {
                    self.queue_packet(space, payload, frames, true, true, now);
                }
            }
            while let Some(chunk) = {
                let sp = self.space_mut(space);
                sp.crypto_pending.pop_front()
            } {
                if space == SpaceId::Data && !self.loss.congestion().can_send(MAX_DATAGRAM_SIZE) {
                    self.space_mut(space).crypto_pending.push_front(chunk);
                    break;
                }
                let offset = self.space(space).crypto_send_offset;
                let mut payload = Vec::new();
                writer::crypto(&mut payload, offset, &chunk);
                self.space_mut(space).crypto_send_offset += chunk.len() as u64;
                let frames = vec![RecoverableFrame::Crypto {
                    offset,
                    data: chunk.clone(),
                }];
                if space == SpaceId::Initial {
                    self.queue_packet_pad_initial(payload, frames, now);
                } else {
                    self.queue_packet(space, payload, frames, true, true, now);
                }
            }
        }

        // STREAM frames on Data.
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            loop {
                if !self.loss.congestion().can_send(MAX_DATAGRAM_SIZE) {
                    break;
                }
                let Some(max_chunk) = self.stream_chunk_budget(id) else {
                    break;
                };
                let Some((offset, data, fin)) = self
                    .streams
                    .get_mut(&id)
                    .and_then(|st| st.send.take_chunk(max_chunk))
                else {
                    break;
                };
                let mut payload = Vec::new();
                writer::stream(&mut payload, id, offset, &data, fin);
                let frames = vec![RecoverableFrame::Stream {
                    id,
                    offset,
                    data: data.clone(),
                    fin,
                }];
                if !self.queue_packet(SpaceId::Data, payload, frames, true, true, now) {
                    // Congestion blocked after size estimate — put data back.
                    if let Some(st) = self.streams.get_mut(&id) {
                        st.send.requeue(offset, data, fin);
                    }
                    break;
                }
                // Track STREAM sent under 0-RTT for reject→1-RTT retransmit.
                if self.side == Side::Client
                    && self.spaces[2].secrets.is_none()
                    && self.early_secret.is_some()
                    && self.early_data_accepted != Some(true)
                {
                    self.pending_0rtt_retransmit
                        .push((id, offset, data.clone(), fin));
                }
                if fin {
                    self.events
                        .push_back(Event::Stream(StreamEvent::Finished { id }));
                }
            }
        }

        // DATAGRAM frames on 1-RTT.
        while let Some(data) = self.datagram_tx.pop_front() {
            if self.spaces[2].secrets.is_none() {
                self.datagram_tx.push_front(data);
                break;
            }
            if !self.loss.congestion().can_send(MAX_DATAGRAM_SIZE) {
                self.datagram_tx.push_front(data);
                break;
            }
            let mut payload = Vec::new();
            writer::datagram(&mut payload, &data);
            // DATAGRAMs are not retransmitted on loss.
            self.queue_packet(SpaceId::Data, payload, Vec::new(), true, true, now);
        }
    }

    /// Largest datagram this endpoint will send: 1200 bytes until path MTU
    /// discovery shows more (RFC 9000 §14), bounded by the peer's
    /// `max_udp_payload_size` (§18.2).
    fn max_datagram_size(&self) -> usize {
        match &self.peer_tp {
            Some(tp) => {
                usize::try_from(tp.max_udp_payload_size).map_or(MAX_DATAGRAM_SIZE, |peer| {
                    MAX_DATAGRAM_SIZE.min(peer)
                })
            }
            None => MAX_DATAGRAM_SIZE,
        }
    }

    /// Largest STREAM payload that keeps the next Data-space packet within
    /// [`Self::max_datagram_size`]: the datagram budget minus the header for
    /// the current connection ID and packet number lengths, the AEAD tag, and
    /// the STREAM frame header for this stream's next offset. `None` if the
    /// stream has nothing to send or the budget cannot fit any payload.
    fn stream_chunk_budget(&self, id: StreamId) -> Option<usize> {
        let send = &self.streams.get(&id)?.send;
        let offset = send.next_offset();
        let space = self.space(SpaceId::Data);
        let pn_len = pn::encoded_length(space.next_pn, space.largest_acked);
        let use_0rtt = space.secrets.is_none()
            && self.early_secret.is_some()
            && self.side == Side::Client;
        let budget = self.max_datagram_size();
        let header_len = if use_0rtt {
            // The Length field is at most two bytes at this size.
            long_header::build_0rtt(
self.version,
&self.rem_cid, &self.local_cid, 0, pn_len, budget).len()
        } else {
            1 + self.rem_cid.len() + pn_len
        };
        // Type + stream ID + offset + a two-byte length varint (payload < 16384).
        let frame_overhead = 1
            + varint::encoded_length(id.as_u64())
            + varint::encoded_length(offset)
            + 2;
        budget.checked_sub(header_len + TAG_LEN + frame_overhead)
            .filter(|n| *n > 0)
    }

    fn queue_packet_pad_initial(
        &mut self,
        payload: Vec<u8>,
        frames: Vec<RecoverableFrame>,
        now: Instant,
    ) {
        // RFC 9000 section 14.1: expand the datagram to at least 1200 octets.
        // `queue_packet` knows the real header length (which varies with the
        // CID lengths, token and packet number), so let it pad exactly.
        let previous = self.gso_pad_to;
        self.gso_pad_to = Some(previous.unwrap_or(0).max(MIN_INITIAL_DATAGRAM_SIZE));
        // Padded Initial is in flight even beyond ack-eliciting frames.
        self.queue_packet(SpaceId::Initial, payload, frames, true, true, now);
        self.gso_pad_to = previous;
    }

    /// Build and enqueue a protected packet. Returns false if congestion-blocked (Data only).
    fn queue_packet(
        &mut self,
        space: SpaceId,
        mut payload_frames: Vec<u8>,
        recoverable: Vec<RecoverableFrame>,
        ack_eliciting: bool,
        in_flight: bool,
        now: Instant,
    ) -> bool {
        let use_0rtt = space == SpaceId::Data
            && self.spaces[2].secrets.is_none()
            && self.early_secret.is_some()
            && self.side == Side::Client;
        let local_keys = if use_0rtt {
            PacketKeys::from_secret(self.version, self.early_aead, self.early_secret.as_ref().unwrap())
        } else {
            match self.space(space).keys(self.side, self.version) {
                Some(k) => k.local,
                None => return false,
            }
        };
        let tag_len = local_keys.tag_len();
        let pn = self.space(space).next_pn;
        let largest_acked = self.space(space).largest_acked;
        let pn_len = pn::encoded_length(pn, largest_acked);

        // Pad with PADDING frames before AEAD when building a GSO batch.
        if let Some(target) = self.gso_pad_to {
            self.pad_payload_for_gso(space, pn_len, tag_len, target, &mut payload_frames);
        }

        let protected_len = payload_frames.len() + tag_len;
        // Rough final size estimate for congestion gating.
        let header_est = match space {
            SpaceId::Data if use_0rtt => 50,
            SpaceId::Data => 1 + self.rem_cid.len() + pn_len,
            _ => 50,
        };
        let est_len = header_est + protected_len;
        if space == SpaceId::Data && in_flight && !self.loss.congestion().can_send(est_len) {
            return false;
        }

        self.space_mut(space).next_pn += 1;

        let header = match space {
            SpaceId::Initial => long_header::build_initial(
self.version,
&self.rem_cid,
                &self.local_cid,
                &self.token,
                pn,
                pn_len,
                protected_len,
            ),
            SpaceId::Handshake => long_header::build_handshake(
self.version,
&self.rem_cid,
                &self.local_cid,
                pn,
                pn_len,
                protected_len,
            ),
            SpaceId::Data if use_0rtt => long_header::build_0rtt(
self.version,
&self.rem_cid,
                &self.local_cid,
                pn,
                pn_len,
                protected_len,
            ),
            SpaceId::Data => short_header::build(&self.rem_cid, false, false, pn, pn_len),
        };
        let pn_offset = header.len() - pn_len;
        let mut payload = payload_frames;
        local_keys.encrypt(pn, &header, &mut payload);
        let mut packet = header;
        packet.append(&mut payload);
        local_keys.protect_header(pn_offset, &mut packet, true);

        self.loss.on_packet_sent(
            space,
            pn,
            now,
            ack_eliciting,
            in_flight,
            packet.len(),
            recoverable,
        );

        let tx = Transmit {
            destination: self.remote,
            ecn: None,
            size: packet.len(),
            segment_size: None,
            src_ip: None,
        };
        self.transmits.push_back((tx, packet));
        true
    }

    /// Expand plaintext with PADDING so `header + ciphertext+tag` equals `target`.
    fn pad_payload_for_gso(
        &self,
        space: SpaceId,
        pn_len: usize,
        tag_len: usize,
        target: usize,
        payload: &mut Vec<u8>,
    ) {
        match space {
            SpaceId::Data => {
                let header_len = 1 + self.rem_cid.len() + pn_len;
                let want = target.saturating_sub(header_len + tag_len);
                if payload.len() < want {
                    writer::pad_to(payload, want);
                }
            }
            SpaceId::Initial | SpaceId::Handshake => {
                // Length varint size depends on protected length; iterate a few times.
                for _ in 0..4 {
                    let protected_len = payload.len() + tag_len;
                    let header_len = match space {
                        SpaceId::Initial => long_header::build_initial(
self.version,
&self.rem_cid,
                            &self.local_cid,
                            &self.token,
                            0,
                            pn_len,
                            protected_len,
                        )
                        .len(),
                        SpaceId::Handshake => long_header::build_handshake(
self.version,
&self.rem_cid,
                            &self.local_cid,
                            0,
                            pn_len,
                            protected_len,
                        )
                        .len(),
                        SpaceId::Data => unreachable!(),
                    };
                    let want = target.saturating_sub(header_len + tag_len);
                    if payload.len() >= want {
                        break;
                    }
                    writer::pad_to(payload, want);
                }
            }
        }
    }

    fn requeue_lost_packet(
        &mut self,
        space: SpaceId,
        lost: &crate::transport::recovery::SentPacket,
    ) {
        for frame in &lost.frames {
            match frame {
                RecoverableFrame::Crypto { offset, data } => {
                    self.space_mut(space)
                        .crypto_retransmit
                        .push_back((*offset, data.clone()));
                }
                RecoverableFrame::Stream {
                    id,
                    offset,
                    data,
                    fin,
                } => {
                    if let Some(st) = self.streams.get_mut(id) {
                        st.send.requeue(*offset, data.clone(), *fin);
                    }
                }
                RecoverableFrame::Ping => {
                    // PTO PINGs are not retransmitted as such; a later PTO
                    // will send a fresh probe if still needed.
                }
            }
        }
    }

    fn peer_address_validated(&self) -> bool {
        // Echo milestone: treat established / handshake-done as validated.
        self.established || self.handshake_done || self.retry_processed
    }

    fn peer_max_ack_delay(&self) -> Duration {
        Duration::from_millis(
            self.peer_tp
                .as_ref()
                .map(|t| t.max_ack_delay.max(1))
                .unwrap_or(25),
        )
    }

    /// Apply remembered peer limits for 0-RTT (RFC 9000 §7.4.1) before EE arrives.
    fn apply_remembered_peer_limits(
        &mut self,
        limits: hopf_core::tls::RememberedTransportLimits,
    ) {
        self.conn_max_data = limits.initial_max_data;
        self.peer_max_streams_bidi = limits.initial_max_streams_bidi;
        self.peer_max_streams_uni = limits.initial_max_streams_uni;
        self.remembered_0rtt_stream_max = Some(limits.initial_max_stream_data_bidi_remote);
    }

    fn ensure_recv_stream(&mut self, id: StreamId) {
        if self.streams.contains_key(&id) {
            return;
        }
        let max = self
            .peer_tp
            .as_ref()
            .map(|t| t.initial_max_stream_data_bidi_remote)
            .unwrap_or(1 << 20);
        self.streams.insert(
            id,
            StreamState {
                send: SendStream {
                    max_data: max,
                    ..Default::default()
                },
                recv: RecvStream::new(1 << 20),
                opened_event: id.initiator() == self.side,
                bidi_credit_granted: false,
            },
        );
    }

    /// After a peer-initiated bi stream finishes (peer FIN), raise the
    /// cumulative MAX_STREAMS limit so the peer can open another.
    fn maybe_grant_bidi_credit(&mut self, id: StreamId) {
        if id.dir() != Dir::Bi || id.initiator() == self.side {
            return;
        }
        let Some(st) = self.streams.get_mut(&id) else {
            return;
        };
        if st.bidi_credit_granted {
            return;
        }
        st.bidi_credit_granted = true;
        self.local_max_streams_bidi = self.local_max_streams_bidi.saturating_add(1);
        self.pending_max_streams_bidi = Some(self.local_max_streams_bidi);
    }

    // ── Stream API (driver-facing) ──────────────────────────────────────

    /// Open a local stream of the given direction.
    pub fn open(&mut self, dir: Dir) -> Option<StreamId> {
        match dir {
            Dir::Bi => self.open_bi(),
            Dir::Uni => self.open_uni(),
        }
    }

    /// Open a local bidirectional stream.
    pub fn open_bi(&mut self) -> Option<StreamId> {
        if self.next_local_bi >= self.peer_max_streams_bidi {
            return None;
        }
        let id = StreamId::new(self.side, Dir::Bi, self.next_local_bi);
        self.next_local_bi += 1;
        let max = self
            .peer_tp
            .as_ref()
            .map(|t| t.initial_max_stream_data_bidi_remote)
            .or(self.remembered_0rtt_stream_max)
            .unwrap_or(1 << 20);
        self.streams.insert(
            id,
            StreamState {
                send: SendStream {
                    max_data: max,
                    ..Default::default()
                },
                recv: RecvStream::new(1 << 20),
                opened_event: true,
                bidi_credit_granted: false,
            },
        );
        Some(id)
    }

    /// Open a local unidirectional stream.
    pub fn open_uni(&mut self) -> Option<StreamId> {
        if self.next_local_uni >= self.peer_max_streams_uni {
            return None;
        }
        let index = self.next_local_uni;
        self.next_local_uni += 1;
        let id = StreamId::new(self.side, Dir::Uni, index);
        let max = self
            .peer_tp
            .as_ref()
            .map(|t| t.initial_max_stream_data_uni)
            .unwrap_or(1 << 20);
        self.streams.insert(
            id,
            StreamState {
                send: SendStream {
                    max_data: max,
                    ..Default::default()
                },
                recv: RecvStream::new(0),
                opened_event: true,
                bidi_credit_granted: false,
            },
        );
        Some(id)
    }

    /// Accept a peer-opened stream.
    pub fn accept(&mut self, dir: Dir) -> Option<StreamId> {
        let peer_side = match self.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let expected = match dir {
            Dir::Bi => self.next_remote_bi_expected,
            Dir::Uni => self.next_remote_uni_expected,
        };
        let mut candidates: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(id, _)| id.dir() == dir && id.initiator() == peer_side)
            .map(|(id, _)| *id)
            .collect();
        candidates.sort_by_key(|id| id.index());
        if let Some(id) = candidates.into_iter().find(|id| id.index() == expected) {
            match dir {
                Dir::Bi => self.next_remote_bi_expected += 1,
                Dir::Uni => self.next_remote_uni_expected += 1,
            }
            return Some(id);
        }
        None
    }

    /// Write to a send stream.
    pub fn write_stream(&mut self, id: StreamId, data: &[u8]) -> Result<usize, WriteError> {
        let st = self.streams.get_mut(&id).ok_or(WriteError::UnknownStream)?;
        st.send.write(data).map_err(|_| WriteError::Blocked)
    }

    /// Finish a send stream.
    pub fn finish_stream(&mut self, id: StreamId) -> Result<(), ()> {
        let st = self.streams.get_mut(&id).ok_or(())?;
        st.send.finish();
        Ok(())
    }

    /// Read from a recv stream.
    pub fn read_stream(&mut self, id: StreamId, max: usize) -> Result<(Bytes, bool), ()> {
        let st = self.streams.get_mut(&id).ok_or(())?;
        Ok(st.recv.read(max))
    }

    /// Reset a send stream.
    pub fn reset_stream(&mut self, _id: StreamId, _error_code: VarInt) {}

    /// STOP_SENDING on a recv stream.
    pub fn stop_stream(&mut self, _id: StreamId, _error_code: VarInt) {}

    /// Set stream priority (no-op for echo).
    pub fn set_priority(&mut self, _id: StreamId, _priority: i32) {}

    /// DATAGRAM send (RFC 9221).
    pub fn send_datagram(&mut self, payload: Bytes) -> Result<(), crate::transport::types::SendDatagramError> {
        use crate::transport::types::SendDatagramError;
        if self.local_tp.max_datagram_frame_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        if self.peer_max_datagram == 0 {
            return Err(SendDatagramError::UnsupportedByPeer);
        }
        let len_vi = crate::transport::varint::encoded_length(payload.len() as u64);
        let encoded = 1 + len_vi + payload.len();
        if encoded as u64 > self.peer_max_datagram {
            return Err(SendDatagramError::TooLarge);
        }
        self.datagram_tx.push_back(payload);
        Ok(())
    }

    /// DATAGRAM recv.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        self.datagram_rx.pop_front()
    }

    // ── Quinn-shaped adapters used by driver.rs ─────────────────────────

    /// Stream open/accept handle.
    pub fn streams(&mut self) -> StreamsApi<'_> {
        StreamsApi { conn: self }
    }

    /// Send half of a stream.
    pub fn send_stream(&mut self, id: StreamId) -> SendStreamApi<'_> {
        SendStreamApi { conn: self, id }
    }

    /// Receive half of a stream.
    pub fn recv_stream(&mut self, id: StreamId) -> RecvStreamApi<'_> {
        RecvStreamApi { conn: self, id }
    }

    /// DATAGRAM API.
    pub fn datagrams(&mut self) -> DatagramsApi<'_> {
        DatagramsApi { conn: self }
    }

    /// Poll transmit, coalescing up to `max_gso` same-destination datagrams for UDP GSO.
    ///
    /// When `max_gso > 1`, pending packets are padded with QUIC PADDING frames before
    /// encryption so all but the last segment share a common size. A single-segment
    /// batch returns `segment_size: None` (drivers dislike one-segment GSO).
    pub fn poll_transmit_gso(
        &mut self,
        now: Instant,
        max_gso: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        if max_gso <= 1 {
            return self.poll_transmit(now, buf);
        }

        let max_udp = self.local_tp.max_udp_payload_size as usize;
        let pad_to = self.max_datagram_size().min(max_udp);
        self.gso_pad_to = Some(pad_to);
        self.flush_pending_packets(now);
        self.gso_pad_to = None;

        let (first_tx, first_data) = self.transmits.pop_front()?;
        let seg = first_data.len();
        buf.clear();
        buf.extend_from_slice(&first_data);

        let mut count = 1usize;
        while count < max_gso {
            let Some((next_tx, next_data)) = self.transmits.front() else {
                break;
            };
            if next_tx.destination != first_tx.destination {
                break;
            }
            let next_len = next_data.len();
            if next_len == seg {
                let (_, data) = self.transmits.pop_front().unwrap();
                buf.extend_from_slice(&data);
                count += 1;
            } else if next_len < seg {
                // Last segment may be shorter.
                let (_, data) = self.transmits.pop_front().unwrap();
                buf.extend_from_slice(&data);
                count += 1;
                break;
            } else {
                // Larger than the first segment — leave for a later transmit.
                break;
            }
        }

        Some(Transmit {
            destination: first_tx.destination,
            ecn: first_tx.ecn,
            size: buf.len(),
            segment_size: if count > 1 { Some(seg) } else { None },
            src_ip: None,
        })
    }

    /// Handle event without explicit now (uses Instant::now).
    pub fn handle_event_now(&mut self, ev: crate::transport::types::ConnectionEvent) {
        self.handle_event(Instant::now(), ev);
    }
}

/// `conn.streams()` facade.
pub struct StreamsApi<'a> {
    conn: &'a mut Connection,
}

impl StreamsApi<'_> {
    /// Open a stream.
    pub fn open(&mut self, dir: Dir) -> Option<StreamId> {
        self.conn.open(dir)
    }

    /// Accept a peer stream.
    pub fn accept(&mut self, dir: Dir) -> Option<StreamId> {
        self.conn.accept(dir)
    }
}

/// `conn.send_stream(id)` facade.
pub struct SendStreamApi<'a> {
    conn: &'a mut Connection,
    id: StreamId,
}

impl SendStreamApi<'_> {
    /// Write bytes.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.conn.write_stream(self.id, data)
    }

    /// Finish send half.
    pub fn finish(&mut self) -> Result<(), ()> {
        self.conn.finish_stream(self.id)
    }

    /// Reset send half.
    pub fn reset(&mut self, code: VarInt) -> Result<(), ()> {
        self.conn.reset_stream(self.id, code);
        Ok(())
    }

    /// Set priority (no-op).
    pub fn set_priority(&mut self, priority: i32) -> Result<(), ()> {
        self.conn.set_priority(self.id, priority);
        Ok(())
    }
}

/// `conn.recv_stream(id)` facade.
pub struct RecvStreamApi<'a> {
    conn: &'a mut Connection,
    id: StreamId,
}

impl RecvStreamApi<'_> {
    /// Begin reading (ordered chunks).
    pub fn read(&mut self, _ordered: bool) -> Result<StreamChunks, ()> {
        let (data, fin) = self.conn.read_stream(self.id, usize::MAX)?;
        Ok(StreamChunks {
            data: if data.is_empty() { None } else { Some(data) },
            fin,
            done: false,
        })
    }

    /// STOP_SENDING.
    pub fn stop(&mut self, code: VarInt) -> Result<(), ()> {
        self.conn.stop_stream(self.id, code);
        Ok(())
    }
}

/// Chunks iterator matching quinn's recv read API.
pub struct StreamChunks {
    data: Option<Bytes>,
    fin: bool,
    done: bool,
}

/// One stream chunk.
pub struct StreamChunk {
    /// Payload bytes.
    pub bytes: Bytes,
}

impl StreamChunks {
    /// Next chunk, or `None` on FIN.
    pub fn next(&mut self, _max: usize) -> Result<Option<StreamChunk>, ()> {
        if let Some(data) = self.data.take() {
            return Ok(Some(StreamChunk { bytes: data }));
        }
        if self.fin && !self.done {
            self.done = true;
            return Ok(None);
        }
        Err(())
    }

    /// Finalize read.
    pub fn finalize(self) -> Result<(), ()> {
        Ok(())
    }
}

/// `conn.datagrams()` facade.
pub struct DatagramsApi<'a> {
    conn: &'a mut Connection,
}

impl DatagramsApi<'_> {
    /// Send a DATAGRAM.
    pub fn send(
        &mut self,
        payload: Bytes,
        _drop: bool,
    ) -> Result<(), crate::transport::types::SendDatagramError> {
        self.conn.send_datagram(payload)
    }

    /// Receive a DATAGRAM.
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.recv_datagram()
    }
}

fn space_index(id: SpaceId) -> usize {
    match id {
        SpaceId::Initial => 0,
        SpaceId::Handshake => 1,
        SpaceId::Data => 2,
    }
}

/// Convert a transport-parameter idle timeout (ms; 0 = infinite) to a [`Duration`].
fn idle_timeout_from_ms(ms: u64) -> Duration {
    if ms == 0 {
        // Effectively infinite for polling purposes.
        Duration::from_secs(365 * 24 * 3600)
    } else {
        Duration::from_millis(ms)
    }
}

/// Negotiate connection idle timeout: min of local and peer, treating 0 as infinite.
fn negotiate_idle_timeout(local_ms: u64, peer_ms: u64) -> Duration {
    let ms = match (local_ms, peer_ms) {
        (0, 0) => 0,
        (0, p) => p,
        (l, 0) => l,
        (l, p) => l.min(p),
    };
    idle_timeout_from_ms(ms)
}

/// Write error.
#[derive(Debug)]
pub enum WriteError {
    /// Unknown stream.
    UnknownStream,
    /// Blocked on flow control.
    Blocked,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::crypto::kx_policy::KxPolicy;
    use hopf_core::tls::{HandshakeMode, HandshakeRole};

    fn test_client(now: Instant) -> Connection {
        test_client_with_dcid_len(now, 8)
    }

    fn test_client_with_dcid_len(now: Instant, dcid_len: usize) -> Connection {
        let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let local = ConnectionId::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let dcid = ConnectionId::from_slice(&vec![9u8; dcid_len]);
        let hs = HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"hq-interop")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: hopf_core::tls::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        };
        let mut conn = Connection::new_client(
            now,
            remote,
            "localhost",
            hs,
            local,
            dcid,
            &[QuicVersion::V1],
            QuicVersion::V1,
            Some(65535),
            None,
            None,
            None,
            None,
        );
        // Drop handshake CRYPTO so flush only sees our Data packets.
        for sp in &mut conn.spaces {
            sp.crypto_pending.clear();
            sp.crypto_retransmit.clear();
            sp.pending_ack.clear();
        }
        conn.transmits.clear();
        let secrets = crate::transport::packet::protection::initial_secrets(QuicVersion::V1, &[1, 2, 3, 4]);
        conn.spaces[2].secrets = Some(secrets);
        conn.peer_max_datagram = 65535;
        conn
    }

    /// A Version Negotiation packet (RFC 9000 section 17.2.1) as a server
    /// would send it to a client whose SCID / DCID are given.
    fn version_negotiation_packet(client_scid: &[u8], client_dcid: &[u8], versions: &[u32]) -> Vec<u8> {
        let mut p = vec![0x80 | 0x2a];
        p.extend_from_slice(&0u32.to_be_bytes());
        p.push(client_scid.len() as u8);
        p.extend_from_slice(client_scid);
        p.push(client_dcid.len() as u8);
        p.extend_from_slice(client_dcid);
        for v in versions {
            p.extend_from_slice(&v.to_be_bytes());
        }
        p
    }

    fn lost_with(conn: &mut Connection) -> Option<ConnectionError> {
        while let Some(ev) = conn.poll() {
            if let Event::ConnectionLost { reason } = ev {
                return Some(reason);
            }
        }
        None
    }

    /// RFC 9000 section 14.1: a client MUST expand every datagram carrying an
    /// Initial packet to at least 1200 octets, or servers drop it. Regression:
    /// the padding used a fixed guess of the header size, which is longer than
    /// a real Initial header, so first flights were about 1180 octets.
    #[test]
    fn the_first_initial_datagram_is_at_least_1200_octets() {
        for version in [QuicVersion::V1, QuicVersion::V2] {
            for (scid_len, dcid_len) in [(8usize, 8usize), (4, 8), (20, 20), (1, 16)] {
                let mut conn = Connection::new_client(
                    Instant::now(),
                    "127.0.0.1:4433".parse().unwrap(),
                    "localhost",
                    HandshakeConfig {
                        role: HandshakeRole::Client,
                        mode: HandshakeMode::Quic,
                        alpn: vec![Bytes::from_static(b"hq-interop")],
                        kx_policy: KxPolicy::classical_only(),
                        ..Default::default()
                    },
                    ConnectionId::from_slice(&vec![1u8; scid_len]),
                    ConnectionId::from_slice(&vec![2u8; dcid_len]),
                    &[version],
                    version,
                    Some(1452),
                    None,
                    None,
                    None,
                    None,
                );
                let mut buf = Vec::new();
                conn.poll_transmit(Instant::now(), &mut buf).expect("a first flight");
                assert!(buf.len() >= 1200, "{version:?} scid {scid_len} dcid {dcid_len}: {} octets", buf.len());
                assert!(buf.len() <= 1252, "not wildly oversized: {}", buf.len());
            }
        }
    }

    fn test_server(version: QuicVersion, server_versions: &[QuicVersion]) -> Connection {
        Connection::new_server(
            Instant::now(),
            "127.0.0.1:50000".parse().unwrap(),
            HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Quic,
                ..Default::default()
            },
            ConnectionId::from_slice(&[0xaa; 8]),
            ConnectionId::from_slice(&[0xbb; 8]),
            version,
            server_versions,
            ConnectionId::from_slice(&[0xcc; 8]),
            ConnectionId::from_slice(&[0xbb; 8]),
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    /// Feed `conn` the peer's transport parameters as the TLS layer would.
    fn receive_peer_tp(conn: &mut Connection, tp: &TransportParameters) {
        conn.apply_tls_events(TlsBridgeEvents {
            peer_tp: Some(Bytes::from(tp.encode())),
            ..Default::default()
        });
    }

    fn tp_with(chosen: u32, available: &[u32]) -> TransportParameters {
        let mut tp = TransportParameters::default();
        tp.version_information = Some(VersionInformation { chosen, available: available.to_vec() });
        tp
    }

    /// The `TransportError` code a connection was closed with, if any.
    fn closed_with(conn: &mut Connection) -> Option<u64> {
        match lost_with(conn) {
            Some(ConnectionError::TransportError { code, .. }) => Some(code),
            _ => None,
        }
    }

    const V1: u32 = 1;
    const V2: u32 = 0x6b33_43cf;

    /// RFC 9369 section 4: every v2-capable endpoint sends version_information.
    /// A client lists only its chosen version as available (compatible version
    /// negotiation off); a server lists its whole deployment.
    #[test]
    fn both_roles_send_version_information() {
        let client = versioned_client(Instant::now(), &[QuicVersion::V2, QuicVersion::V1]);
        assert_eq!(client.local_tp.version_information, Some(VersionInformation { chosen: V1, available: vec![V1] }));
        let mut v2_client = Connection::new_client(
            Instant::now(),
            "127.0.0.1:4433".parse().unwrap(),
            "localhost",
            HandshakeConfig { role: HandshakeRole::Client, mode: HandshakeMode::Quic, ..Default::default() },
            ConnectionId::from_slice(&[1; 8]),
            ConnectionId::from_slice(&[2; 8]),
            &[QuicVersion::V2, QuicVersion::V1],
            QuicVersion::V2,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(v2_client.local_tp.version_information, Some(VersionInformation { chosen: V2, available: vec![V2] }));
        let _ = &mut v2_client;

        let server = test_server(QuicVersion::V1, &[QuicVersion::V2, QuicVersion::V1]);
        assert_eq!(server.local_tp.version_information, Some(VersionInformation { chosen: V1, available: vec![V2, V1] }));
    }

    #[test]
    fn client_accepts_consistent_server_version_information() {
        let mut conn = versioned_client(Instant::now(), &[QuicVersion::V1]);
        receive_peer_tp(&mut conn, &tp_with(V1, &[V1, V2]));
        assert_eq!(closed_with(&mut conn), None);
        // Absent is allowed when the client did not react to Version Negotiation.
        let mut conn = versioned_client(Instant::now(), &[QuicVersion::V1]);
        receive_peer_tp(&mut conn, &TransportParameters::default());
        assert_eq!(closed_with(&mut conn), None);
    }

    /// RFC 9368 section 4: the server's Chosen Version must be the version in
    /// use; anything else is a version negotiation error.
    #[test]
    fn client_closes_when_the_servers_chosen_version_is_not_the_one_in_use() {
        let mut conn = versioned_client(Instant::now(), &[QuicVersion::V1, QuicVersion::V2]);
        receive_peer_tp(&mut conn, &tp_with(V2, &[V1, V2]));
        assert_eq!(closed_with(&mut conn), Some(VERSION_NEGOTIATION_ERROR));
        assert!(conn.closed);
    }

    #[test]
    fn client_closes_on_malformed_version_information() {
        let mut conn = versioned_client(Instant::now(), &[QuicVersion::V1]);
        let mut tp = TransportParameters::default();
        tp.version_information_invalid = true;
        // (decode sets the flag; feed it through the wire form instead.)
        let mut raw = TransportParameters::default().encode();
        varint::encode(0x11, &mut raw);
        varint::encode(3, &mut raw);
        raw.extend_from_slice(&[0, 0, 1]);
        conn.apply_tls_events(TlsBridgeEvents { peer_tp: Some(Bytes::from(raw)), ..Default::default() });
        assert_eq!(closed_with(&mut conn), Some(TRANSPORT_PARAMETER_ERROR));
    }

    /// A client that restarted after Version Negotiation must not complete a
    /// handshake without the server's version information (RFC 9368 section 4).
    #[test]
    fn a_restarted_client_requires_the_servers_version_information() {
        let mut conn = versioned_client(Instant::now(), &[QuicVersion::V2, QuicVersion::V1]);
        conn.version = QuicVersion::V1;
        conn.reacted_to_version_negotiation = true;
        receive_peer_tp(&mut conn, &TransportParameters::default());
        assert_eq!(closed_with(&mut conn), Some(VERSION_NEGOTIATION_ERROR));
    }

    /// The downgrade check: steered to v1 by a Version Negotiation packet, the
    /// client learns from the server's own list whether v2 was on offer.
    #[test]
    fn a_restarted_client_detects_a_forged_downgrade() {
        let steered = |available: &[u32]| {
            let mut conn = versioned_client(Instant::now(), &[QuicVersion::V2, QuicVersion::V1]);
            conn.version = QuicVersion::V1;
            conn.reacted_to_version_negotiation = true;
            receive_peer_tp(&mut conn, &tp_with(V1, available));
            closed_with(&mut conn)
        };
        assert_eq!(steered(&[V1]), None, "a genuinely v1-only server");
        assert_eq!(steered(&[V1, V2]), Some(VERSION_NEGOTIATION_ERROR), "the server also speaks v2: downgrade");
        assert_eq!(steered(&[]), Some(VERSION_NEGOTIATION_ERROR), "an empty list never validates");
    }

    #[test]
    fn server_accepts_consistent_client_version_information() {
        let mut conn = test_server(QuicVersion::V1, &[QuicVersion::V1, QuicVersion::V2]);
        receive_peer_tp(&mut conn, &tp_with(V1, &[V1]));
        assert_eq!(closed_with(&mut conn), None);
        // A missing parameter is tolerated by a server.
        let mut conn = test_server(QuicVersion::V1, &[QuicVersion::V1, QuicVersion::V2]);
        receive_peer_tp(&mut conn, &TransportParameters::default());
        assert_eq!(closed_with(&mut conn), None);
    }

    /// RFC 9368 section 4: the client's Chosen Version must match the
    /// version its first flight used; and it must appear in its own list.
    #[test]
    fn server_closes_on_inconsistent_client_version_information() {
        let mut conn = test_server(QuicVersion::V1, &[QuicVersion::V1, QuicVersion::V2]);
        receive_peer_tp(&mut conn, &tp_with(V2, &[V2]));
        assert_eq!(closed_with(&mut conn), Some(VERSION_NEGOTIATION_ERROR), "chosen differs from the version in use");

        let mut conn = test_server(QuicVersion::V1, &[QuicVersion::V1, QuicVersion::V2]);
        receive_peer_tp(&mut conn, &tp_with(V1, &[V2]));
        assert_eq!(closed_with(&mut conn), Some(TRANSPORT_PARAMETER_ERROR), "chosen not among available");

        let mut conn = test_server(QuicVersion::V1, &[QuicVersion::V1, QuicVersion::V2]);
        let mut raw = TransportParameters::default().encode();
        varint::encode(0x11, &mut raw);
        varint::encode(4, &mut raw);
        raw.extend_from_slice(&[0, 0, 0, 0]);
        conn.apply_tls_events(TlsBridgeEvents { peer_tp: Some(Bytes::from(raw)), ..Default::default() });
        assert_eq!(closed_with(&mut conn), Some(TRANSPORT_PARAMETER_ERROR), "zero chosen version");
    }

    /// A client that speaks `versions` (first = first flight), as the endpoint
    /// builds it.
    fn versioned_client(now: Instant, versions: &[QuicVersion]) -> Connection {
        let mut conn = test_client(now);
        conn.version = versions[0];
        conn.client_versions = versions.to_vec();
        conn
    }

    fn first_initial_version(conn: &mut Connection, now: Instant) -> Option<u32> {
        let mut buf = Vec::new();
        conn.poll_transmit(now, &mut buf)?;
        (buf.len() >= 5 && buf[0] & 0x80 != 0).then(|| u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]))
    }

    /// RFC 9000 section 6.2: a client that speaks several versions restarts
    /// in the first the server offers, instead of abandoning the attempt.
    #[test]
    fn client_restarts_in_a_mutually_supported_version_after_version_negotiation() {
        let now = Instant::now();
        let mut conn = versioned_client(now, &[QuicVersion::V2, QuicVersion::V1]);
        let old_dcid = conn.initial_dcid.clone();
        let vn = version_negotiation_packet(conn.local_cid.as_slice(), old_dcid.as_slice(), &[0xff00_0020, 1]);
        conn.handle_packet(now, &vn);
        assert!(lost_with(&mut conn).is_none(), "not abandoned");
        assert!(!conn.closed);
        assert_eq!(conn.version, QuicVersion::V1);
        assert_ne!(conn.initial_dcid, old_dcid, "a fresh first flight uses a new destination CID");
        // Its Initial keys are the version 1 ones for the new DCID, and the
        // first datagram out is a version 1 Initial.
        assert_eq!(first_initial_version(&mut conn, now), Some(1));
    }

    /// The restart is single-shot: the version negotiation reply to the new
    /// attempt is ignored (RFC 9368 section 4), so a forged follow-up cannot
    /// bounce the client around.
    #[test]
    fn a_restarted_client_ignores_further_version_negotiation() {
        let now = Instant::now();
        let mut conn = versioned_client(now, &[QuicVersion::V2, QuicVersion::V1]);
        let vn = version_negotiation_packet(conn.local_cid.as_slice(), conn.initial_dcid.as_slice(), &[1]);
        conn.handle_packet(now, &vn);
        assert_eq!(conn.version, QuicVersion::V1);
        let again = version_negotiation_packet(conn.local_cid.as_slice(), conn.initial_dcid.as_slice(), &[QuicVersion::V2.wire()]);
        conn.handle_packet(now, &again);
        assert_eq!(conn.version, QuicVersion::V1);
        assert!(!conn.closed);
    }

    #[test]
    fn client_abandons_when_the_server_offers_none_of_its_versions() {
        let now = Instant::now();
        let mut conn = versioned_client(now, &[QuicVersion::V2]);
        let vn = version_negotiation_packet(conn.local_cid.as_slice(), conn.initial_dcid.as_slice(), &[1, 0xff00_0020]);
        conn.handle_packet(now, &vn);
        assert!(matches!(lost_with(&mut conn), Some(ConnectionError::VersionMismatch)));
    }

    /// A packet listing the version the client used is bogus whichever
    /// version that is (RFC 9000 section 6.2).
    #[test]
    fn client_discards_version_negotiation_listing_the_version_it_used() {
        let now = Instant::now();
        let mut conn = versioned_client(now, &[QuicVersion::V2, QuicVersion::V1]);
        let vn = version_negotiation_packet(conn.local_cid.as_slice(), conn.initial_dcid.as_slice(), &[QuicVersion::V2.wire(), 1]);
        conn.handle_packet(now, &vn);
        assert_eq!(conn.version, QuicVersion::V2);
        assert!(!conn.closed);
    }

    /// RFC 9000 section 6.2: a client that supports only version 1 abandons
    /// the attempt when the server offers no version it speaks.
    #[test]
    fn client_abandons_the_attempt_on_version_negotiation_offering_nothing_usable() {
        let mut conn = test_client(Instant::now());
        let vn = version_negotiation_packet(&[1, 2, 3, 4, 5, 6, 7, 8], &[9u8; 8], &[0xff00_0020, 0x6b33_43cf]);
        conn.handle_packet(Instant::now(), &vn);
        assert!(matches!(lost_with(&mut conn), Some(ConnectionError::VersionMismatch)));
        assert!(conn.closed);
    }

    /// A Version Negotiation packet listing the version the client already
    /// chose is bogus (RFC 9000 section 6.2) and must be discarded.
    #[test]
    fn client_discards_version_negotiation_that_lists_its_own_version() {
        let mut conn = test_client(Instant::now());
        let vn = version_negotiation_packet(&[1, 2, 3, 4, 5, 6, 7, 8], &[9u8; 8], &[0xff00_0020, QuicVersion::V1.wire()]);
        conn.handle_packet(Instant::now(), &vn);
        assert!(lost_with(&mut conn).is_none());
        assert!(!conn.closed);
    }

    /// Off-path attackers can't guess our connection IDs: the echoed IDs
    /// must match what we sent.
    #[test]
    fn client_discards_version_negotiation_with_wrong_connection_ids() {
        for (scid, dcid) in [([1u8, 2, 3, 4, 5, 6, 7, 9], [9u8; 8]), ([1, 2, 3, 4, 5, 6, 7, 8], [7u8; 8])] {
            let mut conn = test_client(Instant::now());
            let vn = version_negotiation_packet(&scid, &dcid, &[0xff00_0020]);
            conn.handle_packet(Instant::now(), &vn);
            assert!(lost_with(&mut conn).is_none(), "{scid:?} {dcid:?}");
            assert!(!conn.closed);
        }
    }

    /// Once the client has processed any other server packet (here a Retry),
    /// a later Version Negotiation packet must be ignored.
    #[test]
    fn client_discards_version_negotiation_after_processing_another_packet() {
        let mut conn = test_client(Instant::now());
        conn.retry_processed = true;
        let vn = version_negotiation_packet(&[1, 2, 3, 4, 5, 6, 7, 8], &[9u8; 8], &[0xff00_0020]);
        conn.handle_packet(Instant::now(), &vn);
        assert!(lost_with(&mut conn).is_none());
        assert!(!conn.closed);
    }

    /// A truncated or list-less Version Negotiation packet is just dropped.
    #[test]
    fn malformed_version_negotiation_is_ignored() {
        for len in [7usize, 12, 24] {
            let mut conn = test_client(Instant::now());
            let mut vn = version_negotiation_packet(&[1, 2, 3, 4, 5, 6, 7, 8], &[9u8; 8], &[0xff00_0020]);
            vn.truncate(len.min(vn.len() - 1));
            conn.handle_packet(Instant::now(), &vn);
            assert!(lost_with(&mut conn).is_none(), "len {len}");
        }
    }

    #[test]
    fn poll_transmit_gso_coalesces_padded_data_packets() {
        let now = Instant::now();
        let mut conn = test_client(now);
        conn.send_datagram(Bytes::from_static(b"aaa")).unwrap();
        conn.send_datagram(Bytes::from_static(b"bbb")).unwrap();

        let mut buf = Vec::new();
        let tx = conn
            .poll_transmit_gso(now, 16, &mut buf)
            .expect("gso transmit");
        let seg = tx.segment_size.expect("multi-segment GSO");
        assert_eq!(seg, 1200);
        assert_eq!(buf.len(), 2 * seg);
        assert_eq!(tx.size, buf.len());

        // Single leftover should not advertise GSO.
        assert!(conn.poll_transmit_gso(now, 16, &mut buf).is_none());
    }

    #[test]
    fn poll_transmit_keeps_segment_size_none() {
        let now = Instant::now();
        let mut conn = test_client(now);
        conn.send_datagram(Bytes::from_static(b"x")).unwrap();
        let mut buf = Vec::new();
        let tx = conn.poll_transmit(now, &mut buf).expect("one datagram");
        assert!(tx.segment_size.is_none());
        assert_eq!(tx.size, buf.len());
        assert!(buf.len() < 1200); // not GSO-padded
    }

    #[test]
    fn reject_requeues_0rtt_stream_for_1rtt_retransmit() {
        let now = Instant::now();
        let mut conn = test_client(now);
        conn.early_secret = Some([0x42; 32]);
        let id = conn.open_bi().expect("stream");
        conn.pending_0rtt_retransmit
            .push((id, 0, Bytes::from_static(b"early-payload"), false));
        let events = crate::transport::tls_bridge::TlsBridgeEvents {
            early_data_accepted: Some(false),
            ..Default::default()
        };
        conn.apply_tls_events(events);
        assert!(conn.early_secret.is_none());
        assert!(conn.pending_0rtt_retransmit.is_empty());
        let st = conn.streams.get(&id).unwrap();
        assert_eq!(st.send.retransmit.len(), 1);
        assert_eq!(&st.send.retransmit[0].1[..], b"early-payload");
    }

    /// Drain `poll_transmit`, returning every datagram length.
    fn drain_lens(conn: &mut Connection, now: Instant) -> Vec<usize> {
        let mut lens = Vec::new();
        let mut buf = Vec::new();
        while let Some(tx) = conn.poll_transmit(now, &mut buf) {
            lens.push(tx.size);
        }
        lens
    }

    fn assert_within_max_datagram(lens: &[usize]) {
        assert!(lens.len() > 4, "expected several datagrams, got {}", lens.len());
        let max = *lens.iter().max().unwrap();
        assert!(max <= 1200, "datagram of {max} bytes exceeds 1200");
        // Chunks should still be sized to fill the budget, not shrink far below it.
        assert!(max >= 1150, "largest datagram only {max} bytes");
    }

    #[test]
    fn stream_datagrams_do_not_exceed_max_datagram_size() {
        let now = Instant::now();
        let mut conn = test_client(now);
        let id = conn.open_bi().expect("stream");
        conn.streams.get_mut(&id).unwrap().send.max_data = u64::MAX;
        conn.write_stream(id, &vec![0xab; 200_000]).unwrap();
        assert_within_max_datagram(&drain_lens(&mut conn, now));
    }

    #[test]
    fn stream_datagrams_fit_with_longest_cid_and_long_pn() {
        let now = Instant::now();
        let mut conn = test_client_with_dcid_len(now, 20);
        conn.spaces[2].next_pn = 1 << 30;
        let id = conn.open_bi().expect("stream");
        {
            let send = &mut conn.streams.get_mut(&id).unwrap().send;
            send.max_data = u64::MAX;
            send.offset = 1 << 40;
        }
        conn.write_stream(id, &vec![0xab; 200_000]).unwrap();
        assert_within_max_datagram(&drain_lens(&mut conn, now));
    }

    #[test]
    fn retransmitted_stream_chunk_fits_max_datagram_size() {
        let now = Instant::now();
        let mut conn = test_client(now);
        let id = conn.open_bi().expect("stream");
        conn.streams.get_mut(&id).unwrap().send.requeue(
            1 << 40,
            Bytes::from(vec![0xcd; 100_000]),
            false,
        );
        assert_within_max_datagram(&drain_lens(&mut conn, now));
    }

    #[test]
    fn gso_stream_segments_do_not_exceed_max_datagram_size() {
        let now = Instant::now();
        let mut conn = test_client(now);
        let id = conn.open_bi().expect("stream");
        conn.streams.get_mut(&id).unwrap().send.max_data = u64::MAX;
        conn.write_stream(id, &vec![0xab; 200_000]).unwrap();
        let mut buf = Vec::new();
        let tx = conn.poll_transmit_gso(now, 16, &mut buf).expect("gso");
        assert_eq!(tx.segment_size, Some(1200));
    }
}
