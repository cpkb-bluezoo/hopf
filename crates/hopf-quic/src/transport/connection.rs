// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC connection state machine (minimal echo subset).


use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hopf_core::security::SecurityInfo;
use hopf_core::tls::HandshakeConfig;

use crate::transport::frame::{parse_all, writer, Frame};
use crate::transport::packet::long_header::{self, TYPE_HANDSHAKE, TYPE_INITIAL};
use crate::transport::packet::pn;
use crate::transport::packet::protection::KeyPair;
use crate::transport::packet::short_header;
use crate::transport::packet::TransportParameters;
use crate::transport::stream::{RecvStream, SendStream, StreamReassembler};
use crate::transport::tls_bridge::{self, OutboundCrypto, TlsBridge, TlsBridgeEvents};
use crate::transport::types::{
    ConnectionError, ConnectionId, Dir, Event, Side, SpaceId, StreamEvent, StreamId, Transmit,
    VarInt, DEFAULT_IDLE_TIMEOUT, VERSION_V1,
};

/// Per-PN-space state.
struct Space {
    /// Client and server traffic secrets (when installed).
    secrets: Option<([u8; 32], [u8; 32])>,
    next_pn: u64,
    largest_received: Option<u64>,
    largest_acked: Option<u64>,
    crypto_recv: StreamReassembler,
    crypto_send_offset: u64,
    crypto_pending: VecDeque<Bytes>,
    pending_ack: HashSet<u64>,
}

impl Space {
    fn new() -> Self {
        Self {
            secrets: None,
            next_pn: 0,
            largest_received: None,
            largest_acked: None,
            crypto_recv: StreamReassembler::new(1 << 20),
            crypto_send_offset: 0,
            crypto_pending: VecDeque::new(),
            pending_ack: HashSet::new(),
        }
    }

    fn keys(&self, side: Side) -> Option<KeyPair> {
        let (c, s) = self.secrets?;
        Some(KeyPair::from_traffic_secrets(side, c, s))
    }
}

/// In-tree QUIC connection.
pub struct Connection {
    side: Side,
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
    last_activity: Instant,
    security_info: Option<SecurityInfo>,
    streams: HashMap<StreamId, StreamState>,
    next_local_bi: u64,
    next_remote_bi_expected: u64,
    peer_max_streams_bidi: u64,
    conn_max_data: u64,
    /// Token for Initial (usually empty).
    token: Vec<u8>,
    /// Short-header CID length (peer's CID length we send to).
    short_cid_len: usize,
}

struct StreamState {
    send: SendStream,
    recv: RecvStream,
    opened_event: bool,
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
    ) -> Self {
        let mut local_tp = TransportParameters::default();
        local_tp.initial_src_cid = Some(local_cid.clone());
        let mut hs = handshake;
        if hs.server_name.is_none() {
            hs.server_name = Some(server_name.to_string());
        }
        let (tls, events) = TlsBridge::start_client(hs, &local_tp);
        let mut conn = Self {
            side: Side::Client,
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
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            last_activity: now,
            security_info: None,
            streams: HashMap::new(),
            next_local_bi: 0,
            next_remote_bi_expected: 0,
            peer_max_streams_bidi: 100,
            conn_max_data: 10 * 1024 * 1024,
            token: Vec::new(),
            short_cid_len: initial_dcid.len(),
        };
        conn.spaces[0].secrets = Some(crate::transport::packet::protection::initial_secrets(
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
        client_dst_cid: ConnectionId,
        client_src_cid: ConnectionId,
    ) -> Self {
        let mut local_tp = TransportParameters::default();
        local_tp.initial_src_cid = Some(local_cid.clone());
        local_tp.original_dst_cid = Some(client_dst_cid.clone());
        let tls = TlsBridge::start_server(handshake, &local_tp);
        let mut conn = Self {
            side: Side::Server,
            remote,
            local_cid,
            rem_cid: client_src_cid,
            initial_dcid: client_dst_cid.clone(),
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
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            last_activity: now,
            security_info: None,
            streams: HashMap::new(),
            next_local_bi: 0,
            next_remote_bi_expected: 0,
            peer_max_streams_bidi: 100,
            conn_max_data: 10 * 1024 * 1024,
            token: Vec::new(),
            short_cid_len: 0, // set from peer SCID
        };
        conn.short_cid_len = conn.rem_cid.len();
        conn.spaces[0].secrets = Some(crate::transport::packet::protection::initial_secrets(
            client_dst_cid.as_slice(),
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

    /// Whether 0-RTT is available (always false for echo milestone).
    pub fn has_0rtt(&self) -> bool {
        false
    }

    /// Poll application events.
    pub fn poll(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Poll outbound datagram.
    pub fn poll_transmit(&mut self, _now: Instant, buf: &mut Vec<u8>) -> Option<Transmit> {
        self.flush_pending_packets();
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

    /// Next timeout.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.closed {
            return None;
        }
        Some(self.last_activity + self.idle_timeout)
    }

    /// Handle timeout.
    pub fn handle_timeout(&mut self, now: Instant) {
        if now >= self.last_activity + self.idle_timeout {
            self.closed = true;
            self.events
                .push_back(Event::ConnectionLost {
                    reason: ConnectionError::TimedOut,
                });
        }
    }

    /// Close the connection.
    pub fn close(&mut self, _now: Instant, error_code: VarInt, reason: Bytes) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut payload = Vec::new();
        writer::connection_close(&mut payload, error_code.0, reason.as_ref());
        self.queue_packet(SpaceId::Data, payload);
        self.flush_pending_packets();
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
            let consumed = self.handle_one_packet(rest);
            if consumed == 0 {
                break;
            }
            rest = &rest[consumed..];
        }
        self.flush_pending_packets();
    }

    fn handle_one_packet(&mut self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        if data[0] & 0x80 != 0 {
            self.handle_long_packet(data)
        } else {
            self.handle_short_packet(data)
        }
    }

    fn handle_long_packet(&mut self, data: &[u8]) -> usize {
        let Some(prefix) = long_header::parse_prefix(data) else {
            return data.len();
        };
        if prefix.version != VERSION_V1 {
            return data.len();
        }
        let space = match prefix.packet_type {
            TYPE_INITIAL => SpaceId::Initial,
            TYPE_HANDSHAKE => SpaceId::Handshake,
            _ => return data.len(),
        };
        let packet_len = prefix.pn_offset + prefix.length as usize;
        if data.len() < packet_len {
            return data.len();
        }
        let mut packet = data[..packet_len].to_vec();
        let keys = match self.space(space).keys(self.side) {
            Some(k) => k,
            None => return packet_len,
        };
        keys.remote.protect_header(prefix.pn_offset, &mut packet, false);
        let pn_len = (packet[0] & 0x03) as usize + 1;
        if prefix.pn_offset + pn_len > packet.len() {
            return packet_len;
        }
        let truncated = pn::read_truncated(&packet[prefix.pn_offset..prefix.pn_offset + pn_len]);
        let full_pn = pn::decode(self.space(space).largest_received, truncated, pn_len);
        let header_len = prefix.pn_offset + pn_len;
        let mut payload = packet[header_len..].to_vec();
        let header = &packet[..header_len];
        let Ok(plain_len) = keys.remote.decrypt(full_pn, header, &mut payload) else {
            return packet_len;
        };
        payload.truncate(plain_len);
        // Learn peer CID before queuing ACKs so outbound DCID is correct.
        if self.side == Side::Client && !prefix.src_cid.is_empty() {
            self.rem_cid = prefix.src_cid;
            self.short_cid_len = self.rem_cid.len();
        }
        self.on_decrypted(space, full_pn, &payload);
        packet_len
    }

    fn handle_short_packet(&mut self, data: &[u8]) -> usize {
        let cid_len = self.local_cid.len();
        let Some(prefix) = short_header::parse_prefix(data, cid_len) else {
            return data.len();
        };
        let keys = match self.space(SpaceId::Data).keys(self.side) {
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
        self.on_decrypted(SpaceId::Data, full_pn, &payload);
        data.len()
    }

    fn on_decrypted(&mut self, space: SpaceId, pn: u64, payload: &[u8]) {
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
            self.handle_frame(space, frame);
        }
        if ack_eliciting {
            self.queue_acks(space);
        }
    }

    fn handle_frame(&mut self, space: SpaceId, frame: Frame) {
        match frame {
            Frame::Padding { .. } | Frame::Ping => {}
            Frame::Ack { ranges, .. } => {
                if let Some((_, high)) = ranges.first() {
                    let sp = self.space_mut(space);
                    sp.largest_acked = Some(sp.largest_acked.map(|a| a.max(*high)).unwrap_or(*high));
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
                    }
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
                self.peer_max_streams_bidi = self.peer_max_streams_bidi.max(max);
            }
            Frame::HandshakeDone => {
                if self.side == Side::Client {
                    self.handshake_done = true;
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
        }
        if let Some((c, s)) = events.app_keys {
            self.spaces[2].secrets = Some((c, s));
        }
        if let Some(raw) = events.peer_tp {
            if let Some(tp) = TransportParameters::decode(&raw) {
                self.peer_max_streams_bidi = tp.initial_max_streams_bidi;
                self.conn_max_data = tp.initial_max_data;
                self.idle_timeout = Duration::from_millis(tp.max_idle_timeout.max(1));
                self.peer_tp = Some(tp);
            }
        }
        // Queue outbound CRYPTO. ServerHello stays on Initial; after handshake
        // keys are installed every subsequent server flight goes Handshake.
        // Client post-SH messages similarly move to Handshake.
        for OutboundCrypto { space, data } in events.outbound {
            let space = if self.side == Side::Server && self.spaces[1].secrets.is_some() {
                if data.first() == Some(&0x02) {
                    if let Some((sh, rest)) = tls_bridge::split_server_hello(&data) {
                        self.queue_crypto(SpaceId::Initial, sh);
                        if !rest.is_empty() {
                            self.queue_crypto(SpaceId::Handshake, rest);
                        }
                        continue;
                    }
                    SpaceId::Initial
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
        let sp = self.space_mut(space);
        sp.crypto_pending.push_back(data);
    }

    fn queue_acks(&mut self, space: SpaceId) {
        let pns: Vec<u64> = self.space(space).pending_ack.iter().copied().collect();
        if pns.is_empty() {
            return;
        }
        self.space_mut(space).pending_ack.clear();
        // One ACK per largest PN (sufficient for echo).
        let largest = pns.into_iter().max().unwrap();
        let mut payload = Vec::new();
        writer::ack_single(&mut payload, largest);
        self.queue_packet(space, payload);
    }

    fn flush_pending_packets(&mut self) {
        if self.handshake_done_pending && self.spaces[2].secrets.is_some() {
            self.handshake_done_pending = false;
            let mut payload = Vec::new();
            writer::handshake_done(&mut payload);
            self.queue_packet(SpaceId::Data, payload);
            self.handshake_done = true;
            self.maybe_establish();
        }
        // CRYPTO frames.
        for space in [SpaceId::Initial, SpaceId::Handshake, SpaceId::Data] {
            while let Some(chunk) = {
                let sp = self.space_mut(space);
                sp.crypto_pending.pop_front()
            } {
                let offset = self.space(space).crypto_send_offset;
                let mut payload = Vec::new();
                writer::crypto(&mut payload, offset, &chunk);
                self.space_mut(space).crypto_send_offset += chunk.len() as u64;
                // Initial packets must be padded to ≥1200 bytes (RFC 9000 §14.1).
                if space == SpaceId::Initial {
                    // pad after building full packet — handled in queue_packet
                    self.queue_packet_pad_initial(payload);
                } else {
                    self.queue_packet(space, payload);
                }
            }
        }
        // STREAM frames on Data.
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            while let Some((offset, data, fin)) = self
                .streams
                .get_mut(&id)
                .and_then(|st| st.send.take_chunk(1200))
            {
                let mut payload = Vec::new();
                writer::stream(&mut payload, id, offset, &data, fin);
                self.queue_packet(SpaceId::Data, payload);
                if fin {
                    self.events
                        .push_back(Event::Stream(StreamEvent::Finished { id }));
                }
            }
        }
    }

    fn queue_packet_pad_initial(&mut self, mut payload: Vec<u8>) {
        // Estimate: pad payload so final UDP datagram ≥ 1200.
        // Rough header ~ 50 bytes + tag 16.
        let header_est = 50 + 16;
        let need = 1200usize.saturating_sub(header_est + payload.len());
        let target = payload.len() + need;
        if need > 0 {
            writer::pad_to(&mut payload, target);
        }
        self.queue_packet(SpaceId::Initial, payload);
    }

    fn queue_packet(&mut self, space: SpaceId, payload_frames: Vec<u8>) {
        let keys = match self.space(space).keys(self.side) {
            Some(k) => k,
            None => {
                return;
            }
        };
        let pn = self.space(space).next_pn;
        self.space_mut(space).next_pn += 1;
        let largest_acked = self.space(space).largest_acked;
        let pn_len = pn::encoded_length(pn, largest_acked);
        let tag_len = keys.local.tag_len();
        let protected_len = payload_frames.len() + tag_len;

        let mut header = match space {
            SpaceId::Initial => long_header::build_initial(
                &self.rem_cid,
                &self.local_cid,
                &self.token,
                pn,
                pn_len,
                protected_len,
            ),
            SpaceId::Handshake => long_header::build_handshake(
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
        keys.local.encrypt(pn, &header, &mut payload);
        let mut packet = header;
        packet.append(&mut payload);
        keys.local.protect_header(pn_offset, &mut packet, true);

        let tx = Transmit {
            destination: self.remote,
            ecn: None,
            size: packet.len(),
            segment_size: None,
            src_ip: None,
        };
        self.transmits.push_back((tx, packet));
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
            },
        );
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
            },
        );
        Some(id)
    }

    /// Open a local unidirectional stream.
    pub fn open_uni(&mut self) -> Option<StreamId> {
        // Echo milestone: uni streams share the bi credit counter for simplicity.
        if self.next_local_bi >= self.peer_max_streams_bidi {
            return None;
        }
        let index = self.next_local_bi;
        self.next_local_bi += 1;
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
            },
        );
        Some(id)
    }

    /// Accept a peer-opened stream.
    pub fn accept(&mut self, dir: Dir) -> Option<StreamId> {
        if dir != Dir::Bi {
            return None;
        }
        // Find unread peer-initiated bi streams.
        let peer_side = match self.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        for (id, st) in &self.streams {
            if id.dir() == Dir::Bi && id.initiator() == peer_side && !st.opened_event {
                // already emitted Opened
            }
        }
        // Streams are created on first STREAM frame; return the lowest unread peer bi.
        let mut candidates: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(id, _)| id.dir() == Dir::Bi && id.initiator() == peer_side)
            .map(|(id, _)| *id)
            .collect();
        candidates.sort_by_key(|id| id.index());
        // Accept in order by index matching next_remote_bi_expected.
        if let Some(id) = candidates
            .into_iter()
            .find(|id| id.index() == self.next_remote_bi_expected)
        {
            self.next_remote_bi_expected += 1;
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

    /// DATAGRAM send (unsupported in echo milestone).
    pub fn send_datagram(&mut self, _payload: Bytes) -> Result<(), crate::transport::types::SendDatagramError> {
        Err(crate::transport::types::SendDatagramError::Disabled)
    }

    /// DATAGRAM recv.
    pub fn recv_datagram(&mut self) -> Option<Bytes> {
        None
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

    /// Poll transmit with unused GSO hint (compat with old driver calls).
    pub fn poll_transmit_gso(
        &mut self,
        now: Instant,
        _max_gso: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        self.poll_transmit(now, buf)
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

/// Write error.
#[derive(Debug)]
pub enum WriteError {
    /// Unknown stream.
    UnknownStream,
    /// Blocked on flow control.
    Blocked,
}
