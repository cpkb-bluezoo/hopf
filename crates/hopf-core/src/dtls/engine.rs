// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.3 record/reassembly/retransmission engine — wraps
//! [`HandshakeEngine`] in [`HandshakeMode::Dtls`] the same way
//! [`crate::tls::TlsRecordEngine`] wraps it for TCP: [`DtlsRecordEngine`]
//! owns the handshake engine plus everything genuinely DTLS-specific
//! (epoch/record framing, fragmentation, retransmission), translating
//! [`TlsEventSink`] callbacks into DTLS wire behaviour via an internal
//! bridge, sink-based like every other engine in this crate.
//!
//! Engine tests here are loopback-only. The reactor-driven UDP driver that
//! puts this engine on a real socket is [`super::driver`]; there is still no
//! external DTLS 1.3 interop peer (see the crate-level module doc and
//! `crypto-migration-plan.md` Phase 6 for what's explicitly deferred).

use std::collections::VecDeque;
use std::time::Duration;

use crate::security::SecurityInfo;
use crate::tls::{
    AlertDescription, HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, KeyUpdateDirection, QuicSecrets,
    RecordSizeLimits, Tls13Aead, TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest, VerifyResult,
};

use super::reassembly::{Reassembler, HANDSHAKE_HEADER_LEN, MAX_FRAGMENT};
use super::record::{self, PlaintextReadOutcome, ReadKeys, ReadOutcome, WriteKeys};
use super::retransmit::{RetransmitOutcome, RetransmitState};

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
/// `HandshakeType::key_update` (RFC 8446 §4.6.3).
const HANDSHAKE_KEY_UPDATE: u8 = 24;
/// Most `KeyUpdate` record numbers remembered for re-acknowledgement.
const MAX_REMEMBERED_KEY_UPDATE_ACKS: usize = 4;
const CONTENT_APPLICATION_DATA: u8 = 23;

/// Most content octets a protected record carries when no `record_size_limit`
/// (RFC 8449) applies: 2^14 (RFC 8446 §5.1).
const MAX_PROTECTED_CONTENT: usize = 16384;
/// RFC 9147 §7 — DTLS 1.3's own content type, not part of the shared TLS
/// registry the other constants above come from.
const CONTENT_ACK: u8 = 26;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Events emitted by [`DtlsRecordEngine`] — consumed by whatever owns the
/// UDP socket ([`super::driver`] on a reactor; loopback tests). Shaped like [`crate::tls::TlsRecordSink`], with two DTLS-specific
/// differences: `datagram_ready` hands over one complete outgoing UDP
/// payload rather than an appendable byte stream (UDP has no stream to
/// append to), and `arm_retransmit_timer` is new — DTLS is the first engine
/// in this crate whose record layer itself needs a timer armed, since TCP
/// has no retransmission concept at this layer and QUIC's timer wheel
/// lives entirely inside `hopf-quic`'s own connection state.
pub trait DtlsRecordSink {
    /// One complete outgoing UDP datagram.
    fn datagram_ready(&mut self, data: &[u8]);

    /// Decrypted application data.
    fn application_data(&mut self, plaintext: &[u8]);

    /// Handshake finished; `send_application_data` is now usable.
    fn handshake_complete(&mut self, info: SecurityInfo);

    /// Chain verification should run (possibly on `StorageExecutor`).
    fn verification_requested(&mut self, req: VerifyRequest);

    /// Non-fatal protocol failure.
    fn protocol_error(&mut self, err: TlsProtocolError);

    /// Peer sent a close alert.
    fn peer_closed(&mut self);

    /// Arm (`Some`) or cancel (`None`) the flight-retransmit timer. The
    /// caller owns the actual timer/reactor; when it fires, call
    /// [`DtlsRecordEngine::feed_timer`].
    fn arm_retransmit_timer(&mut self, after: Option<Duration>);
}

/// No-op sink for tests.
#[derive(Debug, Default)]
pub struct NopDtlsRecordSink;

impl DtlsRecordSink for NopDtlsRecordSink {
    fn datagram_ready(&mut self, _data: &[u8]) {}
    fn application_data(&mut self, _plaintext: &[u8]) {}
    fn handshake_complete(&mut self, _info: SecurityInfo) {}
    fn verification_requested(&mut self, _req: VerifyRequest) {}
    fn protocol_error(&mut self, _err: TlsProtocolError) {}
    fn peer_closed(&mut self) {}
    fn arm_retransmit_timer(&mut self, _after: Option<Duration>) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Epoch {
    Plaintext,
    Handshake,
    Application,
}

impl Epoch {
    /// RFC 9147's fixed epoch numbering — 1 (0-RTT) is skipped, unimplemented.
    fn wire_value(self) -> u64 {
        match self {
            Epoch::Plaintext => 0,
            Epoch::Handshake => 2,
            Epoch::Application => 3,
        }
    }
}

/// A `KeyUpdate` we sent whose new write key is not yet in use — RFC 9147
/// §8: the sender must keep protecting under the old epoch until the peer
/// has acknowledged the message.
struct PendingWrite {
    keys: WriteKeys,
    /// `RecordNumber` of the record that carried our `KeyUpdate`.
    record_number: (u64, u64),
}

struct RecordState {
    role: HandshakeRole,
    epoch: Epoch,
    plaintext_write_seq: u64,
    write: Option<WriteKeys>,
    read: Option<ReadKeys>,
    next_write: Option<WriteKeys>,
    next_read: Option<ReadKeys>,
    /// See [`crate::tls::record`]'s (private) `RecordState::alert_sent` —
    /// same purpose: at most one fatal alert per connection, none sent in
    /// reply to a peer's own alert.
    alert_sent: bool,
    /// The peer's `record_size_limit` (RFC 8449), once negotiated: the most
    /// `TLSInnerPlaintext` octets one protected record we send may carry.
    send_limit: Option<usize>,
    /// Our own advertised `record_size_limit`, enforced on every protected
    /// record we receive once negotiated.
    recv_limit: Option<usize>,
    /// Read keys of the epoch before the latest `KeyUpdate`, kept so records
    /// reordered behind the update still decrypt (RFC 9147 §5.8.4); dropped
    /// once a record arrives under the new epoch.
    prev_read: Option<ReadKeys>,
    /// Our unacknowledged `KeyUpdate`s, oldest first, each with the write
    /// key that replaces the current one once acknowledged.
    pending_writes: VecDeque<PendingWrite>,
    /// A confidentiality-limit rotation has been requested of the peer and
    /// their `KeyUpdate` has not yet installed a fresh read key.
    read_update_requested: bool,
    /// `RecordNumber` of the record currently being dispatched.
    current_record: (u64, u64),
    /// Records carrying a peer `KeyUpdate` received during the current
    /// datagram, awaiting an explicit ACK (RFC 9147 §7).
    key_update_acks_due: Vec<(u64, u64)>,
    /// The most recent peer `KeyUpdate` records already acknowledged, so a
    /// retransmission (their ACK was lost) can be acknowledged again.
    acked_key_updates: Vec<(u64, u64)>,
}

impl RecordState {
    fn new(role: HandshakeRole) -> Self {
        Self {
            role,
            epoch: Epoch::Plaintext,
            plaintext_write_seq: 0,
            write: None,
            read: None,
            next_write: None,
            next_read: None,
            alert_sent: false,
            send_limit: None,
            recv_limit: None,
            prev_read: None,
            pending_writes: VecDeque::new(),
            read_update_requested: false,
            current_record: (0, 0),
            key_update_acks_due: Vec::new(),
            acked_key_updates: Vec::new(),
        }
    }

    /// The peer's `KeyUpdate` (RFC 9147 §5.8.4): switch to the next epoch's
    /// read key immediately, keeping the old one for reordered records.
    fn rotate_read_key(&mut self, aead: Tls13Aead, secret: &[u8; 32]) {
        let old = self.read.take().expect("read keys exist once application traffic is established");
        self.read = Some(ReadKeys::from_secret(aead, secret, old.epoch() + 1));
        self.prev_read = Some(old);
        self.read_update_requested = false;
    }

    /// Our own `KeyUpdate` was just written: derive the next epoch's write
    /// key but hold it until the peer acknowledges that record.
    fn queue_write_key(&mut self, aead: Tls13Aead, secret: &[u8; 32]) {
        let current = self.write.as_ref().expect("write keys exist once application traffic is established");
        let next_epoch = self.pending_writes.back().map_or(current.epoch(), |p| p.keys.epoch()) + 1;
        self.pending_writes.push_back(PendingWrite {
            keys: WriteKeys::from_secret(aead, secret, next_epoch),
            record_number: current.last_record_number(),
        });
    }

    /// Most content octets one protected record may carry: the peer's limit
    /// less the inner content-type octet (no padding is ever added), or the
    /// protocol maximum when nothing was negotiated.
    fn max_protected_content(&self) -> usize {
        match self.send_limit {
            Some(limit) => limit.saturating_sub(1).clamp(1, MAX_PROTECTED_CONTENT),
            None => MAX_PROTECTED_CONTENT,
        }
    }

    /// Most handshake-message body octets one fragment may carry, given
    /// that its record also holds the 12-octet DTLS handshake header.
    /// Records sent in the clear are not subject to the limit.
    fn max_fragment_body(&self) -> usize {
        match self.epoch {
            Epoch::Plaintext => MAX_FRAGMENT,
            Epoch::Handshake | Epoch::Application => self
                .max_protected_content()
                .saturating_sub(HANDSHAKE_HEADER_LEN)
                .clamp(1, MAX_FRAGMENT),
        }
    }

    fn install_handshake_keys(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        let (w, r) = match self.role {
            HandshakeRole::Client => (client, server),
            HandshakeRole::Server => (server, client),
        };
        let epoch = Epoch::Handshake.wire_value();
        self.write = Some(WriteKeys::from_secret(aead, &w, epoch));
        self.read = Some(ReadKeys::from_secret(aead, &r, epoch));
        self.epoch = Epoch::Handshake;
    }

    fn stage_application_keys(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        let (w, r) = match self.role {
            HandshakeRole::Client => (client, server),
            HandshakeRole::Server => (server, client),
        };
        let epoch = Epoch::Application.wire_value();
        self.next_write = Some(WriteKeys::from_secret(aead, &w, epoch));
        self.next_read = Some(ReadKeys::from_secret(aead, &r, epoch));
    }

    fn activate_application_keys(&mut self) {
        if let (Some(w), Some(r)) = (self.next_write.take(), self.next_read.take()) {
            self.write = Some(w);
            self.read = Some(r);
            self.epoch = Epoch::Application;
        }
    }
}

fn write_records(state: &mut RecordState, content_type: u8, fragments: &[Vec<u8>], out: &mut Vec<u8>) {
    for frag in fragments {
        match state.epoch {
            Epoch::Plaintext => record::write_plaintext_record(content_type, &mut state.plaintext_write_seq, frag, out),
            Epoch::Handshake | Epoch::Application => {
                let write = state
                    .write
                    .as_mut()
                    .expect("write keys installed once epoch leaves Plaintext");
                record::write_record(write, content_type, frag, out);
            }
        }
    }
}

/// RFC 9147 §7's `ACK` body: `struct { RecordNumber record_numbers<0..2^16-1>; } ACK;`
/// with `RecordNumber { uint64 epoch; uint64 sequence_number; }`.
fn encode_ack(record_numbers: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 16 * record_numbers.len());
    out.extend_from_slice(&((16 * record_numbers.len()) as u16).to_be_bytes());
    for (epoch, seq) in record_numbers {
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
    }
    out
}

/// Decode an `ACK` body's record numbers; a truncated trailing entry is ignored.
fn decode_ack(body: &[u8]) -> Vec<(u64, u64)> {
    let Some((len, entries)) = body.split_first_chunk::<2>() else {
        return Vec::new();
    };
    let len = (u16::from_be_bytes(*len) as usize).min(entries.len());
    entries[..len]
        .chunks_exact(16)
        .map(|e| {
            (
                u64::from_be_bytes(e[..8].try_into().expect("8 bytes")),
                u64::from_be_bytes(e[8..].try_into().expect("8 bytes")),
            )
        })
        .collect()
}

/// Send a fatal alert for a violation *this side* detected (RFC 8446
/// §6.2, via RFC 9147 §5.2's DTLS Alert content type) — at most once per
/// connection, as its own standalone datagram.
fn send_fatal_alert<S: DtlsRecordSink + ?Sized>(state: &mut RecordState, alert: AlertDescription, sink: &mut S) {
    if state.alert_sent {
        return;
    }
    state.alert_sent = true;
    let mut out = Vec::new();
    write_records(state, CONTENT_ALERT, &[vec![ALERT_LEVEL_FATAL, alert.code()]], &mut out);
    sink.datagram_ready(&out);
}

/// Bridges [`HandshakeEngine`]'s handshake-message events onto DTLS
/// fragmentation + record framing, accumulating this stimulus's outbound
/// bytes into `flight` — mirrors [`crate::tls::record`]'s `InnerSink`.
struct InnerSink<'a> {
    state: &'a mut RecordState,
    reassembler: &'a mut Reassembler,
    flight: &'a mut Vec<u8>,
    events: &'a mut EngineEvents,
}

/// Outcomes from [`HandshakeEngine`] that [`DtlsRecordEngine`] needs after
/// the fact but that don't have a natural home mid-callback (e.g.
/// `handshake_complete`'s `SecurityInfo`, deferred until the caller's own
/// `DtlsRecordSink` is back in scope — `InnerSink` doesn't hold one
/// directly so `DtlsRecordEngine`'s own methods can borrow `sink` mutably
/// for the outer calls too).
#[derive(Default)]
struct EngineEvents {
    complete: Option<SecurityInfo>,
    verify: Vec<VerifyRequest>,
    errors: Vec<TlsProtocolError>,
    peer_closed: bool,
}

impl TlsEventSink for InnerSink<'_> {
    fn handshake_data_ready(&mut self, data: &[u8]) {
        let mut frags = Vec::new();
        self.reassembler.fragment_with_max(data, &mut frags, self.state.max_fragment_body());
        write_records(self.state, CONTENT_HANDSHAKE, &frags, self.flight);
    }

    fn handshake_complete(&mut self, info: SecurityInfo, _quic_secrets: Option<QuicSecrets>) {
        self.state.activate_application_keys();
        self.events.complete = Some(info);
    }

    fn verification_requested(&mut self, req: VerifyRequest) {
        self.events.verify.push(req);
    }

    fn quic_handshake_keys_ready(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        self.state.install_handshake_keys(aead, client, server);
    }

    fn application_traffic_keys_ready(&mut self, aead: Tls13Aead, client: [u8; 32], server: [u8; 32]) {
        self.state.stage_application_keys(aead, client, server);
    }

    fn record_size_limit_negotiated(&mut self, limits: RecordSizeLimits) {
        self.state.send_limit = Some(limits.send as usize);
        self.state.recv_limit = Some(limits.receive as usize);
    }

    fn application_traffic_key_updated(&mut self, aead: Tls13Aead, direction: KeyUpdateDirection, secret: [u8; 32]) {
        match direction {
            KeyUpdateDirection::Read => self.state.rotate_read_key(aead, &secret),
            KeyUpdateDirection::Write => self.state.queue_write_key(aead, &secret),
        }
    }

    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.events.errors.push(err);
    }

    fn timeout(&mut self, _kind: TlsTimerKind) {}

    fn peer_closed(&mut self) {
        self.events.peer_closed = true;
    }
}

/// Reactive DTLS 1.3 engine — wraps [`HandshakeEngine`] in
/// [`HandshakeMode::Dtls`] with record framing, fragmentation/reassembly,
/// and flight-retransmission.
pub struct DtlsRecordEngine {
    engine: HandshakeEngine,
    state: RecordState,
    reassembler: Reassembler,
    retransmit: RetransmitState,
    failed: bool,
}

impl DtlsRecordEngine {
    /// Create the engine; `config.mode` is forced to [`HandshakeMode::Dtls`].
    pub fn new(mut config: HandshakeConfig) -> Self {
        config.mode = HandshakeMode::Dtls;
        let role = config.role;
        Self {
            engine: HandshakeEngine::new(config),
            state: RecordState::new(role),
            reassembler: Reassembler::new(),
            retransmit: RetransmitState::new(),
            failed: false,
        }
    }

    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        let mut flight = Vec::new();
        let mut events = EngineEvents::default();
        {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight: &mut flight,
                events: &mut events,
            };
            self.engine.start(&mut inner);
        }
        self.dispatch_events(events, sink);
        self.flush_flight(flight, sink);
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        self.engine.is_complete()
    }

    /// The `record_size_limit` (RFC 8449) limits in force, once both sides
    /// have sent the extension; `None` before that or if either omitted it.
    pub fn record_size_limits(&self) -> Option<RecordSizeLimits> {
        self.engine.record_size_limits()
    }

    /// The most application-data octets one [`Self::send_application_data`]
    /// call may carry: the peer's `record_size_limit` less the content-type
    /// octet when negotiated, otherwise the protocol maximum (16384). Larger
    /// datagrams are refused, not split.
    pub fn max_application_data(&self) -> usize {
        self.state.max_protected_content()
    }

    /// Consume one received UDP datagram — any number of coalesced records.
    pub fn feed_datagram<S: DtlsRecordSink + ?Sized>(&mut self, input: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        let was_complete = self.engine.is_complete();
        let had_pending_key_update = !self.state.pending_writes.is_empty();
        let mut rotate_read_key = false;
        let mut reack_key_updates = false;
        let mut flight = Vec::new();
        let mut last_handshake_record: Option<(u64, u64)> = None;
        let mut pos = 0usize;
        while pos < input.len() {
            let remaining = &input[pos..];
            if remaining.is_empty() {
                break;
            }
            let is_plaintext = remaining[0] & 0b1110_0000 == 0;
            if is_plaintext {
                match record::read_plaintext_record(remaining) {
                    PlaintextReadOutcome::Incomplete => break,
                    PlaintextReadOutcome::Invalid | PlaintextReadOutcome::NotPlaintext => {
                        self.fail(sink, AlertDescription::DecodeError, "malformed DTLS plaintext record");
                        return;
                    }
                    PlaintextReadOutcome::Record {
                        content_type,
                        payload,
                        consumed,
                    } => {
                        pos += consumed;
                        if !self.dispatch_record(content_type, payload, &mut flight, sink) {
                            break;
                        }
                    }
                }
            } else {
                let Some(read) = self.state.read.as_mut() else {
                    self.fail(sink, AlertDescription::UnexpectedMessage, "encrypted DTLS record before keys installed");
                    return;
                };
                // A record for the epoch before the latest `KeyUpdate` is
                // read with the retained old keys (RFC 9147 §5.8.4).
                let (outcome, from_prev) = match record::read_record(read, remaining) {
                    ReadOutcome::WrongEpoch { consumed } => match self.state.prev_read.as_mut() {
                        Some(prev) => (record::read_record(prev, remaining), true),
                        None => (ReadOutcome::WrongEpoch { consumed }, false),
                    },
                    other => (other, false),
                };
                match outcome {
                    ReadOutcome::Incomplete => break,
                    ReadOutcome::Invalid => {
                        self.fail(sink, AlertDescription::BadRecordMac, "malformed or unauthenticated DTLS record");
                        return;
                    }
                    ReadOutcome::WrongEpoch { consumed } | ReadOutcome::Replay { consumed } => {
                        // A stray old/duplicate/not-yet-activated-epoch
                        // record isn't fatal — RFC 9147 §4.5.1 says to drop
                        // silently. Skip past it and keep parsing the rest
                        // of this datagram.
                        pos += consumed;
                        // A replay under the previous epoch may be a
                        // retransmitted `KeyUpdate` whose ACK was lost.
                        reack_key_updates |= from_prev;
                    }
                    ReadOutcome::Record {
                        inner_content_type,
                        plaintext,
                        consumed,
                        record_number,
                        inner_len,
                    } => {
                        pos += consumed;
                        // RFC 8449 §4: a record over our advertised limit is a
                        // fatal record_overflow. (DTLS may alternatively drop
                        // it, but this one authenticated, so the peer is at
                        // fault rather than the network.)
                        if self.state.recv_limit.is_some_and(|limit| inner_len > limit) {
                            self.fail(sink, AlertDescription::RecordOverflow, "record exceeds the advertised record_size_limit");
                            return;
                        }
                        if inner_content_type == CONTENT_HANDSHAKE {
                            last_handshake_record = Some(record_number);
                        }
                        if !from_prev {
                            // First record under the new epoch: the old keys
                            // have served their reordering window.
                            self.state.prev_read = None;
                        }
                        self.state.current_record = record_number;
                        let keep_going = self.dispatch_record(inner_content_type, plaintext, &mut flight, sink);
                        // RFC 8446 §5.5 / RFC 9325 §4.4: our read key has
                        // protected close to its AES-GCM confidentiality
                        // limit's worth of records — ask the peer to rotate
                        // theirs. Checked after dispatch so a `KeyUpdate`
                        // that has just installed a fresh read key is not
                        // itself answered with another request.
                        if !from_prev
                            && !self.state.read_update_requested
                            && self.state.read.as_ref().is_some_and(ReadKeys::over_confidentiality_limit)
                        {
                            self.state.read_update_requested = true;
                            rotate_read_key = true;
                        }
                        if !keep_going {
                            break;
                        }
                    }
                }
            }
        }
        // RFC 9147 §7: a receiver that has nothing else queued to send
        // (piggybacking the acknowledgment implicitly) MUST send an
        // explicit ACK for a handshake message it just processed — proven
        // necessary for real interop (confirmed: wolfSSL's client
        // retransmits its Finished indefinitely, never proceeding to
        // application data, without this). Scoped narrowly to the one
        // case that actually blocks a handshake from completing usefully
        // — acknowledging whatever handshake message completed our own
        // side — not general-purpose ACK generation for every handshake
        // message or reception-informed retransmission tuning.
        if !was_complete && self.engine.is_complete() && flight.is_empty() {
            if let Some(record_number) = last_handshake_record {
                // Its own datagram, not part of a retransmittable flight:
                // an ACK is never itself retransmitted.
                let mut ack = Vec::new();
                write_records(&mut self.state, CONTENT_ACK, &[encode_ack(&[record_number])], &mut ack);
                sink.datagram_ready(&ack);
            }
        }
        if !was_complete && self.engine.is_complete() && self.state.role == HandshakeRole::Server {
            // The client's Finished acknowledges the server's whole flight
            // (RFC 9147 §5.8.1): nothing of it is left to retransmit.
            self.retransmit.on_progress();
            sink.arm_retransmit_timer(None);
        }
        if had_pending_key_update {
            // Both our unacknowledged `KeyUpdate` and a reciprocal one that
            // has just been written must stay retransmittable.
            self.flush_appended_flight(flight, sink);
        } else {
            self.flush_flight(flight, sink);
        }
        self.send_key_update_acks(reack_key_updates, sink);
        if rotate_read_key && !self.failed && !self.request_key_update(sink, true) {
            // Refused (one of ours is still unacknowledged): try again on a
            // later record.
            self.state.read_update_requested = false;
        }
    }

    /// The reactor's armed retransmit timer fired.
    pub fn feed_timer<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        if self.failed {
            return;
        }
        match self.retransmit.on_timer_fired() {
            None => {}
            Some(RetransmitOutcome::Resend(bytes)) => {
                sink.datagram_ready(&bytes);
                sink.arm_retransmit_timer(self.retransmit.current_timeout());
            }
            Some(RetransmitOutcome::GiveUp) if self.engine.is_complete() && self.state.pending_writes.is_empty() => {
                // Only the last handshake flight (or a post-handshake ticket)
                // was never acknowledged; the connection itself is healthy,
                // so stop retransmitting rather than fail it.
                sink.arm_retransmit_timer(None);
            }
            Some(RetransmitOutcome::GiveUp) => {
                self.fail(sink, AlertDescription::HandshakeFailure, "DTLS handshake timed out (retransmit limit exceeded)");
            }
        }
    }

    /// Encrypt and frame application data. Only valid once [`Self::is_complete`].
    pub fn send_application_data<S: DtlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        if self.state.epoch != Epoch::Application {
            sink.protocol_error(TlsProtocolError::new(
                AlertDescription::InternalError,
                "application data sent before handshake completed",
            ));
            return;
        }
        // One call is one datagram, and its record must respect the peer's
        // `record_size_limit` (RFC 8449). Splitting it would silently break
        // the datagram boundary the caller relies on, so it is refused instead.
        if plaintext.len() > self.state.max_protected_content() {
            sink.protocol_error(TlsProtocolError::new(
                AlertDescription::InternalError,
                "application datagram exceeds the peer's record_size_limit",
            ));
            return;
        }
        let mut out = Vec::new();
        write_records(&mut self.state, CONTENT_APPLICATION_DATA, &[plaintext.to_vec()], &mut out);
        sink.datagram_ready(&out);
        // RFC 8446 §5.5 / RFC 9325 §4.4: retire our write key before it
        // exceeds the AES-GCM confidentiality limit. The new key only takes
        // over once the peer acknowledges the `KeyUpdate` (RFC 9147 §8), so
        // records keep using the old key until the ACK arrives; a peer that
        // never acknowledges ends in the retransmit budget failing the
        // connection.
        if self.state.write.as_ref().is_some_and(WriteKeys::over_confidentiality_limit) {
            self.request_key_update(sink, false);
        }
    }

    /// Rotate this connection's own application traffic key forward (RFC
    /// 9147 §5.8.4), optionally asking the peer to reciprocate. The epoch
    /// increments, but records keep going out under the old key until the
    /// peer acknowledges the `KeyUpdate`. Returns `false` with no effect if
    /// the handshake has not completed or an earlier `KeyUpdate` of ours is
    /// still unacknowledged (only one may be outstanding).
    pub fn request_key_update<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S, request_peer_update: bool) -> bool {
        if self.failed || self.state.epoch != Epoch::Application || !self.state.pending_writes.is_empty() {
            return false;
        }
        let mut flight = Vec::new();
        let mut events = EngineEvents::default();
        let sent = {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight: &mut flight,
                events: &mut events,
            };
            self.engine.request_key_update(&mut inner, request_peer_update)
        };
        self.dispatch_events(events, sink);
        self.flush_flight(flight, sink);
        sent
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: DtlsRecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        if self.failed {
            return;
        }
        let mut flight = Vec::new();
        let mut events = EngineEvents::default();
        {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight: &mut flight,
                events: &mut events,
            };
            self.engine.feed_verification_result(result, &mut inner);
        }
        self.dispatch_events(events, sink);
        self.flush_flight(flight, sink);
    }

    /// Send a `close_notify` alert under the current epoch. Not itself
    /// retransmitted (this MVP doesn't retry the close handshake).
    pub fn send_close_notify<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        if self.failed {
            return;
        }
        let mut out = Vec::new();
        let payload = vec![ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY];
        write_records(&mut self.state, CONTENT_ALERT, &[payload], &mut out);
        sink.datagram_ready(&out);
        self.retransmit.on_progress();
        sink.arm_retransmit_timer(None);
    }

    fn dispatch_record<S: DtlsRecordSink + ?Sized>(
        &mut self,
        content_type: u8,
        payload: Vec<u8>,
        flight: &mut Vec<u8>,
        sink: &mut S,
    ) -> bool {
        match content_type {
            CONTENT_CHANGE_CIPHER_SPEC => true,
            CONTENT_ALERT => {
                if payload.len() != 2 {
                    self.fail(sink, AlertDescription::DecodeError, "malformed alert record");
                    return false;
                }
                if payload[1] == ALERT_CLOSE_NOTIFY {
                    self.failed = true;
                    self.state.alert_sent = true; // no close_notify echo needed
                    sink.arm_retransmit_timer(None);
                    sink.peer_closed();
                } else {
                    // Relay the peer's own alert; don't send one back.
                    let level = if payload[0] == ALERT_LEVEL_FATAL { "fatal" } else { "warning" };
                    self.failed = true;
                    self.state.alert_sent = true;
                    sink.arm_retransmit_timer(None);
                    sink.protocol_error(TlsProtocolError::new(
                        AlertDescription::from_code(payload[1]),
                        format!("peer sent {level} alert {}", payload[1]),
                    ));
                }
                false
            }
            CONTENT_HANDSHAKE => {
                let messages = self.reassembler.receive_fragment(&payload);
                if messages.iter().any(|m| m.first() == Some(&HANDSHAKE_KEY_UPDATE)) {
                    self.state.key_update_acks_due.push(self.state.current_record);
                }
                let mut events = EngineEvents::default();
                {
                    let mut inner = InnerSink {
                        state: &mut self.state,
                        reassembler: &mut self.reassembler,
                        flight,
                        events: &mut events,
                    };
                    for msg in &messages {
                        let mut slice = msg.as_slice();
                        self.engine.feed_handshake_data(&mut slice, &mut inner);
                    }
                }
                self.dispatch_events(events, sink);
                true
            }
            CONTENT_APPLICATION_DATA => {
                if !self.engine.is_complete() {
                    self.fail(sink, AlertDescription::UnexpectedMessage, "application data before handshake completed");
                    return false;
                }
                sink.application_data(&payload);
                true
            }
            CONTENT_ACK => {
                // RFC 9147 §7 `ACK` — real peers (confirmed: wolfSSL) send
                // these unprompted to acknowledge received flights/messages.
                // Not generating our own acks or using received ones to
                // inform retransmission yet (a real, scoped-out efficiency
                // gap — see the module doc); recognizing and discarding one
                // is still required for basic interop, since treating its
                // mere arrival as a fatal unknown-content-type error would
                // break every real handshake against an ack-sending peer.
                // The one use made of them is releasing a held `KeyUpdate`
                // write key (RFC 9147 §8).
                self.on_ack(&payload, sink);
                true
            }
            _ => {
                self.fail(sink, AlertDescription::UnexpectedMessage, "unknown DTLS record content type");
                false
            }
        }
    }

    /// An `ACK` arrived: every held `KeyUpdate` write key whose message it
    /// acknowledges (in order) becomes the write key (RFC 9147 §8).
    fn on_ack<S: DtlsRecordSink + ?Sized>(&mut self, body: &[u8], sink: &mut S) {
        if self.state.pending_writes.is_empty() {
            // No `KeyUpdate` outstanding: an ACK after the handshake
            // completed acknowledges the client's final flight (RFC 9147
            // §5.8.1), so stop retransmitting it.
            if self.engine.is_complete() {
                self.retransmit.on_progress();
                sink.arm_retransmit_timer(None);
            }
            return;
        }
        let acked = decode_ack(body);
        while self.state.pending_writes.front().is_some_and(|p| acked.contains(&p.record_number)) {
            let pending = self.state.pending_writes.pop_front().expect("front checked above");
            self.state.write = Some(pending.keys);
        }
        if self.state.pending_writes.is_empty() {
            self.retransmit.on_progress();
            sink.arm_retransmit_timer(None);
        }
    }

    /// Acknowledge peer `KeyUpdate`s received in the datagram just processed
    /// (RFC 9147 §7), or, when `again`, the ones already acknowledged — their
    /// retransmission means our ACK was lost. Sent as its own datagram, not
    /// as a retransmittable flight: an ACK is never itself retransmitted.
    fn send_key_update_acks<S: DtlsRecordSink + ?Sized>(&mut self, again: bool, sink: &mut S) {
        if self.failed {
            return;
        }
        let mut records = std::mem::take(&mut self.state.key_update_acks_due);
        if again {
            records.extend_from_slice(&self.state.acked_key_updates);
        }
        if records.is_empty() {
            return;
        }
        let mut out = Vec::new();
        write_records(&mut self.state, CONTENT_ACK, &[encode_ack(&records)], &mut out);
        sink.datagram_ready(&out);
        for record in records {
            if !self.state.acked_key_updates.contains(&record) {
                if self.state.acked_key_updates.len() == MAX_REMEMBERED_KEY_UPDATE_ACKS {
                    self.state.acked_key_updates.remove(0);
                }
                self.state.acked_key_updates.push(record);
            }
        }
    }

    fn dispatch_events<S: DtlsRecordSink + ?Sized>(&mut self, events: EngineEvents, sink: &mut S) {
        for req in events.verify {
            sink.verification_requested(req);
        }
        for err in events.errors {
            self.failed = true;
            sink.arm_retransmit_timer(None);
            send_fatal_alert(&mut self.state, err.alert, sink);
            sink.protocol_error(err);
        }
        if events.peer_closed {
            self.failed = true;
            sink.arm_retransmit_timer(None);
            sink.peer_closed();
        }
        if let Some(info) = events.complete {
            sink.handshake_complete(info);
        }
    }

    fn flush_flight<S: DtlsRecordSink + ?Sized>(&mut self, flight: Vec<u8>, sink: &mut S) {
        if self.failed || flight.is_empty() {
            return;
        }
        sink.datagram_ready(&flight);
        self.retransmit.on_flight_sent(flight);
        sink.arm_retransmit_timer(self.retransmit.current_timeout());
    }

    /// [`Self::flush_flight`] for a flight sent while an earlier one is still
    /// awaiting acknowledgement and must remain retransmittable too.
    fn flush_appended_flight<S: DtlsRecordSink + ?Sized>(&mut self, flight: Vec<u8>, sink: &mut S) {
        if self.failed || flight.is_empty() {
            return;
        }
        sink.datagram_ready(&flight);
        self.retransmit.append_flight(&flight);
        sink.arm_retransmit_timer(self.retransmit.current_timeout());
    }

    fn fail<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S, alert: AlertDescription, msg: &str) {
        if !self.failed {
            self.failed = true;
            sink.arm_retransmit_timer(None);
            send_fatal_alert(&mut self.state, alert, sink);
            sink.protocol_error(TlsProtocolError::new(alert, msg));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::record::AES_GCM_CONFIDENTIALITY_LIMIT;
    use crate::crypto::kx_policy::KxPolicy;
    use crate::crypto::trust::TrustStore;
    use crate::tls::ServerCredentials;
    use bytes::Bytes;

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
        outbound: Vec<Vec<u8>>,
        app_data: Vec<Vec<u8>>,
        info: Option<SecurityInfo>,
        armed_timeout: Option<Duration>,
        /// Every datagram ever written, kept after `relay` drains `outbound`.
        all_written: Vec<Vec<u8>>,
    }

    impl DtlsRecordSink for RecordingSink {
        fn datagram_ready(&mut self, data: &[u8]) {
            self.events.push(format!("datagram {} bytes", data.len()));
            self.outbound.push(data.to_vec());
            self.all_written.push(data.to_vec());
        }
        fn application_data(&mut self, plaintext: &[u8]) {
            self.events.push(format!("application_data {} bytes", plaintext.len()));
            self.app_data.push(plaintext.to_vec());
        }
        fn handshake_complete(&mut self, info: SecurityInfo) {
            self.events.push("handshake_complete".into());
            self.info = Some(info);
        }
        fn verification_requested(&mut self, req: VerifyRequest) {
            self.events.push(format!("verification_requested id={}", req.id));
        }
        fn protocol_error(&mut self, err: TlsProtocolError) {
            self.events.push(format!("protocol_error: {}", err.message));
        }
        fn peer_closed(&mut self) {
            self.events.push("peer_closed".into());
        }
        fn arm_retransmit_timer(&mut self, after: Option<Duration>) {
            self.armed_timeout = after;
            self.events.push(format!("arm_timer {after:?}"));
        }
    }

    fn test_server_credentials() -> ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn configs() -> (HandshakeConfig, HandshakeConfig) {
        let creds = test_server_credentials();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let client = HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Dtls,
            alpn: vec![Bytes::from_static(b"test")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: KxPolicy::classical_only(),
            trust_store: Some(trust),
            ..Default::default()
        };
        let server = HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Dtls,
            alpn: vec![Bytes::from_static(b"test")],
            server: Some(creds),
            kx_policy: KxPolicy::classical_only(),
            ..Default::default()
        };
        (client, server)
    }

    /// Relay every datagram queued on `from`'s sink to `to_engine`, exactly
    /// as a UDP socket handing over one packet at a time would (each
    /// `feed_datagram` call is one datagram, preserving the boundary —
    /// unlike TCP's flat byte stream, DTLS records never span datagrams).
    fn relay(from: &mut RecordingSink, to_engine: &mut DtlsRecordEngine, to_sink: &mut RecordingSink) {
        for datagram in std::mem::take(&mut from.outbound) {
            to_engine.feed_datagram(&datagram, to_sink);
        }
    }

    fn run_loopback() -> (RecordingSink, RecordingSink, DtlsRecordEngine, DtlsRecordEngine) {
        let (client_cfg, server_cfg) = configs();
        let mut client = DtlsRecordEngine::new(client_cfg);
        let mut server = DtlsRecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s); // ClientHello
        relay(&mut sink_s, &mut client, &mut sink_c); // ServerHello..Finished
        relay(&mut sink_c, &mut server, &mut sink_s); // client Finished (+ maybe NST arrives later)

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        (sink_c, sink_s, client, server)
    }

    // ---- record_size_limit (RFC 8449) ----

    /// Ciphertext body length of every *protected* (unified-header) record
    /// in `datagrams`. A body is inner plaintext plus the 16-octet AEAD tag.
    fn protected_lengths(datagrams: &[Vec<u8>]) -> Vec<usize> {
        let mut out = Vec::new();
        for d in datagrams {
            let mut i = 0;
            while i < d.len() {
                if d[i] & 0b1110_0000 == 0b0010_0000 {
                    let len = u16::from_be_bytes([d[i + 3], d[i + 4]]) as usize;
                    out.push(len);
                    i += 5 + len;
                } else {
                    // Epoch-0 DTLSPlaintext: 13-octet header, length at 11..13.
                    let len = u16::from_be_bytes([d[i + 11], d[i + 12]]) as usize;
                    i += 13 + len;
                }
            }
            assert_eq!(i, d.len(), "datagram must be a whole number of records");
        }
        out
    }

    const TAG: usize = 16;

    fn dtls_with_limits(client: Option<u16>, server: Option<u16>) -> (RecordingSink, RecordingSink, DtlsRecordEngine, DtlsRecordEngine) {
        let (mut client_cfg, mut server_cfg) = configs();
        client_cfg.record_size_limit = client;
        server_cfg.record_size_limit = server;
        let mut client = DtlsRecordEngine::new(client_cfg);
        let mut server = DtlsRecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        (sink_c, sink_s, client, server)
    }

    /// DTLS 1.3 shares the engine's negotiation; this proves the record
    /// layer half over real handshakes: a Certificate that needs many
    /// fragments under a small limit still completes, and no protected
    /// record either side writes exceeds what the peer will accept.
    #[test]
    fn negotiated_limits_cap_every_protected_record_including_handshake_fragments() {
        let (client_limit, server_limit) = (100u16, 130u16);
        let (sink_c, sink_s, client, server) = dtls_with_limits(Some(client_limit), Some(server_limit));

        let server_records = protected_lengths(&sink_s.all_written);
        assert!(server_records.len() > 4, "handshake must have been fragmented: {server_records:?}");
        for len in &server_records {
            assert!(*len <= client_limit as usize + TAG, "server record {len} exceeds the client's {client_limit}");
        }
        for len in protected_lengths(&sink_c.all_written) {
            assert!(len <= server_limit as usize + TAG, "client record {len} exceeds the server's {server_limit}");
        }
        assert_eq!(
            client.record_size_limits(),
            Some(RecordSizeLimits { send: server_limit, receive: client_limit })
        );
        assert_eq!(server.record_size_limits().unwrap().send, client_limit);
    }

    #[test]
    fn application_datagrams_are_capped_and_an_oversize_one_is_refused_not_split() {
        let (mut sink_c, mut sink_s, mut client, mut server) = dtls_with_limits(Some(100), Some(130));
        // The server's limit is 130: 129 content octets + the type octet fit.
        assert_eq!(client.max_application_data(), 129);
        assert_eq!(server.max_application_data(), 99);

        client.send_application_data(&vec![5u8; 129], &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data.last().map(Vec::len), Some(129), "{:?}", sink_s.events);

        // One over: refused as a whole, never split (the boundary matters to
        // a datagram protocol), and not fatal - the connection carries on.
        let written_before = sink_c.all_written.len();
        client.send_application_data(&vec![5u8; 130], &mut sink_c);
        assert_eq!(sink_c.all_written.len(), written_before, "nothing may be sent");
        assert!(
            sink_c.events.iter().any(|e| e.starts_with("protocol_error") && e.contains("record_size_limit")),
            "{:?}",
            sink_c.events
        );
        client.send_application_data(&vec![6u8; 10], &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data.last().map(Vec::len), Some(10), "still usable afterwards");
    }

    #[test]
    fn without_the_extension_nothing_changes() {
        let (mut sink_c, mut sink_s, mut client, mut server) = dtls_with_limits(None, None);
        assert_eq!(client.record_size_limits(), None);
        assert_eq!(client.max_application_data(), 16384);
        client.send_application_data(&vec![1u8; 3000], &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data.last().map(Vec::len), Some(3000));
    }

    #[test]
    fn a_server_limit_alone_changes_nothing_without_the_client_asking() {
        let (mut sink_c, mut sink_s, mut client, mut server) = dtls_with_limits(None, Some(100));
        assert_eq!(client.record_size_limits(), None);
        client.send_application_data(&vec![1u8; 2000], &mut sink_c);
        server.send_application_data(&vec![2u8; 2000], &mut sink_s);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert_eq!(sink_s.app_data.last().map(Vec::len), Some(2000), "{:?}", sink_s.events);
        assert_eq!(sink_c.app_data.last().map(Vec::len), Some(2000), "{:?}", sink_c.events);
    }

    /// A server nobody configured still honours a client that asks, and
    /// answers with the protocol maximum so the client stays unrestricted.
    #[test]
    fn a_server_with_no_limit_configured_still_honours_the_clients() {
        let (mut sink_c, mut sink_s, mut client, mut server) = dtls_with_limits(Some(100), None);
        assert_eq!(server.record_size_limits(), Some(RecordSizeLimits { send: 100, receive: 16385 }));
        assert_eq!(server.max_application_data(), 99);
        assert_eq!(client.max_application_data(), 16384);
        for len in protected_lengths(&sink_s.all_written) {
            assert!(len <= 100 + TAG, "server record {len} exceeds the client's 100");
        }
        client.send_application_data(&vec![1u8; 2000], &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data.last().map(Vec::len), Some(2000), "{:?}", sink_s.events);
    }

    /// RFC 8449 §4: a DTLS endpoint receiving a record over its advertised
    /// limit may alert or discard; this one authenticated, so it alerts.
    #[test]
    fn a_record_over_the_advertised_limit_is_a_fatal_record_overflow() {
        let (mut sink_c, mut sink_s, mut client, mut server) = dtls_with_limits(Some(200), Some(200));
        // Make the server misbehave: forget the client's limit.
        server.state.send_limit = None;
        server.send_application_data(&vec![9u8; 1000], &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert!(
            sink_c.events.iter().any(|e| e.starts_with("protocol_error") && e.contains("record_size_limit")),
            "{:?}",
            sink_c.events
        );
        assert!(sink_c.app_data.is_empty(), "the oversize record must not be delivered");
        // The client told the server why: a real, decodable record_overflow (22).
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error") && e.contains("alert 22")),
            "{:?}",
            sink_s.events
        );
    }

    #[test]
    fn loopback_handshake_completes_and_exposes_alpn() {
        let (sink_c, sink_s, _client, _server) = run_loopback();
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_c.events);
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_s.events);
        let info = sink_c.info.expect("client security info");
        assert_eq!(info.alpn(), Some(&b"test"[..]));
        assert_eq!(info.protocol(), Some("DTLSv1.3"));
    }

    /// RFC 9147 §7: once we've completed the handshake by processing the
    /// peer's Finished, and have nothing else queued to send, we must
    /// send an explicit ACK for it — otherwise a peer still waiting to
    /// confirm we received its Finished keeps retransmitting forever.
    /// Found via real interop, not loopback (hopf's own server never
    /// needed this against hopf's own client until proven necessary
    /// against wolfSSL, whose client sat retransmitting indefinitely
    /// without it). Verified end to end: the queued datagram must be a
    /// real, encrypted ACK record the peer accepts without erroring, not
    /// just "server sent something."
    #[test]
    fn server_sends_an_explicit_ack_for_the_clients_finished_with_nothing_else_to_piggyback() {
        let (mut sink_c, mut sink_s, mut client, _server) = run_loopback();
        let ack = sink_s.outbound.pop().expect("server must have queued an ACK for the client's Finished");
        assert!(sink_s.outbound.is_empty(), "exactly one ACK, no more");
        client.feed_datagram(&ack, &mut sink_c);
        assert!(
            sink_c.events.iter().all(|e| !e.starts_with("protocol_error")),
            "client must accept the server's ACK without erroring: {:?}",
            sink_c.events
        );
    }

    #[test]
    fn application_data_round_trips_after_handshake() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello from client", &mut sink_c);
        let wire = sink_c.outbound.pop().expect("one datagram queued");
        server.feed_datagram(&wire, &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"hello from client".to_vec()]);

        server.send_application_data(b"hello back", &mut sink_s);
        let wire = sink_s.outbound.pop().expect("one datagram queued");
        client.feed_datagram(&wire, &mut sink_c);
        assert_eq!(sink_c.app_data, vec![b"hello back".to_vec()]);
    }

    fn write_epoch(e: &DtlsRecordEngine) -> u64 {
        e.state.write.as_ref().unwrap().epoch()
    }

    fn read_epoch(e: &DtlsRecordEngine) -> u64 {
        e.state.read.as_ref().unwrap().epoch()
    }

    /// Loopback with the post-handshake chatter (tickets, acks) discarded.
    fn established() -> (RecordingSink, RecordingSink, DtlsRecordEngine, DtlsRecordEngine) {
        let (mut sink_c, mut sink_s, client, server) = run_loopback();
        sink_c.outbound.clear();
        sink_s.outbound.clear();
        sink_c.app_data.clear();
        sink_s.app_data.clear();
        (sink_c, sink_s, client, server)
    }

    /// RFC 9147 §5.8.4: a `KeyUpdate` bumps the epoch, but the sender keeps
    /// writing under the old epoch until the peer ACKs the message (§8);
    /// after that, application data flows under epoch 4 with a fresh
    /// replay window, while the untouched direction stays on epoch 3.
    #[test]
    fn key_update_bumps_the_epoch_once_acked_and_data_continues() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        assert!(client.request_key_update(&mut sink_c, false), "{:?}", sink_c.events);
        assert_eq!(write_epoch(&client), 3, "old write key must stay in use until the ACK");

        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(read_epoch(&server), 4, "receiver rotates its read key immediately: {:?}", sink_s.events);
        assert_eq!(write_epoch(&server), 3, "update_not_requested must not rotate the receiver's write key");
        assert!(!sink_s.outbound.is_empty(), "receiver must ACK the KeyUpdate");

        relay(&mut sink_s, &mut client, &mut sink_c);
        assert_eq!(write_epoch(&client), 4, "ACK installs the new write key: {:?}", sink_c.events);

        client.send_application_data(b"after the update", &mut sink_c);
        assert_eq!(sink_c.outbound.last().unwrap()[0] & 0b11, 4 & 0b11, "record must carry epoch 4");
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"after the update".to_vec()], "{:?}", sink_s.events);

        server.send_application_data(b"still epoch 3", &mut sink_s);
        assert_eq!(sink_s.outbound.last().unwrap()[0] & 0b11, 3);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert_eq!(sink_c.app_data, vec![b"still epoch 3".to_vec()], "{:?}", sink_c.events);
        assert!(!client.failed && !server.failed);
    }

    /// `update_requested`: the peer must answer with its own `KeyUpdate`, so
    /// both directions end up on epoch 4.
    #[test]
    fn key_update_requesting_reciprocal_rotates_both_directions() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        assert!(client.request_key_update(&mut sink_c, true), "{:?}", sink_c.events);
        // Ping-pong until quiet: KeyUpdate, ACK + reciprocal KeyUpdate, ACK.
        for _ in 0..3 {
            relay(&mut sink_c, &mut server, &mut sink_s);
            relay(&mut sink_s, &mut client, &mut sink_c);
        }
        assert_eq!((write_epoch(&client), read_epoch(&client)), (4, 4), "{:?}", sink_c.events);
        assert_eq!((write_epoch(&server), read_epoch(&server)), (4, 4), "{:?}", sink_s.events);

        client.send_application_data(b"c->s", &mut sink_c);
        server.send_application_data(b"s->c", &mut sink_s);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert_eq!(sink_s.app_data, vec![b"c->s".to_vec()], "{:?}", sink_s.events);
        assert_eq!(sink_c.app_data, vec![b"s->c".to_vec()], "{:?}", sink_c.events);
        assert!(!client.failed && !server.failed);
    }

    /// Lost ACK: the sender's retransmit timer resends the KeyUpdate, the
    /// receiver (which already rotated, so sees a replay under the previous
    /// epoch's retained keys) must ACK again rather than stay silent.
    #[test]
    fn a_lost_key_update_ack_is_recovered_by_retransmit() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        assert!(client.request_key_update(&mut sink_c, false));
        assert!(sink_c.armed_timeout.is_some(), "unacked KeyUpdate must arm the retransmit timer");
        relay(&mut sink_c, &mut server, &mut sink_s);
        sink_s.outbound.clear(); // the ACK is lost
        assert_eq!(write_epoch(&client), 3);

        client.feed_timer(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert!(!sink_s.outbound.is_empty(), "duplicate KeyUpdate must be re-ACKed: {:?}", sink_s.events);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert_eq!(write_epoch(&client), 4, "{:?}", sink_c.events);
        assert_eq!(sink_c.armed_timeout, None, "ACK must stop the retransmit timer");
        assert!(!client.failed && !server.failed);
    }

    /// RFC 9147 §5.8.4: a datagram protected under the old epoch that is
    /// reordered behind the KeyUpdate must still be readable.
    #[test]
    fn old_epoch_data_reordered_behind_the_key_update_is_still_delivered() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        client.send_application_data(b"sent before, arrives after", &mut sink_c);
        let straggler = sink_c.outbound.pop().unwrap();
        assert!(client.request_key_update(&mut sink_c, false));
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(read_epoch(&server), 4);

        server.feed_datagram(&straggler, &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"sent before, arrives after".to_vec()], "{:?}", sink_s.events);
        assert!(!server.failed);
    }

    /// The old epoch's replay window survives the rotation: a duplicate of
    /// an already-delivered old-epoch datagram is dropped silently.
    #[test]
    fn a_replayed_old_epoch_datagram_is_dropped_after_rotation() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        client.send_application_data(b"once", &mut sink_c);
        let datagram = sink_c.outbound.last().unwrap().clone();
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert!(client.request_key_update(&mut sink_c, false));
        relay(&mut sink_c, &mut server, &mut sink_s);

        server.feed_datagram(&datagram, &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"once".to_vec()], "{:?}", sink_s.events);
        assert!(!server.failed);
    }

    #[test]
    fn key_update_is_refused_before_the_handshake_completes_and_while_one_is_pending() {
        let (client_cfg, _server_cfg) = configs();
        let mut early = DtlsRecordEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        assert!(!early.request_key_update(&mut sink, false));

        let (mut sink_c, _sink_s, mut client, _server) = established();
        assert!(client.request_key_update(&mut sink_c, false));
        assert!(!client.request_key_update(&mut sink_c, false), "RFC 9147 §5.8.4: one unacknowledged KeyUpdate at a time");
    }

    /// RFC 8446 §5.5 / RFC 9325 §4.4: a write key reaching its AES-GCM
    /// confidentiality limit is rotated with a `KeyUpdate`, not the
    /// connection closed, and traffic continues on the new epoch.
    #[test]
    fn write_confidentiality_limit_triggers_a_key_update_instead_of_closing() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        client.state.write.as_mut().unwrap().set_next_seq_for_test(AES_GCM_CONFIDENTIALITY_LIMIT - 1);
        // The server's read window has to track the fast-forwarded counter
        // (see the read-limit test below).
        server.state.read.as_mut().unwrap().set_replay_highest_for_test(AES_GCM_CONFIDENTIALITY_LIMIT - 2);

        client.send_application_data(b"the datagram that crosses the limit", &mut sink_c);
        assert!(!client.failed, "{:?}", sink_c.events);
        relay(&mut sink_c, &mut server, &mut sink_s); // data record + KeyUpdate, in order
        relay(&mut sink_s, &mut client, &mut sink_c); // ACK
        assert_eq!(sink_s.app_data, vec![b"the datagram that crosses the limit".to_vec()], "{:?}", sink_s.events);
        assert_eq!(write_epoch(&client), 4, "{:?}", sink_c.events);

        client.send_application_data(b"fresh key", &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data.last().unwrap(), b"fresh key");
        assert!(!client.failed && !server.failed);
    }

    /// Symmetric case: a read key nearing its limit asks the peer to rotate
    /// (`update_requested`) rather than closing. Encoding the record
    /// directly with `record::write_record` isolates the read-side trigger.
    #[test]
    fn read_confidentiality_limit_requests_a_peer_key_update_instead_of_closing() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        client.state.write.as_mut().unwrap().set_next_seq_for_test(AES_GCM_CONFIDENTIALITY_LIMIT);
        server.state.read.as_mut().unwrap().set_replay_highest_for_test(AES_GCM_CONFIDENTIALITY_LIMIT - 1);
        let mut wire = Vec::new();
        record::write_record(
            client.state.write.as_mut().unwrap(),
            CONTENT_APPLICATION_DATA,
            b"one more under the old key",
            &mut wire,
        );

        server.feed_datagram(&wire, &mut sink_s);
        assert!(!server.failed, "{:?}", sink_s.events);
        assert_eq!(sink_s.app_data, vec![b"one more under the old key".to_vec()]);

        // The server's KeyUpdate(update_requested) makes the client rotate
        // its write key (via the reciprocal) and the server its read key.
        for _ in 0..3 {
            relay(&mut sink_s, &mut client, &mut sink_c);
            relay(&mut sink_c, &mut server, &mut sink_s);
        }
        assert_eq!(write_epoch(&client), 4, "{:?}", sink_c.events);
        assert_eq!(read_epoch(&server), 4, "{:?}", sink_s.events);
        client.send_application_data(b"rotated", &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data.last().unwrap(), b"rotated");
        assert!(!client.failed && !server.failed);
    }

    /// The peer's ACK of the client's final flight (Finished) ends its
    /// retransmission: no timer stays armed and a stray timer fire resends
    /// nothing.
    #[test]
    fn the_peers_ack_of_the_final_flight_stops_client_retransmission() {
        let (mut sink_c, mut sink_s, mut client, _server) = run_loopback();
        assert!(sink_c.armed_timeout.is_some(), "Finished is outstanding until acknowledged");
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert_eq!(sink_c.armed_timeout, None, "{:?}", sink_c.events);
        sink_c.outbound.clear();
        client.feed_timer(&mut sink_c);
        assert!(sink_c.outbound.is_empty(), "nothing left to resend: {:?}", sink_c.events);
    }

    /// The client's Finished implicitly acknowledges the server's flight, so
    /// a completed server has nothing left to retransmit.
    #[test]
    fn a_completed_server_does_not_retransmit_its_handshake_flight() {
        let (_sink_c, mut sink_s, _client, mut server) = run_loopback();
        sink_s.outbound.clear();
        server.feed_timer(&mut sink_s);
        assert!(sink_s.outbound.is_empty(), "{:?}", sink_s.events);
    }

    /// Even if the ACK of the final flight never arrives, exhausting the
    /// retransmit budget must not kill a connection whose handshake already
    /// completed - only an unfinished handshake "times out".
    #[test]
    fn exhausting_retransmits_after_the_handshake_does_not_fail_the_connection() {
        let (mut sink_c, mut sink_s, mut client, mut server) = established();
        for _ in 0..8 {
            client.feed_timer(&mut sink_c);
        }
        assert!(!client.failed, "{:?}", sink_c.events);
        sink_c.outbound.clear();
        client.send_application_data(b"still alive", &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"still alive".to_vec()], "{:?}", sink_s.events);
    }

    #[test]
    fn close_notify_reported_as_peer_closed() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_close_notify(&mut sink_c);
        let wire = sink_c.outbound.pop().expect("close_notify datagram queued");
        server.feed_datagram(&wire, &mut sink_s);
        assert!(sink_s.events.iter().any(|e| e == "peer_closed"), "{:?}", sink_s.events);
    }

    #[test]
    fn tampered_application_record_reports_protocol_error() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello", &mut sink_c);
        let mut wire = sink_c.outbound.pop().expect("one datagram queued");
        let last = wire.len() - 1;
        wire[last] ^= 0xff; // corrupt the AEAD tag
        server.feed_datagram(&wire, &mut sink_s);
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_s.events
        );
        assert!(sink_s.app_data.is_empty());
    }

    /// Same round trip as `tls::record`'s test of the same name, adapted to
    /// DTLS's own datagram framing (RFC 9147 §5.2's Alert content type):
    /// a locally-detected violation must reach the peer as a real fatal
    /// alert datagram, and that alert's code must survive to the peer's
    /// own `TlsProtocolError`.
    #[test]
    fn a_locally_detected_failure_sends_a_real_fatal_alert_the_peer_can_decode() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback();
        client.send_application_data(b"hello", &mut sink_c);
        let mut wire = sink_c.outbound.pop().expect("one datagram queued");
        let last = wire.len() - 1;
        wire[last] ^= 0xff; // corrupt the AEAD tag
        server.feed_datagram(&wire, &mut sink_s);

        let alert_datagram = sink_s.outbound.pop().expect("server must send a fatal alert datagram");
        client.feed_datagram(&alert_datagram, &mut sink_c);
        assert!(
            sink_c.events.iter().any(|e| e.contains("peer sent fatal alert 20")),
            "client must surface the peer's exact alert code: {:?}",
            sink_c.events
        );
        assert!(
            sink_c.outbound.is_empty(),
            "client must not echo an alert back to a peer that already sent one: {:?}",
            sink_c.outbound
        );
    }

    /// The DTLS-specific case with no TCP or QUIC analogue: a flight is
    /// lost entirely (never delivered), the retransmit timer fires, and
    /// resending the exact same bytes lets the handshake complete anyway —
    /// proving [`RetransmitState`] is actually wired into the engine, not
    /// just unit-tested in isolation.
    #[test]
    fn dropped_flight_completes_after_retransmit_timer_fires() {
        let (client_cfg, server_cfg) = configs();
        let mut client = DtlsRecordEngine::new(client_cfg);
        let mut server = DtlsRecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        assert!(
            sink_c.armed_timeout.is_some(),
            "sending ClientHello must arm a retransmit timer: {:?}",
            sink_c.events
        );
        // Simulate ClientHello being lost — drop it instead of relaying,
        // then fire the timer as the reactor would once it expires.
        sink_c.outbound.clear();
        client.feed_timer(&mut sink_c);
        assert!(
            sink_c.outbound.len() == 1,
            "timer fire must resend the same flight: {:?}",
            sink_c.events
        );

        // Now let the resent ClientHello actually get through.
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
    }

    #[test]
    fn giving_up_after_max_retransmits_reports_protocol_error() {
        let (client_cfg, _server_cfg) = configs();
        let mut client = DtlsRecordEngine::new(client_cfg);
        let mut sink_c = RecordingSink::default();
        client.start(&mut sink_c);
        sink_c.outbound.clear();
        for _ in 0..6 {
            client.feed_timer(&mut sink_c);
            sink_c.outbound.clear();
        }
        client.feed_timer(&mut sink_c);
        assert!(
            sink_c.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_c.events
        );
    }
}
