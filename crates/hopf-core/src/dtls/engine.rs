// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.3 record/reassembly/retransmission engine — wraps
//! [`HandshakeEngine`] in [`HandshakeMode::Dtls`] the same way
//! [`crate::tls::TlsRecordEngine`] wraps it for TCP: [`DtlsRecordEngine`]
//! owns the handshake engine plus everything genuinely DTLS-specific
//! (epoch/record framing, fragmentation, retransmission), translating
//! [`TlsEventSink`] callbacks into DTLS wire behaviour via an internal
//! bridge, sink-based like every other engine in this crate.
//!
//! Loopback-only for now — no real UDP driver wiring, no external
//! interop (see the crate-level module doc and `crypto-migration-plan.md`
//! Phase 6 for the reasons and what's explicitly deferred).

use std::time::Duration;

use crate::security::SecurityInfo;
use crate::tls::{
    HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, QuicSecrets, Tls13Aead,
    TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest, VerifyResult,
};

use super::reassembly::Reassembler;
use super::record::{self, PlaintextReadOutcome, ReadKeys, ReadOutcome, WriteKeys};
use super::retransmit::{RetransmitOutcome, RetransmitState};

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Events emitted by [`DtlsRecordEngine`] — consumed by whatever owns the
/// UDP socket (a future `hopf-core`/protocol-crate driver; loopback tests
/// today). Shaped like [`crate::tls::TlsRecordSink`], with two DTLS-specific
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

struct RecordState {
    role: HandshakeRole,
    epoch: Epoch,
    plaintext_write_seq: u64,
    write: Option<WriteKeys>,
    read: Option<ReadKeys>,
    next_write: Option<WriteKeys>,
    next_read: Option<ReadKeys>,
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
        self.reassembler.fragment(data, &mut frags);
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

    /// Consume one received UDP datagram — any number of coalesced records.
    pub fn feed_datagram<S: DtlsRecordSink + ?Sized>(&mut self, input: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        let mut flight = Vec::new();
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
                        self.fail(sink, "malformed DTLS plaintext record");
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
                    self.fail(sink, "encrypted DTLS record before keys installed");
                    return;
                };
                match record::read_record(read, remaining) {
                    ReadOutcome::Incomplete => break,
                    ReadOutcome::Invalid => {
                        self.fail(sink, "malformed or unauthenticated DTLS record");
                        return;
                    }
                    ReadOutcome::WrongEpoch { consumed } | ReadOutcome::Replay { consumed } => {
                        // A stray old/duplicate/not-yet-activated-epoch
                        // record isn't fatal — RFC 9147 §4.5.1 says to drop
                        // silently. Skip past it and keep parsing the rest
                        // of this datagram.
                        pos += consumed;
                    }
                    ReadOutcome::Record {
                        inner_content_type,
                        plaintext,
                        consumed,
                    } => {
                        pos += consumed;
                        // RFC 8446 §5.5 / RFC 9325 §4.4: same reasoning as
                        // the write side in `send_application_data` — no
                        // DTLS 1.3 rekey to fall back to, so close rather
                        // than keep decrypting past the safety margin.
                        if self.state.read.as_ref().is_some_and(ReadKeys::over_confidentiality_limit) {
                            self.fail(sink, "AES-GCM read key exceeded its confidentiality limit");
                            return;
                        }
                        if !self.dispatch_record(inner_content_type, plaintext, &mut flight, sink) {
                            break;
                        }
                    }
                }
            }
        }
        self.flush_flight(flight, sink);
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
            Some(RetransmitOutcome::GiveUp) => {
                self.failed = true;
                sink.arm_retransmit_timer(None);
                sink.protocol_error(TlsProtocolError::new(
                    "DTLS handshake timed out (retransmit limit exceeded)",
                ));
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
                "application data sent before handshake completed",
            ));
            return;
        }
        let mut out = Vec::new();
        write_records(&mut self.state, CONTENT_APPLICATION_DATA, &[plaintext.to_vec()], &mut out);
        sink.datagram_ready(&out);
        // RFC 8446 §5.5 / RFC 9325 §4.4: DTLS 1.3's own `KeyUpdate` isn't
        // implemented (deferred, see the module doc), so a write key
        // nearing its AES-GCM confidentiality limit must close the
        // connection rather than keep encrypting past the safety margin.
        if self.state.write.as_ref().is_some_and(WriteKeys::over_confidentiality_limit) {
            self.fail(sink, "AES-GCM write key exceeded its confidentiality limit");
        }
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
                    self.fail(sink, "malformed alert record");
                    return false;
                }
                if payload[1] == ALERT_CLOSE_NOTIFY {
                    self.failed = true;
                    sink.arm_retransmit_timer(None);
                    sink.peer_closed();
                } else {
                    let level = if payload[0] == ALERT_LEVEL_FATAL { "fatal" } else { "warning" };
                    self.fail(sink, &format!("{level} alert {}", payload[1]));
                }
                false
            }
            CONTENT_HANDSHAKE => {
                let messages = self.reassembler.receive_fragment(&payload);
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
                    self.fail(sink, "application data before handshake completed");
                    return false;
                }
                sink.application_data(&payload);
                true
            }
            _ => {
                self.fail(sink, "unknown DTLS record content type");
                false
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

    fn fail<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S, msg: &str) {
        if !self.failed {
            self.failed = true;
            sink.arm_retransmit_timer(None);
            sink.protocol_error(TlsProtocolError::new(msg));
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
    }

    impl DtlsRecordSink for RecordingSink {
        fn datagram_ready(&mut self, data: &[u8]) {
            self.events.push(format!("datagram {} bytes", data.len()));
            self.outbound.push(data.to_vec());
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

    #[test]
    fn loopback_handshake_completes_and_exposes_alpn() {
        let (sink_c, sink_s, _client, _server) = run_loopback();
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_c.events);
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_s.events);
        let info = sink_c.info.expect("client security info");
        assert_eq!(info.alpn(), Some(&b"test"[..]));
        assert_eq!(info.protocol(), Some("DTLSv1.3"));
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

    /// RFC 8446 §5.5 / RFC 9325 §4.4: DTLS 1.3's own `KeyUpdate` isn't
    /// implemented here (deferred, see `dtls::record`'s module doc), so a
    /// write key nearing its AES-GCM confidentiality limit must close the
    /// connection rather than keep encrypting past the safety margin.
    #[test]
    fn send_application_data_closes_connection_at_write_confidentiality_limit() {
        let (mut sink_c, _sink_s, mut client, _server) = run_loopback();
        client.state.write.as_mut().unwrap().set_next_seq_for_test(AES_GCM_CONFIDENTIALITY_LIMIT - 1);

        client.send_application_data(b"the datagram that crosses the limit", &mut sink_c);

        assert!(client.failed, "{:?}", sink_c.events);
        assert!(
            sink_c.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_c.events
        );
    }

    /// Symmetric case: a read key nearing its limit closes the connection
    /// too. Encoding the record directly with `record::write_record`
    /// (rather than through `client.send_application_data`) keeps this
    /// isolated to the read-side trigger alone — going through the real
    /// client API here would also cross its own write-side limit and fire
    /// that check too, conflating the two cases the test above already
    /// covers separately.
    #[test]
    fn feed_datagram_closes_connection_at_read_confidentiality_limit() {
        let (_sink_c, mut sink_s, mut client, mut server) = run_loopback();
        // Both sides' counters must stay in lockstep — the truncated
        // on-wire sequence number is reconstructed relative to the
        // reader's own `highest`-seen value (RFC 9147 §4.2.2), and the
        // AAD binds the full reconstructed number, so an out-of-sync
        // writer wouldn't authenticate.
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

        assert!(server.failed, "{:?}", sink_s.events);
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_s.events
        );
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
