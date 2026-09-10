// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.2 record/cookie/retransmission engine — wraps
//! [`Tls12Engine`] the same way [`crate::dtls::DtlsRecordEngine`] wraps
//! TLS 1.3's `HandshakeEngine`, reusing [`crate::dtls::reassembly::Reassembler`],
//! [`crate::dtls::retransmit::RetransmitState`], and
//! [`crate::dtls::DtlsRecordSink`]/[`crate::dtls::NopDtlsRecordSink`]
//! directly (none of the three have any TLS-version awareness).
//!
//! The `ClientHello1` → `HelloVerifyRequest` → `ClientHello2` cookie round
//! trip (RFC 6347 §4.2.1) happens entirely in this module, *before*
//! `Tls12Engine` ever sees anything: that RFC excludes the cookie-less
//! first exchange from the transcript hash, so the cleanest and only
//! transcript-correct way to honour that is to never feed it to the engine
//! at all. Concretely: the client always sends a normal `ClientHello`
//! through a real `Tls12Engine` instance first (so ticket-offer / cipher
//! preference logic isn't duplicated here); if a `HelloVerifyRequest`
//! comes back, that engine instance (whose transcript already, correctly
//! but now uselessly, contains the discarded `ClientHello1`) is thrown
//! away, and a fresh one — with the cookie set — builds `ClientHello2`
//! from scratch. The server never creates a `Tls12Engine` at all until it
//! has decided (via [`Dtls12Config::require_cookie`]) that the `ClientHello`
//! in hand is the real one; extracting the cookie to check first uses
//! `messages::parse_client_hello` directly, a plain function, not an engine.
//!
//! **Cookie policy** (see `crypto-migration-plan.md` Phase 6's DTLS 1.2
//! section): real RFC 6347 §4.2.1 anti-amplification protection needs the
//! cookie bound to the client's source address, which this engine — like
//! every other engine in this crate — doesn't have (transport/socket
//! agnostic by design; real address binding needs the deferred UDP driver
//! wiring). The cookie here is `HMAC(secret, ClientHello.random)`: real
//! cryptographic binding to *this* handshake attempt, not to a network
//! address. [`Dtls12Config::require_cookie`] defaults to `false` for
//! exactly this reason — forcing an extra round trip for protection that
//! isn't real yet has a cost and no benefit until address binding lands.

use aws_lc_rs::hmac::{self, Key, HMAC_SHA256};
use bytes::Bytes;

use crate::dtls::reassembly::Reassembler;
use crate::dtls::retransmit::{RetransmitOutcome, RetransmitState};
use crate::dtls::DtlsRecordSink;
use crate::security::SecurityInfo;
use crate::tls::tls12::engine::{CipherKind, DirectionalKeyMaterial, Role, Tls12EventSink, Tls12Engine};
use crate::tls::tls12::messages;
use crate::tls::{Tls12Config, TlsProtocolError, VerifyRequest, VerifyResult};

use super::record::{self, ReadKeys, ReadOutcome, WriteKeys};

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 20;
const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;

const ALERT_LEVEL_WARNING: u8 = 1;
const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_CLOSE_NOTIFY: u8 = 0;

const DTLS12_VERSION: u16 = 0xfefd;
const COOKIE_LEN: usize = 16;

/// Config for [`Dtls12RecordEngine`] — every field [`Tls12Config`] has,
/// plus the cookie policy [`Tls12Config`] has no concept of.
pub struct Dtls12Config {
    /// Base TLS 1.2 config (role, credentials, trust, ticket, client-auth
    /// policy). Its `dtls`/`cookie` fields are managed internally by this
    /// engine and overwritten regardless of what's set here.
    pub base: Tls12Config,
    /// Server role only: send `HelloVerifyRequest` and require the cookie
    /// round trip before proceeding. See this module's doc for why the
    /// default is `false`.
    pub require_cookie: bool,
    /// Server role only: HMAC key for the stateless cookie. Callers should
    /// set this to a value that persists across connections (so a
    /// retransmitted `ClientHello2` still validates) but isn't shared
    /// across restarts in a way that would help an attacker — a random
    /// 32-byte value generated at listener startup is enough.
    pub cookie_secret: [u8; 32],
}

struct RecordState {
    role: Role,
    write: WriteKeys,
    read: ReadKeys,
    // Separate per-direction staging — `activate_write`/`activate_read`
    // fire at genuinely independent times (our own `send_change_cipher_spec`
    // vs. the peer's `ChangeCipherSpec` record arriving), so a single shared
    // "pending" consumed by whichever fires first would starve the other.
    // Mirrors `tls::tls12::record::RecordState`'s proven `pending_write`/
    // `pending_read` split exactly.
    pending_write: Option<(CipherKind, DirectionalKeyMaterial)>,
    pending_read: Option<(CipherKind, DirectionalKeyMaterial)>,
}

impl RecordState {
    fn new(role: Role) -> Self {
        Self {
            role,
            write: WriteKeys::cleartext(),
            read: ReadKeys::cleartext(),
            pending_write: None,
            pending_read: None,
        }
    }

    fn stage_keys(&mut self, cipher: CipherKind, client: DirectionalKeyMaterial, server: DirectionalKeyMaterial) {
        let (w, r) = match self.role {
            Role::Client => (client, server),
            Role::Server => (server, client),
        };
        self.pending_write = Some((cipher, w));
        self.pending_read = Some((cipher, r));
    }

    fn activate_write(&mut self) {
        if let Some((cipher, m)) = self.pending_write.take() {
            self.write = WriteKeys::from_material(&m, cipher).expect("valid key material");
        }
    }

    fn activate_read(&mut self) {
        if let Some((cipher, m)) = self.pending_read.take() {
            self.read = ReadKeys::from_material(&m, cipher).expect("valid key material");
        }
    }
}

fn write_fragmented(state: &mut RecordState, reassembler: &mut Reassembler, content_type: u8, data: &[u8], out: &mut Vec<u8>) {
    if content_type == CONTENT_HANDSHAKE {
        let mut frags = Vec::new();
        reassembler.fragment(data, &mut frags);
        for frag in &frags {
            record::write_record(&mut state.write, content_type, frag, out);
        }
    } else {
        record::write_record(&mut state.write, content_type, data, out);
    }
}

#[derive(Default)]
struct EngineEvents {
    complete: Option<SecurityInfo>,
    verify: Vec<VerifyRequest>,
    errors: Vec<TlsProtocolError>,
}

struct InnerSink<'a> {
    state: &'a mut RecordState,
    reassembler: &'a mut Reassembler,
    flight: &'a mut Vec<u8>,
    events: &'a mut EngineEvents,
}

impl Tls12EventSink for InnerSink<'_> {
    fn handshake_data_ready(&mut self, data: &[u8]) {
        write_fragmented(self.state, self.reassembler, CONTENT_HANDSHAKE, data, self.flight);
    }

    fn keys_ready(&mut self, cipher: CipherKind, client: DirectionalKeyMaterial, server: DirectionalKeyMaterial) {
        self.state.stage_keys(cipher, client, server);
    }

    fn send_change_cipher_spec(&mut self) {
        record::write_record(&mut self.state.write, CONTENT_CHANGE_CIPHER_SPEC, &[0x01], self.flight);
        self.state.activate_write();
    }

    fn handshake_complete(&mut self, info: SecurityInfo) {
        self.events.complete = Some(info);
    }

    fn verification_requested(&mut self, req: VerifyRequest) {
        self.events.verify.push(req);
    }

    fn protocol_error(&mut self, err: TlsProtocolError) {
        self.events.errors.push(err);
    }
}

/// `HMAC-SHA256(secret, client_hello_random)`, truncated — real
/// cryptographic binding to one handshake attempt; see this module's doc
/// for why it isn't (yet) bound to a network address.
fn compute_cookie(secret: &[u8; 32], client_random: &[u8; 32]) -> Bytes {
    let key = Key::new(HMAC_SHA256, secret);
    let tag = hmac::sign(&key, client_random);
    Bytes::copy_from_slice(&tag.as_ref()[..COOKIE_LEN])
}

/// Reactive DTLS 1.2 engine.
pub struct Dtls12RecordEngine {
    base: Tls12Config,
    require_cookie: bool,
    cookie_secret: [u8; 32],
    engine: Option<Tls12Engine>,
    state: RecordState,
    reassembler: Reassembler,
    retransmit: RetransmitState,
    failed: bool,
    /// Client role only: `ClientHello1`'s random, reused verbatim for
    /// `ClientHello2` — see [`Tls12Config::fixed_client_random`]'s doc for
    /// why the cookie's validity depends on this.
    client_hello_random: Option<[u8; 32]>,
}

impl Dtls12RecordEngine {
    /// Create the engine.
    pub fn new(config: Dtls12Config) -> Self {
        let role = config.base.role;
        Self {
            base: config.base,
            require_cookie: config.require_cookie,
            cookie_secret: config.cookie_secret,
            engine: None,
            state: RecordState::new(role),
            reassembler: Reassembler::new(),
            retransmit: RetransmitState::new(),
            failed: false,
            client_hello_random: None,
        }
    }

    /// Begin the handshake — client sends `ClientHello1`; server waits.
    pub fn start<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        if self.base.role != Role::Client {
            return;
        }
        let mut random = [0u8; 32];
        let _ = getrandom::getrandom(&mut random);
        self.client_hello_random = Some(random);
        let mut cfg = self.base.clone();
        cfg.dtls = true;
        cfg.cookie = Bytes::new();
        cfg.fixed_client_random = Some(random);
        let mut engine = Tls12Engine::new(cfg);
        let mut flight = Vec::new();
        let mut events = EngineEvents::default();
        {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight: &mut flight,
                events: &mut events,
            };
            engine.start(&mut inner);
        }
        self.engine = Some(engine);
        self.dispatch_events(events, sink);
        self.flush_flight(flight, sink);
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        self.engine.as_ref().is_some_and(Tls12Engine::is_complete)
    }

    /// Consume one received UDP datagram.
    pub fn feed_datagram<S: DtlsRecordSink + ?Sized>(&mut self, input: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        let mut flight = Vec::new();
        let mut pos = 0usize;
        while pos < input.len() {
            match record::read_record(&mut self.state.read, &input[pos..]) {
                ReadOutcome::Incomplete => break,
                ReadOutcome::Invalid => {
                    self.fail(sink, "malformed or unauthenticated DTLS record");
                    return;
                }
                ReadOutcome::WrongEpoch { consumed } | ReadOutcome::Replay { consumed } => {
                    pos += consumed;
                }
                ReadOutcome::Record { content_type, payload, consumed } => {
                    pos += consumed;
                    // RFC 8446 §5.5 / RFC 9325 §4.4: RFC 6347 predates
                    // this guidance and has no rekey mechanism of its
                    // own, so a read key nearing its AES-GCM
                    // confidentiality limit must close the connection
                    // rather than keep decrypting past the safety margin.
                    if self.state.read.over_confidentiality_limit() {
                        self.fail(sink, "AES-GCM read key exceeded its confidentiality limit");
                        return;
                    }
                    if !self.dispatch_record(content_type, payload, &mut flight, sink) {
                        break;
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
                    "DTLS 1.2 handshake timed out (retransmit limit exceeded)",
                ));
            }
        }
    }

    /// Encrypt and frame application data. Only valid once [`Self::is_complete`].
    pub fn send_application_data<S: DtlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        if self.failed {
            return;
        }
        if !self.is_complete() {
            sink.protocol_error(TlsProtocolError::new(
                "application data sent before handshake completed",
            ));
            return;
        }
        let mut out = Vec::new();
        record::write_record(&mut self.state.write, CONTENT_APPLICATION_DATA, plaintext, &mut out);
        sink.datagram_ready(&out);
        // Same reasoning as the read-side check in `feed_datagram`.
        if self.state.write.over_confidentiality_limit() {
            self.fail(sink, "AES-GCM write key exceeded its confidentiality limit");
        }
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: DtlsRecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        if self.failed {
            return;
        }
        let Some(engine) = self.engine.as_mut() else {
            return;
        };
        let mut flight = Vec::new();
        let mut events = EngineEvents::default();
        {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight: &mut flight,
                events: &mut events,
            };
            engine.feed_verification_result(result, &mut inner);
        }
        self.dispatch_events(events, sink);
        self.flush_flight(flight, sink);
    }

    /// Send a `close_notify` alert under the current epoch.
    pub fn send_close_notify<S: DtlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        if self.failed {
            return;
        }
        let mut out = Vec::new();
        record::write_record(&mut self.state.write, CONTENT_ALERT, &[ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY], &mut out);
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
            CONTENT_CHANGE_CIPHER_SPEC => {
                self.state.activate_read();
                true
            }
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
                let messages_ready = self.reassembler.receive_fragment(&payload);
                for msg in messages_ready {
                    if !self.dispatch_handshake_message(msg, flight, sink) {
                        return false;
                    }
                }
                true
            }
            CONTENT_APPLICATION_DATA => {
                if !self.is_complete() {
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

    fn dispatch_handshake_message<S: DtlsRecordSink + ?Sized>(
        &mut self,
        msg: Vec<u8>,
        flight: &mut Vec<u8>,
        sink: &mut S,
    ) -> bool {
        let msg_type = msg.first().copied();
        match (self.base.role, msg_type) {
            (Role::Client, Some(3)) if self.engine.is_some() => {
                self.handle_hello_verify_request(&msg, flight, sink)
            }
            (Role::Server, Some(1)) if self.engine.is_none() => {
                self.handle_server_client_hello(&msg, flight, sink)
            }
            _ => {
                let Some(engine) = self.engine.as_mut() else {
                    self.fail(sink, "handshake message before ClientHello");
                    return false;
                };
                let mut events = EngineEvents::default();
                {
                    let mut inner = InnerSink {
                        state: &mut self.state,
                        reassembler: &mut self.reassembler,
                        flight,
                        events: &mut events,
                    };
                    let mut slice = msg.as_slice();
                    engine.feed_handshake_data(&mut slice, &mut inner);
                }
                self.dispatch_events(events, sink);
                true
            }
        }
    }

    /// Client role: a `HelloVerifyRequest` arrived. Discard the current
    /// `Tls12Engine` instance (its transcript already, but now uselessly,
    /// contains the just-discarded `ClientHello1` — RFC 6347 §4.2.1 excludes
    /// both from the real transcript) and build `ClientHello2` from a fresh
    /// one, with the server's cookie set.
    fn handle_hello_verify_request<S: DtlsRecordSink + ?Sized>(
        &mut self,
        msg: &[u8],
        flight: &mut Vec<u8>,
        sink: &mut S,
    ) -> bool {
        let Some(cookie) = messages::parse_hello_verify_request(&msg[4..]) else {
            self.fail(sink, "malformed HelloVerifyRequest");
            return false;
        };
        let mut cfg = self.base.clone();
        cfg.dtls = true;
        cfg.cookie = cookie;
        cfg.fixed_client_random = self.client_hello_random;
        // `ClientHello1` (our own message_seq 0) and `HelloVerifyRequest`
        // (the server's message_seq 0) both already happened — RFC 6347's
        // wire message_seq counters don't reset for the retry, only the
        // transcript *content* excludes them (see `Config::dtls_initial_seq`).
        cfg.dtls_initial_seq = (1, 1);
        let mut engine = Tls12Engine::new(cfg);
        let mut events = EngineEvents::default();
        {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight,
                events: &mut events,
            };
            engine.start(&mut inner);
        }
        self.engine = Some(engine);
        self.dispatch_events(events, sink);
        true
    }

    /// Server role: a `ClientHello` arrived and no `Tls12Engine` exists yet
    /// — this could be `ClientHello1` (no cookie) or `ClientHello2` (cookie
    /// echoed). Validate the cookie per [`Self::require_cookie`]; either
    /// respond with `HelloVerifyRequest` and wait, or create the engine and
    /// forward this same message to it as the one and only `ClientHello`
    /// it will ever see.
    fn handle_server_client_hello<S: DtlsRecordSink + ?Sized>(
        &mut self,
        msg: &[u8],
        flight: &mut Vec<u8>,
        sink: &mut S,
    ) -> bool {
        let Some(ch) = messages::parse_client_hello(&msg[4..]) else {
            self.fail(sink, "malformed ClientHello");
            return false;
        };
        if self.require_cookie {
            let expected = compute_cookie(&self.cookie_secret, &ch.random);
            if ch.cookie.as_ref() != expected.as_ref() {
                let cookie = compute_cookie(&self.cookie_secret, &ch.random);
                let hvr = messages::build_hello_verify_request(DTLS12_VERSION, &cookie);
                write_fragmented(&mut self.state, &mut self.reassembler, CONTENT_HANDSHAKE, &hvr, flight);
                return true;
            }
        }
        let mut cfg = self.base.clone();
        cfg.dtls = true;
        cfg.cookie = Bytes::new();
        // Reaching here with `require_cookie` true means the early return
        // above didn't fire, i.e. `ch.cookie` matched — which only happens
        // for a real `ClientHello2` following our own `HelloVerifyRequest`
        // (a bare `ClientHello1` always has an empty cookie, never a
        // matching one). See `Config::dtls_initial_seq`'s doc for why the
        // wire message_seq numbering doesn't restart at 0 in that case.
        cfg.dtls_initial_seq = if self.require_cookie { (1, 1) } else { (0, 0) };
        let mut engine = Tls12Engine::new(cfg);
        let mut events = EngineEvents::default();
        {
            let mut inner = InnerSink {
                state: &mut self.state,
                reassembler: &mut self.reassembler,
                flight,
                events: &mut events,
            };
            let mut slice = msg;
            engine.feed_handshake_data(&mut slice, &mut inner);
        }
        self.engine = Some(engine);
        self.dispatch_events(events, sink);
        true
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
    use crate::crypto::trust::TrustStore;
    use crate::tls::ServerCredentials;
    use std::time::Duration;

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
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn configs(require_cookie: bool) -> (Dtls12Config, Dtls12Config) {
        let creds = test_server_credentials();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let client = Dtls12Config {
            base: Tls12Config {
                role: Role::Client,
                server_name: Some("localhost".into()),
                trust_store: Some(trust),
                ..Default::default()
            },
            require_cookie: false,
            cookie_secret: [0u8; 32],
        };
        let server = Dtls12Config {
            base: Tls12Config {
                role: Role::Server,
                server: Some(creds),
                ..Default::default()
            },
            require_cookie,
            cookie_secret: [0x42u8; 32],
        };
        (client, server)
    }

    fn relay(from: &mut RecordingSink, to_engine: &mut Dtls12RecordEngine, to_sink: &mut RecordingSink) {
        for datagram in std::mem::take(&mut from.outbound) {
            to_engine.feed_datagram(&datagram, to_sink);
        }
    }

    fn run_loopback(require_cookie: bool) -> (RecordingSink, RecordingSink, Dtls12RecordEngine, Dtls12RecordEngine) {
        let (client_cfg, server_cfg) = configs(require_cookie);
        let mut client = Dtls12RecordEngine::new(client_cfg);
        let mut server = Dtls12RecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s); // ClientHello1 (-> HelloVerifyRequest if required)
        relay(&mut sink_s, &mut client, &mut sink_c); // HVR, or ServerHello..ServerHelloDone
        relay(&mut sink_c, &mut server, &mut sink_s); // ClientHello2, or CKE/CCS/client Finished
        if require_cookie {
            // One more round: ServerHello..ServerHelloDone, then the real
            // client flight, then the server's CCS/Finished.
            relay(&mut sink_s, &mut client, &mut sink_c);
            relay(&mut sink_c, &mut server, &mut sink_s);
        }
        relay(&mut sink_s, &mut client, &mut sink_c); // server CCS, Finished

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        (sink_c, sink_s, client, server)
    }

    #[test]
    fn loopback_handshake_completes_without_cookie_requirement() {
        let (sink_c, sink_s, _client, _server) = run_loopback(false);
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_c.events);
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_s.events);
        assert_eq!(sink_c.info.as_ref().and_then(|i| i.protocol()), Some("DTLSv1.2"));
        // No cookie round trip: client sends exactly ClientHello then its
        // CKE/CCS/Finished flight — two datagrams total, not three.
        assert_eq!(
            sink_c.events.iter().filter(|e| e.starts_with("datagram")).count(),
            2,
            "{:?}",
            sink_c.events
        );
    }

    #[test]
    fn loopback_handshake_completes_with_cookie_round_trip() {
        let (sink_c, sink_s, _client, _server) = run_loopback(true);
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_c.events);
        assert!(sink_s.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink_s.events);
        // Client sent at least two datagrams (ClientHello1, then ClientHello2).
        assert!(
            sink_c.events.iter().filter(|e| e.starts_with("datagram")).count() >= 2,
            "{:?}",
            sink_c.events
        );
    }

    #[test]
    fn application_data_round_trips_after_handshake() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback(false);
        client.send_application_data(b"hello from client", &mut sink_c);
        let wire = sink_c.outbound.pop().expect("one datagram queued");
        server.feed_datagram(&wire, &mut sink_s);
        assert_eq!(sink_s.app_data, vec![b"hello from client".to_vec()]);

        server.send_application_data(b"hello back", &mut sink_s);
        let wire = sink_s.outbound.pop().expect("one datagram queued");
        client.feed_datagram(&wire, &mut sink_c);
        assert_eq!(sink_c.app_data, vec![b"hello back".to_vec()]);
    }

    /// RFC 8446 §5.5 / RFC 9325 §4.4: RFC 6347 predates this guidance and
    /// has no rekey mechanism of its own, so a write key nearing its
    /// AES-GCM confidentiality limit must close the connection rather
    /// than keep encrypting past the safety margin.
    #[test]
    fn send_application_data_closes_connection_at_write_confidentiality_limit() {
        let (mut sink_c, _sink_s, mut client, _server) = run_loopback(false);
        client.state.write.set_next_seq_for_test(AES_GCM_CONFIDENTIALITY_LIMIT - 1);

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
    /// isolated to the read-side trigger alone — DTLS 1.2's sequence
    /// number travels in cleartext in the header (unlike DTLS 1.3's
    /// truncated/reconstructed form), so unlike the other three record
    /// layers this doesn't need the two sides' counters kept in lockstep.
    #[test]
    fn feed_datagram_closes_connection_at_read_confidentiality_limit() {
        let (_sink_c, mut sink_s, mut client, mut server) = run_loopback(false);
        client.state.write.set_next_seq_for_test(AES_GCM_CONFIDENTIALITY_LIMIT);
        let mut wire = Vec::new();
        record::write_record(&mut client.state.write, CONTENT_APPLICATION_DATA, b"one more under the old key", &mut wire);

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
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback(false);
        client.send_close_notify(&mut sink_c);
        let wire = sink_c.outbound.pop().expect("close_notify datagram queued");
        server.feed_datagram(&wire, &mut sink_s);
        assert!(sink_s.events.iter().any(|e| e == "peer_closed"), "{:?}", sink_s.events);
    }

    #[test]
    fn tampered_application_record_reports_protocol_error() {
        let (mut sink_c, mut sink_s, mut client, mut server) = run_loopback(false);
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

    /// The DTLS-specific case with no TCP analogue: a flight is lost
    /// entirely, the retransmit timer fires, and resending the exact same
    /// bytes lets the handshake complete anyway — `RetransmitState` is
    /// shared code with DTLS 1.3's engine, but this proves it's actually
    /// wired into this one too, not just inherited by type-checking.
    #[test]
    fn dropped_flight_completes_after_retransmit_timer_fires() {
        let (client_cfg, server_cfg) = configs(false);
        let mut client = Dtls12RecordEngine::new(client_cfg);
        let mut server = Dtls12RecordEngine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        assert!(sink_c.armed_timeout.is_some(), "{:?}", sink_c.events);
        sink_c.outbound.clear(); // simulate ClientHello1 being lost
        client.feed_timer(&mut sink_c);
        assert_eq!(sink_c.outbound.len(), 1, "timer fire must resend the same flight: {:?}", sink_c.events);

        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
    }

    /// RFC 5077 ticket resumption, reused unchanged from `tls12::engine`,
    /// over real DTLS 1.2 record framing — the abbreviated handshake is a
    /// good forcing function for epoch transitions (a second, independent
    /// `WriteKeys`/`ReadKeys` pair, activated at a *different* point in
    /// the flight than the full handshake's).
    #[test]
    fn ticket_resumption_completes_over_dtls_framing() {
        let creds = test_server_credentials();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let mut ticket_key = [0u8; 32];
        getrandom::getrandom(&mut ticket_key).unwrap();
        let store = crate::tls::Tls12ClientTicketStore::shared();

        let client_base = Tls12Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            trust_store: Some(trust),
            client_ticket_store: Some(store.clone()),
            ..Default::default()
        };
        let server_base = Tls12Config {
            role: Role::Server,
            server: Some(creds),
            ticket_key: Some(crate::tls::TicketKeys::single(ticket_key)),
            ..Default::default()
        };
        let client_cfg = || Dtls12Config {
            base: client_base.clone(),
            require_cookie: false,
            cookie_secret: [0u8; 32],
        };
        let server_cfg = || Dtls12Config {
            base: server_base.clone(),
            require_cookie: false,
            cookie_secret: [0x42u8; 32],
        };

        // First connection: full handshake, mints a ticket.
        let mut client = Dtls12RecordEngine::new(client_cfg());
        let mut server = Dtls12RecordEngine::new(server_cfg());
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        relay(&mut sink_c, &mut server, &mut sink_s);
        relay(&mut sink_s, &mut client, &mut sink_c);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        assert!(store.get("localhost").is_some());

        // Second connection: abbreviated handshake (no cookie round trip
        // either — this exercises the *other* early-return path in
        // `handle_server_client_hello`, `require_cookie` false).
        let mut client2 = Dtls12RecordEngine::new(client_cfg());
        let mut server2 = Dtls12RecordEngine::new(server_cfg());
        let mut sink_c2 = RecordingSink::default();
        let mut sink_s2 = RecordingSink::default();
        client2.start(&mut sink_c2);
        relay(&mut sink_c2, &mut server2, &mut sink_s2); // ClientHello
        relay(&mut sink_s2, &mut client2, &mut sink_c2); // SH, CCS, server Finished
        relay(&mut sink_c2, &mut server2, &mut sink_s2); // CCS, client Finished

        assert!(client2.is_complete(), "client2: {:?}", sink_c2.events);
        assert!(server2.is_complete(), "server2: {:?}", sink_s2.events);

        client2.send_application_data(b"resumed hello", &mut sink_c2);
        let wire = sink_c2.outbound.pop().expect("one datagram queued");
        server2.feed_datagram(&wire, &mut sink_s2);
        assert_eq!(sink_s2.app_data, vec![b"resumed hello".to_vec()]);
    }
}

