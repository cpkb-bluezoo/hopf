// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 handshake engine (RFC 5246 full handshake, RFC 4492/8422 ECDHE).
//!
//! Scope for this pass: ECDHE key exchange only (no static-RSA — no forward
//! secrecy, and it doesn't fit this codebase's PQC-first posture), GCM
//! cipher suites only (RFC 5289) — CBC is real, still-needed legacy-server
//! scope per the migration plan, but its MAC-then-encrypt record layer has
//! a real history of subtle timing side channels (Lucky Thirteen and
//! friends) that deserves its own dedicated, carefully-reviewed pass rather
//! than being rushed in alongside the rest of this. No client certificates,
//! no renegotiation. Session resumption is RFC 5077 stateless tickets (see
//! [`super::ticket`]), not RFC 5246 §7.3 session-ID server-side caching —
//! no server-side session state to scale/evict, and it reuses the same
//! opaque-ticket shape this crate already has for TLS 1.3.
//!
//! Reactive/sink-based like every other engine in this crate — see
//! [`Tls12EventSink`]. Deliberately independent of [`super::engine`] (the
//! TLS 1.3 engine) beyond the shared crypto floor; see [`super::messages`]'s
//! module doc for why.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use crate::crypto::digest::{HashAlgorithm, Sha256Context};
use crate::crypto::kx::EphemeralP256KeyPair;
use crate::crypto::prf::{prf, PrfHash};
use crate::crypto::signature::{
    ecdsa_p256_sha256_verify_spki, ecdsa_p256_sign, ecdsa_p384_sha384_verify_spki, ecdsa_p384_sign,
    rsa_sign_pkcs1_sha256, rsa_verify_pkcs1_sha256, EcdsaP256PrivateKey, EcdsaP384PrivateKey, RsaPrivateKey,
    RsaPublicKeyComponents,
};
use crate::crypto::trust::TrustStore;
use crate::crypto::x509::parse_certificate;
use crate::security::SecurityInfo;

use super::super::engine::ServerCredentials;
use super::super::handshake::verify::{pkcs8_key_kind, KeyKind};
use super::super::sink::{TlsProtocolError, VerifyRequest, VerifyResult};
use super::messages::{self, sig_alg, MessageType};
use super::ticket::{self, StoredTls12Ticket, Tls12ClientTicketStore};

/// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289).
pub const ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;
/// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (RFC 5289).
pub const ECDHE_ECDSA_AES256_GCM_SHA384: u16 = 0xC02C;
/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (RFC 5289).
pub const ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xC02F;
/// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (RFC 5289).
pub const ECDHE_RSA_AES256_GCM_SHA384: u16 = 0xC030;

/// Cipher suites this engine offers/accepts, in preference order.
pub const SUPPORTED_CIPHER_SUITES: &[u16] = &[
    ECDHE_ECDSA_AES128_GCM_SHA256,
    ECDHE_RSA_AES128_GCM_SHA256,
    ECDHE_ECDSA_AES256_GCM_SHA384,
    ECDHE_RSA_AES256_GCM_SHA384,
];

/// GCM key size this suite negotiates to (the record layer's concern; named
/// here since suite selection is where it's first known).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
}

impl CipherKind {
    /// AES key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            CipherKind::Aes128Gcm => 16,
            CipherKind::Aes256Gcm => 32,
        }
    }
}

fn cipher_info(suite: u16) -> Option<(CipherKind, PrfHash, KeyKind)> {
    match suite {
        ECDHE_ECDSA_AES128_GCM_SHA256 => Some((CipherKind::Aes128Gcm, PrfHash::Sha256, KeyKind::EcdsaP256)),
        ECDHE_ECDSA_AES256_GCM_SHA384 => Some((CipherKind::Aes256Gcm, PrfHash::Sha384, KeyKind::EcdsaP256)),
        ECDHE_RSA_AES128_GCM_SHA256 => Some((CipherKind::Aes128Gcm, PrfHash::Sha256, KeyKind::Rsa)),
        ECDHE_RSA_AES256_GCM_SHA384 => Some((CipherKind::Aes256Gcm, PrfHash::Sha384, KeyKind::Rsa)),
        _ => None,
    }
}

/// Fixed GCM key material for one direction — RFC 5288 §3 (`GenericAEADCipher`
/// with a per-record explicit nonce; only the 4-byte `salt`/fixed-IV lives
/// here, the explicit part is per-record).
#[derive(Clone)]
pub struct DirectionalKeyMaterial {
    /// AES-GCM key.
    pub key: Bytes,
    /// 4-byte fixed IV (`salt`), prepended to each record's 8-byte explicit nonce.
    pub fixed_iv: [u8; 4],
}

/// Client or server role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// TLS client.
    Client,
    /// TLS server.
    Server,
}

/// Configuration for one TLS 1.2 handshake.
#[derive(Clone)]
pub struct Config {
    /// Client or server.
    pub role: Role,
    /// Client SNI / server expected name.
    pub server_name: Option<String>,
    /// Server certificate + key (server role only) — RSA or ECDSA P-256/P-384
    /// PKCS#8, auto-detected the same way as the TLS 1.3 engine.
    pub server: Option<ServerCredentials>,
    /// Trust anchors for server chain verification (client role). `None`
    /// gates on [`Tls12EventSink::verification_requested`], matching the
    /// TLS 1.3 engine's `insecure_connector` pattern.
    pub trust_store: Option<TrustStore>,
    /// Server-role only: the RFC 5077 ticket-encryption key. `None` disables
    /// both accepting and issuing tickets — every handshake is full.
    pub ticket_key: Option<[u8; 32]>,
    /// Client-role only: shared ticket cache keyed by server name. `None`
    /// disables offering resumption (the `SessionTicket` extension is
    /// omitted entirely, not just sent empty).
    pub client_ticket_store: Option<Arc<Tls12ClientTicketStore>>,
}

/// Events emitted by [`Tls12Engine`] — consumed by the TLS 1.2 record layer.
pub trait Tls12EventSink {
    /// Plaintext handshake message bytes to send, framed by the record
    /// layer under whichever epoch is currently active for writing.
    fn handshake_data_ready(&mut self, data: &[u8]);

    /// Key material for both directions is ready — the record layer should
    /// cache it (not activate yet; that's a separate, later signal, since
    /// TLS 1.2's `ChangeCipherSpec` is a real wire event, not this crate's
    /// TLS 1.3 middlebox-compat theater).
    fn keys_ready(&mut self, cipher: CipherKind, client: DirectionalKeyMaterial, server: DirectionalKeyMaterial);

    /// Emit a real `ChangeCipherSpec` record now, then activate *this
    /// engine's own role's* write epoch using the material from
    /// [`Self::keys_ready`] — e.g. the client sends CCS and starts
    /// encrypting with `client` material; the server sends CCS and starts
    /// encrypting with `server` material. The peer's `ChangeCipherSpec`
    /// (switching *read* epoch) is a record-layer-only event this engine
    /// never sees directly — Finished simply arrives already decrypted.
    fn send_change_cipher_spec(&mut self);

    /// Handshake finished.
    fn handshake_complete(&mut self, info: SecurityInfo);

    /// Chain verification should run (possibly on `StorageExecutor`).
    fn verification_requested(&mut self, req: VerifyRequest);

    /// Non-fatal protocol failure.
    fn protocol_error(&mut self, err: TlsProtocolError);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    // client
    ExpectServerHello,
    ExpectCertificate,
    ExpectServerKeyExchange,
    ExpectServerHelloDone,
    ExpectServerFinished,
    ExpectServerFinishedResumed,
    // server
    ExpectClientKeyExchange,
    ExpectClientFinished,
    ExpectClientFinishedResumed,
    Complete,
    Failed,
}

struct Transcript {
    sha256: Sha256Context,
    sha384: Sha256Context,
}

impl Transcript {
    fn new() -> Self {
        Self {
            sha256: Sha256Context::new(HashAlgorithm::Sha256),
            sha384: Sha256Context::new(HashAlgorithm::Sha384),
        }
    }

    fn add_message(&mut self, wire: &[u8]) {
        self.sha256.update(wire);
        self.sha384.update(wire);
    }

    fn hash(&self, prf_hash: PrfHash) -> Vec<u8> {
        match prf_hash {
            PrfHash::Sha256 => self.sha256.clone().finish().into_bytes().to_vec(),
            PrfHash::Sha384 => self.sha384.clone().finish().into_bytes().to_vec(),
        }
    }
}

/// Incremental message buffer — see this module's doc comment for why
/// messages are pulled one at a time (`take_one`) from inside the engine's
/// own drain loop rather than eagerly batch-decoded: a verification gate
/// stopping mid-batch must leave undispatched messages untouched in here,
/// not silently discard them (the exact bug the TLS 1.3 engine had until
/// Phase 4 — see crypto-migration-plan.md).
struct MessageBuffer {
    buf: BytesMut,
}

/// Guard against a peer claiming an implausibly large handshake message.
const MAX_MESSAGE_LEN: usize = 1 << 20;

impl MessageBuffer {
    fn new() -> Self {
        Self { buf: BytesMut::new() }
    }

    fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// `Err` on a malformed/oversized length; `Ok(None)` if no complete
    /// message is buffered yet; otherwise `(type byte, body, full wire)`.
    fn take_one(&mut self) -> Result<Option<(u8, Bytes, Bytes)>, ()> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(());
        }
        let total = 4 + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let wire = self.buf.split_to(total).freeze();
        let body = wire.slice(4..);
        let msg_type = wire[0];
        Ok(Some((msg_type, body, wire)))
    }
}

/// Reactive TLS 1.2 handshake engine — full client/server ECDHE handshake.
pub struct Tls12Engine {
    config: Config,
    state: State,
    transcript: Transcript,
    parser: MessageBuffer,
    negotiated_suite: Option<u16>,
    cipher_kind: Option<CipherKind>,
    prf_hash: Option<PrfHash>,
    client_random: [u8; 32],
    server_random: [u8; 32],
    local_ecdhe: Option<EphemeralP256KeyPair>,
    peer_ec_point: Option<Bytes>,
    master_secret: Option<[u8; 48]>,
    peer_certs: Vec<Bytes>,
    peer_server_name: Option<String>,
    negotiated_alpn: Option<Bytes>,
    verify_id: u64,
    verify_pending: bool,
    /// Client role: the session ID offered in our own ClientHello, so a
    /// matching echo in ServerHello signals the server accepted our
    /// resumption offer (RFC 5077 §3.4 reuses RFC 5246 §7.3's echo signal).
    sent_session_id: Bytes,
    /// Client role: the cached ticket we offered, pending confirmation via
    /// the session-ID echo above. Cleared once the ServerHello resolves
    /// resumption one way or the other.
    pending_resume_ticket: Option<StoredTls12Ticket>,
    /// Server role: whether to mint and send a `NewSessionTicket` at the
    /// end of the full handshake currently in progress (the client
    /// advertised `SessionTicket` support and this isn't itself a resume).
    should_issue_ticket: bool,
    /// Client role: whether the server echoed `SessionTicket` in its
    /// ServerHello (RFC 5077 §3.2) — only then should a `NewSessionTicket`
    /// message in the final flight be accepted rather than treated as a
    /// protocol violation.
    expect_new_session_ticket: bool,
}

impl Tls12Engine {
    /// Create an engine; call [`Self::start`] to emit the first flight (client).
    pub fn new(config: Config) -> Self {
        Self {
            config,
            state: State::Initial,
            transcript: Transcript::new(),
            parser: MessageBuffer::new(),
            negotiated_suite: None,
            cipher_kind: None,
            prf_hash: None,
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            local_ecdhe: None,
            peer_ec_point: None,
            master_secret: None,
            peer_certs: Vec::new(),
            peer_server_name: None,
            negotiated_alpn: None,
            verify_id: 0,
            verify_pending: false,
            sent_session_id: Bytes::new(),
            pending_resume_ticket: None,
            should_issue_ticket: false,
            expect_new_session_ticket: false,
        }
    }

    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: Tls12EventSink>(&mut self, sink: &mut S) {
        if self.state != State::Initial || self.config.role != Role::Client {
            if self.config.role == Role::Server {
                self.state = State::Initial; // explicit: server "starts" by waiting
            }
            if self.config.role != Role::Client {
                return;
            }
        }
        let mut random = [0u8; 32];
        let _ = getrandom::getrandom(&mut random);
        self.client_random = random;

        let mut session_id = Bytes::new();
        let mut ticket_offer: Option<Bytes> = None;
        if let Some(store) = &self.config.client_ticket_store {
            if let Some(stored) = self.config.server_name.as_deref().and_then(|name| store.get(name)) {
                let mut sid = [0u8; 32];
                let _ = getrandom::getrandom(&mut sid);
                session_id = Bytes::copy_from_slice(&sid);
                ticket_offer = Some(stored.ticket.clone());
                self.pending_resume_ticket = Some(stored);
            } else {
                ticket_offer = Some(Bytes::new()); // advertise support, no ticket yet
            }
        }
        self.sent_session_id = session_id.clone();

        let params = messages::ClientHelloParams {
            random,
            session_id: &session_id,
            cipher_suites: SUPPORTED_CIPHER_SUITES,
            server_name: self.config.server_name.as_deref(),
            session_ticket: ticket_offer.as_deref(),
        };
        let wire = messages::build_client_hello(&params);
        self.emit(&wire, sink);
        self.state = State::ExpectServerHello;
    }

    /// Consume handshake bytes from the peer (already-decrypted record payload).
    pub fn feed_handshake_data<S: Tls12EventSink>(&mut self, input: &mut &[u8], sink: &mut S) {
        self.parser.feed(input);
        *input = &[];
        self.drain(sink);
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: Tls12EventSink>(&mut self, result: VerifyResult, sink: &mut S) {
        if !self.verify_pending || result.id != self.verify_id {
            return;
        }
        self.verify_pending = false;
        if !result.ok {
            self.fail(sink, "certificate verification failed");
            return;
        }
        self.drain(sink);
    }

    /// Whether the handshake has finished successfully.
    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn drain<S: Tls12EventSink>(&mut self, sink: &mut S) {
        loop {
            if self.verify_pending || self.state == State::Complete || self.state == State::Failed {
                return;
            }
            match self.parser.take_one() {
                Err(()) => {
                    self.fail(sink, "oversized or malformed handshake message");
                    return;
                }
                Ok(None) => return,
                Ok(Some((msg_type, body, wire))) => {
                    if !self.dispatch(msg_type, &body, wire, sink) {
                        return;
                    }
                }
            }
        }
    }

    fn dispatch<S: Tls12EventSink>(&mut self, msg_type: u8, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(mt) = MessageType::from_u8(msg_type) else {
            self.fail(sink, "unknown handshake message type");
            return false;
        };
        match (self.config.role, self.state, mt) {
            (Role::Client, State::ExpectServerHello, MessageType::ServerHello) => self.on_server_hello(body, wire, sink),
            (Role::Client, State::ExpectCertificate, MessageType::Certificate) => self.on_certificate(body, wire, sink),
            (Role::Client, State::ExpectServerKeyExchange, MessageType::ServerKeyExchange) => {
                self.on_server_key_exchange(body, wire, sink)
            }
            (Role::Client, State::ExpectServerHelloDone, MessageType::ServerHelloDone) => {
                self.on_server_hello_done(wire, sink)
            }
            (Role::Client, State::ExpectServerFinished, MessageType::Finished) => self.on_server_finished(body, wire, sink),
            (Role::Client, State::ExpectServerFinished, MessageType::NewSessionTicket) => {
                self.on_new_session_ticket(body, wire, sink)
            }
            (Role::Client, State::ExpectServerFinishedResumed, MessageType::Finished) => {
                self.on_server_finished_resumed(body, wire, sink)
            }
            (Role::Server, State::Initial, MessageType::ClientHello) => self.on_client_hello(body, wire, sink),
            (Role::Server, State::ExpectClientKeyExchange, MessageType::ClientKeyExchange) => {
                self.on_client_key_exchange(body, wire, sink)
            }
            (Role::Server, State::ExpectClientFinished, MessageType::Finished) => self.on_client_finished(body, wire, sink),
            (Role::Server, State::ExpectClientFinishedResumed, MessageType::Finished) => {
                self.on_client_finished_resumed(body, wire, sink)
            }
            _ => {
                self.fail(sink, "unexpected handshake message");
                false
            }
        }
    }

    fn emit<S: Tls12EventSink>(&mut self, wire: &[u8], sink: &mut S) {
        self.transcript.add_message(wire);
        sink.handshake_data_ready(wire);
    }

    // ---- client ----

    fn on_server_hello<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(sh) = messages::parse_server_hello(body) else {
            self.fail(sink, "malformed ServerHello");
            return false;
        };
        let Some((kind, prf_hash, _)) = cipher_info(sh.cipher_suite) else {
            self.fail(sink, "server selected an unsupported cipher suite");
            return false;
        };
        self.negotiated_suite = Some(sh.cipher_suite);
        self.cipher_kind = Some(kind);
        self.prf_hash = Some(prf_hash);
        self.server_random = sh.random;
        self.expect_new_session_ticket = sh.session_ticket_offered;
        self.transcript.add_message(&wire);

        let resuming = !self.sent_session_id.is_empty() && sh.session_id == self.sent_session_id;
        if resuming {
            let Some(stored) = self.pending_resume_ticket.take() else {
                self.fail(sink, "server echoed a resumption session id we never offered");
                return false;
            };
            if stored.cipher_suite != sh.cipher_suite {
                self.fail(sink, "server echoed session id for resumption but selected a different cipher suite");
                return false;
            }
            self.master_secret = Some(stored.master_secret);
            let Some((client_keys, server_keys)) = self.compute_key_material() else {
                self.fail(sink, "key material derivation failed");
                return false;
            };
            sink.keys_ready(kind, client_keys, server_keys);
            self.state = State::ExpectServerFinishedResumed;
            return true;
        }
        self.pending_resume_ticket = None;
        self.state = State::ExpectCertificate;
        true
    }

    fn on_server_finished_resumed<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let expected = self.finished_verify_data(false);
        if body != expected.as_slice() {
            self.fail(sink, "server Finished verify failed (resumed handshake)");
            return false;
        }
        self.transcript.add_message(&wire);

        sink.send_change_cipher_spec();
        let vd = self.finished_verify_data(true);
        let fin = messages::build_finished(&vd);
        self.emit(&fin, sink);
        self.finish(sink);
        true
    }

    fn on_new_session_ticket<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        if !self.expect_new_session_ticket {
            self.fail(sink, "unexpected NewSessionTicket (server never echoed SessionTicket support)");
            return false;
        }
        if let Some((lifetime_hint, ticket)) = messages::parse_new_session_ticket(body) {
            if let (Some(store), Some(name), Some(master_secret), Some(cipher_suite)) = (
                &self.config.client_ticket_store,
                self.config.server_name.as_deref(),
                self.master_secret,
                self.negotiated_suite,
            ) {
                let lifetime_secs = if lifetime_hint == 0 { ticket::TICKET_LIFETIME_SECS } else { lifetime_hint };
                store.put(
                    name,
                    StoredTls12Ticket {
                        ticket,
                        master_secret,
                        cipher_suite,
                        received_at: std::time::Instant::now(),
                        lifetime_secs,
                    },
                );
            }
        }
        self.transcript.add_message(&wire);
        true
    }

    fn on_certificate<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(certs) = messages::parse_certificate(body) else {
            self.fail(sink, "malformed Certificate");
            return false;
        };
        self.transcript.add_message(&wire);
        self.peer_certs = certs;
        self.verify_id += 1;
        self.verify_pending = true;
        sink.verification_requested(VerifyRequest {
            id: self.verify_id,
            peer_chain: self.peer_certs.clone(),
            server_name: self.config.server_name.clone(),
        });
        if let Some(store) = &self.config.trust_store {
            let ok = store.verify_server_chain(&self.peer_certs, self.config.server_name.as_deref()).is_ok();
            self.verify_pending = false;
            if !ok {
                self.fail(sink, "certificate verification failed");
                return false;
            }
            self.state = State::ExpectServerKeyExchange;
            return true;
        }
        self.state = State::ExpectServerKeyExchange;
        false // gate: wait for feed_verification_result
    }

    fn on_server_key_exchange<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(ske) = messages::parse_server_key_exchange(body) else {
            self.fail(sink, "malformed or unsupported ServerKeyExchange (only named-curve secp256r1 ECDHE is supported)");
            return false;
        };
        let Some(leaf) = self.peer_certs.first() else {
            self.fail(sink, "ServerKeyExchange before Certificate");
            return false;
        };
        let mut signed = BytesMut::with_capacity(64 + ske.signed_params.len());
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&ske.signed_params);
        if !verify_ske_signature(leaf, ske.sig_hash, ske.sig_alg, &signed, &ske.signature) {
            self.fail(sink, "ServerKeyExchange signature invalid");
            return false;
        }
        self.peer_ec_point = Some(ske.ec_point);
        self.transcript.add_message(&wire);
        self.state = State::ExpectServerHelloDone;
        true
    }

    fn on_server_hello_done<S: Tls12EventSink>(&mut self, wire: Bytes, sink: &mut S) -> bool {
        self.transcript.add_message(&wire);
        let Some(peer_point) = self.peer_ec_point.take() else {
            self.fail(sink, "missing server key share");
            return false;
        };
        let Ok(local) = EphemeralP256KeyPair::generate() else {
            self.fail(sink, "key generation failed");
            return false;
        };
        let client_point = Bytes::copy_from_slice(local.public_key());
        let Ok(pre_master) = local.agree(&peer_point) else {
            self.fail(sink, "key agreement failed");
            return false;
        };
        self.derive_master_secret(&pre_master);

        let cke = messages::build_client_key_exchange(&client_point);
        self.emit(&cke, sink);

        let Some((client_keys, server_keys)) = self.compute_key_material() else {
            self.fail(sink, "key material derivation failed");
            return false;
        };
        sink.keys_ready(self.cipher_kind.expect("cipher negotiated"), client_keys, server_keys);
        sink.send_change_cipher_spec();

        let vd = self.finished_verify_data(true);
        let fin = messages::build_finished(&vd);
        self.emit(&fin, sink);
        self.state = State::ExpectServerFinished;
        true
    }

    fn on_server_finished<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let expected = self.finished_verify_data(false);
        if body != expected.as_slice() {
            self.fail(sink, "server Finished verify failed");
            return false;
        }
        self.transcript.add_message(&wire);
        self.finish(sink);
        true
    }

    // ---- server ----

    fn on_client_hello<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(ch) = messages::parse_client_hello(body) else {
            self.fail(sink, "malformed ClientHello");
            return false;
        };
        let Some(creds) = self.config.server.clone() else {
            self.fail(sink, "server credentials not configured");
            return false;
        };
        let Some(our_kind) = pkcs8_key_kind(&creds.signing_key_pkcs8) else {
            self.fail(sink, "unsupported server signing key");
            return false;
        };

        let resume_payload = ch.session_ticket.as_ref().filter(|t| !t.is_empty()).and_then(|offered| {
            let key = self.config.ticket_key.as_ref()?;
            let payload = ticket::open_ticket(key, offered)?;
            if payload.is_expired() || !ch.cipher_suites.contains(&payload.cipher_suite) || cipher_info(payload.cipher_suite).is_none() {
                return None;
            }
            Some(payload)
        });
        self.should_issue_ticket = self.config.ticket_key.is_some() && ch.session_ticket.is_some() && resume_payload.is_none();
        self.client_random = ch.random;
        self.peer_server_name = ch.server_name.clone();
        self.transcript.add_message(&wire);

        if let Some(payload) = resume_payload {
            let (kind, prf_hash, _) = cipher_info(payload.cipher_suite).expect("checked above");
            self.negotiated_suite = Some(payload.cipher_suite);
            self.cipher_kind = Some(kind);
            self.prf_hash = Some(prf_hash);
            self.master_secret = Some(payload.master_secret);

            let mut server_random = [0u8; 32];
            let _ = getrandom::getrandom(&mut server_random);
            self.server_random = server_random;
            // No new ticket is minted on a resumption in this implementation
            // (see this module's doc comment), so no SessionTicket echo here.
            let sh = messages::build_server_hello(&server_random, &ch.session_id, payload.cipher_suite, false);
            self.emit(&sh, sink);

            let Some((client_keys, server_keys)) = self.compute_key_material() else {
                self.fail(sink, "key material derivation failed");
                return false;
            };
            sink.keys_ready(kind, client_keys, server_keys);
            sink.send_change_cipher_spec();
            let vd = self.finished_verify_data(false);
            let fin = messages::build_finished(&vd);
            self.emit(&fin, sink);
            self.state = State::ExpectClientFinishedResumed;
            return true;
        }

        let Some(suite) = SUPPORTED_CIPHER_SUITES.iter().copied().find(|s| {
            ch.cipher_suites.contains(s) && cipher_info(*s).is_some_and(|(_, _, k)| k == our_kind)
        }) else {
            self.fail(sink, "no mutually supported cipher suite for this server's key type");
            return false;
        };
        let (kind, prf_hash, _) = cipher_info(suite).expect("just matched");
        self.negotiated_suite = Some(suite);
        self.cipher_kind = Some(kind);
        self.prf_hash = Some(prf_hash);

        let mut server_random = [0u8; 32];
        let _ = getrandom::getrandom(&mut server_random);
        self.server_random = server_random;
        let sh = messages::build_server_hello(&server_random, &[], suite, self.should_issue_ticket);
        self.emit(&sh, sink);

        let cert_refs: Vec<&[u8]> = creds.cert_chain.iter().map(|c| c.as_ref()).collect();
        let cert_msg = messages::build_certificate(&cert_refs);
        self.emit(&cert_msg, sink);

        let Ok(local) = EphemeralP256KeyPair::generate() else {
            self.fail(sink, "key generation failed");
            return false;
        };
        let server_point = Bytes::copy_from_slice(local.public_key());
        let signed_params = messages::server_ecdh_params_bytes(&server_point);
        let mut signed = BytesMut::with_capacity(64 + signed_params.len());
        signed.extend_from_slice(&self.client_random);
        signed.extend_from_slice(&self.server_random);
        signed.extend_from_slice(&signed_params);
        let Some((sig_hash, sig_alg, signature)) = sign_ske(&creds.signing_key_pkcs8, &signed) else {
            self.fail(sink, "unsupported or invalid server signing key");
            return false;
        };
        let ske = messages::build_server_key_exchange(&server_point, sig_hash, sig_alg, &signature);
        self.emit(&ske, sink);
        self.local_ecdhe = Some(local);

        let shd = messages::build_server_hello_done();
        self.emit(&shd, sink);

        self.state = State::ExpectClientKeyExchange;
        true
    }

    fn on_client_key_exchange<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(client_point) = messages::parse_client_key_exchange(body) else {
            self.fail(sink, "malformed ClientKeyExchange");
            return false;
        };
        self.transcript.add_message(&wire);
        let Some(local) = self.local_ecdhe.take() else {
            self.fail(sink, "missing server key share");
            return false;
        };
        let Ok(pre_master) = local.agree(&client_point) else {
            self.fail(sink, "key agreement failed");
            return false;
        };
        self.derive_master_secret(&pre_master);
        let Some((client_keys, server_keys)) = self.compute_key_material() else {
            self.fail(sink, "key material derivation failed");
            return false;
        };
        sink.keys_ready(self.cipher_kind.expect("cipher negotiated"), client_keys, server_keys);
        self.state = State::ExpectClientFinished;
        true
    }

    fn on_client_finished<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let expected = self.finished_verify_data(true);
        if body != expected.as_slice() {
            self.fail(sink, "client Finished verify failed");
            return false;
        }
        self.transcript.add_message(&wire);

        if self.should_issue_ticket {
            if let (Some(key), Some(master_secret), Some(suite)) =
                (&self.config.ticket_key, self.master_secret, self.negotiated_suite)
            {
                if let Some(nst) = ticket::mint_new_session_ticket(key, &master_secret, suite) {
                    self.emit(&nst, sink);
                }
            }
        }

        sink.send_change_cipher_spec();
        let vd = self.finished_verify_data(false);
        let fin = messages::build_finished(&vd);
        self.emit(&fin, sink);
        self.finish(sink);
        true
    }

    fn on_client_finished_resumed<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let expected = self.finished_verify_data(true);
        if body != expected.as_slice() {
            self.fail(sink, "client Finished verify failed (resumed handshake)");
            return false;
        }
        self.transcript.add_message(&wire);
        self.finish(sink);
        true
    }

    // ---- shared ----

    fn derive_master_secret(&mut self, pre_master: &[u8]) {
        let prf_hash = self.prf_hash.expect("cipher negotiated");
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.client_random);
        seed.extend_from_slice(&self.server_random);
        let out = prf(prf_hash, pre_master, b"master secret", &seed, 48);
        let mut master = [0u8; 48];
        master.copy_from_slice(&out);
        self.master_secret = Some(master);
    }

    /// Key block (RFC 5246 §6.3): GCM suites need only `enc_key` + `fixed_iv`
    /// per direction (no MAC keys — AEAD). Order matches the RFC:
    /// client_write_key, server_write_key, client_write_IV, server_write_IV.
    fn compute_key_material(&self) -> Option<(DirectionalKeyMaterial, DirectionalKeyMaterial)> {
        let prf_hash = self.prf_hash?;
        let cipher = self.cipher_kind?;
        let master = self.master_secret?;
        let key_len = cipher.key_len();
        let total = 2 * key_len + 2 * 4;
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.server_random);
        seed.extend_from_slice(&self.client_random);
        let block = prf(prf_hash, &master, b"key expansion", &seed, total);

        let mut i = 0;
        let client_key = Bytes::copy_from_slice(&block[i..i + key_len]);
        i += key_len;
        let server_key = Bytes::copy_from_slice(&block[i..i + key_len]);
        i += key_len;
        let mut client_iv = [0u8; 4];
        client_iv.copy_from_slice(&block[i..i + 4]);
        i += 4;
        let mut server_iv = [0u8; 4];
        server_iv.copy_from_slice(&block[i..i + 4]);

        Some((
            DirectionalKeyMaterial { key: client_key, fixed_iv: client_iv },
            DirectionalKeyMaterial { key: server_key, fixed_iv: server_iv },
        ))
    }

    /// `Finished.verify_data` (RFC 5246 §7.4.9) — `for_client` selects the
    /// `"client finished"`/`"server finished"` label, independent of this
    /// engine's own role (the client engine needs both: its own to send,
    /// the server's to verify — and vice versa).
    fn finished_verify_data(&self, for_client: bool) -> Vec<u8> {
        let prf_hash = self.prf_hash.expect("cipher negotiated");
        let master = self.master_secret.expect("master secret derived");
        let label: &[u8] = if for_client { b"client finished" } else { b"server finished" };
        let hash = self.transcript.hash(prf_hash);
        prf(prf_hash, &master, label, &hash, 12)
    }

    fn finish<S: Tls12EventSink>(&mut self, sink: &mut S) {
        if self.state == State::Complete {
            return;
        }
        self.state = State::Complete;
        let sni = match self.config.role {
            Role::Server => self.peer_server_name.clone(),
            Role::Client => self.config.server_name.clone(),
        };
        let suite_name = match self.negotiated_suite {
            Some(ECDHE_ECDSA_AES128_GCM_SHA256) => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            Some(ECDHE_ECDSA_AES256_GCM_SHA384) => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            Some(ECDHE_RSA_AES128_GCM_SHA256) => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            Some(ECDHE_RSA_AES256_GCM_SHA384) => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            _ => "unknown",
        };
        let info = SecurityInfo::secure(self.negotiated_alpn.clone(), Some("TLSv1.2".to_string()), Some(suite_name.to_string()))
            .with_sni(sni);
        sink.handshake_complete(info);
    }

    fn fail<S: Tls12EventSink>(&mut self, sink: &mut S, msg: &str) {
        if self.state != State::Failed {
            self.state = State::Failed;
            sink.protocol_error(TlsProtocolError::new(msg));
        }
    }
}

fn verify_ske_signature(leaf_cert_der: &[u8], sig_hash: u8, sig_alg: u8, message: &[u8], signature: &[u8]) -> bool {
    let Some(parsed) = parse_certificate(leaf_cert_der) else {
        return false;
    };
    match (sig_hash, sig_alg) {
        (sig_alg::HASH_SHA256, sig_alg::SIG_ECDSA) => ecdsa_p256_sha256_verify_spki(&parsed.spki_der, message, signature),
        (sig_alg::HASH_SHA384, sig_alg::SIG_ECDSA) => ecdsa_p384_sha384_verify_spki(&parsed.spki_der, message, signature),
        (sig_alg::HASH_SHA256, sig_alg::SIG_RSA) => {
            let Some((n, e)) = rsa_n_e_from_spki(&parsed.spki_der) else {
                return false;
            };
            rsa_verify_pkcs1_sha256(RsaPublicKeyComponents { n: &n, e: &e }, message, signature)
        }
        _ => false,
    }
}

/// Extract RSA `(n, e)` from an SPKI DER — `verify_cert_signature`'s
/// `UnparsedPublicKey` path takes SPKI directly, but the DKIM-oriented
/// `rsa_verify_pkcs1_sha256` facade function takes raw components instead
/// (RFC 3110 wire shape), so this pulls them out of the SPKI's
/// `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }` inner BIT STRING.
fn rsa_n_e_from_spki(spki_der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
    // `read_tlv` already strips each element's own tag+length, so `bit_string`
    // below is the BIT STRING's raw content (unused-bits count byte + data) —
    // not a fresh TLV to re-parse a length out of.
    let outer = read_sequence(spki_der)?;
    let (_alg, rest) = read_tlv(outer)?;
    let (bit_string, _) = read_tlv(rest)?;
    // First byte of BIT STRING content is the unused-bits count (0 here).
    let rsa_pub = bit_string.get(1..)?;
    let inner = read_sequence(rsa_pub)?;
    let (modulus, rest) = read_tlv(inner)?;
    let (exponent, _) = read_tlv(rest)?;
    Some((strip_int_padding(modulus).to_vec(), strip_int_padding(exponent).to_vec()))
}

fn strip_int_padding(der_integer: &[u8]) -> &[u8] {
    // read_tlv already stripped the 0x02 tag + length; this is just the
    // INTEGER content, which may carry a leading 0x00 pad byte.
    if der_integer.len() > 1 && der_integer[0] == 0 {
        &der_integer[1..]
    } else {
        der_integer
    }
}

fn read_sequence(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() != Some(&0x30) {
        return None;
    }
    let (_, body) = read_tlv_body(bytes)?;
    Some(body)
}

/// Read one DER TLV; returns `(content, rest-of-buffer-after-this-TLV)`.
fn read_tlv(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, body) = read_tlv_body(bytes)?;
    Some((&body[..len], &body[len..]))
}

/// Read one DER TLV's length + content-start, ignoring the tag byte.
fn read_tlv_body(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let first_len_byte = *bytes.get(1)?;
    if first_len_byte & 0x80 == 0 {
        Some((first_len_byte as usize, bytes.get(2..)?))
    } else {
        let n = (first_len_byte & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *bytes.get(2 + i)? as usize;
        }
        Some((len, bytes.get(2 + n..)?))
    }
}

fn sign_ske(signing_key_pkcs8: &[u8], message: &[u8]) -> Option<(u8, u8, Bytes)> {
    match pkcs8_key_kind(signing_key_pkcs8)? {
        KeyKind::EcdsaP256 => {
            let key = EcdsaP256PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((sig_alg::HASH_SHA256, sig_alg::SIG_ECDSA, ecdsa_p256_sign(&key, message).ok()?))
        }
        KeyKind::EcdsaP384 => {
            let key = EcdsaP384PrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((sig_alg::HASH_SHA384, sig_alg::SIG_ECDSA, ecdsa_p384_sign(&key, message).ok()?))
        }
        KeyKind::Rsa => {
            let key = RsaPrivateKey::from_pkcs8(signing_key_pkcs8).ok()?;
            Some((sig_alg::HASH_SHA256, sig_alg::SIG_RSA, rsa_sign_pkcs1_sha256(&key, message).ok()?))
        }
        KeyKind::Ed25519 => None, // TLS 1.2 has no SignatureAndHashAlgorithm codepoint for Ed25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
        outbound: Vec<Bytes>,
        keys: Option<(CipherKind, DirectionalKeyMaterial, DirectionalKeyMaterial)>,
        ccs_sent: bool,
        info: Option<SecurityInfo>,
    }

    impl Tls12EventSink for RecordingSink {
        fn handshake_data_ready(&mut self, data: &[u8]) {
            self.events.push(format!("outbound {} bytes", data.len()));
            self.outbound.push(Bytes::copy_from_slice(data));
        }
        fn keys_ready(&mut self, cipher: CipherKind, client: DirectionalKeyMaterial, server: DirectionalKeyMaterial) {
            self.events.push("keys_ready".into());
            self.keys = Some((cipher, client, server));
        }
        fn send_change_cipher_spec(&mut self) {
            self.events.push("send_change_cipher_spec".into());
            self.ccs_sent = true;
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
    }

    fn test_server_credentials_ecdsa() -> ServerCredentials {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8: Bytes::from(key_pair.serialize_der()),
        }
    }

    fn take_outbound(sink: &mut RecordingSink) -> Vec<Bytes> {
        std::mem::take(&mut sink.outbound)
    }

    fn relay(from: &mut Tls12Engine, into: &mut Tls12Engine, outbound: Vec<Bytes>, sink: &mut RecordingSink) {
        let _ = from;
        for chunk in outbound {
            let mut input = chunk.as_ref();
            into.feed_handshake_data(&mut input, sink);
        }
    }

    #[test]
    fn full_ecdhe_handshake_completes_client_and_server() {
        let creds = test_server_credentials_ecdsa();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());

        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
        };

        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        // ClientHello -> server
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        // ServerHello, Certificate, ServerKeyExchange, ServerHelloDone -> client
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);
        // ClientKeyExchange, Finished -> server
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        // server's Finished -> client
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        assert!(sink_c.keys.is_some(), "client never got keys_ready: {:?}", sink_c.events);
        assert!(sink_s.keys.is_some(), "server never got keys_ready: {:?}", sink_s.events);
        assert!(sink_c.ccs_sent);
        assert!(sink_s.ccs_sent);

        let (kind_c, client_keys_c, server_keys_c) = sink_c.keys.unwrap();
        let (kind_s, client_keys_s, server_keys_s) = sink_s.keys.unwrap();
        assert_eq!(kind_c, CipherKind::Aes128Gcm, "ECDSA cert + client default order should pick 128-GCM first");
        assert_eq!(kind_s, kind_c);
        assert_eq!(client_keys_c.key, client_keys_s.key, "client and server must derive identical client_write key");
        assert_eq!(server_keys_c.key, server_keys_s.key, "client and server must derive identical server_write key");
        assert_eq!(client_keys_c.fixed_iv, client_keys_s.fixed_iv);
        assert_eq!(server_keys_c.fixed_iv, server_keys_s.fixed_iv);

        let info = sink_c.info.expect("client security info");
        assert_eq!(info.protocol(), Some("TLSv1.2"));
    }

    /// Wraps an `aws-lc-rs`-generated RSA key so `rcgen` can build a
    /// self-signed certificate around it without needing `rcgen`'s own RSA
    /// generation (which doesn't exist) or a `rustls-pki-types`
    /// dev-dependency just for this one test.
    /// `rcgen::RemoteKeyPair::public_key()` doesn't want a full SPKI — it
    /// wraps whatever this returns in its own SPKI `SEQUENCE` (algorithm +
    /// this as the BIT STRING content), so it wants exactly the *inner*
    /// `RSAPublicKey ::= SEQUENCE { modulus, publicExponent }` DER.
    struct RemoteRsaSigner {
        key: aws_lc_rs::rsa::KeyPair,
        rsa_public_key_der: Vec<u8>,
    }

    impl rcgen::RemoteKeyPair for RemoteRsaSigner {
        fn public_key(&self) -> &[u8] {
            &self.rsa_public_key_der
        }
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
            rsa_sign_pkcs1_sha256(&RsaPrivateKey::from_pkcs8(&pkcs8_der_of(&self.key)).unwrap(), msg)
                .map(|b| b.to_vec())
                .map_err(|_| rcgen::Error::RemoteKeyError)
        }
        fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
            &rcgen::PKCS_RSA_SHA256
        }
    }

    fn pkcs8_der_of(key: &aws_lc_rs::rsa::KeyPair) -> Vec<u8> {
        use aws_lc_rs::encoding::AsDer;
        key.as_der().unwrap().as_ref().to_vec()
    }

    /// `SEQUENCE { INTEGER n, INTEGER e }` — the DER `RSAPublicKey` rcgen
    /// wants from [`rcgen::RemoteKeyPair::public_key`] (see its doc comment
    /// above), built from the `(n, e)` this module already knows how to
    /// pull out of a full SPKI via [`rsa_n_e_from_spki`].
    fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
        fn asn1_length(len: usize) -> Vec<u8> {
            if len < 128 {
                vec![len as u8]
            } else if len < 256 {
                vec![0x81, len as u8]
            } else {
                vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
            }
        }
        fn asn1_integer(bytes: &[u8]) -> Vec<u8> {
            let needs_pad = !bytes.is_empty() && bytes[0] & 0x80 != 0;
            let len = bytes.len() + usize::from(needs_pad);
            let mut out = vec![0x02u8];
            out.extend(asn1_length(len));
            if needs_pad {
                out.push(0x00);
            }
            out.extend_from_slice(bytes);
            out
        }
        let n_der = asn1_integer(n);
        let e_der = asn1_integer(e);
        let mut content = Vec::with_capacity(n_der.len() + e_der.len());
        content.extend_from_slice(&n_der);
        content.extend_from_slice(&e_der);
        let mut out = vec![0x30u8, 0x82, (content.len() >> 8) as u8, content.len() as u8];
        out.extend_from_slice(&content);
        out
    }

    #[test]
    fn full_ecdhe_handshake_with_rsa_server_cert() {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeyPair as RsaGenKeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;

        let generated = RsaGenKeyPair::generate(KeySize::Rsa2048).unwrap();
        let spki_der = generated.public_key().as_der().unwrap().as_ref().to_vec();
        let (n, e) = rsa_n_e_from_spki(&spki_der).expect("extract n/e from freshly generated key's own SPKI");
        let signing_key_pkcs8 = Bytes::from(pkcs8_der_of(&generated));
        let remote = RemoteRsaSigner { key: generated, rsa_public_key_der: rsa_public_key_der(&n, &e) };
        let rcgen_key = rcgen::KeyPair::from_remote(Box::new(remote)).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&rcgen_key).unwrap();
        let creds = ServerCredentials {
            cert_chain: vec![Bytes::copy_from_slice(cert.der())],
            signing_key_pkcs8,
        };
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());

        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
        };

        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);

        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
    }

    #[test]
    fn tampered_finished_is_rejected() {
        let creds = test_server_credentials_ecdsa();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
        };
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();

        client.start(&mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);

        let mut outbound = take_outbound(&mut sink_c);
        // Corrupt the last message (client Finished) before delivering.
        let last = outbound.last_mut().unwrap();
        let mut corrupted = last.to_vec();
        let n = corrupted.len();
        corrupted[n - 1] ^= 0xff;
        *last = Bytes::from(corrupted);
        relay(&mut client, &mut server, outbound, &mut sink_s);

        assert!(!server.is_complete());
        assert!(sink_s.events.iter().any(|e| e.starts_with("protocol_error")), "{:?}", sink_s.events);
    }

    fn message_types(msgs: &[Bytes]) -> Vec<u8> {
        msgs.iter().map(|m| m[0]).collect()
    }

    fn run_full_handshake(
        client: &mut Tls12Engine,
        server: &mut Tls12Engine,
        sink_c: &mut RecordingSink,
        sink_s: &mut RecordingSink,
    ) {
        client.start(sink_c);
        relay(client, server, take_outbound(sink_c), sink_s);
        relay(server, client, take_outbound(sink_s), sink_c);
        relay(client, server, take_outbound(sink_c), sink_s);
        relay(server, client, take_outbound(sink_s), sink_c);
    }

    #[test]
    fn ticket_resumption_completes_abbreviated_handshake_and_skips_key_exchange() {
        let creds = test_server_credentials_ecdsa();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let mut ticket_key = [0u8; 32];
        getrandom::getrandom(&mut ticket_key).unwrap();
        let store = Tls12ClientTicketStore::shared();

        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: Some(store.clone()),
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: Some(ticket_key),
            client_ticket_store: None,
        };

        // --- first connection: full handshake, server issues a ticket ---
        let mut client = Tls12Engine::new(client_cfg.clone());
        let mut server = Tls12Engine::new(server_cfg.clone());
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        run_full_handshake(&mut client, &mut server, &mut sink_c, &mut sink_s);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        assert!(store.get("localhost").is_some(), "client should have cached a ticket from the full handshake");

        // --- second connection: abbreviated (resumed) handshake ---
        let mut client2 = Tls12Engine::new(client_cfg);
        let mut server2 = Tls12Engine::new(server_cfg);
        let mut sink_c2 = RecordingSink::default();
        let mut sink_s2 = RecordingSink::default();

        client2.start(&mut sink_c2);
        let ch_flight = take_outbound(&mut sink_c2);
        assert_eq!(message_types(&ch_flight), vec![1], "just ClientHello");
        relay(&mut client2, &mut server2, ch_flight, &mut sink_s2);

        let sh_flight = take_outbound(&mut sink_s2);
        assert_eq!(
            message_types(&sh_flight),
            vec![2, 20],
            "abbreviated server flight should be ServerHello + Finished only, no Certificate/ServerKeyExchange/ServerHelloDone"
        );
        relay(&mut server2, &mut client2, sh_flight, &mut sink_c2);

        let cf_flight = take_outbound(&mut sink_c2);
        assert_eq!(message_types(&cf_flight), vec![20], "abbreviated client flight should be just Finished, no ClientKeyExchange");
        relay(&mut client2, &mut server2, cf_flight, &mut sink_s2);

        assert!(client2.is_complete(), "client2: {:?}", sink_c2.events);
        assert!(server2.is_complete(), "server2: {:?}", sink_s2.events);
        let (_, client_keys_c, server_keys_c) = sink_c2.keys.expect("client2 keys_ready");
        let (_, client_keys_s, server_keys_s) = sink_s2.keys.expect("server2 keys_ready");
        assert_eq!(client_keys_c.key, client_keys_s.key);
        assert_eq!(server_keys_c.key, server_keys_s.key);
    }

    #[test]
    fn resumption_attempt_falls_back_to_full_handshake_after_ticket_key_rotation() {
        let creds = test_server_credentials_ecdsa();
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        let mut ticket_key = [0u8; 32];
        getrandom::getrandom(&mut ticket_key).unwrap();
        let store = Tls12ClientTicketStore::shared();

        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: Some(store.clone()),
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds.clone()),
            trust_store: None,
            ticket_key: Some(ticket_key),
            client_ticket_store: None,
        };

        let mut client = Tls12Engine::new(client_cfg.clone());
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        run_full_handshake(&mut client, &mut server, &mut sink_c, &mut sink_s);
        assert!(store.get("localhost").is_some());

        // Server restarts with a freshly generated ticket key — the old
        // ticket can no longer be decrypted (simulates a STEK rotation).
        let mut rotated_key = [0u8; 32];
        getrandom::getrandom(&mut rotated_key).unwrap();
        let server_cfg2 = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: Some(rotated_key),
            client_ticket_store: None,
        };

        let mut client2 = Tls12Engine::new(client_cfg);
        let mut server2 = Tls12Engine::new(server_cfg2);
        let mut sink_c2 = RecordingSink::default();
        let mut sink_s2 = RecordingSink::default();

        client2.start(&mut sink_c2);
        let ch_flight = take_outbound(&mut sink_c2);
        relay(&mut client2, &mut server2, ch_flight, &mut sink_s2);

        let sh_flight = take_outbound(&mut sink_s2);
        assert_eq!(
            message_types(&sh_flight),
            vec![2, 11, 12, 14],
            "server couldn't decrypt the stale ticket, so it must fall back to a full handshake \
             (ServerHello, Certificate, ServerKeyExchange, ServerHelloDone), not get stuck"
        );
        relay(&mut server2, &mut client2, sh_flight, &mut sink_c2);
        relay(&mut client2, &mut server2, take_outbound(&mut sink_c2), &mut sink_s2);
        relay(&mut server2, &mut client2, take_outbound(&mut sink_s2), &mut sink_c2);

        assert!(client2.is_complete(), "client2: {:?}", sink_c2.events);
        assert!(server2.is_complete(), "server2: {:?}", sink_s2.events);
        // The rotated key can mint a fresh ticket too — resumption support recovers.
        assert!(store.get("localhost").is_some());
    }
}
