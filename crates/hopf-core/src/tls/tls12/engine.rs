// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.2 handshake engine (RFC 5246 full handshake, RFC 4492/8422 ECDHE).
//!
//! Scope for this pass: ECDHE key exchange only (no static-RSA — no forward
//! secrecy, and it doesn't fit this codebase's PQC-first posture), AEAD
//! cipher suites only (RFC 5289 GCM today) — CBC suites are **explicitly
//! not planned**, not merely deferred: MAC-then-encrypt CBC has a real,
//! recurring history of timing side channels (Lucky Thirteen and friends,
//! repeatedly reopened by supposedly-fixed implementations across the
//! industry), and AEAD (GCM here; ChaCha20-Poly1305 is a reasonable future
//! addition, per the migration plan) is sufficient for every cipher suite
//! this crate needs to offer. No renegotiation. Session resumption is RFC
//! 5077 stateless tickets (see [`super::ticket`]), not RFC 5246 §7.3
//! session-ID server-side caching — no server-side session state to
//! scale/evict, and it reuses the same opaque-ticket shape this crate
//! already has for TLS 1.3. Client certificate authentication (mTLS) is
//! supported — see [`ClientAuthPolicy`].
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
    rsa_pss_sha256_verify_spki, rsa_sign_pkcs1_sha256, rsa_verify_pkcs1_sha256, EcdsaP256PrivateKey,
    EcdsaP384PrivateKey, RsaPrivateKey, RsaPublicKeyComponents,
};
use crate::asn1::{parse_sequence, read_bit_string_content, read_tlv_content, strip_integer_padding};
use crate::crypto::trust::TrustStore;
use crate::crypto::x509::parse_certificate;
use crate::security::SecurityInfo;

use super::super::engine::{ClientAuthPolicy, ServerCredentials};
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
/// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (RFC 7905).
pub const ECDHE_ECDSA_CHACHA20_POLY1305_SHA256: u16 = 0xCCA9;
/// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (RFC 7905).
pub const ECDHE_RSA_CHACHA20_POLY1305_SHA256: u16 = 0xCCA8;
/// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (RFC 5746 §3.3) — a pseudo-cipher-
/// suite alternative to the `renegotiation_info` extension, for a peer
/// that can't send extensions. This engine's own client never sends it
/// (the extension already covers this engine's own initial handshake),
/// but the server must still recognise it from a peer that does — see
/// `on_client_hello`'s secure-renegotiation check.
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00FF;

/// Cipher suites this engine offers/accepts, in preference order. AES-128-GCM
/// first (broadest hardware/peer support), then ChaCha20-Poly1305 (equally
/// strong, faster without AES-NI), then AES-256-GCM. No CBC suites — see
/// this module's doc comment and `crypto-migration-plan.md`'s Non-goals.
pub const SUPPORTED_CIPHER_SUITES: &[u16] = &[
    ECDHE_ECDSA_AES128_GCM_SHA256,
    ECDHE_RSA_AES128_GCM_SHA256,
    ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
    ECDHE_RSA_CHACHA20_POLY1305_SHA256,
    ECDHE_ECDSA_AES256_GCM_SHA384,
    ECDHE_RSA_AES256_GCM_SHA384,
];

/// AEAD this suite negotiates to (the record layer's concern; named here
/// since suite selection is where it's first known).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305 (RFC 7905).
    ChaCha20Poly1305,
}

impl CipherKind {
    /// AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            CipherKind::Aes128Gcm => 16,
            CipherKind::Aes256Gcm => 32,
            CipherKind::ChaCha20Poly1305 => 32,
        }
    }

    /// Fixed IV length in bytes: 4 for GCM's `salt` (RFC 5288 §3 —
    /// concatenated with an 8-byte explicit per-record nonce carried on the
    /// wire), 12 for ChaCha20-Poly1305's full IV (RFC 7905 §2 — no explicit
    /// nonce at all; XORed with the sequence number instead, the same
    /// construction TLS 1.3 uses throughout).
    pub fn iv_len(self) -> usize {
        match self {
            CipherKind::Aes128Gcm | CipherKind::Aes256Gcm => 4,
            CipherKind::ChaCha20Poly1305 => 12,
        }
    }
}

fn cipher_info(suite: u16) -> Option<(CipherKind, PrfHash, KeyKind)> {
    match suite {
        ECDHE_ECDSA_AES128_GCM_SHA256 => Some((CipherKind::Aes128Gcm, PrfHash::Sha256, KeyKind::EcdsaP256)),
        ECDHE_ECDSA_AES256_GCM_SHA384 => Some((CipherKind::Aes256Gcm, PrfHash::Sha384, KeyKind::EcdsaP256)),
        ECDHE_RSA_AES128_GCM_SHA256 => Some((CipherKind::Aes128Gcm, PrfHash::Sha256, KeyKind::Rsa)),
        ECDHE_RSA_AES256_GCM_SHA384 => Some((CipherKind::Aes256Gcm, PrfHash::Sha384, KeyKind::Rsa)),
        ECDHE_ECDSA_CHACHA20_POLY1305_SHA256 => Some((CipherKind::ChaCha20Poly1305, PrfHash::Sha256, KeyKind::EcdsaP256)),
        ECDHE_RSA_CHACHA20_POLY1305_SHA256 => Some((CipherKind::ChaCha20Poly1305, PrfHash::Sha256, KeyKind::Rsa)),
        _ => None,
    }
}

/// Fixed AEAD key material for one direction. `fixed_iv` is 4 bytes for GCM
/// suites (RFC 5288 §3's `salt`, concatenated with a per-record explicit
/// nonce) or 12 bytes for ChaCha20-Poly1305 (RFC 7905 §2's full IV, XORed
/// with the sequence number) — see [`CipherKind::iv_len`].
#[derive(Clone)]
pub struct DirectionalKeyMaterial {
    /// AEAD key.
    pub key: Bytes,
    /// Fixed IV — length depends on the negotiated cipher, see [`CipherKind::iv_len`].
    pub fixed_iv: Bytes,
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
    /// Client-certificate policy (server role); mTLS. `None` (default)
    /// never sends `CertificateRequest`, matching prior behavior.
    pub client_auth: ClientAuthPolicy,
    /// Trust anchors for verifying the client's certificate chain (server
    /// role) — only consulted when [`Self::client_auth`] isn't
    /// [`ClientAuthPolicy::None`]. `None` gates on
    /// [`Tls12EventSink::verification_requested`] instead.
    pub client_trust_store: Option<TrustStore>,
    /// Certificate + key to present when the server sends
    /// `CertificateRequest` (client role). `None` responds with an empty
    /// certificate list (RFC 5246 §7.4.6 permits this) — the handshake
    /// still proceeds unless the server enforces [`ClientAuthPolicy::Require`].
    pub client_credentials: Option<ServerCredentials>,
    /// Whether this handshake runs over DTLS 1.2 (RFC 6347) rather than TCP
    /// TLS 1.2 — drives `legacy_version` (`0xfefd` vs `0x0303`) and the
    /// completed `SecurityInfo.protocol` string. The DTLS `ClientHello1` →
    /// `HelloVerifyRequest` → `ClientHello2` cookie round trip itself
    /// happens entirely in `hopf-core::dtls12`, outside this engine — RFC
    /// 6347 §4.2.1 excludes the cookie-less first exchange from the
    /// transcript hash, so this engine only ever sees `ClientHello2`, which
    /// it treats exactly as it already treats a TCP `ClientHello` (the one
    /// and only one).
    pub dtls: bool,
    /// Client role only: the cookie to embed in the one `ClientHello` this
    /// engine builds (RFC 6347 §4.2.1) — empty for TCP TLS 1.2, for a
    /// DTLS 1.2 handshake with cookie verification turned off, or for the
    /// standalone `ClientHello1` probe `hopf-core::dtls12` builds itself
    /// (outside this engine, since it's discarded from the transcript
    /// regardless — see this struct's `dtls` doc). Set to the server's
    /// echoed `HelloVerifyRequest` cookie when `dtls12` constructs *this*
    /// engine to build the real `ClientHello2`.
    pub cookie: Bytes,
    /// Client role only: use this exact `ClientHello.random` instead of
    /// generating a fresh one. `hopf-core::dtls12` needs `ClientHello2` to
    /// reuse `ClientHello1`'s random — its stateless cookie is
    /// `HMAC(secret, ClientHello.random)` (RFC 6347 §4.2.1's suggested
    /// construction), computed once against `ClientHello1` and only ever
    /// re-validated by recomputing the same HMAC when `ClientHello2`
    /// arrives; a different random would make a legitimately-echoed cookie
    /// fail to validate. `None` (the default, and TCP TLS 1.2's only mode)
    /// generates a fresh random as before.
    pub fixed_client_random: Option<[u8; 32]>,
    /// DTLS role only: starting values for [`Self::hash_message`]'s
    /// per-direction `message_seq` counters — nonzero exactly when
    /// `hopf-core::dtls12` is constructing the engine that builds/receives
    /// the real `ClientHello2` flight *after* a `HelloVerifyRequest` round
    /// trip. Even though `ClientHello1`/`HelloVerifyRequest` are excluded
    /// from the transcript *content*, RFC 6347's wire `message_seq` counter
    /// is **not** reset by a cookie retry (confirmed against RFC 6347
    /// §4.2.2's own worked example: `ClientHello2` is wire `message_seq =
    /// 1`, continuing from `ClientHello1`'s `0`) — so the hash still needs
    /// to start counting from wherever the real wire numbering left off,
    /// not from 0. `(0, 0)` (both TCP TLS 1.2's only value, and DTLS with
    /// no cookie round trip) leaves [`Self::hash_message`]'s behaviour
    /// unchanged from a plain fresh count.
    pub dtls_initial_seq: (u16, u16),
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role: Role::Client,
            server_name: None,
            server: None,
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            client_auth: ClientAuthPolicy::None,
            client_trust_store: None,
            client_credentials: None,
            dtls: false,
            cookie: Bytes::new(),
            fixed_client_random: None,
            dtls_initial_seq: (0, 0),
        }
    }
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
    /// After ServerKeyExchange — either a `CertificateRequest` or
    /// `ServerHelloDone` may come next (RFC 5246 §7.4.4/§7.4.5).
    ExpectServerHelloDoneOrCertRequest,
    ExpectServerHelloDone,
    ExpectServerFinished,
    ExpectServerFinishedResumed,
    // server
    /// Server sent `CertificateRequest` — waiting for the client's `Certificate`.
    ExpectClientCertificate,
    ExpectClientKeyExchange,
    /// Client's `Certificate` had entries — waiting for `CertificateVerify`
    /// before `Finished`.
    ExpectClientCertificateVerify,
    ExpectClientFinished,
    ExpectClientFinishedResumed,
    Complete,
    Failed,
}

struct Transcript {
    sha256: Sha256Context,
    sha384: Sha256Context,
    /// Raw concatenated handshake message bytes seen so far. TLS 1.2
    /// `CertificateVerify` (RFC 5246 §7.4.8) signs `Hash(handshake_messages)`
    /// directly — not a further-hashed wrapper the way TLS 1.3's
    /// `CertificateVerify` does — and this crate's signing primitives hash
    /// their input themselves (see `crypto::signature`), so the exact raw
    /// bytes are needed here rather than just the running digest.
    raw: BytesMut,
}

impl Transcript {
    fn new() -> Self {
        Self {
            sha256: Sha256Context::new(HashAlgorithm::Sha256),
            sha384: Sha256Context::new(HashAlgorithm::Sha384),
            raw: BytesMut::new(),
        }
    }

    fn add_message(&mut self, wire: &[u8]) {
        self.sha256.update(wire);
        self.sha384.update(wire);
        self.raw.extend_from_slice(wire);
    }

    fn hash(&self, prf_hash: PrfHash) -> Vec<u8> {
        match prf_hash {
            PrfHash::Sha256 => self.sha256.clone().finish().into_bytes().to_vec(),
            PrfHash::Sha384 => self.sha384.clone().finish().into_bytes().to_vec(),
        }
    }

    /// Raw concatenated handshake bytes so far — see the field doc comment.
    fn raw_bytes(&self) -> &[u8] {
        &self.raw
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
    /// Whether Extended Master Secret (RFC 7627 §5.1 / RFC 9846 Appendix D)
    /// was negotiated this handshake. Both roles refuse the handshake
    /// before this would ever read `false` at derivation time — see
    /// `on_client_hello`/`on_server_hello` — so this is effectively always
    /// `true` by the time [`Self::derive_master_secret`] reads it, but it's
    /// still the negotiated value, not a hardcoded assumption.
    use_ems: bool,
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
    /// Client role: the server sent `CertificateRequest` this handshake —
    /// respond with `Certificate` before `ClientKeyExchange`, and
    /// `CertificateVerify` right after it if that `Certificate` was
    /// non-empty (RFC 5246 §7.4.6/§7.4.8).
    client_cert_requested: bool,
    /// Server role: the client's `Certificate` (already processed) had at
    /// least one entry — only then is `CertificateVerify` expected.
    expect_client_certificate_verify: bool,
    /// DTLS role only (`config.dtls`): independent per-direction
    /// `message_seq` counters, incremented once per logical handshake
    /// message — see [`Self::hash_message`] for why this engine needs its
    /// own copy of a number `hopf-core::dtls12`'s `Reassembler` already
    /// tracks, rather than being told it externally.
    dtls_tx_seq: u16,
    dtls_rx_seq: u16,
}

impl Tls12Engine {
    /// Create an engine; call [`Self::start`] to emit the first flight (client).
    pub fn new(config: Config) -> Self {
        let (dtls_tx_seq, dtls_rx_seq) = config.dtls_initial_seq;
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
            use_ems: false,
            peer_certs: Vec::new(),
            peer_server_name: None,
            negotiated_alpn: None,
            verify_id: 0,
            verify_pending: false,
            sent_session_id: Bytes::new(),
            pending_resume_ticket: None,
            should_issue_ticket: false,
            expect_new_session_ticket: false,
            client_cert_requested: false,
            expect_client_certificate_verify: false,
            dtls_tx_seq,
            dtls_rx_seq,
        }
    }

    /// Add one handshake message's bytes to the transcript hash. `wire` is
    /// always the TLS-shaped `{type(1), length(3), body}` form this
    /// engine's own message builders/parsers use — for TCP TLS 1.2
    /// (`!self.config.dtls`) that's exactly what RFC 5246 hashes too, so
    /// it's added unchanged. For DTLS 1.2, RFC 6347 §4.2.6 requires the
    /// *DTLS*-shaped 12-byte header instead — `{type(1), length(3),
    /// message_seq(2), fragment_offset(3)=0, fragment_length(3)=length}` —
    /// *"Hash calculations include entire handshake messages, including
    /// DTLS-specific fields: message_seq, fragment_offset, and
    /// fragment_length. However, in order to remove sensitivity to
    /// handshake message fragmentation, the Finished MAC MUST be computed
    /// as if each handshake message had been sent as a single fragment"* —
    /// i.e. `fragment_offset` is always 0 and `fragment_length` always
    /// equals the message's own total `length` here, regardless of how
    /// `hopf-core::dtls12` actually fragmented it on the wire. This is the
    /// opposite of DTLS 1.3's rule (RFC 9147 §5.2 excludes these fields
    /// entirely) — confirmed against real OpenSSL interop, not assumed by
    /// analogy (an earlier version of this code got that wrong).
    fn hash_message(&mut self, wire: &[u8], outgoing: bool) {
        if !self.config.dtls {
            self.transcript.add_message(wire);
            return;
        }
        debug_assert!(wire.len() >= 4, "wire form always has the 4-byte {{type,length}} header");
        let msg_type = wire[0];
        let length = &wire[1..4];
        let body = &wire[4..];
        let seq = if outgoing {
            let s = self.dtls_tx_seq;
            self.dtls_tx_seq = self.dtls_tx_seq.wrapping_add(1);
            s
        } else {
            let s = self.dtls_rx_seq;
            self.dtls_rx_seq = self.dtls_rx_seq.wrapping_add(1);
            s
        };
        let mut dtls_wire = BytesMut::with_capacity(12 + body.len());
        dtls_wire.extend_from_slice(&[msg_type]);
        dtls_wire.extend_from_slice(length);
        dtls_wire.extend_from_slice(&seq.to_be_bytes());
        dtls_wire.extend_from_slice(&[0, 0, 0]);
        dtls_wire.extend_from_slice(length);
        dtls_wire.extend_from_slice(body);
        self.transcript.add_message(&dtls_wire);
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
        let random = if let Some(fixed) = self.config.fixed_client_random {
            fixed
        } else {
            let mut r = [0u8; 32];
            let _ = getrandom::getrandom(&mut r);
            r
        };
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
            legacy_version: if self.config.dtls { 0xfefd } else { 0x0303 },
            cookie: &self.config.cookie,
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
            (Role::Client, State::ExpectServerHelloDoneOrCertRequest, MessageType::CertificateRequest) => {
                self.on_certificate_request(body, wire, sink)
            }
            (
                Role::Client,
                State::ExpectServerHelloDoneOrCertRequest | State::ExpectServerHelloDone,
                MessageType::ServerHelloDone,
            ) => self.on_server_hello_done(wire, sink),
            (Role::Client, State::ExpectServerFinished, MessageType::Finished) => self.on_server_finished(body, wire, sink),
            (Role::Client, State::ExpectServerFinished, MessageType::NewSessionTicket) => {
                self.on_new_session_ticket(body, wire, sink)
            }
            (Role::Client, State::ExpectServerFinishedResumed, MessageType::Finished) => {
                self.on_server_finished_resumed(body, wire, sink)
            }
            (Role::Server, State::Initial, MessageType::ClientHello) => self.on_client_hello(body, wire, sink),
            (Role::Server, State::ExpectClientCertificate, MessageType::Certificate) => {
                self.on_client_certificate(body, wire, sink)
            }
            (Role::Server, State::ExpectClientKeyExchange, MessageType::ClientKeyExchange) => {
                self.on_client_key_exchange(body, wire, sink)
            }
            (Role::Server, State::ExpectClientCertificateVerify, MessageType::CertificateVerify) => {
                self.on_client_certificate_verify(body, wire, sink)
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
        self.hash_message(wire, true);
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
        if !sh.extended_master_secret {
            self.fail(sink, "server did not negotiate mandatory Extended Master Secret (RFC 7627)");
            return false;
        }
        self.use_ems = true;
        if !Self::secure_renegotiation_ok(&sh.renegotiation_info) {
            self.fail(sink, "server did not confirm RFC 5746 secure renegotiation (missing or invalid renegotiation_info)");
            return false;
        }
        self.negotiated_suite = Some(sh.cipher_suite);
        self.cipher_kind = Some(kind);
        self.prf_hash = Some(prf_hash);
        self.server_random = sh.random;
        self.expect_new_session_ticket = sh.session_ticket_offered;
        self.hash_message(&wire, false);

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
        self.hash_message(&wire, false);

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
        self.hash_message(&wire, false);
        true
    }

    fn on_certificate<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(certs) = messages::parse_certificate(body) else {
            self.fail(sink, "malformed Certificate");
            return false;
        };
        self.hash_message(&wire, false);
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
        self.hash_message(&wire, false);
        self.state = State::ExpectServerHelloDoneOrCertRequest;
        true
    }

    fn on_certificate_request<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        if messages::parse_certificate_request(body).is_none() {
            self.fail(sink, "malformed CertificateRequest");
            return false;
        }
        self.hash_message(&wire, false);
        self.client_cert_requested = true;
        self.state = State::ExpectServerHelloDone;
        true
    }

    fn on_server_hello_done<S: Tls12EventSink>(&mut self, wire: Bytes, sink: &mut S) -> bool {
        self.hash_message(&wire, false);
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

        // Client's response to CertificateRequest — Certificate goes before
        // ClientKeyExchange (RFC 5246 §7.4.6); CertificateVerify (if we
        // presented a non-empty chain) goes right after it, below.
        let sent_client_cert = if self.client_cert_requested {
            self.client_cert_requested = false;
            let creds = self.config.client_credentials.clone();
            let cert_refs: Vec<&[u8]> = creds
                .as_ref()
                .map(|c| c.cert_chain.iter().map(|c| c.as_ref()).collect())
                .unwrap_or_default();
            let cert_msg = messages::build_certificate(&cert_refs);
            self.emit(&cert_msg, sink);
            creds.filter(|c| !c.cert_chain.is_empty())
        } else {
            None
        };

        let cke = messages::build_client_key_exchange(&client_point);
        self.emit(&cke, sink);
        // RFC 7627 §3: session_hash covers handshake_messages up to and
        // including ClientKeyExchange, so the master secret can only be
        // derived once the transcript includes it — but before
        // CertificateVerify, which the session_hash excludes even though
        // it's sent after CKE in this same flight.
        self.derive_master_secret(&pre_master);

        if let Some(creds) = sent_client_cert {
            let message = self.transcript.raw_bytes().to_vec();
            let Some((sig_hash, sig_alg, signature)) = sign_ske(&creds.signing_key_pkcs8, &message) else {
                self.fail(sink, "unsupported or invalid client signing key");
                return false;
            };
            let cv = messages::build_certificate_verify(sig_hash, sig_alg, &signature);
            self.emit(&cv, sink);
        }

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
        self.hash_message(&wire, false);
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
        if !ch.extended_master_secret {
            self.fail(sink, "ClientHello missing mandatory Extended Master Secret extension (RFC 7627)");
            return false;
        }
        self.use_ems = true;
        // RFC 5746 §3.6: a present-but-malformed extension always aborts,
        // regardless of the SCSV — the SCSV is only an alternate signal
        // for a peer that omits the extension entirely, not a bypass for
        // a peer that sends a broken one.
        let renegotiation_ok = match &ch.renegotiation_info {
            Some(data) => data.as_ref() == [0u8],
            None => ch.cipher_suites.contains(&TLS_EMPTY_RENEGOTIATION_INFO_SCSV),
        };
        if !renegotiation_ok {
            self.fail(sink, "ClientHello missing or invalid RFC 5746 secure renegotiation signal");
            return false;
        }
        // RFC 9846 §1.4: content-mandatory-if-present, presence-optional —
        // unlike EMS/5746, a TLS-1.2-only client has no established-practice
        // reason to send this (its usual purpose is signalling upward TLS
        // 1.3 capability), so absence is tolerated; but if it's there, it
        // must actually include this engine's own version.
        let expected_version = if self.config.dtls { 0xfefd } else { 0x0303 };
        if let Some(versions) = &ch.supported_versions {
            if !versions.contains(&expected_version) {
                self.fail(sink, "ClientHello supported_versions doesn't include this engine's own version");
                return false;
            }
        }

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
        self.hash_message(&wire, false);

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
            let sh = messages::build_server_hello(
                &server_random,
                &ch.session_id,
                payload.cipher_suite,
                false,
                if self.config.dtls { 0xfefd } else { 0x0303 },
                true,
            );
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
        let sh = messages::build_server_hello(
            &server_random,
            &[],
            suite,
            self.should_issue_ticket,
            if self.config.dtls { 0xfefd } else { 0x0303 },
            true,
        );
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

        if self.config.client_auth != ClientAuthPolicy::None {
            let cr = messages::build_certificate_request();
            self.emit(&cr, sink);
        }

        let shd = messages::build_server_hello_done();
        self.emit(&shd, sink);

        self.state = if self.config.client_auth != ClientAuthPolicy::None {
            State::ExpectClientCertificate
        } else {
            State::ExpectClientKeyExchange
        };
        true
    }

    fn on_client_certificate<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(certs) = messages::parse_certificate(body) else {
            self.fail(sink, "malformed Certificate");
            return false;
        };
        self.hash_message(&wire, false);
        if certs.is_empty() {
            if self.config.client_auth == ClientAuthPolicy::Require {
                self.fail(sink, "client certificate required but none presented");
                return false;
            }
            self.state = State::ExpectClientKeyExchange;
            return true;
        }
        self.peer_certs = certs;
        self.expect_client_certificate_verify = true;
        self.verify_id += 1;
        self.verify_pending = true;
        sink.verification_requested(VerifyRequest {
            id: self.verify_id,
            peer_chain: self.peer_certs.clone(),
            server_name: None,
        });
        if let Some(store) = &self.config.client_trust_store {
            let ok = store.verify_server_chain(&self.peer_certs, None).is_ok();
            self.verify_pending = false;
            if !ok {
                self.fail(sink, "client certificate verification failed");
                return false;
            }
            self.state = State::ExpectClientKeyExchange;
            return true;
        }
        self.state = State::ExpectClientKeyExchange;
        false // gate: wait for feed_verification_result
    }

    fn on_client_key_exchange<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some(client_point) = messages::parse_client_key_exchange(body) else {
            self.fail(sink, "malformed ClientKeyExchange");
            return false;
        };
        self.hash_message(&wire, false);
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
        self.state = if self.expect_client_certificate_verify {
            State::ExpectClientCertificateVerify
        } else {
            State::ExpectClientFinished
        };
        true
    }

    fn on_client_certificate_verify<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let Some((sig_hash, sig_alg, signature)) = messages::parse_certificate_verify(body) else {
            self.fail(sink, "malformed CertificateVerify");
            return false;
        };
        let Some(leaf) = self.peer_certs.first() else {
            self.fail(sink, "CertificateVerify without client certificate");
            return false;
        };
        // Signs the transcript through ClientKeyExchange — `wire` (this
        // message) is not yet added to it below.
        let message = self.transcript.raw_bytes().to_vec();
        if !verify_ske_signature(leaf, sig_hash, sig_alg, &message, &signature) {
            self.fail(sink, "client CertificateVerify signature invalid");
            return false;
        }
        self.hash_message(&wire, false);
        self.expect_client_certificate_verify = false;
        self.state = State::ExpectClientFinished;
        true
    }

    fn on_client_finished<S: Tls12EventSink>(&mut self, body: &[u8], wire: Bytes, sink: &mut S) -> bool {
        let expected = self.finished_verify_data(true);
        if body != expected.as_slice() {
            self.fail(sink, "client Finished verify failed");
            return false;
        }
        self.hash_message(&wire, false);

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
        self.hash_message(&wire, false);
        self.finish(sink);
        true
    }

    // ---- shared ----

    /// RFC 5746 §3.5 (client) / §3.6 (server): on an initial handshake,
    /// `renegotiation_info` — if present at all — MUST be exactly the
    /// empty `renegotiated_connection<0..255>` vector, i.e. this engine's
    /// own encoding of it: a single zero length-prefix byte. Anything
    /// else (wrong length, non-zero content) is a spec violation; there's
    /// no prior handshake for a real value to reference on an initial one.
    fn secure_renegotiation_ok(info: &Option<Bytes>) -> bool {
        matches!(info, Some(data) if data.as_ref() == [0u8])
    }

    /// RFC 7627 §4: when Extended Master Secret is negotiated, the seed is
    /// `session_hash` (the transcript hash through `ClientKeyExchange`,
    /// but excluding `CertificateVerify`) instead of `client_random ||
    /// server_random`, under the `"extended master secret"` label. Both
    /// `on_client_hello`/`on_server_hello` refuse the handshake before
    /// `use_ems` could ever be `false` here — see their mandatory checks —
    /// but this stays a live branch on the negotiated value rather than a
    /// hardcoded assumption the caller can't verify.
    fn derive_master_secret(&mut self, pre_master: &[u8]) {
        let prf_hash = self.prf_hash.expect("cipher negotiated");
        let (label, seed): (&[u8], Vec<u8>) = if self.use_ems {
            (b"extended master secret", self.transcript.hash(prf_hash))
        } else {
            let mut seed = Vec::with_capacity(64);
            seed.extend_from_slice(&self.client_random);
            seed.extend_from_slice(&self.server_random);
            (b"master secret", seed)
        };
        let out = prf(prf_hash, pre_master, label, &seed, 48);
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
        let iv_len = cipher.iv_len();
        let total = 2 * key_len + 2 * iv_len;
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.server_random);
        seed.extend_from_slice(&self.client_random);
        let block = prf(prf_hash, &master, b"key expansion", &seed, total);

        let mut i = 0;
        let client_key = Bytes::copy_from_slice(&block[i..i + key_len]);
        i += key_len;
        let server_key = Bytes::copy_from_slice(&block[i..i + key_len]);
        i += key_len;
        let client_iv = Bytes::copy_from_slice(&block[i..i + iv_len]);
        i += iv_len;
        let server_iv = Bytes::copy_from_slice(&block[i..i + iv_len]);

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
            Some(ECDHE_ECDSA_CHACHA20_POLY1305_SHA256) => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            Some(ECDHE_RSA_CHACHA20_POLY1305_SHA256) => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            _ => "unknown",
        };
        let protocol_name = if self.config.dtls { "DTLSv1.2" } else { "TLSv1.2" };
        let mut info = SecurityInfo::secure(self.negotiated_alpn.clone(), Some(protocol_name.to_string()), Some(suite_name.to_string()))
            .with_sni(sni);
        if self.config.role == Role::Server {
            if let Some(leaf) = self.peer_certs.first() {
                info = info
                    .with_peer_certificate_fingerprint(Some(crate::crypto::sha256_fingerprint_hex(leaf)))
                    .with_peer_certificate_chain(Some(self.peer_certs.clone()));
            }
        }
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
        (sig_alg::RSA_PSS_SHA256_BYTE0, sig_alg::RSA_PSS_SHA256_BYTE1) => {
            rsa_pss_sha256_verify_spki(&parsed.spki_der, message, signature)
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
    let mut outer = parse_sequence(spki_der)?;
    let _alg = outer.next()?;
    let bit_string = outer.next()?;
    let rsa_pub = read_bit_string_content(bit_string)?;
    let mut inner = parse_sequence(rsa_pub)?;
    let modulus = read_tlv_content(inner.next()?, 0x02)?;
    let exponent = read_tlv_content(inner.next()?, 0x02)?;
    Some((strip_integer_padding(modulus).to_vec(), strip_integer_padding(exponent).to_vec()))
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
            ..Default::default()
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
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
        let mut encoder = crate::asn1::BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_bytes(n);
        encoder.write_integer_bytes(e);
        encoder.end_sequence();
        encoder.into_bytes()
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
            ..Default::default()
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
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
    fn verify_ske_signature_accepts_rsa_pss_sha256() {
        use aws_lc_rs::encoding::AsDer;
        use aws_lc_rs::rsa::{KeyPair as RsaGenKeyPair, KeySize};
        use aws_lc_rs::signature::KeyPair as _;
        use crate::crypto::signature::rsa_sign_pss_sha256;

        let generated = RsaGenKeyPair::generate(KeySize::Rsa2048).unwrap();
        let spki_der = generated.public_key().as_der().unwrap().as_ref().to_vec();
        let (n, e) = rsa_n_e_from_spki(&spki_der).expect("extract n/e from freshly generated key's own SPKI");
        let signing_key_pkcs8 = pkcs8_der_of(&generated);
        let remote = RemoteRsaSigner { key: generated, rsa_public_key_der: rsa_public_key_der(&n, &e) };
        let rcgen_key = rcgen::KeyPair::from_remote(Box::new(remote)).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&rcgen_key).unwrap();

        let rsa_key = RsaPrivateKey::from_pkcs8(&signing_key_pkcs8).unwrap();
        let message = b"arbitrary transcript-shaped bytes to sign";
        let signature = rsa_sign_pss_sha256(&rsa_key, message).expect("PSS sign");

        assert!(verify_ske_signature(
            cert.der(),
            sig_alg::RSA_PSS_SHA256_BYTE0,
            sig_alg::RSA_PSS_SHA256_BYTE1,
            message,
            &signature,
        ));
        // A PSS signature must not verify against PKCS1v1.5's pair either.
        assert!(!verify_ske_signature(cert.der(), sig_alg::HASH_SHA256, sig_alg::SIG_RSA, message, &signature));
    }

    #[test]
    fn offered_signature_algorithms_include_rsa_pss_sha256() {
        let params = messages::ClientHelloParams {
            random: [4u8; 32],
            session_id: &[],
            cipher_suites: &[ECDHE_ECDSA_AES128_GCM_SHA256],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        let body = &wire[4..];
        let parsed = messages::parse_client_hello(body).expect("parse");
        assert!(
            parsed
                .signature_algorithms
                .contains(&(sig_alg::RSA_PSS_SHA256_BYTE0, sig_alg::RSA_PSS_SHA256_BYTE1)),
            "{:?}",
            parsed.signature_algorithms
        );
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
            ..Default::default()
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
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

    /// Removes one extension from a `ClientHello`/`ServerHello` wire
    /// message built by this module's own builders — both put extensions
    /// as the final field, `ext_len(2) || extensions`, so `prefix_len` is
    /// just the byte count of everything before that. Used to simulate a
    /// peer that doesn't offer/echo a given extension without duplicating
    /// this crate's own message-building code.
    fn strip_extension(wire: &Bytes, prefix_len: usize, ext_type: u16) -> Bytes {
        let body = &wire[4..];
        let ext_len = u16::from_be_bytes([body[prefix_len], body[prefix_len + 1]]) as usize;
        let ext_block = &body[prefix_len + 2..prefix_len + 2 + ext_len];
        let mut new_ext = BytesMut::new();
        let mut k = 0;
        while k + 4 <= ext_block.len() {
            let et = u16::from_be_bytes([ext_block[k], ext_block[k + 1]]);
            let el = u16::from_be_bytes([ext_block[k + 2], ext_block[k + 3]]) as usize;
            let entry = &ext_block[k..k + 4 + el];
            if et != ext_type {
                new_ext.extend_from_slice(entry);
            }
            k += 4 + el;
        }
        let mut new_body = BytesMut::new();
        new_body.extend_from_slice(&body[..prefix_len]);
        new_body.extend_from_slice(&(new_ext.len() as u16).to_be_bytes());
        new_body.extend_from_slice(&new_ext);
        messages::encode_message(MessageType::from_u8(wire[0]).unwrap(), &new_body)
    }

    /// Same shape as [`strip_extension`], but replaces one extension's
    /// `extension_data` instead of removing the entry — used to simulate a
    /// peer sending a malformed (non-empty) `renegotiation_info` on an
    /// initial handshake.
    fn replace_extension(wire: &Bytes, prefix_len: usize, ext_type: u16, new_data: &[u8]) -> Bytes {
        let body = &wire[4..];
        let ext_len = u16::from_be_bytes([body[prefix_len], body[prefix_len + 1]]) as usize;
        let ext_block = &body[prefix_len + 2..prefix_len + 2 + ext_len];
        let mut new_ext = BytesMut::new();
        let mut k = 0;
        while k + 4 <= ext_block.len() {
            let et = u16::from_be_bytes([ext_block[k], ext_block[k + 1]]);
            let el = u16::from_be_bytes([ext_block[k + 2], ext_block[k + 3]]) as usize;
            if et == ext_type {
                new_ext.extend_from_slice(&et.to_be_bytes());
                new_ext.extend_from_slice(&(new_data.len() as u16).to_be_bytes());
                new_ext.extend_from_slice(new_data);
            } else {
                new_ext.extend_from_slice(&ext_block[k..k + 4 + el]);
            }
            k += 4 + el;
        }
        let mut new_body = BytesMut::new();
        new_body.extend_from_slice(&body[..prefix_len]);
        new_body.extend_from_slice(&(new_ext.len() as u16).to_be_bytes());
        new_body.extend_from_slice(&new_ext);
        messages::encode_message(MessageType::from_u8(wire[0]).unwrap(), &new_body)
    }

    #[test]
    fn server_refuses_client_hello_with_nonempty_renegotiation_info() {
        let creds = test_server_credentials_ecdsa();
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_s = RecordingSink::default();

        let params = messages::ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[ECDHE_ECDSA_AES128_GCM_SHA256, ECDHE_RSA_AES128_GCM_SHA256],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        let tampered = replace_extension(&wire, 43, messages::ext::RENEGOTIATION_INFO, &[1, 2, 3]);
        let mut input = tampered.as_ref();
        server.feed_handshake_data(&mut input, &mut sink_s);

        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.contains("protocol_error") && e.contains("renegotiation")),
            "{:?}",
            sink_s.events
        );
        assert!(sink_s.outbound.is_empty(), "server must not send ServerHello: {:?}", sink_s.events);
    }

    #[test]
    fn server_refuses_client_hello_without_renegotiation_info_or_scsv() {
        let creds = test_server_credentials_ecdsa();
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_s = RecordingSink::default();

        let params = messages::ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[ECDHE_ECDSA_AES128_GCM_SHA256, ECDHE_RSA_AES128_GCM_SHA256],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        let stripped = strip_extension(&wire, 43, messages::ext::RENEGOTIATION_INFO);
        let mut input = stripped.as_ref();
        server.feed_handshake_data(&mut input, &mut sink_s);

        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.contains("protocol_error") && e.contains("renegotiation")),
            "{:?}",
            sink_s.events
        );
        assert!(sink_s.outbound.is_empty(), "server must not send ServerHello: {:?}", sink_s.events);
    }

    #[test]
    fn server_refuses_client_hello_with_wrong_supported_versions() {
        let creds = test_server_credentials_ecdsa();
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_s = RecordingSink::default();

        let params = messages::ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[ECDHE_ECDSA_AES128_GCM_SHA256, ECDHE_RSA_AES128_GCM_SHA256],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        // supported_versions listing only TLS 1.0 (0x0301), not 0x0303.
        let tampered = replace_extension(&wire, 43, messages::ext::SUPPORTED_VERSIONS, &[2, 0x03, 0x01]);
        let mut input = tampered.as_ref();
        server.feed_handshake_data(&mut input, &mut sink_s);

        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.contains("protocol_error") && e.contains("supported_versions")),
            "{:?}",
            sink_s.events
        );
        assert!(sink_s.outbound.is_empty(), "server must not send ServerHello: {:?}", sink_s.events);
    }

    #[test]
    fn server_accepts_client_hello_without_supported_versions() {
        let creds = test_server_credentials_ecdsa();
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_s = RecordingSink::default();

        let params = messages::ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[ECDHE_ECDSA_AES128_GCM_SHA256, ECDHE_RSA_AES128_GCM_SHA256],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        let stripped = strip_extension(&wire, 43, messages::ext::SUPPORTED_VERSIONS);
        let mut input = stripped.as_ref();
        server.feed_handshake_data(&mut input, &mut sink_s);

        assert!(
            sink_s.events.iter().all(|e| !e.contains("supported_versions")),
            "absence of supported_versions must be tolerated: {:?}",
            sink_s.events
        );
        assert!(!sink_s.outbound.is_empty(), "server should proceed to send ServerHello: {:?}", sink_s.events);
    }

    #[test]
    fn server_accepts_client_hello_signalling_via_scsv_instead_of_extension() {
        let creds = test_server_credentials_ecdsa();
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_s = RecordingSink::default();

        let params = messages::ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[
                ECDHE_ECDSA_AES128_GCM_SHA256,
                ECDHE_RSA_AES128_GCM_SHA256,
                TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        // Same prefix as the other tests plus one extra cipher suite (2 bytes).
        let stripped = strip_extension(&wire, 45, messages::ext::RENEGOTIATION_INFO);
        let mut input = stripped.as_ref();
        server.feed_handshake_data(&mut input, &mut sink_s);

        assert!(
            sink_s.events.iter().all(|e| !e.contains("renegotiation")),
            "SCSV should satisfy RFC 5746 without the extension: {:?}",
            sink_s.events
        );
        assert!(!sink_s.outbound.is_empty(), "server should proceed to send ServerHello: {:?}", sink_s.events);
    }

    #[test]
    fn client_refuses_server_hello_with_nonempty_renegotiation_info() {
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
            ..Default::default()
        };
        let mut client = Tls12Engine::new(client_cfg);
        let mut sink_c = RecordingSink::default();
        client.start(&mut sink_c);
        take_outbound(&mut sink_c); // ClientHello, not needed here

        let wire = messages::build_server_hello(&[2u8; 32], &[], ECDHE_ECDSA_AES128_GCM_SHA256, false, 0x0303, true);
        // legacy_version(2) + random(32) + session_id_len(1) + session_id(0)
        // + cipher_suite(2) + compression_method(1).
        let tampered = replace_extension(&wire, 38, messages::ext::RENEGOTIATION_INFO, &[9]);
        let mut input = tampered.as_ref();
        client.feed_handshake_data(&mut input, &mut sink_c);

        assert!(!client.is_complete());
        assert!(
            sink_c.events.iter().any(|e| e.contains("protocol_error") && e.contains("renegotiation")),
            "{:?}",
            sink_c.events
        );
    }

    #[test]
    fn server_refuses_client_hello_without_extended_master_secret() {
        let creds = test_server_credentials_ecdsa();
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_s = RecordingSink::default();

        let params = messages::ClientHelloParams {
            random: [1u8; 32],
            session_id: &[],
            cipher_suites: &[ECDHE_ECDSA_AES128_GCM_SHA256, ECDHE_RSA_AES128_GCM_SHA256],
            server_name: None,
            session_ticket: None,
            legacy_version: 0x0303,
            cookie: &[],
        };
        let wire = messages::build_client_hello(&params);
        // legacy_version(2) + random(32) + session_id_len(1) + session_id(0)
        // + cipher_suites_len(2) + cipher_suites(4) + compression(2).
        let stripped = strip_extension(&wire, 43, messages::ext::EXTENDED_MASTER_SECRET);
        let mut input = stripped.as_ref();
        server.feed_handshake_data(&mut input, &mut sink_s);

        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.contains("protocol_error") && e.contains("Extended Master Secret")),
            "{:?}",
            sink_s.events
        );
        assert!(sink_s.outbound.is_empty(), "server must not send ServerHello: {:?}", sink_s.events);
    }

    #[test]
    fn client_refuses_server_hello_without_extended_master_secret() {
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
            ..Default::default()
        };
        let mut client = Tls12Engine::new(client_cfg);
        let mut sink_c = RecordingSink::default();
        client.start(&mut sink_c);
        take_outbound(&mut sink_c); // ClientHello, not needed here

        let wire = messages::build_server_hello(
            &[2u8; 32],
            &[],
            ECDHE_ECDSA_AES128_GCM_SHA256,
            false,
            0x0303,
            false, // no extended_master_secret
        );
        let mut input = wire.as_ref();
        client.feed_handshake_data(&mut input, &mut sink_c);

        assert!(!client.is_complete());
        assert!(
            sink_c.events.iter().any(|e| e.contains("protocol_error") && e.contains("Extended Master Secret")),
            "{:?}",
            sink_c.events
        );
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
            ..Default::default()
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds),
            trust_store: None,
            ticket_key: Some(ticket_key),
            client_ticket_store: None,
            ..Default::default()
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
            ..Default::default()
        };
        let server_cfg = Config {
            role: Role::Server,
            server_name: None,
            server: Some(creds.clone()),
            trust_store: None,
            ticket_key: Some(ticket_key),
            client_ticket_store: None,
            ..Default::default()
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
            ..Default::default()
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

    // ---- mTLS (client certificate authentication) ----

    fn client_config_with_cert(server_creds: &ServerCredentials, client_creds: ServerCredentials) -> Config {
        let mut trust = TrustStore::new();
        trust.add_anchor(server_creds.cert_chain[0].clone());
        Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
            client_credentials: Some(client_creds),
            ..Default::default()
        }
    }

    fn server_config_requiring_client_cert(
        server_creds: ServerCredentials,
        client_creds: &ServerCredentials,
        policy: ClientAuthPolicy,
    ) -> Config {
        let mut trust = TrustStore::new();
        trust.add_anchor(client_creds.cert_chain[0].clone());
        Config {
            role: Role::Server,
            server_name: None,
            server: Some(server_creds),
            trust_store: None,
            ticket_key: None,
            client_ticket_store: None,
            client_auth: policy,
            client_trust_store: Some(trust),
            client_credentials: None,
            dtls: false,
            cookie: Bytes::new(),
            fixed_client_random: None,
            dtls_initial_seq: (0, 0),
        }
    }

    #[test]
    fn mtls_require_completes_when_client_presents_a_trusted_certificate() {
        let server_creds = test_server_credentials_ecdsa();
        let client_creds = test_server_credentials_ecdsa();
        let client_cfg = client_config_with_cert(&server_creds, client_creds.clone());
        let server_cfg = server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        run_full_handshake(&mut client, &mut server, &mut sink_c, &mut sink_s);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("verification_requested")),
            "{:?}",
            sink_s.events
        );
    }

    /// Same guarantee as the TLS 1.3 engine's analogous test: the server's
    /// `SecurityInfo` must expose the verified client certificate's
    /// fingerprint and chain (SASL EXTERNAL's `cert_key`), and the client's
    /// own `SecurityInfo` must not.
    #[test]
    fn mtls_exposes_client_certificate_fingerprint_and_chain_on_the_server_side() {
        let server_creds = test_server_credentials_ecdsa();
        let client_creds = test_server_credentials_ecdsa();
        let expected_fp = crate::crypto::sha256_fingerprint_hex(&client_creds.cert_chain[0]);
        let client_cfg = client_config_with_cert(&server_creds, client_creds.clone());
        let server_cfg = server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        run_full_handshake(&mut client, &mut server, &mut sink_c, &mut sink_s);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);

        let server_info = sink_s.info.expect("server SecurityInfo");
        assert_eq!(server_info.peer_certificate_fingerprint(), Some(expected_fp.as_str()));
        assert_eq!(
            server_info.peer_certificate_chain(),
            Some(client_creds.cert_chain.as_slice())
        );
        let client_info = sink_c.info.expect("client SecurityInfo");
        assert_eq!(client_info.peer_certificate_fingerprint(), None);
    }

    #[test]
    fn mtls_require_rejects_handshake_when_client_has_no_certificate() {
        let server_creds = test_server_credentials_ecdsa();
        let client_creds = test_server_credentials_ecdsa();
        let mut trust = TrustStore::new();
        trust.add_anchor(server_creds.cert_chain[0].clone());
        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let server_cfg = server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_s.events
        );
    }

    #[test]
    fn mtls_request_completes_when_client_has_no_certificate() {
        let server_creds = test_server_credentials_ecdsa();
        let client_creds = test_server_credentials_ecdsa();
        let mut trust = TrustStore::new();
        trust.add_anchor(server_creds.cert_chain[0].clone());
        let client_cfg = Config {
            role: Role::Client,
            server_name: Some("localhost".into()),
            server: None,
            trust_store: Some(trust),
            ticket_key: None,
            client_ticket_store: None,
            ..Default::default()
        };
        let server_cfg = server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Request);
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        run_full_handshake(&mut client, &mut server, &mut sink_c, &mut sink_s);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
    }

    #[test]
    fn mtls_rejects_untrusted_client_certificate() {
        let server_creds = test_server_credentials_ecdsa();
        let client_creds = test_server_credentials_ecdsa();
        let untrusted_client_creds = test_server_credentials_ecdsa(); // not the one in client_trust_store
        let client_cfg = client_config_with_cert(&server_creds, untrusted_client_creds);
        let server_cfg = server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_s.events
        );
    }

    #[test]
    fn mtls_rejects_tampered_client_certificate_verify_signature() {
        let server_creds = test_server_credentials_ecdsa();
        let client_creds = test_server_credentials_ecdsa();
        let client_cfg = client_config_with_cert(&server_creds, client_creds.clone());
        let server_cfg = server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut client = Tls12Engine::new(client_cfg);
        let mut server = Tls12Engine::new(server_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay(&mut client, &mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay(&mut server, &mut client, take_outbound(&mut sink_s), &mut sink_c);

        let mut outbound = take_outbound(&mut sink_c);
        // Client's second flight: [Certificate, ClientKeyExchange, CertificateVerify, Finished].
        assert_eq!(
            message_types(&outbound),
            vec![11, 16, 15, 20],
            "expected Certificate, ClientKeyExchange, CertificateVerify, Finished: {:?}",
            message_types(&outbound)
        );
        let cv_index = 2;
        let mut corrupted = outbound[cv_index].to_vec();
        let n = corrupted.len();
        corrupted[n - 1] ^= 0xff;
        outbound[cv_index] = Bytes::from(corrupted);
        relay(&mut client, &mut server, outbound, &mut sink_s);

        assert!(!server.is_complete());
        assert!(
            sink_s.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink_s.events
        );
    }
}
