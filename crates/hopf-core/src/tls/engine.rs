// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reactive TLS 1.3 handshake engine — QUIC-first (no record layer in Phase 2).

use getrandom::getrandom;
use bytes::Bytes;

use crate::crypto::kx::{server_agree, LocalKeyShare, NamedGroup};
use crate::crypto::trust::TrustStore;
use crate::crypto::kx_policy::KxPolicy;
use crate::security::SecurityInfo;
use std::sync::Arc;

use super::handshake::verify::{sign_certificate_verify, verify_certificate_verify};

use super::handshake::{
    build_certificate, build_certificate_request, build_certificate_verify, build_client_hello,
    build_client_hello_with_binder, build_encrypted_extensions_ext, build_finished,
    build_server_hello_ext, compute_finished_verify_data, compute_psk_binder,
    derive_application_traffic_with_psk, derive_early_traffic,
    derive_handshake_traffic_with_psk, derive_resumption_master_secret, derive_resumption_psk,
    ApplicationTrafficSecrets, ClientHelloParams, HandshakeMessage, HandshakeTrafficSecrets,
    HandshakeType, KeyShareEntry, OfferedPsk, Transcript,
};
use super::handshake::collect::{MessageCollector, ParsedIncoming};
use super::handshake::parser::{HandshakeEvents, HandshakeParser};
use super::handshake::ticket::{
    mint_new_session_ticket, open_ticket, recover_ticket_age, AntiReplay, ClientTicketStore,
    StoredTicket, DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
};
use super::handshake::transport_params::{RememberedTransportLimits, encode_initial_max_data};
use super::sink::{QuicSecrets, TlsEventSink, TlsProtocolError, VerifyResult};

/// Client or server role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    /// TLS client.
    Client,
    /// TLS server.
    Server,
}

/// Transport binding for handshake bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMode {
    /// Raw handshake messages (QUIC CRYPTO stream — RFC 9001).
    Quic,
    /// TLS record layer wraps messages (Phase 4 TCP).
    TcpRecordLayer,
}

/// `TLS_AES_128_GCM_SHA256` (RFC 8446 §B.4) — MUST implement per RFC 8446 §9.1.
pub const AES_128_GCM_SHA256: u16 = 0x1301;
/// `TLS_CHACHA20_POLY1305_SHA256` (RFC 8446 §B.4) — SHOULD implement per RFC 8446 §9.1.
pub const CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Cipher suites this engine offers/accepts, in preference order. Both use
/// SHA-256 as the handshake/key-schedule hash (RFC 8446 §B.4), so
/// negotiating between them only changes the record/packet-protection AEAD,
/// never the transcript hash. No CBC, no AES-256-GCM — see
/// `crypto-migration-plan.md`'s Non-goals and Phase 2 entry.
pub const SUPPORTED_CIPHER_SUITES: &[u16] = &[AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256];

/// Negotiated TLS 1.3 AEAD — one of [`SUPPORTED_CIPHER_SUITES`]. Threaded
/// through [`super::sink::TlsEventSink`]'s key-ready callbacks so both this
/// crate's own TCP record layer ([`super::record`]) and `hopf-quic`'s packet
/// protection (which consumes the same callbacks directly, bypassing the
/// TCP record layer) know which AEAD to instantiate — key length is the only
/// thing that varies (16 vs 32 bytes); nonce construction is identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13Aead {
    /// `TLS_AES_128_GCM_SHA256`.
    Aes128GcmSha256,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha20Poly1305Sha256,
}

impl Tls13Aead {
    /// AEAD key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Tls13Aead::Aes128GcmSha256 => 16,
            Tls13Aead::ChaCha20Poly1305Sha256 => 32,
        }
    }

    /// Map a wire cipher-suite code to its AEAD, if this crate supports it.
    pub fn from_suite(suite: u16) -> Option<Self> {
        match suite {
            AES_128_GCM_SHA256 => Some(Tls13Aead::Aes128GcmSha256),
            CHACHA20_POLY1305_SHA256 => Some(Tls13Aead::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Wire cipher-suite code for this AEAD.
    pub fn suite(self) -> u16 {
        match self {
            Tls13Aead::Aes128GcmSha256 => AES_128_GCM_SHA256,
            Tls13Aead::ChaCha20Poly1305Sha256 => CHACHA20_POLY1305_SHA256,
        }
    }

    /// Display name for [`crate::security::SecurityInfo::cipher_suite`].
    pub fn name(self) -> &'static str {
        match self {
            Tls13Aead::Aes128GcmSha256 => "TLS_AES_128_GCM_SHA256",
            Tls13Aead::ChaCha20Poly1305Sha256 => "TLS_CHACHA20_POLY1305_SHA256",
        }
    }
}

/// Server identity for the 1-RTT full handshake (Ed25519 leaf cert in Phase 2).
#[derive(Debug, Clone)]
pub struct ServerCredentials {
    /// DER certificate chain (leaf first).
    pub cert_chain: Vec<Bytes>,
    /// PKCS#8 private key matching the leaf certificate (Ed25519).
    pub signing_key_pkcs8: Bytes,
}

/// Custom server-chain verification callback (client role) — peer chain
/// (DER, leaf first) and SNI in, trusted-or-not out. Wraps a plain `Fn` so
/// callers with their own trust model (DANE TLSA, pinned SPKI, …) don't need
/// to shape a fixed root set into a [`crate::crypto::trust::TrustStore`].
#[derive(Clone)]
pub struct VerifyOverride(pub Arc<dyn Fn(&[Bytes], Option<&str>) -> bool + Send + Sync>);

impl std::fmt::Debug for VerifyOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifyOverride(..)")
    }
}

/// Client-certificate authentication policy (server role) — RFC 8446
/// §4.3.2 / RFC 5246 §7.4.4 `CertificateRequest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuthPolicy {
    /// Never send `CertificateRequest` (default — today's behavior).
    #[default]
    None,
    /// Send `CertificateRequest`; proceed even if the client presents no
    /// certificate or an untrusted one — the peer identity (if any) is
    /// still reported via [`super::sink::VerifyRequest`] for the caller
    /// to act on.
    Request,
    /// Send `CertificateRequest`; fail the handshake unless the client
    /// presents a certificate that verifies against
    /// [`HandshakeConfig::client_trust_store`].
    Require,
}

/// Configuration for a single handshake.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Client or server.
    pub role: HandshakeRole,
    /// QUIC vs TCP record layer.
    pub mode: HandshakeMode,
    /// ALPN protocol names (e.g. `b"h3"`).
    pub alpn: Vec<Bytes>,
    /// Client SNI / server expected name.
    pub server_name: Option<String>,
    /// Server certificate + key (server role only).
    pub server: Option<ServerCredentials>,
    /// Key-exchange group preference (hybrid PQC first by default).
    pub kx_policy: KxPolicy,
    /// Local QUIC transport parameters (RFC 9001 §8.2) sent in ClientHello / EncryptedExtensions.
    pub local_transport_parameters: Option<Bytes>,
    /// Trust anchors for server chain verification (client role). Checked
    /// before [`Self::verify_override`] when both are set.
    pub trust_store: Option<TrustStore>,
    /// Custom server-chain verification (client role) — e.g. DANE TLSA
    /// matching, where trust isn't anchored in a fixed root set at all.
    /// Ignored when [`Self::trust_store`] is set. Resolved inline, exactly
    /// like `trust_store` — not a `StorageExecutor`-backed async gate.
    pub verify_override: Option<VerifyOverride>,
    /// Offer / accept TLS 1.3 early data (0-RTT).
    pub enable_early_data: bool,
    /// Server max early data size advertised in NewSessionTicket.
    pub max_early_data_size: u32,
    /// Max recovered ticket age (ms) for accepting 0-RTT; resume may still succeed.
    pub max_early_data_freshness_ms: u32,
    /// Server opaque-ticket sealing key (AES-128-GCM; 32 bytes).
    pub ticket_key: Option<[u8; 32]>,
    /// Shared client ticket cache (keyed by server name).
    pub ticket_store: Option<Arc<ClientTicketStore>>,
    /// Server early-data anti-replay (shared across connections).
    pub anti_replay: Option<Arc<AntiReplay>>,
    /// Client-certificate policy (server role); mTLS. `None` (default)
    /// never sends `CertificateRequest`, matching prior behavior.
    pub client_auth: ClientAuthPolicy,
    /// Trust anchors for verifying the client's certificate chain (server
    /// role) — only consulted when [`Self::client_auth`] isn't
    /// [`ClientAuthPolicy::None`]. `None` gates on
    /// [`super::sink::TlsEventSink::verification_requested`] instead,
    /// exactly like [`Self::trust_store`] does for the client role.
    pub client_trust_store: Option<TrustStore>,
    /// Certificate + key to present when the server sends
    /// `CertificateRequest` (client role). `None` responds with an empty
    /// certificate list (RFC 8446 §4.4.2 permits this) — the handshake
    /// still proceeds unless the server enforces [`ClientAuthPolicy::Require`].
    pub client_credentials: Option<ServerCredentials>,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: Vec::new(),
            server_name: None,
            server: None,
            kx_policy: KxPolicy::default(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: super::handshake::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            client_auth: ClientAuthPolicy::None,
            client_trust_store: None,
            client_credentials: None,
        }
    }
}

/// Reactive TLS 1.3 handshake engine with full 1-RTT client/server FSM (+ optional 0-RTT).
pub struct HandshakeEngine {
    config: HandshakeConfig,
    state: State,
    transcript: Transcript,
    parser: HandshakeParser,
    local_key_share: Option<LocalKeyShare>,
    negotiated_group: Option<NamedGroup>,
    shared_secret: Option<Bytes>,
    handshake_traffic: Option<HandshakeTrafficSecrets>,
    application_traffic: Option<ApplicationTrafficSecrets>,
    early_client_secret: Option<[u8; 32]>,
    /// Resumption PSK in use for this handshake (if any).
    psk: Option<[u8; 32]>,
    /// True when this handshake is PSK-resumption (omit Certificate).
    resumed: bool,
    /// Client offered early data; server may accept.
    early_data_offered: bool,
    /// Server accepted early data (echoed in EE).
    early_data_accepted: bool,
    /// Resumption master secret retained until NST is minted / stored.
    resumption_master: Option<[u8; 32]>,
    negotiated_alpn: Option<Bytes>,
    /// ALPN from the ticket offered in ClientHello (client role; for EE check).
    offered_ticket_alpn: Option<Bytes>,
    /// Peer server limits from EncryptedExtensions (client; for ticket cache / 0-RTT).
    peer_remembered_limits: Option<RememberedTransportLimits>,
    /// SNI from the peer ClientHello (server role).
    peer_server_name: Option<String>,
    /// Server role: peer's certificate chain. Client role: server's chain.
    /// Reused for both directions — a given engine only ever verifies one
    /// side's chain, matching its own fixed role.
    peer_certs: Vec<Bytes>,
    verify_id: u64,
    verify_pending: bool,
    /// Client role: the `certificate_request_context` from the server's
    /// `CertificateRequest`, if one was received this handshake — echoed
    /// back verbatim in the client's own `Certificate` response.
    client_cert_request_context: Option<Bytes>,
    /// Server role: whether the client's `Certificate` response (already
    /// processed) carried at least one entry — only then is a
    /// `CertificateVerify` expected next.
    expect_client_certificate_verify: bool,
    /// Server role: transcript hash captured right after this engine sent
    /// its own Finished (RFC 8446 §7.1's `application_traffic_secret_0`
    /// input) — needed verbatim in `on_client_finished` since the
    /// transcript may have grown further by then (an mTLS client
    /// Certificate/CertificateVerify response), which must not affect it.
    server_finished_hash: Option<[u8; 32]>,
    /// Negotiated AEAD (client: from `ServerHello`; server: selected in
    /// `on_client_hello`, before anything that needs it — including 0-RTT
    /// key installation). Threaded into every `*_keys_ready` callback and
    /// the completion `SecurityInfo`.
    negotiated_aead: Option<Tls13Aead>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    ClientHelloSent,
    ReadingServerFlight,
    /// After EE on a resumed handshake — expect Finished next (no Cert).
    ReadingServerFinished,
    /// Server role: sent `CertificateRequest`, waiting for the client's `Certificate`.
    AwaitingClientCertificate,
    /// Server role: client's `Certificate` had entries — waiting for `CertificateVerify`.
    AwaitingClientCertificateVerify,
    AwaitingClientFinished,
    Complete,
    Failed,
}

impl HandshakeEngine {
    /// Create an engine; call [`Self::start`] to emit the first flight (client).
    pub fn new(config: HandshakeConfig) -> Self {
        Self {
            config,
            state: State::Initial,
            transcript: Transcript::new(),
            parser: HandshakeParser::new(),
            local_key_share: None,
            negotiated_group: None,
            shared_secret: None,
            handshake_traffic: None,
            application_traffic: None,
            early_client_secret: None,
            psk: None,
            resumed: false,
            early_data_offered: false,
            early_data_accepted: false,
            resumption_master: None,
            negotiated_alpn: None,
            offered_ticket_alpn: None,
            peer_remembered_limits: None,
            peer_server_name: None,
            peer_certs: Vec::new(),
            verify_id: 0,
            verify_pending: false,
            client_cert_request_context: None,
            expect_client_certificate_verify: false,
            server_finished_hash: None,
            negotiated_aead: None,
        }
    }

    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: TlsEventSink>(&mut self, sink: &mut S) {
        if self.state != State::Initial {
            return;
        }
        match self.config.role {
            HandshakeRole::Client => self.client_send_hello(sink),
            HandshakeRole::Server => {}
        }
    }

    /// Consume handshake bytes from the peer (QUIC CRYPTO plaintext).
    ///
    /// Returns the number of bytes consumed from the front of `input`.
    pub fn feed_handshake_data<S: TlsEventSink>(&mut self, input: &mut &[u8], sink: &mut S) -> usize {
        let n = input.len();
        // Allow post-handshake NewSessionTicket after Complete (client).
        if self.state == State::Failed {
            *input = &[];
            return n;
        }
        if self.state == State::Complete && self.config.role != HandshakeRole::Client {
            *input = &[];
            return n;
        }
        // While a verification gate is pending, still buffer incoming bytes
        // (parser.receive always does) rather than dropping them — the gate
        // may resolve after more of the peer's flight has already arrived in
        // a *separate* feed_handshake_data call (its own TLS record); those
        // bytes must survive to be parsed once feed_verification_result
        // resumes, not be silently discarded here. should_stop() (checking
        // self.verify_pending) keeps drain_complete_messages from popping
        // and dispatching anything while gated.
        let mut parser = HandshakeParser::new();
        std::mem::swap(&mut self.parser, &mut parser);
        {
            let mut bridge = EngineCodecBridge {
                engine: self,
                sink,
                collector: MessageCollector::default(),
                stop: false,
            };
            parser.receive(input, &mut bridge);
        }
        std::mem::swap(&mut self.parser, &mut parser);
        n
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: TlsEventSink>(&mut self, result: VerifyResult, sink: &mut S) {
        if !self.verify_pending || result.id != self.verify_id {
            return;
        }
        self.verify_pending = false;
        if result.ok {
            self.drain_parser(sink);
        } else {
            self.fail(sink, "certificate verification failed");
        }
    }

    /// Resume parsing after a gate (verification) without new input.
    fn drain_parser<S: TlsEventSink>(&mut self, sink: &mut S) {
        if self.verify_pending || self.state == State::Complete || self.state == State::Failed {
            return;
        }
        let mut parser = HandshakeParser::new();
        std::mem::swap(&mut self.parser, &mut parser);
        {
            let mut bridge = EngineCodecBridge {
                engine: self,
                sink,
                collector: MessageCollector::default(),
                stop: false,
            };
            let mut empty = &[][..];
            parser.receive(&mut empty, &mut bridge);
        }
        std::mem::swap(&mut self.parser, &mut parser);
    }

    /// Whether the handshake has finished successfully.
    pub fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn handle_parsed<S: TlsEventSink>(
        &mut self,
        msg_type: HandshakeType,
        parsed: ParsedIncoming,
        wire: Bytes,
        sink: &mut S,
    ) -> bool {
        match (self.config.role, msg_type, self.state, parsed) {
            (HandshakeRole::Client, HandshakeType::ServerHello, State::ClientHelloSent, ParsedIncoming::ServerHello(sh)) => {
                self.on_server_hello(sh, wire, sink)
            }
            (
                HandshakeRole::Client,
                HandshakeType::EncryptedExtensions,
                State::ReadingServerFlight,
                ParsedIncoming::EncryptedExtensions(ee),
            ) => self.on_encrypted_extensions(ee, wire, sink),
            (HandshakeRole::Client, HandshakeType::Certificate, State::ReadingServerFlight, ParsedIncoming::Certificate(_ctx, certs)) => {
                self.on_certificate(certs, wire, sink)
            }
            (
                HandshakeRole::Client,
                HandshakeType::CertificateRequest,
                State::ReadingServerFlight,
                ParsedIncoming::CertificateRequest(ctx),
            ) => self.on_certificate_request(ctx, wire, sink),
            (
                HandshakeRole::Client,
                HandshakeType::CertificateVerify,
                State::ReadingServerFlight,
                ParsedIncoming::CertificateVerify(scheme, sig),
            ) => self.on_certificate_verify(scheme, sig, wire, sink),
            (
                HandshakeRole::Client,
                HandshakeType::Finished,
                State::ReadingServerFlight | State::ReadingServerFinished,
                ParsedIncoming::Finished(vd),
            ) => self.on_server_finished(vd, wire, sink),
            (
                HandshakeRole::Client,
                HandshakeType::NewSessionTicket,
                State::Complete,
                ParsedIncoming::NewSessionTicket(nst),
            ) => {
                self.on_new_session_ticket(nst, sink);
                true
            }
            (HandshakeRole::Server, HandshakeType::ClientHello, State::Initial, ParsedIncoming::ClientHello(ch)) => {
                self.on_client_hello(ch, wire, sink)
            }
            (
                HandshakeRole::Server,
                HandshakeType::Certificate,
                State::AwaitingClientCertificate,
                ParsedIncoming::Certificate(ctx, certs),
            ) => self.on_client_certificate(ctx, certs, wire, sink),
            (
                HandshakeRole::Server,
                HandshakeType::CertificateVerify,
                State::AwaitingClientCertificateVerify,
                ParsedIncoming::CertificateVerify(scheme, sig),
            ) => self.on_client_certificate_verify(scheme, sig, wire, sink),
            (HandshakeRole::Server, HandshakeType::Finished, State::AwaitingClientFinished, ParsedIncoming::Finished(vd)) => {
                self.on_client_finished(vd, wire, sink)
            }
            _ => {
                self.fail(sink, "unexpected handshake message or state");
                false
            }
        }
    }

    fn client_send_hello<S: TlsEventSink>(&mut self, sink: &mut S) {
        let offer = self.config.kx_policy.preferred();
        let Ok(local) = LocalKeyShare::generate(offer) else {
            self.fail(sink, "key generation failed");
            return;
        };
        let mut random = [0u8; 32];
        let _ = getrandom(&mut random);
        let groups: Vec<u16> = self
            .config
            .kx_policy
            .groups()
            .iter()
            .map(|g| g.code())
            .collect();

        let ticket = self
            .config
            .server_name
            .as_ref()
            .and_then(|n| self.config.ticket_store.as_ref().and_then(|s| s.get(n)));

        let want_early = self.config.enable_early_data
            && ticket
                .as_ref()
                .map(|t| t.max_early_data_size > 0)
                .unwrap_or(false);

        let psk_offer = ticket.as_ref().map(|t| {
            self.psk = Some(t.psk);
            self.offered_ticket_alpn = Some(t.alpn.clone());
            OfferedPsk {
                identity: t.identity.clone(),
                obfuscated_ticket_age: t.obfuscated_ticket_age(),
                binder: [0u8; 32],
            }
        });

        let params = ClientHelloParams {
            random,
            cipher_suites: SUPPORTED_CIPHER_SUITES.to_vec(),
            key_share: KeyShareEntry {
                group: local.group().code(),
                share: local.client_share_bytes(),
            },
            supported_groups: groups,
            alpn: self.config.alpn.clone(),
            server_name: self.config.server_name.clone(),
            transport_parameters: self.config.local_transport_parameters.clone(),
            early_data: want_early,
            psk: psk_offer,
        };

        let hello = if let Some(psk) = self.psk {
            build_client_hello_with_binder(params, |hash| compute_psk_binder(&psk, hash))
        } else {
            build_client_hello(&params)
        };

        if want_early {
            if let Some(psk) = self.psk {
                let wire = hello.encode();
                let ch_hash = {
                    use aws_lc_rs::digest::{digest, SHA256};
                    let d = digest(&SHA256, &wire);
                    let mut out = [0u8; 32];
                    out.copy_from_slice(d.as_ref());
                    out
                };
                let early = derive_early_traffic(&psk, &ch_hash);
                self.early_client_secret = Some(early.client);
                self.early_data_offered = true;
                // The server's actual suite selection hasn't happened yet
                // (that's the whole point of 0-RTT), so this can't read
                // `self.negotiated_aead`. Safe by construction rather than
                // guesswork: 0-RTT only ever resumes a hopf-issued ticket
                // against a hopf server (see crypto-migration-plan.md's
                // Non-goals — foreign ticket ciphertext is never decrypted),
                // both always offering/preferring the same fixed
                // `SUPPORTED_CIPHER_SUITES` — so the server's pick is always
                // this crate's own top preference.
                let early_aead = Tls13Aead::from_suite(SUPPORTED_CIPHER_SUITES[0])
                    .expect("SUPPORTED_CIPHER_SUITES[0] is always a supported suite");
                sink.quic_early_keys_ready(early_aead, early.client);
                if let Some(limits) = ticket
                    .as_ref()
                    .and_then(|t| t.remembered_peer_limits)
                {
                    sink.quic_0rtt_peer_limits(limits);
                }
            }
        }

        self.emit_outgoing(&hello, sink);
        self.local_key_share = Some(local);
        self.state = State::ClientHelloSent;
    }

    fn on_server_hello<S: TlsEventSink>(
        &mut self,
        sh: super::handshake::ParsedServerHello,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(aead) = Tls13Aead::from_suite(sh.cipher_suite) else {
            self.fail(sink, "unsupported cipher suite");
            return false;
        };
        self.negotiated_aead = Some(aead);
        let Some(group) = NamedGroup::from_code(sh.selected_group) else {
            self.fail(sink, "unsupported key exchange group");
            return false;
        };
        let Some(local) = self.local_key_share.take() else {
            self.fail(sink, "missing local key share");
            return false;
        };
        let Ok(shared) = local.agree_client(group, &sh.key_share) else {
            self.fail(sink, "key agreement failed");
            return false;
        };
        self.resumed = sh.psk_selected_identity.is_some();
        self.transcript.add_message(&encoded);
        self.negotiated_group = Some(group);
        sink.key_exchange_group_negotiated(group.code());
        self.shared_secret = Some(shared);
        let psk = self.psk.as_ref();
        self.handshake_traffic = Some(derive_handshake_traffic_with_psk(
            psk,
            self.shared_secret.as_ref().unwrap(),
            &self.transcript.hash(),
        ));
        if let Some(traffic) = self.handshake_traffic.as_ref() {
            sink.quic_handshake_keys_ready(aead, traffic.client, traffic.server);
        }
        self.state = State::ReadingServerFlight;
        true
    }

    fn on_encrypted_extensions<S: TlsEventSink>(
        &mut self,
        ee: super::handshake::ParsedEncryptedExtensions,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        self.transcript.add_message(&encoded);
        self.negotiated_alpn = ee.alpn.clone();
        if ee.early_data {
            if let Some(ticket_alpn) = self.offered_ticket_alpn.as_ref() {
                if !ticket_alpn.is_empty() && ee.alpn.as_ref() != Some(ticket_alpn) {
                    self.fail(sink, "early_data accepted with ALPN mismatch");
                    return false;
                }
            }
            self.early_data_accepted = true;
            sink.early_data_accepted(true);
        } else {
            self.early_data_accepted = false;
            if self.early_data_offered {
                // Do not export early keys at handshake_complete after reject.
                self.early_client_secret = None;
                sink.early_data_accepted(false);
            }
        }
        if let Some(tp) = ee.transport_parameters {
            if self.config.role == HandshakeRole::Client {
                self.peer_remembered_limits = RememberedTransportLimits::decode_from_tp_blob(&tp);
            }
            sink.peer_transport_parameters(&tp);
        }
        if self.resumed {
            self.state = State::ReadingServerFinished;
        }
        true
    }

    fn on_certificate<S: TlsEventSink>(
        &mut self,
        certs: Vec<Bytes>,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        if self.resumed {
            self.fail(sink, "unexpected Certificate on resumed handshake");
            return false;
        }
        if certs.is_empty() {
            self.fail(sink, "server Certificate must not be empty");
            return false;
        }
        self.transcript.add_message(&encoded);
        self.peer_certs = certs;
        self.verify_id += 1;
        self.verify_pending = true;
        sink.verification_requested(super::sink::VerifyRequest {
            id: self.verify_id,
            peer_chain: self.peer_certs.clone(),
            server_name: self.config.server_name.clone(),
        });
        if let Some(store) = &self.config.trust_store {
            let ok = store
                .verify_server_chain(&self.peer_certs, self.config.server_name.as_deref())
                .is_ok();
            self.verify_pending = false;
            if !ok {
                self.fail(sink, "certificate verification failed");
                return false;
            }
            return true;
        }
        if let Some(verify) = &self.config.verify_override {
            let ok = (verify.0)(&self.peer_certs, self.config.server_name.as_deref());
            self.verify_pending = false;
            if !ok {
                self.fail(sink, "certificate verification failed");
                return false;
            }
            return true;
        }
        false
    }

    fn on_certificate_verify<S: TlsEventSink>(
        &mut self,
        scheme: u16,
        sig: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(leaf) = self.peer_certs.first() else {
            self.fail(sink, "certificate verify without certificate");
            return false;
        };
        let th = self.transcript.hash();
        if !verify_certificate_verify(false, leaf.as_ref(), scheme, &sig, &th) {
            self.fail(sink, "CertificateVerify signature invalid");
            return false;
        }
        self.transcript.add_message(&encoded);
        true
    }

    fn on_certificate_request<S: TlsEventSink>(
        &mut self,
        ctx: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        if self.resumed {
            self.fail(sink, "unexpected CertificateRequest on resumed handshake");
            return false;
        }
        self.transcript.add_message(&encoded);
        self.client_cert_request_context = Some(ctx);
        true
    }

    fn on_server_finished<S: TlsEventSink>(
        &mut self,
        vd: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(traffic) = self.handshake_traffic.as_ref() else {
            self.fail(sink, "missing handshake traffic");
            return false;
        };
        let th = self.transcript.hash();
        let expected = compute_finished_verify_data(&traffic.server, &th);
        if vd.as_ref() != expected {
            self.fail(sink, "server Finished verify failed");
            return false;
        }
        self.transcript.add_message(&encoded);
        self.client_send_finished(sink)
    }

    fn client_send_finished<S: TlsEventSink>(&mut self, sink: &mut S) -> bool {
        // RFC 8446 §7.1: application_traffic_secret_0 covers the transcript
        // through the *server's* Finished only — captured here, before any
        // client Certificate/CertificateVerify response joins the
        // transcript below (client Finished's own verify_data, in
        // contrast, must cover those too — it uses a separate, later hash).
        let th_for_app_traffic = self.transcript.hash();
        if let Some(ctx) = self.client_cert_request_context.take() {
            if !self.send_client_certificate_response(&ctx, sink) {
                return false;
            }
        }
        let Some(traffic) = self.handshake_traffic.as_ref() else {
            self.fail(sink, "missing handshake traffic");
            return false;
        };
        let th = self.transcript.hash();
        let vd = compute_finished_verify_data(&traffic.client, &th);
        let fin = build_finished(&vd);
        let Some(shared) = self.shared_secret.clone() else {
            self.fail(sink, "missing shared secret");
            return false;
        };
        let psk = self.psk;
        // See on_client_finished's comment: application_traffic_secret_0 uses
        // `th_for_app_traffic` (through server Finished only); resumption_master_secret
        // uses the transcript after this client Finished is added, below.
        self.application_traffic = Some(derive_application_traffic_with_psk(psk.as_ref(), &shared, &th_for_app_traffic));
        self.emit_outgoing(&fin, sink);
        let res_hash = self.transcript.hash();
        self.resumption_master = Some(derive_resumption_master_secret(psk.as_ref(), &shared, &res_hash));
        self.finish(sink);
        true
    }

    /// Respond to a `CertificateRequest`: `Certificate` (our chain, or empty
    /// if [`HandshakeConfig::client_credentials`] is unset — RFC 8446
    /// §4.4.2 permits this), and `CertificateVerify` when a non-empty chain
    /// was actually sent.
    fn send_client_certificate_response<S: TlsEventSink>(&mut self, ctx: &Bytes, sink: &mut S) -> bool {
        let creds = self.config.client_credentials.clone();
        let cert_refs: Vec<&[u8]> = creds
            .as_ref()
            .map(|c| c.cert_chain.iter().map(|c| c.as_ref()).collect())
            .unwrap_or_default();
        let cert_msg = build_certificate(ctx, &cert_refs);
        self.emit_outgoing(&cert_msg, sink);
        if let Some(creds) = creds.filter(|c| !c.cert_chain.is_empty()) {
            let cv_th = self.transcript.hash();
            let Some((scheme, sig)) = sign_certificate_verify(true, &creds.signing_key_pkcs8, &cv_th) else {
                self.fail(sink, "unsupported or invalid client signing key");
                return false;
            };
            let cv = build_certificate_verify(scheme, sig.as_ref());
            self.emit_outgoing(&cv, sink);
        }
        true
    }

    fn on_new_session_ticket<S: TlsEventSink>(
        &mut self,
        nst: super::handshake::collect::ParsedNewSessionTicket,
        _sink: &mut S,
    ) {
        let Some(rms) = self.resumption_master else {
            return;
        };
        let Some(name) = self.config.server_name.as_ref() else {
            return;
        };
        let Some(store) = self.config.ticket_store.as_ref() else {
            return;
        };
        let psk = derive_resumption_psk(&rms, &nst.nonce);
        let alpn = self
            .negotiated_alpn
            .clone()
            .or_else(|| self.config.alpn.first().cloned())
            .unwrap_or_default();
        store.put(
            name,
            StoredTicket {
                identity: nst.ticket,
                psk,
                max_early_data_size: nst.max_early_data,
                alpn,
                ticket_age_add: nst.age_add,
                lifetime_secs: nst.lifetime,
                received_at: std::time::Instant::now(),
                remembered_peer_limits: self
                    .peer_remembered_limits
                    .or(Some(RememberedTransportLimits::default_missing())),
            },
        );
    }

    fn on_client_hello<S: TlsEventSink>(
        &mut self,
        ch: super::handshake::ParsedClientHello,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        if let Some(tp) = &ch.transport_parameters {
            sink.peer_transport_parameters(tp);
        }

        // Selected up front (before the 0-RTT branch below, which needs it
        // too) rather than alongside group selection further down.
        let Some(&suite) = SUPPORTED_CIPHER_SUITES.iter().find(|s| ch.cipher_suites.contains(s)) else {
            self.fail(sink, "no mutually supported cipher suite");
            return false;
        };
        let aead = Tls13Aead::from_suite(suite).expect("suite drawn from SUPPORTED_CIPHER_SUITES");
        self.negotiated_aead = Some(aead);

        // Try PSK resumption.
        if let (Some(identity), Some(binder), Some(ticket_key)) = (
            ch.psk_identity.as_ref(),
            ch.psk_binder.as_ref(),
            self.config.ticket_key.as_ref(),
        ) {
            if let Some(payload) = open_ticket(ticket_key, identity) {
                // Verify binder over truncated ClientHello (drop last binder entry = 33 bytes).
                if encoded.len() > 33 && binder.len() == 32 {
                    let truncated = &encoded[..encoded.len() - 33];
                    let trunc_hash = {
                        use aws_lc_rs::digest::{digest, SHA256};
                        let d = digest(&SHA256, truncated);
                        let mut out = [0u8; 32];
                        out.copy_from_slice(d.as_ref());
                        out
                    };
                    let expected = compute_psk_binder(&payload.psk, &trunc_hash);
                    if binder.as_ref() == expected {
                        let obfuscated = ch.obfuscated_ticket_age.unwrap_or(0);
                        let age_ms = recover_ticket_age(obfuscated, payload.ticket_age_add);
                        let lifetime_ms = u64::from(payload.lifetime_secs).saturating_mul(1000);
                        if u64::from(age_ms) > lifetime_ms {
                            // Ticket past lifetime — ignore PSK, fall through to full handshake.
                        } else {
                            self.psk = Some(payload.psk);
                            self.resumed = true;
                            self.early_data_offered = ch.early_data;

                            let alpn_ok = payload.alpn.is_empty()
                                || ch.alpn.iter().any(|a| a == &payload.alpn);
                            let freshness_ms = u64::from(self.config.max_early_data_freshness_ms);
                            let fresh_enough = u64::from(age_ms) <= freshness_ms;
                            let tp_ok = match payload.remembered_limits.as_ref() {
                                Some(remembered) => {
                                    let current = self
                                        .config
                                        .local_transport_parameters
                                        .as_deref()
                                        .and_then(RememberedTransportLimits::decode_from_tp_blob)
                                        .unwrap_or_else(RememberedTransportLimits::default_missing);
                                    remembered.current_supports_0rtt(&current)
                                }
                                None => false,
                            };

                            if ch.early_data
                                && self.config.enable_early_data
                                && payload.max_early_data_size > 0
                                && alpn_ok
                                && fresh_enough
                                && tp_ok
                            {
                                let anti_ok = self
                                    .config
                                    .anti_replay
                                    .as_ref()
                                    .map(|ar| ar.check_and_record(identity.as_ref()))
                                    .unwrap_or(true);
                                if anti_ok {
                                    let ch_hash = {
                                        use aws_lc_rs::digest::{digest, SHA256};
                                        let d = digest(&SHA256, &encoded);
                                        let mut out = [0u8; 32];
                                        out.copy_from_slice(d.as_ref());
                                        out
                                    };
                                    let early = derive_early_traffic(&payload.psk, &ch_hash);
                                    self.early_client_secret = Some(early.client);
                                    self.early_data_accepted = true;
                                    sink.quic_early_keys_ready(aead, early.client);
                                }
                            }
                        }
                    }
                }
            }
        }

        let Some(group) = self.config.kx_policy.select_mutual(&ch.supported_groups) else {
            self.fail(sink, "no mutually supported key exchange group");
            return false;
        };
        let Some(peer_share) = ch.peer_key_share else {
            self.fail(sink, "missing client key share");
            return false;
        };
        if ch.key_share_group != Some(group.code()) {
            self.fail(sink, "client key share group mismatch");
            return false;
        }
        let Ok((server_share, shared)) = server_agree(group, &peer_share) else {
            self.fail(sink, "key agreement failed");
            return false;
        };
        self.transcript.add_message(&encoded);

        let mut server_random = [0u8; 32];
        let _ = getrandom(&mut server_random);
        let selected_psk = if self.resumed { Some(0u16) } else { None };
        let sh = build_server_hello_ext(
            &server_random,
            &ch.legacy_session_id,
            suite,
            group.code(),
            server_share.as_ref(),
            selected_psk,
        );
        self.emit_outgoing(&sh, sink);

        self.negotiated_group = Some(group);
        sink.key_exchange_group_negotiated(group.code());
        self.shared_secret = Some(shared);
        let psk = self.psk.as_ref();
        self.handshake_traffic = Some(derive_handshake_traffic_with_psk(
            psk,
            self.shared_secret.as_ref().unwrap(),
            &self.transcript.hash(),
        ));
        if let Some(traffic) = self.handshake_traffic.as_ref() {
            sink.quic_handshake_keys_ready(aead, traffic.client, traffic.server);
        }

        if ch.server_name.is_some() {
            self.peer_server_name = ch.server_name.clone();
        }
        let alpn = pick_alpn(&ch.alpn, &self.config.alpn);
        self.negotiated_alpn = alpn.clone();
        let ee = build_encrypted_extensions_ext(
            alpn.as_deref(),
            self.config.local_transport_parameters.as_deref(),
            self.early_data_accepted,
        );
        self.emit_outgoing(&ee, sink);

        let request_client_cert = !self.resumed && self.config.client_auth != ClientAuthPolicy::None;
        if !self.resumed {
            let Some(creds) = self.config.server.clone() else {
                self.fail(sink, "server credentials not configured");
                return false;
            };
            if request_client_cert {
                let cr = build_certificate_request(&[]);
                self.emit_outgoing(&cr, sink);
            }
            let cert_refs: Vec<&[u8]> = creds.cert_chain.iter().map(|c| c.as_ref()).collect();
            let cert_msg = build_certificate(&[], &cert_refs);
            self.emit_outgoing(&cert_msg, sink);

            let cv_th = self.transcript.hash();
            let Some((scheme, sig)) = sign_certificate_verify(false, &creds.signing_key_pkcs8, &cv_th) else {
                self.fail(sink, "unsupported or invalid server signing key");
                return false;
            };
            let cv = build_certificate_verify(scheme, sig.as_ref());
            self.emit_outgoing(&cv, sink);
        }

        let fin_th = self.transcript.hash();
        let traffic = self.handshake_traffic.as_ref().expect("hs traffic");
        let vd = compute_finished_verify_data(&traffic.server, &fin_th);
        let fin = build_finished(&vd);
        self.emit_outgoing(&fin, sink);
        // RFC 8446 §7.1: application_traffic_secret_0 covers the transcript
        // through the server's own Finished (just added above) — captured
        // here so `on_client_finished` uses this exact hash rather than
        // whatever the transcript grows to include by then (the client's
        // optional Certificate/CertificateVerify response, which must NOT
        // factor into this derivation).
        self.server_finished_hash = Some(self.transcript.hash());

        self.state = if request_client_cert {
            State::AwaitingClientCertificate
        } else {
            State::AwaitingClientFinished
        };
        true
    }

    fn on_client_certificate<S: TlsEventSink>(
        &mut self,
        ctx: Bytes,
        certs: Vec<Bytes>,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        if !ctx.is_empty() {
            self.fail(sink, "client Certificate context does not match CertificateRequest");
            return false;
        }
        self.transcript.add_message(&encoded);
        if certs.is_empty() {
            if self.config.client_auth == ClientAuthPolicy::Require {
                self.fail(sink, "client certificate required but none presented");
                return false;
            }
            self.state = State::AwaitingClientFinished;
            return true;
        }
        self.peer_certs = certs;
        self.expect_client_certificate_verify = true;
        self.verify_id += 1;
        self.verify_pending = true;
        sink.verification_requested(super::sink::VerifyRequest {
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
            self.state = State::AwaitingClientCertificateVerify;
            return true;
        }
        self.state = State::AwaitingClientCertificateVerify;
        false // gate: wait for feed_verification_result
    }

    fn on_client_certificate_verify<S: TlsEventSink>(
        &mut self,
        scheme: u16,
        sig: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(leaf) = self.peer_certs.first() else {
            self.fail(sink, "certificate verify without certificate");
            return false;
        };
        let th = self.transcript.hash();
        if !verify_certificate_verify(true, leaf.as_ref(), scheme, &sig, &th) {
            self.fail(sink, "client CertificateVerify signature invalid");
            return false;
        }
        self.transcript.add_message(&encoded);
        self.state = State::AwaitingClientFinished;
        true
    }

    fn on_client_finished<S: TlsEventSink>(
        &mut self,
        vd: Bytes,
        encoded: Bytes,
        sink: &mut S,
    ) -> bool {
        let Some(traffic) = self.handshake_traffic.as_ref() else {
            self.fail(sink, "missing handshake traffic");
            return false;
        };
        let th = self.transcript.hash();
        let expected = compute_finished_verify_data(&traffic.client, &th);
        if vd.as_ref() != expected {
            self.fail(sink, "client Finished verify failed");
            return false;
        }
        let Some(shared) = self.shared_secret.as_ref() else {
            self.fail(sink, "missing shared secret");
            return false;
        };
        let psk = self.psk.as_ref();
        // RFC 8446 §7.1: application_traffic_secret_0 is derived over the
        // transcript through *server* Finished only — `self.server_finished_hash`,
        // captured right when this engine sent its own Finished, before any
        // client Certificate/CertificateVerify (mTLS) or this client Finished
        // itself joined the transcript. `th` above (used for the Finished MAC
        // check) is NOT the right hash here once a client cert response is in
        // play. resumption_master_secret, in contrast, is derived through the
        // client's Finished too, so it needs the transcript *after* this add.
        let app_th = self
            .server_finished_hash
            .take()
            .expect("server Finished sent before client Finished");
        self.application_traffic = Some(derive_application_traffic_with_psk(psk, shared, &app_th));
        self.transcript.add_message(&encoded);
        let res_hash = self.transcript.hash();
        self.resumption_master = Some(derive_resumption_master_secret(psk, shared, &res_hash));
        self.finish(sink);
        true
    }

    fn emit_outgoing<S: TlsEventSink>(&mut self, msg: &HandshakeMessage, sink: &mut S) {
        let wire = msg.encode();
        self.transcript.add_message(&wire);
        sink.handshake_data_ready(&wire);
    }

    fn finish<S: TlsEventSink>(&mut self, sink: &mut S) {
        if self.state == State::Complete {
            return;
        }
        let app = self.application_traffic.take();
        let hs = self.handshake_traffic.take();
        let (client_hs, server_hs) = match hs {
            Some(t) => (t.client, t.server),
            None => {
                self.fail(sink, "handshake traffic missing at completion");
                return;
            }
        };
        let sni = match self.config.role {
            HandshakeRole::Server => self.peer_server_name.clone(),
            HandshakeRole::Client => self.config.server_name.clone(),
        };
        let aead = self.negotiated_aead.expect("cipher suite negotiated before completion");
        let mut info = SecurityInfo::secure(
            self.negotiated_alpn
                .clone()
                .or_else(|| self.config.alpn.first().cloned()),
            Some("TLSv1.3".to_string()),
            Some(aead.name().to_string()),
        )
        .with_sni(sni);
        if self.config.role == HandshakeRole::Server {
            if let Some(leaf) = self.peer_certs.first() {
                info = info
                    .with_peer_certificate_fingerprint(Some(crate::crypto::sha256_fingerprint_hex(leaf)))
                    .with_peer_certificate_chain(Some(self.peer_certs.clone()));
            }
        }
        if let Some(a) = app.as_ref() {
            sink.application_traffic_keys_ready(aead, a.client, a.server);
        }
        let early = self.early_client_secret;
        let quic = match self.config.mode {
            HandshakeMode::Quic => Some(QuicSecrets {
                aead,
                client_handshake_traffic_secret: client_hs,
                server_handshake_traffic_secret: server_hs,
                client_application_traffic_secret: app.as_ref().map(|a| a.client),
                server_application_traffic_secret: app.as_ref().map(|a| a.server),
                client_early_traffic_secret: early,
            }),
            HandshakeMode::TcpRecordLayer => None,
        };
        self.state = State::Complete;
        sink.handshake_complete(info, quic);

        // Server: mint NewSessionTicket on 1-RTT CRYPTO after handshake_complete.
        if self.config.role == HandshakeRole::Server {
            if let (Some(key), Some(rms)) = (self.config.ticket_key, self.resumption_master) {
                let max_early = if self.config.enable_early_data {
                    if self.config.max_early_data_size == 0 {
                        u32::MAX
                    } else {
                        self.config.max_early_data_size
                    }
                } else {
                    0
                };
                let alpn = self
                    .negotiated_alpn
                    .as_deref()
                    .or_else(|| self.config.alpn.first().map(|a| a.as_ref()))
                    .unwrap_or(b"h3");
                let remembered = self
                    .config
                    .local_transport_parameters
                    .as_deref()
                    .and_then(RememberedTransportLimits::decode_from_tp_blob)
                    .or(Some(RememberedTransportLimits::default_missing()));
                if let Some((msg, _)) =
                    mint_new_session_ticket(&key, &rms, max_early, alpn, remembered)
                {
                    // NST is post-handshake: do not add to the handshake transcript used
                    // for Finished; emit as raw CRYPTO only.
                    let wire = msg.encode();
                    sink.handshake_data_ready(&wire);
                }
            }
        }
    }

    fn fail<S: TlsEventSink>(&mut self, sink: &mut S, msg: &str) {
        if self.state != State::Failed {
            self.state = State::Failed;
            sink.protocol_error(TlsProtocolError::new(msg));
        }
    }
}

/// Codec seam: forwards parse events into a [`MessageCollector`], then dispatches
/// assembled messages to [`HandshakeEngine::handle_parsed`].
struct EngineCodecBridge<'a, S: TlsEventSink> {
    engine: &'a mut HandshakeEngine,
    sink: &'a mut S,
    collector: MessageCollector,
    stop: bool,
}

impl<S: TlsEventSink> HandshakeEvents for EngineCodecBridge<'_, S> {
    fn should_stop(&self) -> bool {
        self.stop || self.engine.verify_pending
    }

    fn message_begin(&mut self, msg_type: HandshakeType) {
        self.collector.message_begin(msg_type);
    }

    fn legacy_version(&mut self, version: u16) {
        self.collector.legacy_version(version);
    }

    fn random(&mut self, value: &[u8; 32]) {
        self.collector.random(value);
    }

    fn session_id(&mut self, value: &[u8]) {
        self.collector.session_id(value);
    }

    fn cipher_suite_offered(&mut self, suite: u16) {
        self.collector.cipher_suite_offered(suite);
    }

    fn cipher_suite_selected(&mut self, suite: u16) {
        self.collector.cipher_suite_selected(suite);
    }

    fn compression_method(&mut self, method: u8) {
        self.collector.compression_method(method);
    }

    fn supported_group(&mut self, group: u16) {
        self.collector.supported_group(group);
    }

    fn key_share(&mut self, group: u16, share: &[u8]) {
        self.collector.key_share(group, share);
    }

    fn alpn_protocol(&mut self, proto: &[u8]) {
        self.collector.alpn_protocol(proto);
    }

    fn server_name(&mut self, host: &str) {
        self.collector.server_name(host);
    }

    fn transport_parameters(&mut self, params: &[u8]) {
        self.collector.transport_parameters(params);
    }

    fn early_data(&mut self) {
        self.collector.early_data();
    }

    fn psk_identity(&mut self, identity: &[u8], obfuscated_ticket_age: u32) {
        self.collector.psk_identity(identity, obfuscated_ticket_age);
    }

    fn psk_binder(&mut self, binder: &[u8]) {
        self.collector.psk_binder(binder);
    }

    fn psk_selected_identity(&mut self, index: u16) {
        self.collector.psk_selected_identity(index);
    }

    fn new_session_ticket(
        &mut self,
        lifetime: u32,
        age_add: u32,
        nonce: &[u8],
        ticket: &[u8],
        max_early_data: u32,
    ) {
        self.collector
            .new_session_ticket(lifetime, age_add, nonce, ticket, max_early_data);
    }

    fn extension(&mut self, ext_type: u16, data: &[u8]) {
        self.collector.extension(ext_type, data);
    }

    fn certificate_request_context(&mut self, ctx: &[u8]) {
        self.collector.certificate_request_context(ctx);
    }

    fn certificate_entry(&mut self, der: &[u8]) {
        self.collector.certificate_entry(der);
    }

    fn certificate_verify(&mut self, scheme: u16, signature: &[u8]) {
        self.collector.certificate_verify(scheme, signature);
    }

    fn finished_verify_data(&mut self, data: &[u8]) {
        self.collector.finished_verify_data(data);
    }

    fn message_end(&mut self, msg_type: HandshakeType, wire: Bytes) {
        if self.stop {
            return;
        }
        let Some(parsed) = self.collector.take_parsed(msg_type) else {
            self.engine.fail(
                self.sink,
                match msg_type {
                    HandshakeType::Certificate => "invalid Certificate message",
                    HandshakeType::CertificateVerify => "invalid CertificateVerify message",
                    HandshakeType::Finished => "invalid Finished message",
                    other => {
                        let _ = other;
                        "invalid handshake message"
                    }
                },
            );
            self.stop = true;
            return;
        };
        if !self.engine.handle_parsed(msg_type, parsed, wire, self.sink) {
            self.stop = true;
        }
    }

    fn parse_error(&mut self, detail: &'static str) {
        self.engine.fail(self.sink, detail);
        self.stop = true;
    }
}

/// RFC 7301 §3.2: the first of the server's own preferences that the client
/// also offered — `None` (not a unilateral server pick) when the client
/// offered no ALPN extension at all, or none of its offers matched.
fn pick_alpn(client: &[Bytes], server: &[Bytes]) -> Option<Bytes> {
    server.iter().find(|s| client.contains(s)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::sink::{TlsEventSink, VerifyRequest, VerifyResult};

    #[derive(Default)]
    struct RecordingSink {
        events: Vec<String>,
        outbound: Vec<Bytes>,
        quic: Option<QuicSecrets>,
        peer_tp: Option<Bytes>,
        negotiated_group: Option<u16>,
        early_keys: Option<[u8; 32]>,
        early_data_accepted: Option<bool>,
        info: Option<SecurityInfo>,
        negotiated_aead: Option<Tls13Aead>,
    }

    impl TlsEventSink for RecordingSink {
        fn handshake_data_ready(&mut self, data: &[u8]) {
            self.events.push(format!("outbound {} bytes", data.len()));
            self.outbound.push(Bytes::copy_from_slice(data));
        }
        fn handshake_complete(&mut self, info: SecurityInfo, quic: Option<QuicSecrets>) {
            self.events.push("handshake_complete".into());
            self.quic = quic;
            self.info = Some(info);
        }
        fn verification_requested(&mut self, req: VerifyRequest) {
            self.events
                .push(format!("verification_requested id={}", req.id));
        }
        fn peer_transport_parameters(&mut self, params: &[u8]) {
            self.peer_tp = Some(Bytes::copy_from_slice(params));
            self.events.push(format!("peer_tp {} bytes", params.len()));
        }
        fn quic_handshake_keys_ready(&mut self, aead: Tls13Aead, _client: [u8; 32], _server: [u8; 32]) {
            self.negotiated_aead = Some(aead);
            self.events.push("handshake_keys".into());
        }
        fn quic_early_keys_ready(&mut self, aead: Tls13Aead, client_early: [u8; 32]) {
            self.negotiated_aead = Some(aead);
            self.early_keys = Some(client_early);
            self.events.push("early_keys".into());
        }
        fn application_traffic_keys_ready(&mut self, aead: Tls13Aead, _client: [u8; 32], _server: [u8; 32]) {
            self.negotiated_aead = Some(aead);
        }
        fn early_data_accepted(&mut self, accepted: bool) {
            self.early_data_accepted = Some(accepted);
            self.events
                .push(format!("early_data_accepted={accepted}"));
        }
        fn key_exchange_group_negotiated(&mut self, group: u16) {
            self.negotiated_group = Some(group);
            self.events
                .push(format!("negotiated_group=0x{group:04x}"));
        }
        fn protocol_error(&mut self, err: TlsProtocolError) {
            self.events.push(format!("protocol_error: {}", err.message));
        }
        fn timeout(&mut self, _kind: super::super::sink::TlsTimerKind) {}
        fn peer_closed(&mut self) {
            self.events.push("peer_closed".into());
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

    fn take_outbound(sink: &mut RecordingSink) -> Vec<Bytes> {
        std::mem::take(&mut sink.outbound)
    }

    fn relay_server(server: &mut HandshakeEngine, outbound: Vec<Bytes>, sink: &mut RecordingSink) {
        for chunk in outbound {
            let mut input = chunk.as_ref();
            server.feed_handshake_data(&mut input, sink);
        }
    }

    fn relay_client(client: &mut HandshakeEngine, outbound: Vec<Bytes>, sink: &mut RecordingSink) {
        for chunk in outbound {
            let mut input = chunk.as_ref();
            client.feed_handshake_data(&mut input, sink);
        }
    }

    fn run_loopback(client_cfg: HandshakeConfig, server_cfg: HandshakeConfig) -> RecordingSink {
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        assert!(client.is_complete(), "client: {:?}", sink.events);
        assert!(server.is_complete(), "server: {:?}", sink.events);
        sink
    }

    fn client_config_with_trust(creds: &ServerCredentials, kx: KxPolicy, tp: Option<Bytes>) -> HandshakeConfig {
        let mut trust = TrustStore::new();
        trust.add_anchor(creds.cert_chain[0].clone());
        HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: kx,
            local_transport_parameters: tp,
            trust_store: Some(trust),
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        }
    }

    #[test]
    fn client_start_emits_client_hello() {
        let mut engine = HandshakeEngine::new(HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("example.com".into()),
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        });
        let mut sink = RecordingSink::default();
        engine.start(&mut sink);
        assert_eq!(sink.events.len(), 1);
        assert!(sink.outbound[0].len() > 40);
    }

    #[test]
    fn full_1rtt_with_early_data_mints_and_resumes() {
        use std::sync::Arc;
        let creds = test_server_credentials();
        let store = ClientTicketStore::shared();
        let mut ticket_key = [0u8; 32];
        let _ = getrandom(&mut ticket_key);
        let mut client_cfg = client_config_with_trust(&creds, KxPolicy::classical_only(), None);
        client_cfg.enable_early_data = true;
        client_cfg.max_early_data_size = u32::MAX;
        client_cfg.ticket_store = Some(Arc::clone(&store));
        let server_cfg = HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: None,
            server: Some(creds.clone()),
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: true,
            max_early_data_size: u32::MAX,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: Some(ticket_key),
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        };
        let mut server = HandshakeEngine::new(server_cfg.clone());
        let mut client = HandshakeEngine::new(client_cfg.clone());
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        // Drain any NST from server after complete.
        let nst = take_outbound(&mut sink);
        relay_client(&mut client, nst, &mut sink);
        assert!(client.is_complete(), "{:?}", sink.events);
        assert!(server.is_complete(), "{:?}", sink.events);
        assert!(store.get("localhost").is_some(), "ticket stored");

        // Second handshake with PSK.
        let mut server2 = HandshakeEngine::new(server_cfg);
        let mut client2 = HandshakeEngine::new(client_cfg);
        let mut sink2 = RecordingSink::default();
        client2.start(&mut sink2);
        assert!(sink2.events.iter().any(|e| e.contains("outbound")), "{:?}", sink2.events);
        // early keys should have been installed
        relay_server(&mut server2, take_outbound(&mut sink2), &mut sink2);
        relay_client(&mut client2, take_outbound(&mut sink2), &mut sink2);
        relay_server(&mut server2, take_outbound(&mut sink2), &mut sink2);
        assert!(client2.is_complete(), "resume client: {:?}", sink2.events);
        assert!(server2.is_complete(), "resume server: {:?}", sink2.events);
        assert_eq!(sink2.early_data_accepted, Some(true));
    }

    fn mint_ticket_pair(
        store: &std::sync::Arc<ClientTicketStore>,
    ) -> (HandshakeConfig, HandshakeConfig, [u8; 32]) {
        let creds = test_server_credentials();
        let mut ticket_key = [0u8; 32];
        let _ = getrandom(&mut ticket_key);
        let mut client_cfg = client_config_with_trust(&creds, KxPolicy::classical_only(), None);
        client_cfg.enable_early_data = true;
        client_cfg.max_early_data_size = u32::MAX;
        client_cfg.ticket_store = Some(std::sync::Arc::clone(store));
        let server_tp = encode_initial_max_data(2_000_000);
        let server_cfg = HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: None,
            server: Some(creds),
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: Some(server_tp),
            trust_store: None,
            verify_override: None,
            enable_early_data: true,
            max_early_data_size: u32::MAX,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: Some(ticket_key),
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        };
        let mut server = HandshakeEngine::new(server_cfg.clone());
        let mut client = HandshakeEngine::new(client_cfg.clone());
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        assert!(store.get("localhost").is_some());
        (client_cfg, server_cfg, ticket_key)
    }

    fn resume_once(
        client_cfg: HandshakeConfig,
        server_cfg: HandshakeConfig,
    ) -> (RecordingSink, RecordingSink) {
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        // Feed CH to server using server sink so we can observe early_keys.
        for chunk in take_outbound(&mut sink_c) {
            let mut input = chunk.as_ref();
            server.feed_handshake_data(&mut input, &mut sink_s);
        }
        for chunk in take_outbound(&mut sink_s) {
            let mut input = chunk.as_ref();
            client.feed_handshake_data(&mut input, &mut sink_c);
        }
        for chunk in take_outbound(&mut sink_c) {
            let mut input = chunk.as_ref();
            server.feed_handshake_data(&mut input, &mut sink_s);
        }
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);
        (sink_c, sink_s)
    }

    #[test]
    fn resume_rejects_early_when_ticket_stale_for_freshness() {
        use std::time::{Duration, Instant};
        let store = ClientTicketStore::shared();
        let (client_cfg, mut server_cfg, _) = mint_ticket_pair(&store);
        // Age beyond freshness but within lifetime.
        {
            let mut t = store.get("localhost").unwrap();
            t.received_at = Instant::now() - Duration::from_secs(60);
            store.put("localhost", t);
        }
        server_cfg.max_early_data_freshness_ms = 10_000;
        let (sink_c, sink_s) = resume_once(client_cfg, server_cfg);
        assert_eq!(sink_c.early_data_accepted, Some(false));
        assert!(sink_s.early_keys.is_none(), "server must not install early keys");
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"));
    }

    #[test]
    fn anti_replay_blocks_second_early_data() {
        use std::sync::Arc;
        let store = ClientTicketStore::shared();
        let (client_cfg, mut server_cfg, _) = mint_ticket_pair(&store);
        let ar = AntiReplay::shared_default();
        server_cfg.anti_replay = Some(Arc::clone(&ar));
        let (sink_c1, sink_s1) = resume_once(client_cfg.clone(), server_cfg.clone());
        assert_eq!(sink_c1.early_data_accepted, Some(true));
        assert!(sink_s1.early_keys.is_some());
        let (sink_c2, sink_s2) = resume_once(client_cfg, server_cfg);
        assert_eq!(sink_c2.early_data_accepted, Some(false));
        assert!(sink_s2.early_keys.is_none());
        assert!(sink_c2.events.iter().any(|e| e == "handshake_complete"));
    }

    #[test]
    fn alpn_mismatch_rejects_early_data() {
        let store = ClientTicketStore::shared();
        let (mut client_cfg, server_cfg, _) = mint_ticket_pair(&store);
        // Ticket ALPN is h3; offer a different ALPN only.
        client_cfg.alpn = vec![Bytes::from_static(b"hq-interop")];
        let (sink_c, sink_s) = resume_once(client_cfg, server_cfg);
        assert_eq!(sink_c.early_data_accepted, Some(false));
        assert!(sink_s.early_keys.is_none());
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"));
    }

    #[test]
    fn resume_rejects_early_when_transport_parameters_shrink() {
        let store = ClientTicketStore::shared();
        let (client_cfg, mut server_cfg, _) = mint_ticket_pair(&store);
        // Ticket sealed with initial_max_data=2_000_000; resume with a smaller offer.
        server_cfg.local_transport_parameters = Some(encode_initial_max_data(1_000_000));
        let (sink_c, sink_s) = resume_once(client_cfg, server_cfg);
        assert_eq!(sink_c.early_data_accepted, Some(false));
        assert!(sink_s.early_keys.is_none());
        assert!(sink_c.events.iter().any(|e| e == "handshake_complete"));
    }

    #[test]
    fn expired_ticket_cleared_from_store() {
        use std::time::{Duration, Instant};
        let store = ClientTicketStore::shared();
        let (client_cfg, _, _) = mint_ticket_pair(&store);
        {
            let mut t = store.get("localhost").unwrap();
            t.lifetime_secs = 1;
            t.received_at = Instant::now() - Duration::from_secs(5);
            store.put("localhost", t);
        }
        assert!(store.get("localhost").is_none());
        // ClientHello should not offer PSK.
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        assert!(sink.early_keys.is_none());
    }

    fn full_1rtt_client_server_loopback() {
        let creds = test_server_credentials();
        let sink = run_loopback(
            client_config_with_trust(&creds, KxPolicy::classical_only(), None),
            HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Quic,
                alpn: vec![Bytes::from_static(b"h3")],
                server_name: None,
                server: Some(creds),
                kx_policy: KxPolicy::classical_only(),
                local_transport_parameters: None,
                trust_store: None,
                verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        },
        );
        let quic = sink.quic.expect("quic secrets");
        assert!(quic.client_application_traffic_secret.is_some());
        assert_eq!(sink.negotiated_group, Some(NamedGroup::X25519.code()));
    }

    fn client_config_with_verify_override(
        verify: VerifyOverride,
        kx: KxPolicy,
    ) -> HandshakeConfig {
        HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: kx,
            local_transport_parameters: None,
            trust_store: None,
            verify_override: Some(verify),
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        }
    }

    fn server_config_for(creds: ServerCredentials, kx: KxPolicy) -> HandshakeConfig {
        HandshakeConfig {
            role: HandshakeRole::Server,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: None,
            server: Some(creds),
            kx_policy: kx,
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        }
    }

    /// DANE-style custom verification: `verify_override` is checked instead of
    /// `trust_store` (server credentials generated fresh, so no fixed root
    /// would trust it — the point is that this connector doesn't need one).
    #[test]
    fn verify_override_accepts_when_callback_returns_true() {
        let creds = test_server_credentials();
        let expected_chain = creds.cert_chain.clone();
        let sink = run_loopback(
            client_config_with_verify_override(
                VerifyOverride(Arc::new(move |chain, name| {
                    chain == expected_chain.as_slice() && name == Some("localhost")
                })),
                KxPolicy::classical_only(),
            ),
            server_config_for(creds, KxPolicy::classical_only()),
        );
        assert!(sink.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink.events);
    }

    #[test]
    fn verify_override_rejects_when_callback_returns_false() {
        let creds = test_server_credentials();
        let mut server = HandshakeEngine::new(server_config_for(creds.clone(), KxPolicy::classical_only()));
        let mut client = HandshakeEngine::new(client_config_with_verify_override(
            VerifyOverride(Arc::new(|_chain, _name| false)),
            KxPolicy::classical_only(),
        ));
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        assert!(!client.is_complete());
        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }

    /// No trust_store and no verify_override — the `insecure_connector`
    /// shape — must gate on `feed_verification_result` and actually resume
    /// (not just accept the gate, but successfully process whatever
    /// CertificateVerify/Finished bytes were already buffered in the same
    /// relayed chunk) once it's fed `ok: true`.
    #[test]
    fn deferred_verification_result_resumes_and_completes_handshake() {
        let creds = test_server_credentials();
        let server_cfg = server_config_for(creds, KxPolicy::classical_only());
        let client_cfg = HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: Some("localhost".into()),
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        };
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);

        assert!(!client.is_complete(), "must gate before verification resolves");
        let req_id = sink
            .events
            .iter()
            .find_map(|e| e.strip_prefix("verification_requested id=").map(|s| s.parse::<u64>().unwrap()))
            .expect("verification_requested fired");

        client.feed_verification_result(VerifyResult { id: req_id, ok: true }, &mut sink);
        assert!(client.is_complete(), "must resume and finish after ok:true: {:?}", sink.events);

        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        assert!(server.is_complete(), "server: {:?}", sink.events);
    }

    #[test]
    fn full_1rtt_hybrid_pqc_and_transport_parameters() {
        use super::super::handshake::encode_initial_max_data;
        let creds = test_server_credentials();
        let client_tp = encode_initial_max_data(1_048_576);
        let server_tp = encode_initial_max_data(2_097_152);
        let sink = run_loopback(
            client_config_with_trust(&creds, KxPolicy::pqc_first(), Some(client_tp)),
            HandshakeConfig {
                role: HandshakeRole::Server,
                mode: HandshakeMode::Quic,
                alpn: vec![Bytes::from_static(b"h3")],
                server_name: None,
                server: Some(creds),
                kx_policy: KxPolicy::pqc_first(),
                local_transport_parameters: Some(server_tp),
                trust_store: None,
                verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        },
        );
        assert_eq!(
            sink.negotiated_group,
            Some(NamedGroup::X25519MLKEM768.code())
        );
        assert!(sink.peer_tp.is_some());
    }

    #[test]
    fn client_event_sequence_bad_server_hello() {
        let mut engine = HandshakeEngine::new(HandshakeConfig {
            role: HandshakeRole::Client,
            mode: HandshakeMode::Quic,
            alpn: vec![Bytes::from_static(b"h3")],
            server_name: None,
            server: None,
            kx_policy: KxPolicy::classical_only(),
            local_transport_parameters: None,
            trust_store: None,
            verify_override: None,
            enable_early_data: false,
            max_early_data_size: 0,
            max_early_data_freshness_ms: DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
            ticket_key: None,
            ticket_store: None,
            anti_replay: None,
            ..Default::default()
        });
        let mut sink = RecordingSink::default();
        engine.start(&mut sink);
        let bad_sh = HandshakeMessage {
            msg_type: HandshakeType::ServerHello,
            body: Bytes::from(vec![0u8; 8]),
        };
        let enc = bad_sh.encode();
        let mut slice = enc.as_ref();
        engine.feed_handshake_data(&mut slice, &mut sink);
        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }

    // ---- mTLS (client certificate authentication) ----

    fn client_config_with_cert(
        server_creds: &ServerCredentials,
        client_creds: ServerCredentials,
    ) -> HandshakeConfig {
        let mut cfg = client_config_with_trust(server_creds, KxPolicy::classical_only(), None);
        cfg.client_credentials = Some(client_creds);
        cfg
    }

    fn server_config_requiring_client_cert(
        server_creds: ServerCredentials,
        client_creds: &ServerCredentials,
        policy: ClientAuthPolicy,
    ) -> HandshakeConfig {
        let mut cfg = server_config_for(server_creds, KxPolicy::classical_only());
        cfg.client_auth = policy;
        let mut trust = TrustStore::new();
        trust.add_anchor(client_creds.cert_chain[0].clone());
        cfg.client_trust_store = Some(trust);
        cfg
    }

    #[test]
    fn mtls_require_completes_when_client_presents_a_trusted_certificate() {
        let server_creds = test_server_credentials();
        let client_creds = test_server_credentials();
        let client_cfg = client_config_with_cert(&server_creds, client_creds.clone());
        let server_cfg =
            server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let sink = run_loopback(client_cfg, server_cfg);
        assert!(sink.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink.events);
        // Server must have run its own verification_requested for the client's chain,
        // not just the (absent, server-role) one for a server chain.
        assert!(
            sink.events.iter().filter(|e| e.starts_with("verification_requested")).count() >= 1,
            "{:?}",
            sink.events
        );
    }

    /// The server side's `SecurityInfo` (the only role that runs
    /// mTLS verification) must expose the verified client certificate's
    /// fingerprint and chain — this is what SASL EXTERNAL
    /// (`hopf_auth::external`) keys off via `peer_certificate_fingerprint`.
    #[test]
    fn mtls_exposes_client_certificate_fingerprint_and_chain_on_the_server_side() {
        let server_creds = test_server_credentials();
        let client_creds = test_server_credentials();
        let expected_fp = crate::crypto::sha256_fingerprint_hex(&client_creds.cert_chain[0]);
        let client_cfg = client_config_with_cert(&server_creds, client_creds.clone());
        let server_cfg =
            server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink_c = RecordingSink::default();
        let mut sink_s = RecordingSink::default();
        client.start(&mut sink_c);
        relay_server(&mut server, take_outbound(&mut sink_c), &mut sink_s);
        relay_client(&mut client, take_outbound(&mut sink_s), &mut sink_c);
        relay_server(&mut server, take_outbound(&mut sink_c), &mut sink_s);
        assert!(client.is_complete(), "client: {:?}", sink_c.events);
        assert!(server.is_complete(), "server: {:?}", sink_s.events);

        let server_info = sink_s.info.expect("server SecurityInfo");
        assert_eq!(server_info.peer_certificate_fingerprint(), Some(expected_fp.as_str()));
        assert_eq!(
            server_info.peer_certificate_chain(),
            Some(client_creds.cert_chain.as_slice())
        );
        // Client side never runs mTLS verification of its own cert — its
        // SecurityInfo must not carry a client-certificate fingerprint.
        let client_info = sink_c.info.expect("client SecurityInfo");
        assert_eq!(client_info.peer_certificate_fingerprint(), None);
    }

    #[test]
    fn mtls_require_rejects_handshake_when_client_has_no_certificate() {
        let server_creds = test_server_credentials();
        let client_creds = test_server_credentials();
        // Client configured with no client_credentials at all.
        let client_cfg = client_config_with_trust(&server_creds, KxPolicy::classical_only(), None);
        let server_cfg =
            server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        assert!(!server.is_complete());
        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }

    #[test]
    fn mtls_request_completes_when_client_has_no_certificate() {
        let server_creds = test_server_credentials();
        let client_creds = test_server_credentials();
        let client_cfg = client_config_with_trust(&server_creds, KxPolicy::classical_only(), None);
        let server_cfg =
            server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Request);
        let sink = run_loopback(client_cfg, server_cfg);
        assert!(sink.events.iter().any(|e| e == "handshake_complete"), "{:?}", sink.events);
    }

    #[test]
    fn mtls_rejects_untrusted_client_certificate() {
        let server_creds = test_server_credentials();
        let client_creds = test_server_credentials();
        let untrusted_client_creds = test_server_credentials(); // not the one in client_trust_store
        let client_cfg = client_config_with_cert(&server_creds, untrusted_client_creds);
        let server_cfg =
            server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        relay_client(&mut client, take_outbound(&mut sink), &mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);
        assert!(!server.is_complete());
        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }

    #[test]
    fn mtls_rejects_tampered_client_certificate_verify_signature() {
        let server_creds = test_server_credentials();
        let client_creds = test_server_credentials();
        let client_cfg = client_config_with_cert(&server_creds, client_creds.clone());
        let server_cfg =
            server_config_requiring_client_cert(server_creds, &client_creds, ClientAuthPolicy::Require);
        let mut server = HandshakeEngine::new(server_cfg);
        let mut client = HandshakeEngine::new(client_cfg);
        let mut sink = RecordingSink::default();
        client.start(&mut sink);
        relay_server(&mut server, take_outbound(&mut sink), &mut sink);

        let mut outbound = take_outbound(&mut sink);
        // Client's second flight is [Certificate, CertificateVerify, Finished] in
        // one call — corrupt the last byte of the CertificateVerify message
        // (not the final Finished, which would just fail differently).
        assert!(outbound.len() >= 2, "expected a multi-message client flight: {outbound:?}");
        let cv_index = outbound.len() - 2;
        let mut corrupted = outbound[cv_index].to_vec();
        let n = corrupted.len();
        corrupted[n - 1] ^= 0xff;
        outbound[cv_index] = Bytes::from(corrupted);
        relay_client(&mut client, outbound, &mut sink);

        assert!(!server.is_complete());
        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }

    // ---- ChaCha20-Poly1305 cipher suite negotiation ----

    /// A normal client always offers both `SUPPORTED_CIPHER_SUITES` entries
    /// (AES-128-GCM first preference), so a Hopf-vs-Hopf loopback can't
    /// reach ChaCha20-Poly1305 negotiation deterministically — this drives
    /// the real `on_client_hello` selection logic directly with a
    /// ChaCha-only offer (as a peer that doesn't support AES-128-GCM would
    /// send) and inspects the real `ServerHello` wire bytes. Real
    /// negotiation against an independent peer is additionally proven by
    /// the `rustls` interop tests in `hopf-tls`.
    #[test]
    fn server_selects_chacha20_poly1305_when_its_the_only_offered_suite() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let creds = test_server_credentials();
        let server_cfg = server_config_for(creds, KxPolicy::classical_only());
        let mut server = HandshakeEngine::new(server_cfg);
        let mut sink = RecordingSink::default();

        let kp = EphemeralKeyPair::generate().unwrap();
        let hello = build_client_hello(&ClientHelloParams {
            random: [3u8; 32],
            cipher_suites: vec![CHACHA20_POLY1305_SHA256],
            key_share: KeyShareEntry {
                group: NamedGroup::X25519.code(),
                share: Bytes::copy_from_slice(&kp.public_key()),
            },
            supported_groups: vec![NamedGroup::X25519.code()],
            alpn: vec![],
            server_name: None,
            transport_parameters: None,
            early_data: false,
            psk: None,
        });
        let wire = hello.encode();
        let mut input = wire.as_ref();
        server.feed_handshake_data(&mut input, &mut sink);

        assert!(
            !sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "server must accept a ChaCha-only offer: {:?}",
            sink.events
        );
        let sh_wire = sink.outbound.first().expect("ServerHello emitted");
        let parsed = crate::tls::handshake::parse_server_hello(&sh_wire[4..]).expect("valid ServerHello");
        assert_eq!(parsed.cipher_suite, CHACHA20_POLY1305_SHA256);
        assert_eq!(sink.negotiated_aead, Some(Tls13Aead::ChaCha20Poly1305Sha256));
    }

    #[test]
    fn server_rejects_client_hello_with_no_mutually_supported_cipher_suite() {
        use crate::crypto::kx::{EphemeralKeyPair, NamedGroup};
        let creds = test_server_credentials();
        let server_cfg = server_config_for(creds, KxPolicy::classical_only());
        let mut server = HandshakeEngine::new(server_cfg);
        let mut sink = RecordingSink::default();

        let kp = EphemeralKeyPair::generate().unwrap();
        let hello = build_client_hello(&ClientHelloParams {
            random: [3u8; 32],
            cipher_suites: vec![0xffff], // unrecognized/unsupported
            key_share: KeyShareEntry {
                group: NamedGroup::X25519.code(),
                share: Bytes::copy_from_slice(&kp.public_key()),
            },
            supported_groups: vec![NamedGroup::X25519.code()],
            alpn: vec![],
            server_name: None,
            transport_parameters: None,
            early_data: false,
            psk: None,
        });
        let wire = hello.encode();
        let mut input = wire.as_ref();
        server.feed_handshake_data(&mut input, &mut sink);

        assert!(
            sink.events.iter().any(|e| e.starts_with("protocol_error")),
            "{:?}",
            sink.events
        );
    }

}
