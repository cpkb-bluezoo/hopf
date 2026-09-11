// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reactive TLS event sink (Phase 2+ in-tree engine).

use bytes::Bytes;

use crate::security::SecurityInfo;

use super::engine::Tls13Aead;

/// TLS protocol error surfaced to the connection pump — not a `Result` from `feed_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsProtocolError {
    /// The alert this side either sent to the peer (a locally-detected
    /// violation) or received from them (relayed verbatim, not re-sent —
    /// see [`super::TlsRecordEngine`]'s module doc for why).
    pub alert: AlertDescription,
    /// Human-readable detail for logs.
    pub message: String,
}

impl TlsProtocolError {
    /// Construct from an alert description and a static or owned message.
    pub fn new(alert: AlertDescription, message: impl Into<String>) -> Self {
        Self {
            alert,
            message: message.into(),
        }
    }
}

/// RFC 8446 §6.2 alert description codes. TLS 1.2 (RFC 5246 §7.2.2) and
/// DTLS 1.2/1.3 (RFC 6347/RFC 9147, which both defer to the TLS alert
/// registry) assign the same numeric values to every code they share with
/// TLS 1.3, so one enum serves every engine in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AlertDescription {
    /// Orderly connection shutdown, warning-level only.
    CloseNotify,
    /// A message arrived out of order, in the wrong state, or of a kind
    /// not valid here.
    UnexpectedMessage,
    /// Record-layer MAC/AEAD-tag verification failed.
    BadRecordMac,
    /// A record exceeded its maximum permitted length.
    RecordOverflow,
    /// Negotiation couldn't produce an acceptable set of parameters.
    HandshakeFailure,
    /// A certificate was corrupt, unparseable, or otherwise failed to verify.
    BadCertificate,
    /// A certificate's type isn't supported.
    UnsupportedCertificate,
    /// A certificate has been revoked by its signer.
    CertificateRevoked,
    /// A certificate has expired or isn't yet valid.
    CertificateExpired,
    /// A certificate is unusable for a reason not covered by a more
    /// specific code.
    CertificateUnknown,
    /// A field in the handshake was out of range or inconsistent with
    /// other fields.
    IllegalParameter,
    /// A valid certificate chain led to an untrusted or unknown CA.
    UnknownCa,
    /// A valid certificate was rejected by local policy.
    AccessDenied,
    /// A message couldn't be decoded because a field was out of range or
    /// the message length was wrong.
    DecodeError,
    /// A handshake cryptographic operation failed — signature, Finished,
    /// or PSK binder verification.
    DecryptError,
    /// The protocol version the peer attempted isn't supported or
    /// recognized.
    ProtocolVersion,
    /// The negotiated security parameters don't meet local requirements.
    InsufficientSecurity,
    /// An error local to this side, unrelated to the peer or protocol
    /// correctness.
    InternalError,
    /// A client's fallback to a lower protocol version was rejected
    /// (RFC 7507).
    InappropriateFallback,
    /// The handshake was canceled by the user for a reason unrelated to a
    /// protocol failure.
    UserCanceled,
    /// A required extension was missing.
    MissingExtension,
    /// An extension was present that isn't permitted in this message.
    UnsupportedExtension,
    /// The `server_name` extension carried an unrecognized name (RFC 6066).
    UnrecognizedName,
    /// The OCSP response carried in the `status_request` extension was
    /// invalid.
    BadCertificateStatusResponse,
    /// The offered PSK identity isn't recognized.
    UnknownPskIdentity,
    /// A client certificate was required but none was presented
    /// (TLS 1.3 only).
    CertificateRequired,
    /// No application-layer protocol overlapped during ALPN negotiation
    /// (RFC 7301).
    NoApplicationProtocol,
    /// A wire code outside the set above — only constructed when relaying
    /// an alert the *peer* sent, never when this crate sends its own.
    Other(u8),
}

impl AlertDescription {
    /// The RFC 8446 §6.2 wire value.
    pub fn code(self) -> u8 {
        match self {
            Self::CloseNotify => 0,
            Self::UnexpectedMessage => 10,
            Self::BadRecordMac => 20,
            Self::RecordOverflow => 22,
            Self::HandshakeFailure => 40,
            Self::BadCertificate => 42,
            Self::UnsupportedCertificate => 43,
            Self::CertificateRevoked => 44,
            Self::CertificateExpired => 45,
            Self::CertificateUnknown => 46,
            Self::IllegalParameter => 47,
            Self::UnknownCa => 48,
            Self::AccessDenied => 49,
            Self::DecodeError => 50,
            Self::DecryptError => 51,
            Self::ProtocolVersion => 70,
            Self::InsufficientSecurity => 71,
            Self::InternalError => 80,
            Self::InappropriateFallback => 86,
            Self::UserCanceled => 90,
            Self::MissingExtension => 109,
            Self::UnsupportedExtension => 110,
            Self::UnrecognizedName => 112,
            Self::BadCertificateStatusResponse => 113,
            Self::UnknownPskIdentity => 115,
            Self::CertificateRequired => 116,
            Self::NoApplicationProtocol => 120,
            Self::Other(code) => code,
        }
    }

    /// Parse a wire value received from a peer — never fails, since an
    /// alert code this crate doesn't otherwise construct is still worth
    /// surfacing to the embedder verbatim rather than discarding.
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => Self::CloseNotify,
            10 => Self::UnexpectedMessage,
            20 => Self::BadRecordMac,
            22 => Self::RecordOverflow,
            40 => Self::HandshakeFailure,
            42 => Self::BadCertificate,
            43 => Self::UnsupportedCertificate,
            44 => Self::CertificateRevoked,
            45 => Self::CertificateExpired,
            46 => Self::CertificateUnknown,
            47 => Self::IllegalParameter,
            48 => Self::UnknownCa,
            49 => Self::AccessDenied,
            50 => Self::DecodeError,
            51 => Self::DecryptError,
            70 => Self::ProtocolVersion,
            71 => Self::InsufficientSecurity,
            80 => Self::InternalError,
            86 => Self::InappropriateFallback,
            90 => Self::UserCanceled,
            109 => Self::MissingExtension,
            110 => Self::UnsupportedExtension,
            112 => Self::UnrecognizedName,
            113 => Self::BadCertificateStatusResponse,
            115 => Self::UnknownPskIdentity,
            116 => Self::CertificateRequired,
            120 => Self::NoApplicationProtocol,
            other => Self::Other(other),
        }
    }
}

/// Timer kinds the handshake engine may arm (retransmit / overall timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTimerKind {
    /// Overall handshake deadline.
    HandshakeTimeout,
}

/// Which direction's application traffic key a `KeyUpdate` ratcheted
/// (RFC 8446 §4.6.3) — relative to this engine's own role, not
/// client/server, since the ratchet logic itself is role-symmetric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUpdateDirection {
    /// The peer's traffic key (their `KeyUpdate` was received) — update
    /// our read key.
    Read,
    /// Our own traffic key (we sent a `KeyUpdate`) — update our write key.
    Write,
}

/// Certificate chain verification request — engine idles until [`HandshakeEngine::feed_verification_result`].
#[derive(Debug, Clone)]
pub struct VerifyRequest {
    /// Opaque correlation id matching the verification result.
    pub id: u64,
    /// Peer certificate chain (DER, leaf first).
    pub peer_chain: Vec<Bytes>,
    /// SNI hostname to verify, if any.
    pub server_name: Option<String>,
}

/// Outcome of asynchronous (or inline) chain verification.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    /// Matches [`VerifyRequest::id`].
    pub id: u64,
    /// Whether the chain verified for `server_name`.
    pub ok: bool,
}

/// RFC 9001 QUIC-TLS traffic secrets exported when the handshake completes (QUIC-first path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicSecrets {
    /// Negotiated AEAD — see [`TlsEventSink::quic_handshake_keys_ready`].
    pub aead: Tls13Aead,
    /// Client handshake traffic secret (32 bytes).
    pub client_handshake_traffic_secret: [u8; 32],
    /// Server handshake traffic secret (32 bytes).
    pub server_handshake_traffic_secret: [u8; 32],
    /// Client application traffic secret — present once the full 1-RTT handshake finishes.
    pub client_application_traffic_secret: Option<[u8; 32]>,
    /// Server application traffic secret.
    pub server_application_traffic_secret: Option<[u8; 32]>,
    /// Client early (0-RTT) traffic secret, when early data was negotiated.
    pub client_early_traffic_secret: Option<[u8; 32]>,
}

/// Events emitted by [`super::HandshakeEngine`] — consumed by the QUIC driver or TCP pump.
pub trait TlsEventSink {
    /// Handshake transcript bytes to send (QUIC CRYPTO stream or TCP TLS records in Phase 4).
    fn handshake_data_ready(&mut self, data: &[u8]);

    /// Handshake finished; QUIC driver installs keys from `quic_secrets`.
    fn handshake_complete(&mut self, info: SecurityInfo, quic_secrets: Option<QuicSecrets>);

    /// Chain verification should run (possibly on `StorageExecutor`).
    fn verification_requested(&mut self, req: VerifyRequest);

    /// Peer's QUIC transport parameters (RFC 9001 §8.2), when received.
    fn peer_transport_parameters(&mut self, _params: &[u8]) {}

    /// Handshake traffic secrets are available — install Handshake packet-space keys.
    /// `aead` is the negotiated cipher suite's AEAD (RFC 8446 §9.1's MUST
    /// `TLS_AES_128_GCM_SHA256` or SHOULD `TLS_CHACHA20_POLY1305_SHA256`) — the
    /// only thing that differs between them is AEAD key length.
    fn quic_handshake_keys_ready(&mut self, _aead: Tls13Aead, _client: [u8; 32], _server: [u8; 32]) {}

    /// Client early traffic secret available (0-RTT keys) — before or with ClientHello send /
    /// after accepting a PSK on the server. See [`Self::quic_handshake_keys_ready`] for `aead`.
    fn quic_early_keys_ready(&mut self, _aead: Tls13Aead, _client_early: [u8; 32]) {}

    /// Application traffic secrets — fired alongside `handshake_complete` in both
    /// [`super::HandshakeMode::Quic`] and [`super::HandshakeMode::TcpRecordLayer`] (the QUIC
    /// path also gets these via `handshake_complete`'s `QuicSecrets`; the TCP record layer has
    /// no other way to learn them, since `QuicSecrets` is QUIC-only). See
    /// [`Self::quic_handshake_keys_ready`] for `aead`.
    fn application_traffic_keys_ready(&mut self, _aead: Tls13Aead, _client: [u8; 32], _server: [u8; 32]) {}

    /// One direction's application traffic secret ratcheted forward by a
    /// `KeyUpdate` (RFC 8446 §4.6.3/§7.2), TCP-TLS-1.3 only — never fired
    /// for [`super::HandshakeMode::Quic`] or [`super::HandshakeMode::Dtls`].
    /// Carries the raw new secret, same shape as
    /// [`Self::application_traffic_keys_ready`] — the record layer
    /// re-derives key+iv itself.
    fn application_traffic_key_updated(&mut self, _aead: Tls13Aead, _direction: KeyUpdateDirection, _secret: [u8; 32]) {}

    /// Negotiated TLS key-exchange group (IANA code, e.g. 0x11ec for X25519MLKEM768).
    fn key_exchange_group_negotiated(&mut self, _group: u16) {}

    /// Whether the server accepted early data (client only; after EncryptedExtensions).
    fn early_data_accepted(&mut self, _accepted: bool) {}

    /// Client-only: peer limits to apply for 0-RTT before EncryptedExtensions (RFC 9000 §7.4.1).
    fn quic_0rtt_peer_limits(&mut self, _limits: super::handshake::RememberedTransportLimits) {}

    /// Non-fatal protocol failure.
    fn protocol_error(&mut self, err: TlsProtocolError);

    /// Timer fired.
    fn timeout(&mut self, kind: TlsTimerKind);

    /// Peer closed cleanly or with alert.
    fn peer_closed(&mut self);
}

/// No-op sink for tests.
#[derive(Debug, Default)]
pub struct NopTlsEventSink;

impl TlsEventSink for NopTlsEventSink {
    fn handshake_data_ready(&mut self, _data: &[u8]) {}
    fn handshake_complete(&mut self, _info: SecurityInfo, _quic_secrets: Option<QuicSecrets>) {}
    fn verification_requested(&mut self, _req: VerifyRequest) {}
    fn peer_transport_parameters(&mut self, _params: &[u8]) {}
    fn quic_handshake_keys_ready(&mut self, _aead: Tls13Aead, _client: [u8; 32], _server: [u8; 32]) {}
    fn quic_early_keys_ready(&mut self, _aead: Tls13Aead, _client_early: [u8; 32]) {}
    fn application_traffic_keys_ready(&mut self, _aead: Tls13Aead, _client: [u8; 32], _server: [u8; 32]) {}
    fn application_traffic_key_updated(&mut self, _aead: Tls13Aead, _direction: KeyUpdateDirection, _secret: [u8; 32]) {}
    fn key_exchange_group_negotiated(&mut self, _group: u16) {}
    fn early_data_accepted(&mut self, _accepted: bool) {}
    fn quic_0rtt_peer_limits(&mut self, _limits: super::handshake::RememberedTransportLimits) {}
    fn protocol_error(&mut self, _err: TlsProtocolError) {}
    fn timeout(&mut self, _kind: TlsTimerKind) {}
    fn peer_closed(&mut self) {}
}
