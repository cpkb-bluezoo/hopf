// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Reactive TLS event sink (Phase 2+ in-tree engine).

use bytes::Bytes;

use crate::security::SecurityInfo;

/// TLS protocol error surfaced to the connection pump — not a `Result` from `feed_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsProtocolError {
    /// Human-readable detail for logs.
    pub message: String,
}

impl TlsProtocolError {
    /// Construct from a static or owned message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Timer kinds the handshake engine may arm (retransmit / overall timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTimerKind {
    /// Overall handshake deadline.
    HandshakeTimeout,
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
    /// Client handshake traffic secret (32 bytes).
    pub client_handshake_traffic_secret: [u8; 32],
    /// Server handshake traffic secret (32 bytes).
    pub server_handshake_traffic_secret: [u8; 32],
    /// Client application traffic secret — present once the full 1-RTT handshake finishes.
    pub client_application_traffic_secret: Option<[u8; 32]>,
    /// Server application traffic secret.
    pub server_application_traffic_secret: Option<[u8; 32]>,
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
    fn quic_handshake_keys_ready(&mut self, _client: [u8; 32], _server: [u8; 32]) {}

    /// Negotiated TLS key-exchange group (IANA code, e.g. 0x11ec for X25519MLKEM768).
    fn key_exchange_group_negotiated(&mut self, _group: u16) {}

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
    fn quic_handshake_keys_ready(&mut self, _client: [u8; 32], _server: [u8; 32]) {}
    fn key_exchange_group_negotiated(&mut self, _group: u16) {}
    fn protocol_error(&mut self, _err: TlsProtocolError) {}
    fn timeout(&mut self, _kind: TlsTimerKind) {}
    fn peer_closed(&mut self) {}
}
