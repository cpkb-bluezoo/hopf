// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! In-tree TLS 1.3: [`HandshakeEngine`] (Phase 2, QUIC-first) plus [`record`],
//! the Phase 4 TCP record layer wrapping it in [`HandshakeMode::TcpRecordLayer`]
//! behind [`TlsRecordEngine`]. [`pem`] loads PEM certs/keys into
//! [`TlsAcceptor`]/[`TlsConnector`] factories that `TcpConnection` pumps
//! directly — `hopf-tls` (rustls) is no longer in `TcpConnection`'s path.

mod engine;
mod handshake;
mod pem;
mod record;
mod sink;
// `pub(crate)`, not private: `hopf-core::dtls12` (DTLS 1.2) wraps
// `tls12::engine::Tls12Engine` directly, the same way `hopf-core::dtls`
// wraps `engine::HandshakeEngine` (TLS 1.3) — needs `tls12::engine`'s
// `CipherKind`/`DirectionalKeyMaterial`/`Tls12EventSink`/`Tls12Engine`
// reachable via the full path, none of which `tls/mod.rs`'s own `pub use`
// list re-exports today.
pub(crate) mod tls12;

pub use engine::{
    ClientAuthPolicy, HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, ServerCredentials,
    Tls13Aead, VerifyOverride, AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256, SUPPORTED_CIPHER_SUITES,
};
pub use handshake::ticket::{
    AntiReplay, ClientTicketStore, DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS, TICKET_LIFETIME_SECS,
};
pub use handshake::transport_params::{
    decode_initial_max_data, encode_initial_max_data, RememberedTransportLimits,
};
pub use pem::{
    acceptor_from_pem, acceptor_from_pem_tls12, acceptor_from_pem_tls12_with_client_auth,
    acceptor_from_pem_with_client_auth, connector_from_pem, connector_from_pem_tls12,
    connector_from_pem_tls12_with_client_cert, connector_from_pem_with_client_cert,
    connector_with_verify_override, insecure_connector, insecure_connector_tls12,
    public_trust_connector, server_credentials_from_pem, SharedTlsAcceptor, SharedTlsConnector,
    TlsAcceptor, TlsConnector,
};
pub use record::{NopTlsRecordSink, TlsRecordEngine, TlsRecordSink};
pub use sink::{
    NopTlsEventSink, QuicSecrets, TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest,
    VerifyResult,
};
pub use tls12::engine::{Config as Tls12Config, Role as Tls12Role, SUPPORTED_CIPHER_SUITES as TLS12_SUPPORTED_CIPHER_SUITES};
pub use tls12::record::Tls12RecordEngine;
pub use tls12::ticket::{StoredTls12Ticket, Tls12ClientTicketStore, TICKET_LIFETIME_SECS as TLS12_TICKET_LIFETIME_SECS};

/// Either TLS version's record engine — `TcpConnection` pumps whichever one
/// its configured acceptor/connector produced through one shared surface
/// (both engines expose the same method set and the same
/// [`TlsRecordSink`], so this is a thin, no-behavior-of-its-own dispatch).
pub enum TlsVariant {
    /// TLS 1.3 (the default; every existing `hopf-core::tls::pem` helper builds this).
    V13(TlsRecordEngine),
    /// TLS 1.2 (legacy mail/FTPS interop; ECDHE + GCM only for now).
    V12(Tls12RecordEngine),
}

impl TlsVariant {
    /// Begin the handshake — client emits `ClientHello`; server waits for input.
    pub fn start<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.start(sink),
            TlsVariant::V12(e) => e.start(sink),
        }
    }

    /// Whether the handshake has completed.
    pub fn is_complete(&self) -> bool {
        match self {
            TlsVariant::V13(e) => e.is_complete(),
            TlsVariant::V12(e) => e.is_complete(),
        }
    }

    /// Consume raw bytes off the TCP stream.
    pub fn feed_ciphertext<S: TlsRecordSink + ?Sized>(&mut self, input: &mut &[u8], sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.feed_ciphertext(input, sink),
            TlsVariant::V12(e) => e.feed_ciphertext(input, sink),
        }
    }

    /// Encrypt and frame application data. Only valid once [`Self::is_complete`].
    pub fn send_application_data<S: TlsRecordSink + ?Sized>(&mut self, plaintext: &[u8], sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.send_application_data(plaintext, sink),
            TlsVariant::V12(e) => e.send_application_data(plaintext, sink),
        }
    }

    /// Resume after chain verification (from `StorageExecutor` or inline).
    pub fn feed_verification_result<S: TlsRecordSink + ?Sized>(&mut self, result: VerifyResult, sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.feed_verification_result(result, sink),
            TlsVariant::V12(e) => e.feed_verification_result(result, sink),
        }
    }

    /// Send a `close_notify` alert under the current epoch.
    pub fn send_close_notify<S: TlsRecordSink + ?Sized>(&mut self, sink: &mut S) {
        match self {
            TlsVariant::V13(e) => e.send_close_notify(sink),
            TlsVariant::V12(e) => e.send_close_notify(sink),
        }
    }
}
