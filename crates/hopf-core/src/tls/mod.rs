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

pub use engine::{
    HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, ServerCredentials, VerifyOverride,
};
pub use handshake::ticket::{
    AntiReplay, ClientTicketStore, DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS, TICKET_LIFETIME_SECS,
};
pub use handshake::transport_params::{
    decode_initial_max_data, encode_initial_max_data, RememberedTransportLimits,
};
pub use pem::{
    acceptor_from_pem, connector_from_pem, connector_with_verify_override, insecure_connector,
    server_credentials_from_pem, SharedTlsAcceptor, SharedTlsConnector, TlsAcceptor, TlsConnector,
};
pub use record::{NopTlsRecordSink, TlsRecordEngine, TlsRecordSink};
pub use sink::{
    NopTlsEventSink, QuicSecrets, TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest,
    VerifyResult,
};
