// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS integration: interim [`session`] traits (rustls) and in-tree [`HandshakeEngine`].
//!
//! Phase 2 adds the reactive QUIC-first handshake engine under [`handshake`] and
//! [`HandshakeEngine`]. TCP record layer and full 1-RTT authentication land in
//! Phases 4–5; `hopf-tls` remains the interim adapter until Phase 8.

mod engine;
mod handshake;
mod session;
mod sink;

pub use engine::{HandshakeConfig, HandshakeEngine, HandshakeMode, HandshakeRole, ServerCredentials};
pub use handshake::transport_params::{decode_initial_max_data, encode_initial_max_data};
pub use session::{
    SharedTlsAcceptor, SharedTlsConnector, TlsAcceptor, TlsConnector, TlsProgress, TlsSession,
};
pub use sink::{
    NopTlsEventSink, QuicSecrets, TlsEventSink, TlsProtocolError, TlsTimerKind, VerifyRequest,
    VerifyResult,
};
