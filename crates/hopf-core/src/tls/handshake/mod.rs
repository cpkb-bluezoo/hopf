// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 handshake (RFC 8446 §4) — shared by QUIC and (Phase 4+) TCP.

pub mod collect;
pub mod key_schedule;
pub mod messages;
pub mod parser;
pub mod ticket;
pub mod transcript;
pub mod transport_params;
pub mod verify;

pub use collect::{
    ParsedClientHello, ParsedEncryptedExtensions, ParsedServerHello,
};
pub use key_schedule::{
    compute_finished_verify_data, compute_psk_binder,
    derive_application_traffic_with_psk, derive_early_traffic,
    derive_handshake_traffic_with_psk, derive_resumption_master_secret, derive_resumption_psk, ApplicationTrafficSecrets, HandshakeTrafficSecrets,
};
pub use messages::{
    build_certificate, build_certificate_request, build_certificate_verify, build_client_hello,
    build_client_hello_with_binder, build_encrypted_extensions_ext,
    build_finished, build_hello_retry_request, build_key_update, build_server_hello_ext, key_update_request, ClientHelloParams,
    HandshakeMessage, HandshakeType, KeyShareEntry, OfferedPsk,
};
pub use ticket::DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS;
pub use transcript::Transcript;
pub use transport_params::RememberedTransportLimits;
