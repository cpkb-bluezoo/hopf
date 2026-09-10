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
    parse_certificate, parse_certificate_verify, parse_client_hello, parse_encrypted_extensions,
    parse_finished, parse_server_hello, ParsedClientHello, ParsedEncryptedExtensions,
    ParsedNewSessionTicket, ParsedServerHello,
};
pub use key_schedule::{
    compute_finished_verify_data, compute_psk_binder, derive_application_traffic,
    derive_application_traffic_with_psk, derive_early_traffic, derive_handshake_traffic,
    derive_handshake_traffic_with_psk, derive_resumption_master_secret, derive_resumption_psk,
    early_secret, ApplicationTrafficSecrets, EarlyTrafficSecrets, HandshakeTrafficSecrets,
};
pub use messages::{
    build_certificate, build_certificate_request, build_certificate_verify, build_client_hello,
    build_client_hello_with_binder, build_encrypted_extensions, build_encrypted_extensions_ext,
    build_finished, build_hello_retry_request, build_key_update, build_new_session_ticket,
    build_server_hello, build_server_hello_ext, key_update_request, ClientHelloParams,
    HandshakeMessage, HandshakeType, KeyShareEntry, OfferedPsk,
};
pub use parser::{HandshakeEvents, HandshakeParser};
pub use ticket::{
    AntiReplay, ClientTicketStore, StoredTicket, DEFAULT_MAX_EARLY_DATA_FRESHNESS_MS,
    TICKET_LIFETIME_SECS,
};
pub use transcript::Transcript;
pub use transport_params::{
    encode_initial_max_data, RememberedTransportLimits, INITIAL_MAX_DATA,
};
pub use verify::{
    sign_certificate_verify, sign_ed25519_certificate_verify, verify_certificate_verify,
    SUPPORTED_SIGNATURE_SCHEMES,
};
