// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 handshake (RFC 8446 §4) — shared by QUIC and (Phase 4+) TCP.

pub mod collect;
pub mod key_schedule;
pub mod messages;
pub mod parser;
pub mod transcript;
pub mod transport_params;
pub mod verify;

pub use collect::{
    parse_certificate, parse_certificate_verify, parse_client_hello, parse_encrypted_extensions,
    parse_finished, parse_server_hello, ParsedClientHello, ParsedEncryptedExtensions,
    ParsedServerHello,
};
pub use key_schedule::{
    compute_finished_verify_data, derive_application_traffic, derive_handshake_traffic,
    ApplicationTrafficSecrets, HandshakeTrafficSecrets,
};
pub use messages::{
    build_certificate, build_certificate_verify, build_client_hello, build_encrypted_extensions,
    build_finished, build_server_hello, ClientHelloParams, HandshakeMessage, HandshakeType,
    KeyShareEntry,
};
pub use parser::{HandshakeEvents, HandshakeParser};
pub use transcript::Transcript;
pub use transport_params::encode_initial_max_data;
pub use verify::{sign_ed25519_certificate_verify, verify_certificate_verify};
