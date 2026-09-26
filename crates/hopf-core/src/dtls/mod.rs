// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.3 (RFC 9147, Phase 6) — reuses [`crate::tls::HandshakeEngine`] in
//! [`crate::tls::HandshakeMode::Dtls`] for handshake semantics (cipher
//! negotiation, key schedule, transcript, `Certificate`/`Finished`,
//! ticket/PSK resumption) unchanged from TLS 1.3; everything in this module
//! is genuinely DTLS-specific, with no TCP or QUIC equivalent: the record
//! layer ([`record`]: epoch/sequence-numbered `DTLSCiphertext` framing,
//! record sequence-number encryption, anti-replay), handshake-message
//! fragmentation and reassembly ([`reassembly`]), and flight-based
//! retransmission ([`retransmit`]).
//!
//! ## TLS 1.2 vs 1.3 on one UDP port
//!
//! Use [`DtlsVersionPolicy`] (alias of [`crate::tls::TcpTlsVersionPolicy`]) with
//! [`dtls_server_engine`] / [`dtls_client_engine`] or [`driver::DtlsEngine::Negotiating`].
//! Default is **negotiate** (prefer 1.3 from the first handshake flight, no version
//! change afterward). Pin with `Tls13Only` / `Tls12Only`, or build a fixed
//! `DtlsEngine::V13` / `V12` directly. QUIC is unrelated (TLS 1.3 only).

pub mod driver;
mod engine;
mod negotiating;
mod version_pick;
// `pub(crate)`, not private: `hopf-core::dtls12` (DTLS 1.2) reuses
// `reassembly::Reassembler`, `retransmit::RetransmitState`, and
// `record::ReplayWindow` directly — none of the three have any
// TLS-version awareness, so there's nothing DTLS-1.3-specific to
// duplicate. See `dtls12`'s own module doc.
pub(crate) mod reassembly;
pub(crate) mod record;
pub(crate) mod retransmit;

#[cfg(test)]
mod ech_tests;

pub use engine::{DtlsRecordEngine, DtlsRecordSink, NopDtlsRecordSink};
pub use negotiating::{dtls_client_engine, dtls_server_engine, DtlsServerMaterial, DtlsVersionPolicy};
