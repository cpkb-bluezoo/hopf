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

mod engine;
// `pub(crate)`, not private: `hopf-core::dtls12` (DTLS 1.2) reuses
// `reassembly::Reassembler`, `retransmit::RetransmitState`, and
// `record::ReplayWindow` directly — none of the three have any
// TLS-version awareness, so there's nothing DTLS-1.3-specific to
// duplicate. See `dtls12`'s own module doc.
pub(crate) mod reassembly;
pub(crate) mod record;
pub(crate) mod retransmit;

pub use engine::{DtlsRecordEngine, DtlsRecordSink, NopDtlsRecordSink};
