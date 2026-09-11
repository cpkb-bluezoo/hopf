// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DTLS 1.2 (RFC 6347) — reuses [`crate::tls::tls12::Tls12Engine`] for
//! handshake semantics (cipher negotiation, key derivation via RFC 5246's
//! PRF unmodified, `Certificate`/`Finished`, RFC 5077 ticket resumption)
//! and [`crate::dtls`]'s transport-agnostic pieces (`Reassembler`,
//! `RetransmitState`, `ReplayWindow`, `DtlsRecordSink`) directly — only the
//! record layer ([`record`], structurally simpler than DTLS 1.3's: one
//! header shape, no sequence-number reconstruction, no record
//! sequence-number encryption) and the `HelloVerifyRequest` cookie round
//! trip ([`engine`], entirely outside `Tls12Engine` — RFC 6347 §4.2.1
//! excludes it from the transcript) are genuinely new.

mod engine;
#[cfg(all(test, feature = "integration"))]
mod interop_tests;
mod record;

pub use engine::{Dtls12Config, Dtls12RecordEngine};
