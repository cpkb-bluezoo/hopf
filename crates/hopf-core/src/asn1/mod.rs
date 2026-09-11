// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Definite-length BER/DER (ITU-T X.690) — general TLV machinery, no
//! protocol-specific message types.
//!
//! One codec serves two different needs across this workspace:
//! - LDAP (RFC 4511 §5.1) needs genuinely incremental decoding of BER
//!   arriving in arbitrary TCP chunks — [`BerDecoder::push`] is this
//!   crate's standard push-parser shape (feed bytes, get a synchronous
//!   callback per complete unit; see `hopf_http::h2::H2Parser::push`).
//! - X.509 certificates, PKCS#8 keys, and DER signatures (`crate::crypto`,
//!   `crate::tls`) are always already-complete in-memory buffers with no
//!   incremental feeding involved — [`parse_der`] is a one-shot
//!   convenience over the same machinery for that case, and
//!   [`BerEncoder`] doubles as a DER writer (see
//!   [`BerEncoder::write_integer_bytes`]).
//!
//! Indefinite length is rejected outright — DER doesn't have it, and this
//! codebase's own LDAP encoder never produces it either.

mod decoder;
mod der;
mod element;
mod encoder;
mod error;
mod types;

pub use decoder::{parse_der, BerDecoder, BerEventSink};
pub use der::{parse_sequence, read_bit_string_content, read_length, read_oid, read_tlv_content, strip_integer_padding, DerReader};
pub use element::Asn1Element;
pub use encoder::BerEncoder;
pub use error::Asn1Error;
pub use types::Asn1Type;
