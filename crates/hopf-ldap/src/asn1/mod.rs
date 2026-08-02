// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Definite-length BER (ITU-T X.690) for LDAP (RFC 4511 §5.1).
//!
//! Port of Gumdrop `org.bluezoo.gumdrop.ldap.asn1`. General TLV machinery —
//! no LDAP message types. Indefinite length is rejected.

mod decoder;
mod element;
mod encoder;
mod error;
mod types;

pub use decoder::BerDecoder;
pub use element::Asn1Element;
pub use encoder::BerEncoder;
pub use error::Asn1Error;
pub use types::Asn1Type;
