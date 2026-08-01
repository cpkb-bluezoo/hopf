// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! DNS wire format (RFC 1035 + EDNS / DNSSEC types).

pub mod base32hex;
mod bitmap;
mod class;
mod error;
mod message;
mod name;
mod query_id;
mod question;
mod rr;
mod r#type;

pub use class::DnsClass;
pub use error::DnsFormatError;
pub use message::{
    FLAG_AA, FLAG_AD, FLAG_CD, FLAG_QR, FLAG_RA, FLAG_RD, FLAG_TC, HEADER_SIZE, OPCODE_QUERY,
    RCODE_BADVERS, RCODE_FORMERR, RCODE_NOERROR, RCODE_NOTIMP, RCODE_NXDOMAIN, RCODE_REFUSED,
    RCODE_SERVFAIL, DnsMessage,
};
pub use name::{canonical_compare, decode_name, encode_name, normalize_name};
pub use query_id::DnsQueryIdGenerator;
pub use question::DnsQuestion;
pub use rr::{
    encode_edns_padding, DnsResourceRecord, EDNS_FLAG_DO, EDNS_OPTION_PADDING, OPT_UDP_PAYLOAD,
};
pub use r#type::DnsType;
