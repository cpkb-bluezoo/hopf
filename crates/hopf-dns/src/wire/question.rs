// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use super::class::DnsClass;
use super::r#type::DnsType;

/// DNS question (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    /// QNAME.
    pub name: String,
    /// Parsed QTYPE, if it's one this crate recognizes.
    pub qtype: Option<DnsType>,
    /// Raw QTYPE wire value — always present, even when `qtype` is `None`
    /// for a type this crate doesn't recognize (RFC 3597: an unknown
    /// QTYPE/QCLASS shouldn't fail the whole message, mirroring how
    /// `DnsResourceRecord` preserves `raw_type`/`raw_class`).
    pub raw_qtype: u16,
    /// Parsed QCLASS, if it's one this crate recognizes.
    pub qclass: Option<DnsClass>,
    /// Raw QCLASS wire value — always present, even when `qclass` is `None`.
    pub raw_qclass: u16,
}

impl DnsQuestion {
    /// Build a question for a known type/class (IN class by default helpers use this).
    pub fn new(name: impl Into<String>, qtype: DnsType, qclass: DnsClass) -> Self {
        Self {
            name: name.into(),
            qtype: Some(qtype),
            raw_qtype: qtype.value(),
            qclass: Some(qclass),
            raw_qclass: qclass.value(),
        }
    }

    /// IN-class question.
    pub fn in_class(name: impl Into<String>, qtype: DnsType) -> Self {
        Self::new(name, qtype, DnsClass::In)
    }

    /// Build from raw wire values, preserving an unrecognized QTYPE/QCLASS
    /// (RFC 3597) instead of the caller having to reject the message.
    pub fn opaque(name: impl Into<String>, raw_qtype: u16, raw_qclass: u16) -> Self {
        Self {
            name: name.into(),
            qtype: DnsType::from_value(raw_qtype),
            raw_qtype,
            qclass: DnsClass::from_value(raw_qclass),
            raw_qclass,
        }
    }
}
