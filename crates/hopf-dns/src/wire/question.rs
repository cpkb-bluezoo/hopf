// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use super::class::DnsClass;
use super::r#type::DnsType;

/// DNS question (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    /// QNAME.
    pub name: String,
    /// QTYPE.
    pub qtype: DnsType,
    /// QCLASS.
    pub qclass: DnsClass,
}

impl DnsQuestion {
    /// Build a question (IN class by default helpers use this).
    pub fn new(name: impl Into<String>, qtype: DnsType, qclass: DnsClass) -> Self {
        Self {
            name: name.into(),
            qtype,
            qclass,
        }
    }

    /// IN-class question.
    pub fn in_class(name: impl Into<String>, qtype: DnsType) -> Self {
        Self::new(name, qtype, DnsClass::In)
    }
}
