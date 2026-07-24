// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

/// DNS class (RFC 1035 §3.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    /// Internet.
    In = 1,
    /// Chaos.
    Ch = 3,
    /// Hesiod.
    Hs = 4,
    /// Any class (QCLASS).
    Any = 255,
}

impl DnsClass {
    /// Wire numeric value.
    pub fn value(self) -> u16 {
        self as u16
    }

    /// Parse a known class.
    pub fn from_value(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::In,
            3 => Self::Ch,
            4 => Self::Hs,
            255 => Self::Any,
            _ => return None,
        })
    }
}
