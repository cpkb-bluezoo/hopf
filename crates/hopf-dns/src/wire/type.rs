// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

/// DNS resource record / question type (RFC 1035 §3.2.2 + DNSSEC / EDNS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsType {
    /// IPv4 address.
    A = 1,
    /// Name server.
    Ns = 2,
    /// Canonical name.
    Cname = 5,
    /// Start of authority.
    Soa = 6,
    /// Pointer (reverse).
    Ptr = 12,
    /// Mail exchange.
    Mx = 15,
    /// Text.
    Txt = 16,
    /// IPv6 address.
    Aaaa = 28,
    /// Service locator.
    Srv = 33,
    /// EDNS OPT pseudo-RR.
    Opt = 41,
    /// Delegation signer.
    Ds = 43,
    /// DNSSEC signature.
    Rrsig = 46,
    /// Next secure.
    Nsec = 47,
    /// DNS key.
    Dnskey = 48,
    /// NSEC3.
    Nsec3 = 50,
    /// NSEC3 parameters.
    Nsec3Param = 51,
    /// Query all types.
    Any = 255,
}

impl DnsType {
    /// Wire numeric value.
    pub fn value(self) -> u16 {
        self as u16
    }

    /// Parse a known type; `None` for unknown (RFC 3597 opaque on RRs).
    pub fn from_value(v: u16) -> Option<Self> {
        Some(match v {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            41 => Self::Opt,
            43 => Self::Ds,
            46 => Self::Rrsig,
            47 => Self::Nsec,
            48 => Self::Dnskey,
            50 => Self::Nsec3,
            51 => Self::Nsec3Param,
            255 => Self::Any,
            _ => return None,
        })
    }
}
