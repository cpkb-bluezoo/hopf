// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

/// DNSSEC algorithm numbers (RFC 4034 / 8624).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnssecAlgorithm {
    /// RSASHA256.
    RsaSha256 = 8,
    /// RSASHA512.
    RsaSha512 = 10,
    /// ECDSA P-256 SHA-256.
    EcdsaP256Sha256 = 13,
    /// ECDSA P-384 SHA-384.
    EcdsaP384Sha384 = 14,
    /// Ed25519.
    Ed25519 = 15,
    /// Ed448.
    Ed448 = 16,
}

impl DnssecAlgorithm {
    /// Wire numeric value.
    pub fn value(self) -> u8 {
        self as u8
    }

    /// From wire byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            8 => Self::RsaSha256,
            10 => Self::RsaSha512,
            13 => Self::EcdsaP256Sha256,
            14 => Self::EcdsaP384Sha384,
            15 => Self::Ed25519,
            16 => Self::Ed448,
            _ => return None,
        })
    }
}
