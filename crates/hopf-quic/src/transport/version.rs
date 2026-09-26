// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The QUIC versions this stack speaks and everything that differs between
//! them at the packet layer.
//!
//! QUIC version 2 (RFC 9369) is deliberately near-identical to version 1. It
//! changes only the version number, the Initial salt, the HKDF labels used to
//! derive packet protection keys, the two long-header packet type bits, and
//! the Retry Integrity Tag key and nonce; everything else is shared. A
//! connection carries one [`QuicVersion`] and consults it at those points.

/// A QUIC version this stack can speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicVersion {
    /// QUIC version 1 (RFC 9000, RFC 9001), `0x00000001`.
    V1,
    /// QUIC version 2 (RFC 9369), `0x6b3343cf`.
    V2,
}

impl QuicVersion {
    /// Every version, in default preference order (newest first).
    pub const ALL: [QuicVersion; 2] = [Self::V2, Self::V1];

    /// The 32-bit value in a long header's Version field.
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    /// The version a Version field value names, if this stack speaks it
    /// (`None` for zero, which marks Version Negotiation, and for every
    /// version we do not implement).
    pub fn from_wire(wire: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.wire() == wire)
    }

    /// HKDF-Expand-Label prefix for packet protection keys, header
    /// protection keys and key updates (RFC 9001 section 5.1, RFC 9369
    /// section 3.3.2).
    pub const fn label_prefix(self) -> &'static str {
        match self {
            Self::V1 => "quic ",
            Self::V2 => "quicv2 ",
        }
    }

    /// The salt Initial secrets are derived from (RFC 9001 section 5.2, RFC
    /// 9369 section 3.3.1).
    pub const fn initial_salt(self) -> [u8; 20] {
        match self {
            Self::V1 => [
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc,
                0xbb, 0x7f, 0x0a,
            ],
            Self::V2 => [
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9,
                0xbd, 0x2e, 0xd9,
            ],
        }
    }

    /// AES-128-GCM key of the Retry Integrity Tag (RFC 9001 section 5.8, RFC
    /// 9369 section 3.3.3).
    pub(crate) const fn retry_key(self) -> [u8; 16] {
        match self {
            Self::V1 => [
                0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
            ],
            Self::V2 => [
                0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
            ],
        }
    }

    /// Nonce of the Retry Integrity Tag.
    pub(crate) const fn retry_nonce(self) -> [u8; 12] {
        match self {
            Self::V1 => [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb],
            Self::V2 => [0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a],
        }
    }

    /// Client-side ticket cache partition (`HandshakeConfig::ticket_namespace`):
    /// each version resumes only with tickets it earned itself (RFC 9369
    /// section 5). Version 1 keeps the plain per-server key, so its cached
    /// tickets are unaffected.
    pub(crate) const fn ticket_namespace(self) -> u32 {
        match self {
            Self::V1 => 0,
            Self::V2 => self.wire(),
        }
    }

    /// The ticket-sealing keys this version uses: the configured ones for
    /// version 1 (so tickets issued before this existed still resume), a
    /// derived set for version 2. A ticket sealed for one version therefore
    /// fails to open under the other and the handshake falls back to a full
    /// one (RFC 9369 section 5).
    pub(crate) fn ticket_keys(self, keys: hopf_core::tls::TicketKeys) -> hopf_core::tls::TicketKeys {
        match self {
            Self::V1 => keys,
            Self::V2 => keys.derived(b"quic version 2"),
        }
    }

    /// The two long-header type bits this version puts on the wire for a
    /// packet type given as a version 1 value (`TYPE_*` in `long_header`:
    /// Initial 0, 0-RTT 1, Handshake 2, Retry 3). RFC 9369 section 3.2.
    pub(crate) const fn wire_type(self, v1_type: u8) -> u8 {
        match self {
            Self::V1 => v1_type & 0x03,
            // Initial 0b01, 0-RTT 0b10, Handshake 0b11, Retry 0b00.
            Self::V2 => (v1_type + 1) & 0x03,
        }
    }

    /// Inverse of [`Self::wire_type`]: the version 1 value of the two type
    /// bits read off a packet of this version.
    pub(crate) const fn logical_type(self, wire_bits: u8) -> u8 {
        match self {
            Self::V1 => wire_bits & 0x03,
            Self::V2 => (wire_bits + 3) & 0x03,
        }
    }
}

/// The client's choice from a Version Negotiation offer: its most preferred
/// version the server offers (RFC 9368 section 2.1).
pub(crate) fn select_from_offer(preference: &[QuicVersion], offered: &[u32]) -> Option<QuicVersion> {
    preference.iter().copied().find(|v| offered.contains(&v.wire()))
}

/// RFC 9368 section 4: after acting on a Version Negotiation packet, the
/// client validates the server's Available Versions by checking it would
/// have made the same choice had that packet listed them plus the version
/// now in use. An empty list never validates.
pub(crate) fn validates_negotiation(preference: &[QuicVersion], server_available: &[u32], negotiated: QuicVersion) -> bool {
    if server_available.is_empty() {
        return false;
    }
    let mut offer = server_available.to_vec();
    offer.push(negotiated.wire());
    select_from_offer(preference, &offer) == Some(negotiated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_round_trip_and_reject_everything_else() {
        assert_eq!(QuicVersion::V1.wire(), 1);
        assert_eq!(QuicVersion::V2.wire(), 0x6b33_43cf);
        for v in QuicVersion::ALL {
            assert_eq!(QuicVersion::from_wire(v.wire()), Some(v));
        }
        assert_eq!(QuicVersion::from_wire(0), None, "0 marks Version Negotiation");
        assert_eq!(QuicVersion::from_wire(0x0a0a_0a0a), None, "a greased version");
        assert_eq!(QuicVersion::from_wire(0x709a_50c4), None, "the v2 draft codepoint");
    }

    /// RFC 9369 section 3.2 spells the v2 type bits out.
    #[test]
    fn v2_long_header_type_bits_match_the_rfc() {
        // (v1 logical type, v2 wire bits): Initial 0b01, 0-RTT 0b10, Handshake 0b11, Retry 0b00.
        for (logical, wire) in [(0u8, 0b01u8), (1, 0b10), (2, 0b11), (3, 0b00)] {
            assert_eq!(QuicVersion::V2.wire_type(logical), wire);
            assert_eq!(QuicVersion::V2.logical_type(wire), logical);
        }
        for t in 0..4u8 {
            assert_eq!(QuicVersion::V1.wire_type(t), t);
            assert_eq!(QuicVersion::V1.logical_type(t), t);
        }
    }

    #[test]
    fn label_prefixes_match_the_rfcs() {
        assert_eq!(QuicVersion::V1.label_prefix(), "quic ");
        assert_eq!(QuicVersion::V2.label_prefix(), "quicv2 ");
    }

    /// RFC 9368 section 4's worked example, translated to the versions we
    /// have: a client preferring v2 that was steered to v1 by a forged
    /// Version Negotiation packet must notice the server also offers v2.
    #[test]
    fn negotiation_validation_catches_a_forced_downgrade() {
        let pref = [QuicVersion::V2, QuicVersion::V1];
        // Genuine: the server is v1-only, so its Available Versions are just v1.
        assert!(validates_negotiation(&pref, &[1], QuicVersion::V1));
        // Forged downgrade: the server actually supports both.
        assert!(!validates_negotiation(&pref, &[1, QuicVersion::V2.wire()], QuicVersion::V1));
        // Never valid with nothing listed, and reserved versions are ignored.
        assert!(!validates_negotiation(&pref, &[], QuicVersion::V1));
        assert!(validates_negotiation(&pref, &[1, 0x1a2a_3a4a], QuicVersion::V1));
        // A v1-only client can only ever be steered to v1.
        assert!(validates_negotiation(&[QuicVersion::V1], &[1, QuicVersion::V2.wire()], QuicVersion::V1));
    }

    #[test]
    fn selection_prefers_the_clients_order_not_the_servers() {
        let pref = [QuicVersion::V2, QuicVersion::V1];
        assert_eq!(select_from_offer(&pref, &[1, QuicVersion::V2.wire()]), Some(QuicVersion::V2));
        assert_eq!(select_from_offer(&pref, &[QuicVersion::V2.wire(), 1]), Some(QuicVersion::V2));
        assert_eq!(select_from_offer(&pref, &[1]), Some(QuicVersion::V1));
        assert_eq!(select_from_offer(&pref, &[0xff00_0020]), None);
    }

    #[test]
    fn tickets_are_partitioned_by_version_on_both_sides() {
        let keys = hopf_core::tls::TicketKeys::single([9u8; 32]);
        // v1 keeps the configured keys and the plain cache key.
        assert_eq!(QuicVersion::V1.ticket_keys(keys).current().as_bytes(), keys.current().as_bytes());
        assert_eq!(QuicVersion::V1.ticket_namespace(), 0);
        // v2 gets its own of each, so v1's tickets neither open nor are offered there.
        assert_ne!(QuicVersion::V2.ticket_keys(keys).current().as_bytes(), keys.current().as_bytes());
        assert_ne!(QuicVersion::V2.ticket_namespace(), 0);
    }
}
