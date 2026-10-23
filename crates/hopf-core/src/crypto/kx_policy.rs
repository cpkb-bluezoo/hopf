// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 key-exchange group preference — hybrid PQC first (Phase 2 seed; Phase 7 expands).

use super::kx::NamedGroup;

/// Preferred [`NamedGroup`] order for ClientHello / server selection.
///
/// Default matches today's rustls `prefer-post-quantum`: [`NamedGroup::X25519MLKEM768`]
/// first, then the other two RFC 10024 hybrid groups as classical-curve
/// alternatives, then classical X25519 as a pure-classical fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KxPolicy {
    groups: Vec<NamedGroup>,
}

impl Default for KxPolicy {
    fn default() -> Self {
        Self::pqc_first()
    }
}

impl KxPolicy {
    /// All three RFC 10024 hybrid groups (X25519MLKEM768 preferred), then
    /// classical X25519 as a pure-classical fallback.
    pub fn pqc_first() -> Self {
        Self {
            groups: vec![
                NamedGroup::X25519MLKEM768,
                NamedGroup::SecP256r1MLKEM768,
                NamedGroup::SecP384r1MLKEM1024,
                NamedGroup::X25519,
            ],
        }
    }

    /// Caller-chosen groups, most preferred first.
    pub fn new(groups: Vec<NamedGroup>) -> Self {
        Self { groups }
    }

    /// The classical NIST groups only: secp256r1, then secp384r1. No
    /// X25519 and no hybrid groups; the key-exchange half of an approved
    /// (FIPS) profile.
    pub fn nist_only() -> Self {
        Self::new(vec![NamedGroup::SecP256r1, NamedGroup::SecP384r1])
    }

    /// Classical X25519 only (interop / tests).
    pub fn classical_only() -> Self {
        Self {
            groups: vec![NamedGroup::X25519],
        }
    }

    /// Ordered group list.
    pub fn groups(&self) -> &[NamedGroup] {
        &self.groups
    }

    /// First group offered on the wire (client key share).
    pub fn preferred(&self) -> NamedGroup {
        self.groups
            .first()
            .copied()
            .unwrap_or(NamedGroup::X25519)
    }

    /// Pick the highest-preference group also advertised by the peer.
    pub fn select_mutual(&self, peer_group_codes: &[u16]) -> Option<NamedGroup> {
        for g in &self.groups {
            if peer_group_codes.contains(&g.code()) {
                return Some(*g);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_hybrid() {
        assert_eq!(KxPolicy::default().preferred(), NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn select_mutual_respects_order() {
        let policy = KxPolicy::default();
        let peer = [NamedGroup::X25519.code()];
        assert_eq!(policy.select_mutual(&peer), Some(NamedGroup::X25519));
        let peer = [NamedGroup::X25519MLKEM768.code(), NamedGroup::X25519.code()];
        assert_eq!(policy.select_mutual(&peer), Some(NamedGroup::X25519MLKEM768));
    }

    /// A peer that only advertises one of the newer NIST-curve hybrid
    /// groups (not `X25519MLKEM768`) must still negotiate PQC — proving
    /// the two new groups are actually reachable through the default
    /// policy, not just constructible in `crypto::kx`.
    #[test]
    fn select_mutual_reaches_secp384r1_mlkem1024_when_that_is_all_the_peer_offers() {
        let policy = KxPolicy::default();
        let peer = [NamedGroup::SecP384r1MLKEM1024.code()];
        assert_eq!(policy.select_mutual(&peer), Some(NamedGroup::SecP384r1MLKEM1024));
    }

    #[test]
    fn select_mutual_prefers_secp256r1_mlkem768_over_secp384r1_mlkem1024() {
        let policy = KxPolicy::default();
        let peer = [NamedGroup::SecP384r1MLKEM1024.code(), NamedGroup::SecP256r1MLKEM768.code()];
        assert_eq!(policy.select_mutual(&peer), Some(NamedGroup::SecP256r1MLKEM768));
    }

    #[test]
    fn nist_only_offers_just_the_two_classical_nist_groups() {
        let policy = KxPolicy::nist_only();
        assert_eq!(policy.groups(), &[NamedGroup::SecP256r1, NamedGroup::SecP384r1]);
        assert_eq!(policy.preferred(), NamedGroup::SecP256r1);
    }

    #[test]
    fn nist_only_never_selects_x25519_or_hybrids() {
        let policy = KxPolicy::nist_only();
        let peer = [
            NamedGroup::X25519MLKEM768.code(),
            NamedGroup::SecP256r1MLKEM768.code(),
            NamedGroup::X25519.code(),
        ];
        assert_eq!(policy.select_mutual(&peer), None);
        let peer = [NamedGroup::X25519.code(), NamedGroup::SecP384r1.code()];
        assert_eq!(policy.select_mutual(&peer), Some(NamedGroup::SecP384r1));
    }

    #[test]
    fn new_keeps_the_given_order_and_defaults_are_unchanged() {
        let policy = KxPolicy::new(vec![NamedGroup::SecP384r1]);
        assert_eq!(policy.groups(), &[NamedGroup::SecP384r1]);
        assert_eq!(KxPolicy::default().groups().len(), 4);
        assert!(!KxPolicy::default().groups().contains(&NamedGroup::SecP256r1));
    }
}
