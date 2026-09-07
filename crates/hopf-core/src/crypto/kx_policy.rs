// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS 1.3 key-exchange group preference — hybrid PQC first (Phase 2 seed; Phase 7 expands).

use super::kx::NamedGroup;

/// Preferred [`NamedGroup`] order for ClientHello / server selection.
///
/// Default matches today's rustls `prefer-post-quantum`: [`NamedGroup::X25519MLKEM768`]
/// then classical X25519.
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
    /// Hybrid ML-KEM + X25519 first, then X25519 alone.
    pub fn pqc_first() -> Self {
        Self {
            groups: vec![NamedGroup::X25519MLKEM768, NamedGroup::X25519],
        }
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
}
