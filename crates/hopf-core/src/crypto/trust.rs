// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Trust anchor storage — chain building and hostname verification land in
//! Phase 2 (in-tree TLS handshake engine).

/// Collection of DER-encoded trust anchors (typically self-signed root CAs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustStore {
    anchors: Vec<Vec<u8>>,
}

impl TrustStore {
    /// Empty store — caller must add anchors before verification (Phase 2+).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a DER-encoded trust anchor.
    pub fn add_anchor_der(&mut self, der: Vec<u8>) {
        self.anchors.push(der);
    }

    /// Immutable view of stored anchors.
    pub fn anchors(&self) -> &[Vec<u8>] {
        &self.anchors
    }

    /// Number of anchors.
    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store has no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}
