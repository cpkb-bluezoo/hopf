// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use crate::wire::{normalize_name, DnsResourceRecord};

use super::validator;

/// DS trust-anchor entry (RFC 4033 §5).
#[derive(Debug, Clone)]
pub struct AnchorDs {
    /// Key tag.
    pub key_tag: u16,
    /// Algorithm.
    pub algorithm: u8,
    /// Digest type (1=SHA-1, 2=SHA-256, 4=SHA-384).
    pub digest_type: u8,
    /// Digest bytes.
    pub digest: Vec<u8>,
}

/// DNSSEC trust anchor store (IANA root KSK DS preloaded).
#[derive(Debug, Clone)]
pub struct DnssecTrustAnchor {
    /// zone (normalized) → DS anchors
    anchors: Vec<(String, Vec<AnchorDs>)>,
}

impl Default for DnssecTrustAnchor {
    fn default() -> Self {
        Self::with_iana_root()
    }
}

impl DnssecTrustAnchor {
    /// Empty store (no anchors).
    pub fn empty() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// IANA root zone DS anchors (KSK 20326 + 38696).
    ///
    /// Source: <https://data.iana.org/root-anchors/root-anchors.xml>
    pub fn with_iana_root() -> Self {
        let mut s = Self::empty();
        s.add_anchor(
            ".",
            20326,
            8,
            2,
            &hex_decode("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
        );
        s.add_anchor(
            ".",
            38696,
            8,
            2,
            &hex_decode("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
        );
        s
    }

    /// Add a DS-based trust anchor.
    pub fn add_anchor(
        &mut self,
        zone: &str,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &[u8],
    ) {
        let key = normalize_zone(zone);
        let entry = AnchorDs {
            key_tag,
            algorithm,
            digest_type,
            digest: digest.to_vec(),
        };
        if let Some((_, list)) = self.anchors.iter_mut().find(|(z, _)| z == &key) {
            list.push(entry);
        } else {
            self.anchors.push((key, vec![entry]));
        }
    }

    /// Anchors for a zone.
    pub fn anchors_for(&self, zone: &str) -> &[AnchorDs] {
        let key = normalize_zone(zone);
        self.anchors
            .iter()
            .find(|(z, _)| z == &key)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[])
    }

    /// Whether any anchors are configured.
    pub fn is_empty(&self) -> bool {
        self.anchors.iter().all(|(_, v)| v.is_empty())
    }

    /// True if `dnskey` matches a configured DS trust anchor for `zone`.
    pub fn is_dnskey_trusted(&self, zone: &str, dnskey: &DnsResourceRecord) -> bool {
        let Some(key_tag) = dnskey.dnskey_key_tag() else {
            return false;
        };
        let Some(algorithm) = dnskey.dnskey_algorithm() else {
            return false;
        };
        for anchor in self.anchors_for(zone) {
            if anchor.key_tag != key_tag || anchor.algorithm != algorithm {
                continue;
            }
            let ds = DnsResourceRecord::ds(
                zone,
                0,
                anchor.key_tag,
                anchor.algorithm,
                anchor.digest_type,
                &anchor.digest,
            );
            if validator::verify_ds(dnskey, &ds) {
                return true;
            }
        }
        false
    }
}

fn normalize_zone(zone: &str) -> String {
    if zone.is_empty() || zone == "." {
        return ".".to_string();
    }
    let n = normalize_name(zone);
    if n.is_empty() {
        ".".to_string()
    } else {
        n
    }
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_val(bytes[i]);
        let lo = hex_val(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
