// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HKDF helpers for TLS 1.3 (RFC 8446 §7.1) via AWS-LC.

use bytes::{Bytes, BytesMut};

use aws_lc_rs::hkdf::{self, KeyType, Prk, Salt, HKDF_SHA256};

/// TLS 1.3 HKDF-SHA-256.
pub const TLS13_HKDF: hkdf::Algorithm = HKDF_SHA256;

/// Opaque HKDF pseudo-random key from Extract.
pub struct HkdfPrk(Prk);

impl HkdfPrk {
    /// Derive-Secret (RFC 8446 §7.1).
    pub fn derive_secret(&self, label: &str, context: &[u8]) -> [u8; 32] {
        let hkdf_label = build_tls_hkdf_label(label, context, 32);
        let label_slice = [hkdf_label.as_ref()];
        let mut out = [0u8; 32];
        self.0
            .expand(&label_slice, Len(32))
            .expect("HKDF expand")
            .fill(&mut out)
            .expect("fill");
        out
    }
}

/// Hash of the empty string with the TLS 1.3 cipher-suite hash (SHA-256).
pub fn empty_hash() -> [u8; 32] {
    use aws_lc_rs::digest::{digest, SHA256};
    let d = digest(&SHA256, b"");
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// HKDF-Extract; salt defaults to 32 zero octets when `None`.
pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> HkdfPrk {
    let salt_bytes = salt.unwrap_or(&[0u8; 32]);
    let salt = Salt::new(TLS13_HKDF, salt_bytes);
    HkdfPrk(salt.extract(ikm))
}

/// HKDF-Extract where salt is a prior Derive-Secret output.
pub fn extract_derived(derived: &[u8; 32], ikm: &[u8]) -> HkdfPrk {
    extract(Some(derived), ikm)
}

/// HKDF-Expand-Label from raw 32-byte secret (post-Derive-Secret).
pub fn expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    let hkdf_label = build_tls_hkdf_label(label, context, len);
    let prk = Prk::new_less_safe(TLS13_HKDF, secret);
    let label_slice = [hkdf_label.as_ref()];
    let okm = prk
        .expand(&label_slice, Len(len))
        .expect("HKDF expand length fits");
    let mut out = vec![0u8; len];
    okm.fill(&mut out).expect("fill");
    Bytes::from(out)
}

fn build_hkdf_label(prefix: &str, label: &str, context: &[u8], length: usize) -> Bytes {
    let tls_label = format!("{prefix}{label}");
    let mut out = BytesMut::with_capacity(2 + 1 + tls_label.len() + 1 + context.len());
    out.extend_from_slice(&(length as u16).to_be_bytes());
    out.extend_from_slice(&[tls_label.len() as u8]);
    out.extend_from_slice(tls_label.as_bytes());
    out.extend_from_slice(&[context.len() as u8]);
    out.extend_from_slice(context);
    out.freeze()
}

fn build_tls_hkdf_label(label: &str, context: &[u8], length: usize) -> Bytes {
    build_hkdf_label("tls13 ", label, context, length)
}

/// HKDF-Expand-Label for RFC 9001 QUIC packet protection (uses the `quic ` prefix).
pub fn quic_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    let hkdf_label = build_hkdf_label("quic ", label, context, len);
    let prk = Prk::new_less_safe(TLS13_HKDF, secret);
    let label_slice = [hkdf_label.as_ref()];
    let okm = prk
        .expand(&label_slice, Len(len))
        .expect("HKDF expand length fits");
    let mut out = vec![0u8; len];
    okm.fill(&mut out).expect("fill");
    Bytes::from(out)
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// RFC 8448 §3 — derive secret for handshake "tls13 derived".
    #[test]
    fn rfc8448_derived_from_early() {
        let early = extract(Some(&[0u8; 32]), &[0u8; 32]);
        let empty = empty_hash();
        let derived = early.derive_secret("derived", &empty);
        assert_eq!(
            derived,
            hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        );
    }

    /// RFC 8448 §3 — extract secret "handshake" after ECDHE.
    #[test]
    fn rfc8448_handshake_secret() {
        let derived = hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        let shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let hs = extract_derived(&derived, &shared);
        let hs_traffic = hs.derive_secret("c hs traffic", &hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
        assert_eq!(
            hs_traffic,
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
    }
}
