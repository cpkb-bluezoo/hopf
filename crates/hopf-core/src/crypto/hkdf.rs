// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HKDF helpers for TLS 1.3 (RFC 8446 §7.1) via AWS-LC.

use bytes::{Bytes, BytesMut};

use aws_lc_rs::hkdf::{self, KeyType, Prk, Salt, HKDF_SHA256};

/// TLS 1.3 HKDF-SHA-256.
pub const TLS13_HKDF: hkdf::Algorithm = HKDF_SHA256;

/// Opaque HKDF pseudo-random key from Extract. Remembers which
/// `HKDF-Expand-Label` prefix (`"tls13 "` or `"dtls13 "`) it was constructed
/// with, so [`Self::derive_secret`] doesn't need it passed again — every
/// `HkdfPrk` derived *from* one (via [`extract_derived`]/[`extract_derived_dtls`])
/// inherits the same prefix through the caller threading the right variant,
/// same as the rest of the key schedule in `handshake::key_schedule`.
pub struct HkdfPrk(Prk, &'static str);

impl HkdfPrk {
    /// Derive-Secret (RFC 8446 §7.1).
    pub fn derive_secret(&self, label: &str, context: &[u8]) -> [u8; 32] {
        let hkdf_label = build_hkdf_label(self.1, label, context, 32);
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
    extract_with_prefix(TLS13_LABEL_PREFIX, salt, ikm)
}

/// HKDF-Extract where salt is a prior Derive-Secret output.
pub fn extract_derived(derived: &[u8; 32], ikm: &[u8]) -> HkdfPrk {
    extract(Some(derived), ikm)
}

/// HKDF-Expand-Label from raw 32-byte secret (post-Derive-Secret).
pub fn expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    expand_label_with_prefix(TLS13_LABEL_PREFIX, secret, label, context, len)
}

/// DTLS 1.3 label prefix (RFC 9147 §5.9): *"Section 7.1 of \[TLS13\] specifies
/// that HKDF-Expand-Label uses a label prefix of 'tls13 '. For DTLS 1.3,
/// that label SHALL be 'dtls13'."* — note there is deliberately **no
/// trailing space**, unlike TLS 1.3's `"tls13 "`: the full label is the
/// literal concatenation `"dtls13" + label` (e.g. `"dtls13key"`, not
/// `"dtls13 key"`). Confirmed against a real independent DTLS 1.3 peer
/// (wolfSSL) — an earlier version of this constant included the space by
/// analogy with TLS 1.3, which decrypted nothing but was invisible to
/// hopf-vs-hopf loopback testing (both sides made the same mistake
/// symmetrically). Unlike RFC 9001's QUIC (which layers its own
/// `"quic "`-prefixed derivation on top of an *unmodified* TLS 1.3 key
/// schedule), this amends RFC 8446 §7.1 itself, so it applies to every
/// `HKDF-Expand-Label` call throughout the handshake's key schedule, not
/// just a final record-protection-key step — see [`extract_dtls`] /
/// [`extract_derived_dtls`] / [`dtls_expand_label`], used throughout
/// `handshake::key_schedule` wherever its functions are called with
/// `dtls: true`.
const DTLS13_LABEL_PREFIX: &str = "dtls13";
const TLS13_LABEL_PREFIX: &str = "tls13 ";

/// [`extract`], but for DTLS 1.3 (RFC 9147 §5.9's `"dtls13 "` prefix).
pub fn extract_dtls(salt: Option<&[u8]>, ikm: &[u8]) -> HkdfPrk {
    extract_with_prefix(DTLS13_LABEL_PREFIX, salt, ikm)
}

/// [`extract_derived`], but for DTLS 1.3.
pub fn extract_derived_dtls(derived: &[u8; 32], ikm: &[u8]) -> HkdfPrk {
    extract_dtls(Some(derived), ikm)
}

/// [`expand_label`], but for DTLS 1.3.
pub fn dtls_expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    expand_label_with_prefix(DTLS13_LABEL_PREFIX, secret, label, context, len)
}

fn extract_with_prefix(prefix: &'static str, salt: Option<&[u8]>, ikm: &[u8]) -> HkdfPrk {
    let salt_bytes = salt.unwrap_or(&[0u8; 32]);
    let salt = Salt::new(TLS13_HKDF, salt_bytes);
    HkdfPrk(salt.extract(ikm), prefix)
}

fn expand_label_with_prefix(prefix: &'static str, secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    let hkdf_label = build_hkdf_label(prefix, label, context, len);
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

    /// RFC 9147 §5.9: *"For DTLS 1.3, that label SHALL be 'dtls13'"* — with
    /// **no trailing space**, unlike TLS 1.3's `"tls13 "`. An earlier
    /// version of this crate's `DTLS13_LABEL_PREFIX` included the space by
    /// analogy with TLS 1.3; every derived key was consequently wrong, but
    /// symmetrically wrong on both sides of a hopf-vs-hopf handshake, so it
    /// went undetected until interop-tested against a real DTLS 1.3 peer
    /// (wolfSSL) — decryption failed on the very first Handshake-epoch
    /// record. This pins the exact wire bytes so that regression can't
    /// recur silently again.
    #[test]
    fn dtls_expand_label_has_no_space_after_the_dtls13_prefix() {
        assert_eq!(DTLS13_LABEL_PREFIX, "dtls13", "must NOT have a trailing space — RFC 9147 §5.9");
        // Pin the exact wire bytes of the constructed `HkdfLabel`
        // (RFC 8446 §7.1) for the concatenation "dtls13" + "key", so a
        // regression back to the wrong ("dtls13 key") shape fails loudly
        // even without official RFC 9147 test vectors to check against.
        let hkdf_label = build_hkdf_label(DTLS13_LABEL_PREFIX, "key", &[], 16);
        assert_eq!(
            hkdf_label.as_ref(),
            [
                0x00, 0x10, // length = 16
                0x09, // label length = 9 ("dtls13key")
                b'd', b't', b'l', b's', b'1', b'3', b'k', b'e', b'y', 0x00, // context length = 0
            ]
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
