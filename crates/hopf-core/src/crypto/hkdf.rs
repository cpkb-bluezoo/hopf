// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HKDF helpers for TLS 1.3 (RFC 8446 §7.1) via AWS-LC.

use bytes::{Bytes, BytesMut};

use aws_lc_rs::hkdf::{self, KeyType, Prk, Salt};

/// Longest `Hash.length` any supported TLS 1.3 suite uses (SHA-384).
pub const MAX_HASH_LEN: usize = 48;

/// The hash a TLS 1.3 cipher suite names (RFC 8446 §B.4): it drives the
/// transcript hash, HKDF and the `Finished` HMAC, so every secret derived in
/// one handshake is `Hash.length` bytes of this size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13Hash {
    /// SHA-256 (`Hash.length` 32), used by `TLS_AES_128_GCM_SHA256` and
    /// `TLS_CHACHA20_POLY1305_SHA256`. Also the hash of QUIC Initial secrets
    /// (RFC 9001 §5.2) whatever suite is later negotiated.
    Sha256,
    /// SHA-384 (`Hash.length` 48), used by `TLS_AES_256_GCM_SHA384`.
    Sha384,
}

impl Tls13Hash {
    /// `Hash.length` in bytes.
    pub fn len(self) -> usize {
        match self {
            Tls13Hash::Sha256 => 32,
            Tls13Hash::Sha384 => 48,
        }
    }

    /// The HKDF algorithm over this hash.
    pub(crate) fn hkdf(self) -> hkdf::Algorithm {
        match self {
            Tls13Hash::Sha256 => hkdf::HKDF_SHA256,
            Tls13Hash::Sha384 => hkdf::HKDF_SHA384,
        }
    }

    /// The HMAC algorithm over this hash.
    pub(crate) fn hmac(self) -> aws_lc_rs::hmac::Algorithm {
        match self {
            Tls13Hash::Sha256 => aws_lc_rs::hmac::HMAC_SHA256,
            Tls13Hash::Sha384 => aws_lc_rs::hmac::HMAC_SHA384,
        }
    }

    /// The digest algorithm.
    pub(crate) fn digest(self) -> &'static aws_lc_rs::digest::Algorithm {
        match self {
            Tls13Hash::Sha256 => &aws_lc_rs::digest::SHA256,
            Tls13Hash::Sha384 => &aws_lc_rs::digest::SHA384,
        }
    }

    /// One-shot hash of `data`.
    pub fn hash(self, data: &[u8]) -> Secret {
        Secret::from_slice(aws_lc_rs::digest::digest(self.digest(), data).as_ref())
    }
}

/// A key-schedule value of up to [`MAX_HASH_LEN`] bytes held inline: a
/// secret, transcript hash or PSK whose length is the negotiated suite's
/// `Hash.length`. Copy so it can be handed to callbacks by value, like the
/// fixed 32-byte arrays it replaces.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secret {
    buf: [u8; MAX_HASH_LEN],
    len: u8,
}

impl Secret {
    /// Copy `bytes` (at most [`MAX_HASH_LEN`] long).
    ///
    /// # Panics
    ///
    /// If `bytes` is longer than [`MAX_HASH_LEN`]: every producer is a hash
    /// output or HKDF expansion sized by [`Tls13Hash::len`], so that is a
    /// programming error, not peer input.
    pub fn from_slice(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= MAX_HASH_LEN, "secret longer than any supported hash output");
        let mut buf = [0u8; MAX_HASH_LEN];
        buf[..bytes.len()].copy_from_slice(bytes);
        Self { buf, len: bytes.len() as u8 }
    }

    /// `len` zero bytes (the `Hash.length` zeros of RFC 8446 §7.1).
    pub fn zeros(len: usize) -> Self {
        Self::from_slice(&[0u8; MAX_HASH_LEN][..len])
    }

    /// The secret octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// `true` for a zero-length value.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Opaque HKDF pseudo-random key from Extract. Remembers which
/// `HKDF-Expand-Label` prefix (`"tls13 "` or `"dtls13 "`) it was constructed
/// with, so [`Self::derive_secret`] doesn't need it passed again — every
/// `HkdfPrk` derived *from* one (via [`extract_derived`]/[`extract_derived_dtls`])
/// inherits the same prefix through the caller threading the right variant,
/// same as the rest of the key schedule in `handshake::key_schedule`. It
/// also remembers its hash, so a derived secret is always `Hash.length` long.
pub struct HkdfPrk(Prk, &'static str, Tls13Hash);

impl HkdfPrk {
    /// Derive-Secret (RFC 8446 §7.1).
    pub fn derive_secret(&self, label: &str, context: &[u8]) -> Secret {
        let len = self.2.len();
        let hkdf_label = build_hkdf_label(self.1, label, context, len);
        let label_slice = [hkdf_label.as_ref()];
        let mut out = [0u8; MAX_HASH_LEN];
        self.0
            .expand(&label_slice, Len(len))
            .expect("HKDF expand")
            .fill(&mut out[..len])
            .expect("fill");
        Secret::from_slice(&out[..len])
    }
}

/// Hash of the empty string with the TLS 1.3 cipher-suite hash.
pub fn empty_hash(hash: Tls13Hash) -> Secret {
    hash.hash(b"")
}

/// HKDF-Extract; salt defaults to `Hash.length` zero octets when `None`.
pub fn extract(hash: Tls13Hash, salt: Option<&[u8]>, ikm: &[u8]) -> HkdfPrk {
    extract_with_prefix(TLS13_LABEL_PREFIX, hash, salt, ikm)
}

/// HKDF-Extract where salt is a prior Derive-Secret output.
pub fn extract_derived(hash: Tls13Hash, derived: &Secret, ikm: &[u8]) -> HkdfPrk {
    extract(hash, Some(derived.as_bytes()), ikm)
}

/// HKDF-Expand-Label from a raw secret (post-Derive-Secret).
pub fn expand_label(hash: Tls13Hash, secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    expand_label_with_prefix(TLS13_LABEL_PREFIX, hash, secret, label, context, len)
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
pub fn extract_dtls(hash: Tls13Hash, salt: Option<&[u8]>, ikm: &[u8]) -> HkdfPrk {
    extract_with_prefix(DTLS13_LABEL_PREFIX, hash, salt, ikm)
}

/// [`extract_derived`], but for DTLS 1.3.
pub fn extract_derived_dtls(hash: Tls13Hash, derived: &Secret, ikm: &[u8]) -> HkdfPrk {
    extract_dtls(hash, Some(derived.as_bytes()), ikm)
}

/// [`expand_label`], but for DTLS 1.3.
pub fn dtls_expand_label(hash: Tls13Hash, secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    expand_label_with_prefix(DTLS13_LABEL_PREFIX, hash, secret, label, context, len)
}

/// The 8-octet ECH acceptance signal of RFC 9849 §7.2 / §7.2.1:
/// `HKDF-Expand-Label(HKDF-Extract(0, client_random), label, transcript_hash, 8)`,
/// where `label` is `"ech accept confirmation"` (ServerHello) or
/// `"hrr ech accept confirmation"` (HelloRetryRequest), `client_random` is
/// the `ClientHelloInner.random`, and `dtls` selects RFC 9147 §5.9's label
/// prefix.
pub fn ech_accept_confirmation(
    hash: Tls13Hash,
    client_random: &[u8; 32],
    label: &str,
    transcript_hash: &[u8],
    dtls: bool,
) -> [u8; 8] {
    use aws_lc_rs::hmac;
    // HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm); the salt is Hash.length zeros.
    let prk = hmac::sign(&hmac::Key::new(hash.hmac(), &[0u8; MAX_HASH_LEN][..hash.len()]), client_random);
    let prefix = if dtls { DTLS13_LABEL_PREFIX } else { TLS13_LABEL_PREFIX };
    let out = expand_label_with_prefix(prefix, hash, prk.as_ref(), label, transcript_hash, 8);
    let mut conf = [0u8; 8];
    conf.copy_from_slice(&out);
    conf
}

fn extract_with_prefix(prefix: &'static str, hash: Tls13Hash, salt: Option<&[u8]>, ikm: &[u8]) -> HkdfPrk {
    let salt_bytes = salt.unwrap_or(&[0u8; MAX_HASH_LEN][..hash.len()]);
    let salt = Salt::new(hash.hkdf(), salt_bytes);
    HkdfPrk(salt.extract(ikm), prefix, hash)
}

fn expand_label_with_prefix(
    prefix: &'static str,
    hash: Tls13Hash,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Bytes {
    let hkdf_label = build_hkdf_label(prefix, label, context, len);
    let prk = Prk::new_less_safe(hash.hkdf(), secret);
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

/// HKDF-Expand-Label for RFC 9001 QUIC packet protection (label prefix `quic `,
/// after the `tls13 ` prefix HKDF-Expand-Label itself adds).
pub fn quic_expand_label(hash: Tls13Hash, secret: &[u8], label: &str, context: &[u8], len: usize) -> Bytes {
    quic_expand_label_with_prefix(hash, "quic ", secret, label, context, len)
}

/// [`quic_expand_label`] with a caller-chosen label prefix: QUIC version 2
/// (RFC 9369 section 3.3.2) derives packet protection keys under `quicv2 `.
pub fn quic_expand_label_with_prefix(
    hash: Tls13Hash,
    prefix: &str,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Bytes {
    // RFC 9001 section 5.1 names the label "quic key"; HKDF-Expand-Label
    // (RFC 8446 section 7.1) prepends "tls13 " to whatever it is given, so the
    // bytes hashed are "tls13 quic key" (RFC 9001 Appendix A.1). Omitting it
    // yields keys no other QUIC implementation can read.
    let hkdf_label = build_hkdf_label(&format!("{TLS13_LABEL_PREFIX}{prefix}"), label, context, len);
    let prk = Prk::new_less_safe(hash.hkdf(), secret);
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

    fn hex(s: &str) -> Secret {
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        Secret::from_slice(&v)
    }

    /// RFC 8448 §3 — derive secret for handshake "tls13 derived".
    #[test]
    fn rfc8448_derived_from_early() {
        let early = extract(Tls13Hash::Sha256, Some(&[0u8; 32]), &[0u8; 32]);
        let empty = empty_hash(Tls13Hash::Sha256);
        let derived = early.derive_secret("derived", empty.as_bytes());
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
        let hs = extract_derived(Tls13Hash::Sha256, &derived, shared.as_bytes());
        let hs_traffic = hs.derive_secret(
            "c hs traffic",
            hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8").as_bytes(),
        );
        assert_eq!(
            hs_traffic,
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );
    }
}
