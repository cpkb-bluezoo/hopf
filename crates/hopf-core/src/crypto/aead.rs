// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AEAD seal/open over a raw key + explicit nonce (AWS-LC via `aws-lc-rs`).
//!
//! Sequence-number-to-nonce construction (record layers, packet protection)
//! stays with the caller — this wraps only the AEAD operation itself.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

/// AES-128-GCM key bound to a fixed 12-byte IV; caller derives the
/// per-record/per-packet nonce (typically IV XOR a sequence number).
pub struct Aes128GcmKey {
    key: LessSafeKey,
}

/// Seal or open failed (bad key length, or authentication failure on open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl Aes128GcmKey {
    /// Build from a 16-byte key.
    pub fn new(key_bytes: &[u8]) -> Result<Self, AeadError> {
        let key = UnboundKey::new(&AES_128_GCM, key_bytes).map_err(|_| AeadError)?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    /// Encrypt `plaintext` in place under `nonce`/`aad`; appends the 16-byte tag.
    pub fn seal_in_place_append_tag(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), plaintext)
            .map_err(|_| AeadError)
    }

    /// Decrypt `ciphertext` (tag included) in place under `nonce`/`aad`.
    /// Returns the plaintext length (tag truncated) on success.
    pub fn open_in_place(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, AeadError> {
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), ciphertext)
            .map_err(|_| AeadError)?;
        Ok(plain.len())
    }
}

/// AES-128- or AES-256-GCM key, selected by key length (16 or 32 bytes) —
/// what TLS 1.2's GCM cipher suites need (RFC 5288 offers both key sizes;
/// TLS 1.3 in this crate only ever uses AES-128-GCM, hence [`Aes128GcmKey`]
/// staying a separate, narrower type rather than being generalized into this).
pub struct AesGcmKey {
    key: LessSafeKey,
}

impl AesGcmKey {
    /// Build from a 16-byte (AES-128) or 32-byte (AES-256) key.
    pub fn new(key_bytes: &[u8]) -> Result<Self, AeadError> {
        let alg = match key_bytes.len() {
            16 => &AES_128_GCM,
            32 => &AES_256_GCM,
            _ => return Err(AeadError),
        };
        let key = UnboundKey::new(alg, key_bytes).map_err(|_| AeadError)?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    /// Encrypt `plaintext` in place under `nonce`/`aad`; appends the 16-byte tag.
    pub fn seal_in_place_append_tag(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), plaintext)
            .map_err(|_| AeadError)
    }

    /// Decrypt `ciphertext` (tag included) in place under `nonce`/`aad`.
    /// Returns the plaintext length (tag truncated) on success.
    pub fn open_in_place(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &mut [u8]) -> Result<usize, AeadError> {
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), ciphertext)
            .map_err(|_| AeadError)?;
        Ok(plain.len())
    }
}

/// ChaCha20-Poly1305 key (RFC 8439), 32 bytes, bound to a fixed 12-byte IV —
/// same nonce-construction contract as [`Aes128GcmKey`]. A separate type
/// rather than folded into [`AesGcmKey`]'s length dispatch: both this and
/// AES-256-GCM take 32-byte keys, so key length alone can't disambiguate
/// them — callers already know which cipher was negotiated (TLS 1.2's
/// `CipherKind`, TLS 1.3's negotiated suite) and construct the matching type.
pub struct ChaCha20Poly1305Key {
    key: LessSafeKey,
}

impl ChaCha20Poly1305Key {
    /// Build from a 32-byte key.
    pub fn new(key_bytes: &[u8]) -> Result<Self, AeadError> {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes).map_err(|_| AeadError)?;
        Ok(Self {
            key: LessSafeKey::new(key),
        })
    }

    /// Encrypt `plaintext` in place under `nonce`/`aad`; appends the 16-byte tag.
    pub fn seal_in_place_append_tag(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        self.key
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), plaintext)
            .map_err(|_| AeadError)
    }

    /// Decrypt `ciphertext` (tag included) in place under `nonce`/`aad`.
    /// Returns the plaintext length (tag truncated) on success.
    pub fn open_in_place(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &mut [u8]) -> Result<usize, AeadError> {
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(aad), ciphertext)
            .map_err(|_| AeadError)?;
        Ok(plain.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_key_round_trips_both_sizes() {
        for key_bytes in [&[7u8; 16][..], &[7u8; 32][..]] {
            let key = AesGcmKey::new(key_bytes).unwrap();
            let mut buf = b"hello world".to_vec();
            key.seal_in_place_append_tag([0u8; 12], b"aad", &mut buf).unwrap();
            assert_ne!(buf, b"hello world");
            let n = key.open_in_place([0u8; 12], b"aad", &mut buf).unwrap();
            assert_eq!(&buf[..n], b"hello world");
        }
    }

    #[test]
    fn aes_gcm_key_rejects_wrong_length() {
        assert!(AesGcmKey::new(&[7u8; 24]).is_err());
    }

    #[test]
    fn round_trip() {
        let key = Aes128GcmKey::new(&[7u8; 16]).unwrap();
        let mut buf = b"hello world".to_vec();
        key.seal_in_place_append_tag([0u8; 12], b"aad", &mut buf).unwrap();
        assert_ne!(buf, b"hello world");
        let n = key.open_in_place([0u8; 12], b"aad", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn wrong_aad_rejected() {
        let key = Aes128GcmKey::new(&[7u8; 16]).unwrap();
        let mut buf = b"hello world".to_vec();
        key.seal_in_place_append_tag([0u8; 12], b"aad", &mut buf).unwrap();
        assert_eq!(key.open_in_place([0u8; 12], b"different", &mut buf), Err(AeadError));
    }

    #[test]
    fn chacha20_poly1305_key_round_trips() {
        let key = ChaCha20Poly1305Key::new(&[7u8; 32]).unwrap();
        let mut buf = b"hello world".to_vec();
        key.seal_in_place_append_tag([0u8; 12], b"aad", &mut buf).unwrap();
        assert_ne!(buf, b"hello world");
        let n = key.open_in_place([0u8; 12], b"aad", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn chacha20_poly1305_key_rejects_wrong_length() {
        assert!(ChaCha20Poly1305Key::new(&[7u8; 16]).is_err());
    }
}
