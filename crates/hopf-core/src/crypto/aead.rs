// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! AEAD seal/open over a raw key + explicit nonce (AWS-LC via `aws-lc-rs`).
//!
//! Sequence-number-to-nonce construction (record layers, packet protection)
//! stays with the caller — this wraps only the AEAD operation itself.

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
