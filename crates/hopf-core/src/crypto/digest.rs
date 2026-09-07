// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Hash digests via AWS-LC.

use bytes::Bytes;

use aws_lc_rs::digest;

/// Supported hash algorithms exposed through the facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-1 — legacy DNSSEC (NSEC3, DS digest type 1) only.
    Sha1Legacy,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
}

impl HashAlgorithm {
    fn aws_alg(self) -> &'static digest::Algorithm {
        match self {
            HashAlgorithm::Sha1Legacy => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            HashAlgorithm::Sha256 => &digest::SHA256,
            HashAlgorithm::Sha384 => &digest::SHA384,
        }
    }
}

/// Finished digest bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest(Bytes);

impl Digest {
    /// Raw digest octets.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume into owned bytes.
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// One-shot hash of `data`.
pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Digest {
    Digest(Bytes::copy_from_slice(
        digest::digest(algorithm.aws_alg(), data).as_ref(),
    ))
}

/// Incremental SHA-256 hasher (DKIM body hash, streaming canonicalization).
pub struct Sha256Context {
    inner: digest::Context,
    algorithm: HashAlgorithm,
}

impl Sha256Context {
    /// Start hashing with `algorithm` (typically [`HashAlgorithm::Sha256`]).
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            inner: digest::Context::new(algorithm.aws_alg()),
            algorithm,
        }
    }

    /// Feed more input.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finish and return the digest.
    pub fn finish(self) -> Digest {
        let _ = self.algorithm;
        Digest(Bytes::copy_from_slice(self.inner.finish().as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let d = hash(HashAlgorithm::Sha256, b"abc");
        assert_eq!(
            d.as_bytes(),
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let one = hash(HashAlgorithm::Sha256, b"hello world");
        let mut ctx = Sha256Context::new(HashAlgorithm::Sha256);
        ctx.update(b"hello ");
        ctx.update(b"world");
        assert_eq!(ctx.finish(), one);
    }
}
