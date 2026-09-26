// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS certificate compression (RFC 8879): the `CompressedCertificate`
//! handshake message (type 25) and its Brotli codec.
//!
//! Decompression is push-driven like the rest of the handshake codec: the
//! caller hands over each chunk of compressed bytes as it arrives and gets
//! control straight back, so a large (e.g. post-quantum) chain is inflated
//! while the rest of the message is still on the wire rather than after the
//! whole compressed body has been buffered. Output is capped by the
//! `uncompressed_length` the peer declared (itself bounded by
//! [`MAX_UNCOMPRESSED_CERTIFICATE_LEN`]), so a decompression bomb is cut off
//! at the first byte past that, before any ASN.1 or chain parsing.

use std::io::Write;

use brotli::{BrotliResult, BrotliState, CompressorWriter, HeapAlloc, HuffmanCode};

/// `CertificateCompressionAlgorithm` codepoint for Brotli (RFC 8879 §3).
pub const ALG_BROTLI: u16 = 2;

/// Algorithms this implementation can decompress and compress, in
/// preference order. Only Brotli for now (zlib = 1 and zstd = 3 are
/// deliberately not offered).
pub const SUPPORTED_ALGORITHMS: &[u16] = &[ALG_BROTLI];

/// Largest `uncompressed_length` a peer may declare for a compressed
/// `Certificate` body. RFC 8879 §4 says implementations SHOULD bound it; an
/// ML-DSA-87 chain of several certificates is a few tens of KiB, so 256 KiB
/// leaves generous headroom while keeping a hostile declaration cheap.
pub const MAX_UNCOMPRESSED_CERTIFICATE_LEN: usize = 256 * 1024;

const SCRATCH_LEN: usize = 8 * 1024;
const ENCODER_QUALITY: u32 = 5;
const ENCODER_LGWIN: u32 = 18;

/// Why a `CompressedCertificate` could not be turned into a `Certificate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertCompressionError {
    /// Received a `CompressedCertificate` without having offered
    /// `compress_certificate` (RFC 8879 §4: `illegal_parameter`).
    Unsolicited,
    /// Algorithm not one we offered (`illegal_parameter`).
    UnsupportedAlgorithm,
    /// Declared `uncompressed_length` is zero or above
    /// [`MAX_UNCOMPRESSED_CERTIFICATE_LEN`] (`bad_certificate`).
    BadDeclaredLength,
    /// The message framing itself is truncated or its inner length doesn't
    /// match the handshake length (`decode_error`).
    Malformed,
    /// The compressed stream is corrupt, ends early, or has trailing bytes
    /// (`bad_certificate`).
    Corrupt,
    /// The stream inflated past, or stopped short of, the declared
    /// `uncompressed_length` (`bad_certificate`).
    LengthMismatch,
}

impl CertCompressionError {
    /// Short diagnostic.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Unsolicited => "CompressedCertificate received but compress_certificate was not offered",
            Self::UnsupportedAlgorithm => "CompressedCertificate uses an algorithm that was not offered",
            Self::BadDeclaredLength => "CompressedCertificate declares an unacceptable uncompressed_length",
            Self::Malformed => "malformed CompressedCertificate",
            Self::Corrupt => "CompressedCertificate body failed to decompress",
            Self::LengthMismatch => "CompressedCertificate inflated to a different size than declared",
        }
    }
}

type State = BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>;

/// Bounded push decoder for one compressed `Certificate` body.
pub(crate) struct CertDecoder {
    state: State,
    scratch: Box<[u8]>,
    total_out: usize,
    expected: usize,
    out: Vec<u8>,
    done: bool,
}

impl std::fmt::Debug for CertDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertDecoder")
            .field("expected", &self.expected)
            .field("produced", &self.out.len())
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl CertDecoder {
    /// Decoder for a body declared to inflate to exactly `expected` bytes
    /// with `algorithm`.
    pub(crate) fn new(algorithm: u16, expected: usize) -> Result<Self, CertCompressionError> {
        if algorithm != ALG_BROTLI {
            return Err(CertCompressionError::UnsupportedAlgorithm);
        }
        if expected == 0 || expected > MAX_UNCOMPRESSED_CERTIFICATE_LEN {
            return Err(CertCompressionError::BadDeclaredLength);
        }
        let mut state = BrotliState::new(
            HeapAlloc::<u8>::new(0),
            HeapAlloc::<u32>::new(0),
            HeapAlloc::<HuffmanCode>::new(HuffmanCode::default()),
        );
        state.large_window = false;
        Ok(Self {
            state,
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
            total_out: 0,
            expected,
            out: Vec::with_capacity(expected),
            done: false,
        })
    }

    /// Feed the next chunk of compressed bytes (may be empty; may split the
    /// stream anywhere). Never blocks: returns as soon as the chunk is
    /// consumed.
    pub(crate) fn push(&mut self, input: &[u8]) -> Result<(), CertCompressionError> {
        if self.done {
            return if input.is_empty() { Ok(()) } else { Err(CertCompressionError::Corrupt) };
        }
        let mut avail_in = input.len();
        let mut in_off = 0usize;
        loop {
            let mut avail_out = self.scratch.len();
            let mut out_off = 0usize;
            let r = brotli::BrotliDecompressStream(
                &mut avail_in,
                &mut in_off,
                input,
                &mut avail_out,
                &mut out_off,
                &mut self.scratch,
                &mut self.total_out,
                &mut self.state,
            );
            if out_off > 0 {
                if self.out.len() + out_off > self.expected {
                    return Err(CertCompressionError::LengthMismatch);
                }
                self.out.extend_from_slice(&self.scratch[..out_off]);
            }
            match r {
                BrotliResult::ResultSuccess => {
                    self.done = true;
                    return if in_off < input.len() { Err(CertCompressionError::Corrupt) } else { Ok(()) };
                }
                BrotliResult::NeedsMoreOutput => continue,
                BrotliResult::NeedsMoreInput => return Ok(()),
                BrotliResult::ResultFailure => return Err(CertCompressionError::Corrupt),
            }
        }
    }

    /// The compressed body is complete: yield the inflated `Certificate`
    /// body, which must be exactly the declared length.
    pub(crate) fn finish(self) -> Result<Vec<u8>, CertCompressionError> {
        if !self.done {
            return Err(CertCompressionError::Corrupt);
        }
        if self.out.len() != self.expected {
            return Err(CertCompressionError::LengthMismatch);
        }
        Ok(self.out)
    }
}

/// Compress a `Certificate` message body with `algorithm`; `None` for an
/// unsupported algorithm or a failure to compress.
pub(crate) fn compress(algorithm: u16, body: &[u8]) -> Option<Vec<u8>> {
    if algorithm != ALG_BROTLI {
        return None;
    }
    let mut w = CompressorWriter::new(Vec::new(), SCRATCH_LEN, ENCODER_QUALITY, ENCODER_LGWIN);
    w.write_all(body).ok()?;
    w.flush().ok()?;
    Some(w.into_inner())
}

/// Encode a `CompressedCertificate` body (RFC 8879 §4): algorithm,
/// `uncompressed_length` (uint24), then the compressed bytes behind a
/// uint24 length.
pub(crate) fn encode_compressed_certificate(algorithm: u16, uncompressed_len: usize, compressed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + compressed.len());
    out.extend_from_slice(&algorithm.to_be_bytes());
    out.extend_from_slice(&(uncompressed_len as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&(compressed.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(compressed);
    out
}

/// Fixed prefix of a `CompressedCertificate` body: algorithm (2) +
/// `uncompressed_length` (3) + `compressed_certificate_message` length (3).
pub(crate) const HEADER_LEN: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        // Semi-compressible: repeated structure with a changing counter.
        (0..n).map(|i| ((i * 31 + (i >> 7)) % 251) as u8).collect()
    }

    #[test]
    fn round_trip_in_one_push() {
        let body = sample(40_000);
        let c = compress(ALG_BROTLI, &body).unwrap();
        let mut d = CertDecoder::new(ALG_BROTLI, body.len()).unwrap();
        d.push(&c).unwrap();
        assert_eq!(d.finish().unwrap(), body);
    }

    #[test]
    fn round_trip_one_byte_at_a_time() {
        let body = sample(20_000);
        let c = compress(ALG_BROTLI, &body).unwrap();
        let mut d = CertDecoder::new(ALG_BROTLI, body.len()).unwrap();
        for b in &c {
            d.push(std::slice::from_ref(b)).unwrap();
        }
        assert_eq!(d.finish().unwrap(), body);
    }

    #[test]
    fn rejects_unknown_algorithm_and_bad_declared_length() {
        assert_eq!(CertDecoder::new(1, 10).err(), Some(CertCompressionError::UnsupportedAlgorithm));
        assert_eq!(CertDecoder::new(0x7777, 10).err(), Some(CertCompressionError::UnsupportedAlgorithm));
        assert_eq!(CertDecoder::new(ALG_BROTLI, 0).err(), Some(CertCompressionError::BadDeclaredLength));
        assert_eq!(
            CertDecoder::new(ALG_BROTLI, MAX_UNCOMPRESSED_CERTIFICATE_LEN + 1).err(),
            Some(CertCompressionError::BadDeclaredLength)
        );
    }

    /// A tiny stream that inflates to far more than it declared is cut off
    /// as soon as it overshoots, not after inflating in full.
    #[test]
    fn decompression_bomb_is_cut_off_at_the_declared_length() {
        let bomb = vec![0u8; MAX_UNCOMPRESSED_CERTIFICATE_LEN];
        let c = compress(ALG_BROTLI, &bomb).unwrap();
        assert!(c.len() < 1024, "test needs a highly compressible stream");
        let mut d = CertDecoder::new(ALG_BROTLI, 100).unwrap();
        assert_eq!(d.push(&c), Err(CertCompressionError::LengthMismatch));
    }

    #[test]
    fn short_output_and_truncated_stream_are_rejected() {
        let body = sample(5_000);
        let c = compress(ALG_BROTLI, &body).unwrap();
        // Declared longer than actual.
        let mut d = CertDecoder::new(ALG_BROTLI, body.len() + 1).unwrap();
        d.push(&c).unwrap();
        assert_eq!(d.finish(), Err(CertCompressionError::LengthMismatch));
        // Truncated stream.
        let mut d = CertDecoder::new(ALG_BROTLI, body.len()).unwrap();
        d.push(&c[..c.len() / 2]).unwrap();
        assert_eq!(d.finish(), Err(CertCompressionError::Corrupt));
        // Trailing garbage after the end of the stream.
        let mut d = CertDecoder::new(ALG_BROTLI, body.len()).unwrap();
        let mut extra = c.clone();
        extra.push(0);
        assert_eq!(d.push(&extra), Err(CertCompressionError::Corrupt));
    }

    #[test]
    fn garbage_is_corrupt() {
        let mut d = CertDecoder::new(ALG_BROTLI, 1000).unwrap();
        let r = d.push(&[0xffu8; 64]).and_then(|_| d.finish().map(|_| ()));
        assert_eq!(r, Err(CertCompressionError::Corrupt));
    }
}
