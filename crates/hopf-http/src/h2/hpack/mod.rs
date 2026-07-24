// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HPACK header compression (RFC 7541).
//!
//! Re-exports [`Decoder`], [`Encoder`], and [`Error`].
//! Internal modules handle the static table, Huffman codec, and dynamic table.

mod decode;
mod dynamic;
mod encode;
pub mod huffman;
pub mod static_table;

pub use decode::Decoder;
pub use encode::Encoder;

/// Errors that can occur during HPACK decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Input ended before the field was fully read.
    Truncated,
    /// A table index of zero or beyond the combined table size was used.
    InvalidIndex(usize),
    /// A Huffman-encoded string contained illegal padding or an EOS symbol.
    InvalidHuffman,
    /// A string literal was not valid UTF-8.
    InvalidUtf8,
    /// The byte stream contained an unrecognised pattern.
    InvalidData,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "HPACK: truncated input"),
            Error::InvalidIndex(i) => write!(f, "HPACK: invalid index {i}"),
            Error::InvalidHuffman => write!(f, "HPACK: invalid Huffman encoding"),
            Error::InvalidUtf8 => write!(f, "HPACK: string literal is not UTF-8"),
            Error::InvalidData => write!(f, "HPACK: unrecognised encoding"),
        }
    }
}

impl std::error::Error for Error {}
