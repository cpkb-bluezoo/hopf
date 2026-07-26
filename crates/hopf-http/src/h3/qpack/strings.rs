// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Huffman-or-raw string literals with an N-bit length prefix (RFC 9204
//! §4.5.4's `H` bit convention) — shared by field-line representations and
//! encoder-stream instructions, whose formats differ only in which prefix
//! width the surrounding representation allots to the length.

use super::prefix_int;
use crate::h2::hpack::huffman;

/// Malformed Huffman-coded string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidHuffman;

/// Write `value` Huffman-coded if that's shorter, else raw, setting the `H`
/// bit (`1 << prefix_bits`) accordingly.
pub(crate) fn write(out: &mut Vec<u8>, value: &[u8], prefix_bits: u8, first_byte_bits: u8) {
    let encoded = huffman::encode(value);
    if encoded.len() < value.len() {
        prefix_int::encode(out, encoded.len() as u64, prefix_bits, first_byte_bits | (1 << prefix_bits));
        out.extend_from_slice(&encoded);
    } else {
        prefix_int::encode(out, value.len() as u64, prefix_bits, first_byte_bits);
        out.extend_from_slice(value);
    }
}

/// Read a string written by [`write`]. `Ok(None)` means `input` doesn't yet
/// hold the complete string — this doubles as a streaming-instruction
/// reader, where "incomplete" means "wait for more bytes", not an error.
pub(crate) fn try_read(input: &[u8], prefix_bits: u8) -> Result<Option<(Vec<u8>, usize)>, InvalidHuffman> {
    let h_bit = 1u8 << prefix_bits;
    let Some(&first) = input.first() else {
        return Ok(None);
    };
    let huffman_coded = first & h_bit != 0;
    let Some((len, used)) = prefix_int::decode(input, prefix_bits) else {
        return Ok(None);
    };
    let Ok(len) = usize::try_from(len) else {
        return Ok(None); // absurd length; treat like "not enough bytes yet"
    };
    let Some(raw) = input.get(used..used + len) else {
        return Ok(None);
    };
    let bytes = if huffman_coded {
        huffman::decode(raw).map_err(|_| InvalidHuffman)?
    } else {
        raw.to_vec()
    };
    Ok(Some((bytes, used + len)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_huffman_and_raw() {
        for value in ["a".repeat(200), "Q7z$k2!Xv9@pL".to_string(), String::new()] {
            let mut out = Vec::new();
            write(&mut out, value.as_bytes(), 7, 0);
            let (decoded, used) = try_read(&out, 7).unwrap().unwrap();
            assert_eq!(used, out.len());
            assert_eq!(decoded, value.as_bytes());
        }
    }

    #[test]
    fn incomplete_input_is_none() {
        let mut out = Vec::new();
        write(&mut out, b"hello world", 7, 0);
        for cut in 0..out.len() {
            assert_eq!(try_read(&out[..cut], 7).unwrap(), None, "cut at {cut}");
        }
    }
}
