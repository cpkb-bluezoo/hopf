// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HPACK encoder (RFC 7541 §6).
//!
//! Strategy: prefer fully-indexed representation when the static table has an
//! exact name+value match; otherwise use literal with incremental indexing.
//! Huffman encoding is used when it produces shorter output.

use super::dynamic::DynamicTable;
use super::huffman;
use super::static_table;

/// HPACK header block encoder.
///
/// Maintains a dynamic table in sync with the peer's decoder.
pub struct Encoder {
    table: DynamicTable,
}

impl Encoder {
    /// Create an encoder with the given initial dynamic table capacity.
    pub fn new(max_table_size: usize) -> Self {
        Self {
            table: DynamicTable::new(max_table_size),
        }
    }

    /// Encode an iterable of `(name, value)` pairs into an HPACK header block.
    pub fn encode<'a, I>(&mut self, headers: I) -> Vec<u8>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut out = Vec::new();
        for (name, value) in headers {
            self.encode_header(&mut out, name, value);
        }
        out
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn encode_header(&mut self, out: &mut Vec<u8>, name: &str, value: &str) {
        // Try static table full match first (indexed representation).
        if let Some((idx, true)) = static_table::find(name, value) {
            encode_int(out, idx, 7, 0x80);
            return;
        }

        // Try dynamic table full match (indexed representation).
        if let Some((dyn_idx, true)) = self.table.find(name, value) {
            encode_int(out, dyn_idx + 62, 7, 0x80);
            return;
        }

        // Literal with incremental indexing (RFC 7541 §6.2.1).
        // Try name-only match to reference the name from either table.
        let name_idx = static_table::find(name, value)
            .map(|(i, _)| i)
            .or_else(|| self.table.find(name, value).map(|(i, _)| i + 62));

        if let Some(idx) = name_idx {
            // First byte encodes 0x40 prefix + 6-bit index (index > 0).
            encode_int(out, idx, 6, 0x40);
        } else {
            // Index = 0 signals a new name literal follows.
            out.push(0x40);
            encode_string(out, name.as_bytes());
        }

        encode_string(out, value.as_bytes());
        self.table.insert(name.to_owned(), value.to_owned());
    }
}

/// Write `value` as a Huffman-or-raw string literal, choosing whichever is shorter.
fn encode_string(out: &mut Vec<u8>, raw: &[u8]) {
    let huffman = huffman::encode(raw);
    if huffman.len() < raw.len() {
        encode_int(out, huffman.len(), 7, 0x80);
        out.extend_from_slice(&huffman);
    } else {
        encode_int(out, raw.len(), 7, 0x00);
        out.extend_from_slice(raw);
    }
}

/// Write an HPACK integer with an `n`-bit prefix.
/// `prefix_byte` has the high bits already set (e.g. `0x80` for indexed).
pub(super) fn encode_int(out: &mut Vec<u8>, value: usize, prefix_bits: u8, prefix_byte: u8) {
    let max = (1usize << prefix_bits) - 1;
    if value < max {
        out.push(prefix_byte | value as u8);
    } else {
        out.push(prefix_byte | max as u8);
        let mut remain = value - max;
        loop {
            if remain < 128 {
                out.push(remain as u8);
                break;
            }
            out.push((remain & 0x7f) as u8 | 0x80);
            remain >>= 7;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::decode::Decoder;
    use super::*;

    #[test]
    fn encode_decode_roundtrip_static_and_literal() {
        let mut enc = Encoder::new(4096);
        let headers = [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            ("custom-x", "hello"),
        ];
        let block = enc.encode(headers.iter().copied());
        let mut dec = Decoder::new(4096);
        let out = dec.decode(&block).unwrap();
        assert_eq!(out.len(), 4);
        assert_eq!(out[0], (":method".into(), "GET".into()));
        assert_eq!(out[3], ("custom-x".into(), "hello".into()));

        // Second encode should hit dynamic table for custom-x.
        let block2 = enc.encode([("custom-x", "hello")]);
        let out2 = dec.decode(&block2).unwrap();
        assert_eq!(out2, vec![("custom-x".into(), "hello".into())]);
    }

    #[test]
    fn encode_int_small_and_large() {
        let mut out = Vec::new();
        encode_int(&mut out, 10, 7, 0x80);
        assert_eq!(out, vec![0x8a]);
        out.clear();
        encode_int(&mut out, 1337, 5, 0);
        // RFC 7541 C.1.2 example pattern for 1337 with 5-bit prefix
        assert_eq!(out[0] & 0x1f, 0x1f);
        assert!(!out.is_empty());
    }
}

