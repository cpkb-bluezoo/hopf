// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HPACK decoder (RFC 7541 §3, §5, §6).
//!
//! Decodes a header block fragment into a sequence of `(name, value)` pairs.
//! The dynamic table is updated in-place during decoding.

use super::dynamic::DynamicTable;
use super::huffman;
use super::static_table;
use super::Error;

/// HPACK header block decoder.
///
/// Holds the dynamic table that persists across header block fragments on the
/// same connection.
pub struct Decoder {
    table: DynamicTable,
}

impl Decoder {
    /// Create a decoder with the given initial dynamic table capacity (bytes).
    pub fn new(max_table_size: usize) -> Self {
        Self {
            table: DynamicTable::new(max_table_size),
        }
    }

    /// Decode one complete header block fragment.
    ///
    /// Returns the ordered list of `(name, value)` pairs. Pseudo-headers
    /// (`:method`, `:path`, etc.) appear first in the returned sequence, exactly
    /// as encoded by the peer.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>, Error> {
        let mut pos = 0;
        let mut headers = Vec::new();

        while pos < block.len() {
            let first = block[pos];

            if first & 0x80 != 0 {
                // Indexed header field (RFC 7541 §6.1)
                let (idx, n) = decode_int(block, pos, 7)?;
                pos += n;
                if idx == 0 {
                    return Err(Error::InvalidIndex(0));
                }
                let (name, value) = self.lookup(idx)?;
                headers.push((name.to_owned(), value.to_owned()));
            } else if first & 0xc0 == 0x40 {
                // Literal with incremental indexing (RFC 7541 §6.2.1)
                let (name, value, n) = self.decode_literal(block, pos, 6)?;
                pos += n;
                self.table.insert(name.clone(), value.clone());
                headers.push((name, value));
            } else if first & 0xf0 == 0x00 {
                // Literal without indexing (RFC 7541 §6.2.2)
                let (name, value, n) = self.decode_literal(block, pos, 4)?;
                pos += n;
                headers.push((name, value));
            } else if first & 0xf0 == 0x10 {
                // Literal — never indexed (RFC 7541 §6.2.3)
                let (name, value, n) = self.decode_literal(block, pos, 4)?;
                pos += n;
                headers.push((name, value));
            } else if first & 0xe0 == 0x20 {
                // Dynamic table size update (RFC 7541 §6.3)
                let (new_max, n) = decode_int(block, pos, 5)?;
                pos += n;
                self.table.set_max_size(new_max);
            } else {
                return Err(Error::InvalidData);
            }
        }

        Ok(headers)
    }

    /// Applies a dynamic table size update without decoding a header block.
    pub fn set_max_table_size(&mut self, size: usize) {
        self.table.set_max_size(size);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn lookup(&self, idx: usize) -> Result<(&str, &str), Error> {
        if idx <= 61 {
            static_table::get(idx).ok_or(Error::InvalidIndex(idx))
        } else {
            let dyn_idx = idx - 62;
            self.table.get(dyn_idx).ok_or(Error::InvalidIndex(idx))
        }
    }

    /// Decode a literal header field starting at `pos` with an `n`-bit prefix.
    /// Returns `(name, value, bytes_consumed)`.
    fn decode_literal(
        &self,
        block: &[u8],
        pos: usize,
        prefix_bits: u8,
    ) -> Result<(String, String, usize), Error> {
        let start = pos;
        let (name_idx, n) = decode_int(block, pos, prefix_bits)?;
        let mut pos = pos + n;

        let name = if name_idx == 0 {
            let (s, n) = decode_string(block, pos)?;
            pos += n;
            s
        } else {
            let (n, _) = self.lookup(name_idx)?;
            n.to_owned()
        };

        let (value, n) = decode_string(block, pos)?;
        pos += n;

        Ok((name, value, pos - start))
    }
}

/// Decode an HPACK integer with an `n`-bit prefix (RFC 7541 §5.1).
/// Returns `(value, bytes_consumed)`.
pub(super) fn decode_int(
    data: &[u8],
    pos: usize,
    prefix_bits: u8,
) -> Result<(usize, usize), Error> {
    if pos >= data.len() {
        return Err(Error::Truncated);
    }
    let mask = (1usize << prefix_bits) - 1;
    let first = (data[pos] as usize) & mask;
    if first < mask {
        return Ok((first, 1));
    }
    // Multi-byte integer
    let mut value: usize = mask;
    let mut m: usize = 0;
    let mut i = pos + 1;
    loop {
        if i >= data.len() {
            return Err(Error::Truncated);
        }
        let b = data[i] as usize;
        i += 1;
        value += (b & 0x7f) << m;
        m += 7;
        if b & 0x80 == 0 {
            break;
        }
        if m > 28 {
            return Err(Error::InvalidData);
        }
    }
    Ok((value, i - pos))
}

/// Decode an HPACK string literal (RFC 7541 §5.2).
/// Returns `(string, bytes_consumed)`.
fn decode_string(data: &[u8], pos: usize) -> Result<(String, usize), Error> {
    if pos >= data.len() {
        return Err(Error::Truncated);
    }
    let huffman_flag = data[pos] & 0x80 != 0;
    let (len, n) = decode_int(data, pos, 7)?;
    let start = pos + n;
    let end = start + len;
    if end > data.len() {
        return Err(Error::Truncated);
    }
    let raw = &data[start..end];
    let bytes = if huffman_flag {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    let s = String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    Ok((s, end - pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_c2_1_literal_with_indexing() {
        // RFC 7541 C.2.1: Literal Header Field with Incremental Indexing
        // name = "custom-key", value = "custom-header"
        #[rustfmt::skip]
        let block = &[
            0x40,
            0x0a, b'c',b'u',b's',b't',b'o',b'm',b'-',b'k',b'e',b'y',
            0x0d, b'c',b'u',b's',b't',b'o',b'm',b'-',b'h',b'e',b'a',b'd',b'e',b'r',
        ];
        let mut dec = Decoder::new(4096);
        let pairs = dec.decode(block).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "custom-key");
        assert_eq!(pairs[0].1, "custom-header");
    }

    #[test]
    fn indexed_static_method_get() {
        // Index 2 = :method GET
        let block = &[0x82u8]; // 0x80 | 2
        let mut dec = Decoder::new(4096);
        let pairs = dec.decode(block).unwrap();
        assert_eq!(pairs[0].0, ":method");
        assert_eq!(pairs[0].1, "GET");
    }
}
