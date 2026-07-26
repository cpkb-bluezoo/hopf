// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stateless QPACK field-section decoder for static-table-only peers.

use super::static_table;
use crate::h2::hpack::huffman;

/// QPACK decoding error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended in a partial integer or string.
    Truncated,
    /// Dynamic-table references are unsupported.
    DynamicTable,
    /// Static-table index is invalid.
    InvalidIndex,
    /// A field representation is unsupported.
    Unsupported,
    /// Header bytes are not valid UTF-8.
    InvalidText,
    /// Malformed Huffman-coded string.
    InvalidHuffman,
}

fn integer(input: &[u8], prefix: u8) -> Result<(u64, usize), DecodeError> {
    let mask = if prefix == 8 {
        u8::MAX
    } else {
        (1u8 << prefix) - 1
    };
    let mut value = u64::from(*input.first().ok_or(DecodeError::Truncated)? & mask);
    if value < u64::from(mask) {
        return Ok((value, 1));
    }
    let mut used = 1;
    let mut shift = 0;
    loop {
        let byte = *input.get(used).ok_or(DecodeError::Truncated)?;
        used += 1;
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, used));
        }
        shift += 7;
        if shift > 56 {
            return Err(DecodeError::Unsupported);
        }
    }
}

fn string(input: &[u8]) -> Result<(String, usize), DecodeError> {
    let huffman_coded = input.first().ok_or(DecodeError::Truncated)? & 0x80 != 0;
    let (len, used) = integer(input, 7)?;
    let end = used + usize::try_from(len).map_err(|_| DecodeError::Truncated)?;
    let raw = input.get(used..end).ok_or(DecodeError::Truncated)?;
    let text = if huffman_coded {
        let decoded = huffman::decode(raw).map_err(|_| DecodeError::InvalidHuffman)?;
        String::from_utf8(decoded).map_err(|_| DecodeError::InvalidText)?
    } else {
        std::str::from_utf8(raw)
            .map_err(|_| DecodeError::InvalidText)?
            .to_owned()
    };
    Ok((text, end))
}

/// Decode a QPACK field section with Required Insert Count zero.
pub fn decode(block: &[u8]) -> Result<Vec<(String, String)>, DecodeError> {
    let (ric, a) = integer(block, 8)?;
    if ric != 0 {
        return Err(DecodeError::DynamicTable);
    }
    let (_, b) = integer(&block[a..], 7)?; // Base, always zero in this encoder.
    let mut at = a + b;
    let mut fields = Vec::new();
    while at < block.len() {
        let first = block[at];
        if first & 0x80 != 0 {
            if first & 0x40 == 0 {
                return Err(DecodeError::DynamicTable);
            }
            let (index, used) = integer(&block[at..], 6)?;
            let entry = static_table::get(index as usize).ok_or(DecodeError::InvalidIndex)?;
            fields.push((entry.name.to_owned(), entry.value.to_owned()));
            at += used;
        } else if first & 0xc0 == 0x40 {
            if first & 0x10 == 0 {
                return Err(DecodeError::DynamicTable);
            }
            let (index, used) = integer(&block[at..], 4)?;
            let entry = static_table::get(index as usize).ok_or(DecodeError::InvalidIndex)?;
            let (value, value_used) = string(&block[at + used..])?;
            fields.push((entry.name.to_owned(), value));
            at += used + value_used;
        } else if first & 0xe0 == 0x20 {
            let (name_len, used) = integer(&block[at..], 3)?;
            let name_end = at + used + name_len as usize;
            let name = std::str::from_utf8(
                block
                    .get(at + used..name_end)
                    .ok_or(DecodeError::Truncated)?,
            )
            .map_err(|_| DecodeError::InvalidText)?
            .to_owned();
            let (value, value_used) = string(&block[name_end..])?;
            fields.push((name, value));
            at = name_end + value_used;
        } else {
            return Err(DecodeError::Unsupported);
        }
    }
    Ok(fields)
}
