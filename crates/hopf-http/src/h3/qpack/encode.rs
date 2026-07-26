// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Static-table-only QPACK field-section encoder.

use super::static_table;
use crate::h2::hpack::huffman;

fn integer(out: &mut Vec<u8>, value: u64, prefix: u8, bits: u8) {
    let max = (1u64 << prefix) - 1;
    if value < max {
        out.push(bits | value as u8);
        return;
    }
    out.push(bits | max as u8);
    let mut remaining = value - max;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

/// Write `value` as a Huffman-or-raw string literal (RFC 9204 §4.5.1's `H`
/// bit), choosing whichever is shorter — same table as HPACK
/// (RFC 9204 §4.1.2 references RFC 7541 Appendix B).
fn string(out: &mut Vec<u8>, value: &str) {
    let raw = value.as_bytes();
    let encoded = huffman::encode(raw);
    if encoded.len() < raw.len() {
        integer(out, encoded.len() as u64, 7, 0x80);
        out.extend_from_slice(&encoded);
    } else {
        integer(out, raw.len() as u64, 7, 0);
        out.extend_from_slice(raw);
    }
}

/// Encode fields with an empty dynamic table.
pub fn encode<'a>(fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<u8> {
    let mut out = vec![0, 0]; // Required Insert Count = 0, Base = 0.
    for (name, value) in fields {
        if let Some(index) = static_table::find(name, value) {
            integer(&mut out, index as u64, 6, 0xc0); // Indexed, static.
        } else if let Some(index) = static_table::find_name(name) {
            integer(&mut out, index as u64, 4, 0x50); // Literal, static name ref.
            string(&mut out, value);
        } else {
            integer(&mut out, name.len() as u64, 3, 0x20); // Literal name, no Huffman.
            out.extend_from_slice(name.as_bytes());
            string(&mut out, value);
        }
    }
    out
}
