// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QPACK encoder-stream instructions (RFC 9204 §4.3): written by our
//! encoder to grow its dynamic table and tell the peer decoder about it;
//! parsed by our decoder from the peer encoder's stream.
//!
//! Index interpretation is left to the caller: a name reference's dynamic-
//! table index (`static_table: false`) and a Duplicate's index are both
//! *relative* indices (RFC 9204 §3.2.6 — 0 is the most recently inserted
//! entry at the time the instruction was written), which only the caller
//! (holding the live [`super::dynamic::DynamicTable`] state) can resolve to
//! an absolute index.

use super::prefix_int;
use super::strings;

/// Error decoding an encoder-stream instruction already fully buffered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InvalidHuffman;

impl From<strings::InvalidHuffman> for InvalidHuffman {
    fn from(_: strings::InvalidHuffman) -> Self {
        InvalidHuffman
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EncoderInstruction {
    /// §4.3.1 — set the dynamic table's capacity in bytes.
    SetDynamicTableCapacity(u64),
    /// §4.3.2 — insert an entry with a referenced name (static if
    /// `static_table`, else dynamic-relative) and a literal value.
    InsertWithNameReference {
        static_table: bool,
        name_index: u64,
        value: Vec<u8>,
    },
    /// §4.3.3 — insert an entry with both name and value given literally.
    InsertWithLiteralName { name: Vec<u8>, value: Vec<u8> },
    /// §4.3.4 — duplicate an existing (dynamic-relative-indexed) entry.
    Duplicate(u64),
}

pub(crate) fn write_set_dynamic_table_capacity(out: &mut Vec<u8>, capacity: u64) {
    prefix_int::encode(out, capacity, 5, 0x20);
}

pub(crate) fn write_insert_with_name_reference(
    out: &mut Vec<u8>,
    static_table: bool,
    name_index: u64,
    value: &[u8],
) {
    let t_bit = if static_table { 0x40 } else { 0x00 };
    prefix_int::encode(out, name_index, 6, 0x80 | t_bit);
    strings::write(out, value, 7, 0x00);
}

pub(crate) fn write_insert_with_literal_name(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    strings::write(out, name, 5, 0x40);
    strings::write(out, value, 7, 0x00);
}

pub(crate) fn write_duplicate(out: &mut Vec<u8>, relative_index: u64) {
    prefix_int::encode(out, relative_index, 5, 0x00);
}

/// Parse the next complete instruction from the start of `input`. Returns
/// `Ok(None)` if `input` doesn't yet hold a full instruction (the caller
/// should retain the bytes and wait for more to arrive on the stream).
pub(crate) fn parse_next(input: &[u8]) -> Result<Option<(EncoderInstruction, usize)>, InvalidHuffman> {
    let Some(&first) = input.first() else {
        return Ok(None);
    };
    if first & 0x80 != 0 {
        let static_table = first & 0x40 != 0;
        let Some((name_index, used)) = prefix_int::decode(input, 6) else {
            return Ok(None);
        };
        let Some((value, value_used)) = strings::try_read(&input[used..], 7)? else {
            return Ok(None);
        };
        Ok(Some((
            EncoderInstruction::InsertWithNameReference { static_table, name_index, value },
            used + value_used,
        )))
    } else if first & 0x40 != 0 {
        let Some((name, used)) = strings::try_read(input, 5)? else {
            return Ok(None);
        };
        let Some((value, value_used)) = strings::try_read(&input[used..], 7)? else {
            return Ok(None);
        };
        Ok(Some((
            EncoderInstruction::InsertWithLiteralName { name, value },
            used + value_used,
        )))
    } else if first & 0x20 != 0 {
        let Some((capacity, used)) = prefix_int::decode(input, 5) else {
            return Ok(None);
        };
        Ok(Some((EncoderInstruction::SetDynamicTableCapacity(capacity), used)))
    } else {
        let Some((index, used)) = prefix_int::decode(input, 5) else {
            return Ok(None);
        };
        Ok(Some((EncoderInstruction::Duplicate(index), used)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_dynamic_table_capacity_round_trips() {
        let mut out = Vec::new();
        write_set_dynamic_table_capacity(&mut out, 4096);
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((EncoderInstruction::SetDynamicTableCapacity(4096), out.len()))
        );
    }

    #[test]
    fn insert_with_static_name_reference_round_trips() {
        let mut out = Vec::new();
        write_insert_with_name_reference(&mut out, true, 17, b"GET");
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((
                EncoderInstruction::InsertWithNameReference {
                    static_table: true,
                    name_index: 17,
                    value: b"GET".to_vec(),
                },
                out.len()
            ))
        );
    }

    #[test]
    fn insert_with_dynamic_name_reference_round_trips() {
        let mut out = Vec::new();
        write_insert_with_name_reference(&mut out, false, 3, b"some-value");
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((
                EncoderInstruction::InsertWithNameReference {
                    static_table: false,
                    name_index: 3,
                    value: b"some-value".to_vec(),
                },
                out.len()
            ))
        );
    }

    #[test]
    fn insert_with_literal_name_round_trips() {
        let mut out = Vec::new();
        write_insert_with_literal_name(&mut out, b"x-custom", b"widget-value");
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((
                EncoderInstruction::InsertWithLiteralName {
                    name: b"x-custom".to_vec(),
                    value: b"widget-value".to_vec(),
                },
                out.len()
            ))
        );
    }

    #[test]
    fn duplicate_round_trips() {
        let mut out = Vec::new();
        write_duplicate(&mut out, 9);
        assert_eq!(parse_next(&out).unwrap(), Some((EncoderInstruction::Duplicate(9), out.len())));
    }

    #[test]
    fn long_literal_value_is_huffman_coded() {
        let mut out = Vec::new();
        let value = "a".repeat(200);
        write_insert_with_name_reference(&mut out, true, 0, value.as_bytes());
        assert!(out.len() < value.len(), "expected Huffman compression to fire");
        let (instr, used) = parse_next(&out).unwrap().unwrap();
        assert_eq!(used, out.len());
        match instr {
            EncoderInstruction::InsertWithNameReference { value: decoded, .. } => {
                assert_eq!(decoded, value.as_bytes());
            }
            other => panic!("unexpected instruction: {other:?}"),
        }
    }

    #[test]
    fn truncated_instruction_yields_none_not_error() {
        let mut out = Vec::new();
        write_insert_with_literal_name(&mut out, b"a-fairly-long-header-name", b"a-fairly-long-value");
        for cut in 1..out.len() {
            assert_eq!(parse_next(&out[..cut]).unwrap(), None, "cut at {cut} should be incomplete");
        }
    }

    #[test]
    fn concatenated_instructions_parse_one_at_a_time() {
        let mut out = Vec::new();
        write_set_dynamic_table_capacity(&mut out, 100);
        write_duplicate(&mut out, 2);
        let (first, used1) = parse_next(&out).unwrap().unwrap();
        assert_eq!(first, EncoderInstruction::SetDynamicTableCapacity(100));
        let (second, used2) = parse_next(&out[used1..]).unwrap().unwrap();
        assert_eq!(second, EncoderInstruction::Duplicate(2));
        assert_eq!(used1 + used2, out.len());
    }
}
