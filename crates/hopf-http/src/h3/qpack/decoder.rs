// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stateful QPACK field-section decoder (RFC 9204 §4.5), backed by a real
//! dynamic table mirrored from the peer encoder's instruction stream.
//! Decodes arbitrary spec-compliant encodings — including dynamic-table
//! and post-base references — since a real peer encoder isn't obligated to
//! follow hopf's own non-blocking encoding policy. The one thing this
//! decoder does not do is *buffer and wait* for a blocked stream: since we
//! advertise `SETTINGS_QPACK_BLOCKED_STREAMS = 0` (RFC 9204 §5), a compliant
//! peer never sends a Required Insert Count we can't already satisfy, so
//! [`DecodeError::Blocked`] should never occur against a compliant encoder.

use super::dynamic::DynamicTable;
use super::encoder_stream::EncoderInstruction;
use super::insert_count;
use super::prefix_int;
use super::static_table;
use super::strings;
use super::decoder_stream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// Input ended in a partial integer or string.
    Truncated,
    /// A static or dynamic table index doesn't resolve to a live entry.
    InvalidIndex,
    /// A field representation's leading bits are unrecognized.
    Unsupported,
    /// Header bytes are not valid UTF-8.
    InvalidText,
    /// Malformed Huffman-coded string.
    InvalidHuffman,
    /// The Required Insert Count depends on entries we haven't received
    /// yet — would require blocking, which this decoder never permits.
    Blocked,
    /// A `Set Dynamic Table Capacity` instruction exceeded the capacity
    /// this decoder declared via `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
    /// (RFC 9204 §3.2.3 — a hard connection error, not a clamp).
    CapacityExceeded,
}

pub(crate) struct Decoder {
    table: DynamicTable,
    /// The capacity ceiling this decoder declared via
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, fixed at construction. RFC 9204
    /// §3.2.3 requires a peer exceeding this to be treated as a connection
    /// error — never silently honored.
    max_capacity: usize,
}

fn integer(input: &[u8], prefix: u8) -> Result<(u64, usize), DecodeError> {
    prefix_int::decode(input, prefix).ok_or(DecodeError::Truncated)
}

fn read_string(input: &[u8], prefix_bits: u8) -> Result<(String, usize), DecodeError> {
    let (bytes, used) = strings::try_read(input, prefix_bits)
        .map_err(|_| DecodeError::InvalidHuffman)?
        .ok_or(DecodeError::Truncated)?;
    Ok((String::from_utf8(bytes).map_err(|_| DecodeError::InvalidText)?, used))
}

impl Decoder {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            table: DynamicTable::new(capacity),
            max_capacity: capacity,
        }
    }

    /// Apply an encoder-stream instruction already parsed by
    /// [`super::encoder_stream::parse_next`], mirroring it into this
    /// decoder's dynamic table. Returns the decoder-stream Insert Count
    /// Increment bytes to send back (RFC 9204 §4.4.3) — sent unconditionally
    /// per processed insertion, which is always a valid choice per spec.
    pub(crate) fn apply_encoder_instruction(&mut self, instr: EncoderInstruction) -> Result<Vec<u8>, DecodeError> {
        match instr {
            EncoderInstruction::SetDynamicTableCapacity(capacity) => {
                let capacity = usize::try_from(capacity).map_err(|_| DecodeError::InvalidIndex)?;
                if capacity > self.max_capacity {
                    return Err(DecodeError::CapacityExceeded);
                }
                self.table.set_capacity(capacity);
                Ok(Vec::new())
            }
            EncoderInstruction::InsertWithNameReference { static_table: is_static, name_index, value } => {
                let name = self.resolve_name_reference(is_static, name_index)?;
                let value = String::from_utf8(value).map_err(|_| DecodeError::InvalidText)?;
                self.table.insert_mirrored(name, value);
                Ok(self.insert_count_increment())
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                let name = String::from_utf8(name).map_err(|_| DecodeError::InvalidText)?;
                let value = String::from_utf8(value).map_err(|_| DecodeError::InvalidText)?;
                self.table.insert_mirrored(name, value);
                Ok(self.insert_count_increment())
            }
            EncoderInstruction::Duplicate(relative_index) => {
                let abs = self.resolve_relative_to_insert_count(relative_index)?;
                let (name, value) = self.table.get(abs).ok_or(DecodeError::InvalidIndex)?;
                let (name, value) = (name.to_owned(), value.to_owned());
                self.table.insert_mirrored(name, value);
                Ok(self.insert_count_increment())
            }
        }
    }

    fn insert_count_increment(&self) -> Vec<u8> {
        let mut out = Vec::new();
        decoder_stream::write_insert_count_increment(&mut out, 1);
        out
    }

    /// RFC 9204 §4.3.2 — the dynamic-table index in Insert With Name
    /// Reference is relative to the Insert Count at the time of the
    /// instruction (0 = most recently inserted), not to a field section's
    /// Base.
    fn resolve_relative_to_insert_count(&self, relative_index: u64) -> Result<u64, DecodeError> {
        self.table
            .insert_count()
            .checked_sub(1)
            .and_then(|newest| newest.checked_sub(relative_index))
            .ok_or(DecodeError::InvalidIndex)
    }

    fn resolve_name_reference(&self, is_static: bool, name_index: u64) -> Result<String, DecodeError> {
        if is_static {
            let index = usize::try_from(name_index).map_err(|_| DecodeError::InvalidIndex)?;
            Ok(static_table::get(index).ok_or(DecodeError::InvalidIndex)?.name.to_owned())
        } else {
            let abs = self.resolve_relative_to_insert_count(name_index)?;
            Ok(self.table.get(abs).ok_or(DecodeError::InvalidIndex)?.0.to_owned())
        }
    }

    /// Decode one field section received on `stream_id`. Returns the
    /// decoded fields and the decoder-stream Section Acknowledgment bytes
    /// to send back (RFC 9204 §4.4.1) — empty if the section didn't
    /// reference the dynamic table, since acknowledging then would be a
    /// meaningless no-op.
    pub(crate) fn decode(&self, stream_id: u64, block: &[u8]) -> Result<(Vec<(String, String)>, Vec<u8>), DecodeError> {
        let (encoded_ric, a) = integer(block, 8)?;
        let ric = insert_count::decode(encoded_ric, self.table.insert_count(), self.table.capacity())
            .ok_or(DecodeError::Blocked)?;
        // The wraparound math above only reconstructs a plausible RIC; it
        // doesn't check we've actually received that many insertions yet.
        // A RIC beyond what we've processed would require blocking, which
        // this decoder never permits (see module docs).
        if ric > self.table.insert_count() {
            return Err(DecodeError::Blocked);
        }

        let sign = *block.get(a).ok_or(DecodeError::Truncated)? & 0x80 != 0;
        let (delta, b) = integer(&block[a..], 7)?;
        let base = if sign {
            ric.checked_sub(delta).and_then(|v| v.checked_sub(1)).ok_or(DecodeError::InvalidIndex)?
        } else {
            ric.checked_add(delta).ok_or(DecodeError::InvalidIndex)?
        };

        let mut at = a + b;
        let mut fields = Vec::new();
        while at < block.len() {
            let first = block[at];
            if first & 0x80 != 0 {
                let is_static = first & 0x40 != 0;
                let (index, used) = integer(&block[at..], 6)?;
                let entry = if is_static {
                    let e = static_table::get(usize::try_from(index).map_err(|_| DecodeError::InvalidIndex)?)
                        .ok_or(DecodeError::InvalidIndex)?;
                    (e.name.to_owned(), e.value.to_owned())
                } else {
                    let abs = base.checked_sub(1).and_then(|m| m.checked_sub(index)).ok_or(DecodeError::InvalidIndex)?;
                    let (n, v) = self.table.get(abs).ok_or(DecodeError::InvalidIndex)?;
                    (n.to_owned(), v.to_owned())
                };
                fields.push(entry);
                at += used;
            } else if first & 0xc0 == 0x40 {
                let is_static = first & 0x10 != 0;
                let (index, used) = integer(&block[at..], 4)?;
                let name = if is_static {
                    static_table::get(usize::try_from(index).map_err(|_| DecodeError::InvalidIndex)?)
                        .ok_or(DecodeError::InvalidIndex)?
                        .name
                        .to_owned()
                } else {
                    let abs = base.checked_sub(1).and_then(|m| m.checked_sub(index)).ok_or(DecodeError::InvalidIndex)?;
                    self.table.get(abs).ok_or(DecodeError::InvalidIndex)?.0.to_owned()
                };
                let (value, value_used) = read_string(&block[at + used..], 7)?;
                fields.push((name, value));
                at += used + value_used;
            } else if first & 0xe0 == 0x20 {
                let (name, used) = read_string(&block[at..], 3)?;
                let (value, value_used) = read_string(&block[at + used..], 7)?;
                fields.push((name, value));
                at += used + value_used;
            } else if first & 0xf0 == 0x10 {
                let (index, used) = integer(&block[at..], 4)?;
                let abs = base.checked_add(index).ok_or(DecodeError::InvalidIndex)?;
                let (n, v) = self.table.get(abs).ok_or(DecodeError::InvalidIndex)?;
                fields.push((n.to_owned(), v.to_owned()));
                at += used;
            } else if first & 0xf0 == 0x00 {
                let (index, used) = integer(&block[at..], 3)?;
                let abs = base.checked_add(index).ok_or(DecodeError::InvalidIndex)?;
                let name = self.table.get(abs).ok_or(DecodeError::InvalidIndex)?.0.to_owned();
                let (value, value_used) = read_string(&block[at + used..], 7)?;
                fields.push((name, value));
                at += used + value_used;
            } else {
                return Err(DecodeError::Unsupported);
            }
        }

        let ack = if ric > 0 {
            let mut out = Vec::new();
            decoder_stream::write_section_acknowledgment(&mut out, stream_id);
            out
        } else {
            Vec::new()
        };
        Ok((fields, ack))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_static_only_section_with_no_ack() {
        let dec = Decoder::new(4096);
        let block = vec![0, 0, 0xc0 | 25]; // RIC=0, Base=0, :status: 200
        let (fields, ack) = dec.decode(0, &block).unwrap();
        assert_eq!(fields, vec![(":status".into(), "200".into())]);
        assert!(ack.is_empty());
    }

    #[test]
    fn applying_insert_with_literal_name_grows_table_and_acks() {
        let mut dec = Decoder::new(4096);
        let ack = dec
            .apply_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
                name: b"x-custom".to_vec(),
                value: b"widget".to_vec(),
            })
            .unwrap();
        assert_eq!(
            super::super::decoder_stream::parse_next(&ack),
            Some((super::super::decoder_stream::DecoderInstruction::InsertCountIncrement { increment: 1 }, ack.len()))
        );
        assert_eq!(dec.table.get(0), Some(("x-custom", "widget")));
    }

    #[test]
    fn duplicate_instruction_reinserts_at_a_new_absolute_index() {
        let mut dec = Decoder::new(4096);
        dec.apply_encoder_instruction(EncoderInstruction::InsertWithLiteralName {
            name: b"a".to_vec(),
            value: b"1".to_vec(),
        })
        .unwrap();
        dec.apply_encoder_instruction(EncoderInstruction::Duplicate(0)).unwrap(); // duplicate the only (most recent) entry
        assert_eq!(dec.table.get(0), Some(("a", "1")));
        assert_eq!(dec.table.get(1), Some(("a", "1")));
    }

    #[test]
    fn set_dynamic_table_capacity_within_limit_is_honored() {
        let mut dec = Decoder::new(4096);
        dec.apply_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(2048))
            .unwrap();
        assert_eq!(dec.table.capacity(), 2048);
    }

    #[test]
    fn set_dynamic_table_capacity_exceeding_local_max_is_a_connection_error() {
        // RFC 9204 §3.2.3: exceeding the declared
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY is a hard connection error, not
        // something to silently honor (issue #178).
        let mut dec = Decoder::new(4096);
        let err = dec
            .apply_encoder_instruction(EncoderInstruction::SetDynamicTableCapacity(1_000_000))
            .unwrap_err();
        assert_eq!(err, DecodeError::CapacityExceeded);
        // The rejected instruction must not have taken effect.
        assert_eq!(dec.table.capacity(), 4096);
    }

    #[test]
    fn blocked_required_insert_count_is_rejected() {
        let dec = Decoder::new(4096);
        // Encoded RIC=2 with an empty table: no insertions received yet,
        // so any nonzero RIC can't be satisfied.
        let block = vec![2, 0];
        assert_eq!(dec.decode(0, &block), Err(DecodeError::Blocked));
    }
}
