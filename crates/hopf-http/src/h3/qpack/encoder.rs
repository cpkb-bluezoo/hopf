// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stateful QPACK field-section encoder (RFC 9204 §4.5), backed by a real
//! dynamic table. Operates in strictly non-blocking mode: it never
//! references an entry the peer decoder hasn't yet acknowledged, so it
//! always emits `Base = Required Insert Count = Known Received Count` and
//! never uses post-base indexing (§4.5.3/§4.5.5) — a compliant peer never
//! blocks decoding our field sections, which is why hopf's own decoder can
//! safely advertise `SETTINGS_QPACK_BLOCKED_STREAMS = 0`.

use std::collections::HashMap;

use super::dynamic::DynamicTable;
use super::encoder_stream;
use super::insert_count;
use super::prefix_int;
use super::static_table;
use super::strings;

pub(crate) struct Encoder {
    table: DynamicTable,
    /// Entries the peer decoder has acknowledged processing through
    /// (RFC 9204 §2.1.4) — our non-blocking policy's Base/RIC value.
    known_received_count: u64,
    /// Per-outstanding (not yet acknowledged/cancelled) stream: the
    /// Required Insert Count it was encoded with, and the absolute indices
    /// it references, so [`Self::on_section_acknowledgment`] /
    /// [`Self::on_stream_cancellation`] can release the right table refs.
    outstanding: HashMap<u64, (u64, Vec<u64>)>,
}

impl Encoder {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            table: DynamicTable::new(capacity),
            known_received_count: 0,
            outstanding: HashMap::new(),
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Change the dynamic table's capacity, returning the encoder-stream
    /// instruction bytes to send (RFC 9204 §4.3.1).
    pub(crate) fn set_capacity(&mut self, capacity: usize) -> Vec<u8> {
        self.table.set_capacity(capacity);
        let mut instructions = Vec::new();
        encoder_stream::write_set_dynamic_table_capacity(&mut instructions, capacity as u64);
        instructions
    }

    /// Encode one field section for `stream_id` (the request/response
    /// stream it belongs to). Returns `(field_line_bytes,
    /// encoder_stream_instructions)`: send the first on `stream_id`, and
    /// the second (often empty) on the encoder stream, preserving order
    /// relative to instructions from other calls.
    pub(crate) fn encode<'a>(
        &mut self,
        stream_id: u64,
        fields: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> (Vec<u8>, Vec<u8>) {
        let base = self.known_received_count; // non-blocking policy: Base = RIC = KRC
        let mut field_lines = Vec::new();
        let mut instructions = Vec::new();
        let mut referenced = Vec::new();

        for (name, value) in fields {
            if let Some(index) = static_table::find(name, value) {
                prefix_int::encode(&mut field_lines, index as u64, 6, 0xc0);
                continue;
            }
            if let Some((abs, true)) = self.table.find(name, value, base) {
                self.table.add_ref(abs);
                referenced.push(abs);
                prefix_int::encode(&mut field_lines, base - 1 - abs, 6, 0x80);
                continue;
            }

            // Not referenceable yet under our non-blocking policy. Emit a
            // literal for this section; opportunistically insert for
            // future reuse, unless an equivalent entry is already
            // in-flight (skip to avoid duplicate insert instructions).
            let already_present = self
                .table
                .find(name, value, self.table.insert_count())
                .is_some_and(|(_, full)| full);
            if !already_present && self.table.insert(name.to_owned(), value.to_owned()).is_some() {
                if let Some(static_index) = static_table::find_name(name) {
                    encoder_stream::write_insert_with_name_reference(
                        &mut instructions,
                        true,
                        static_index as u64,
                        value.as_bytes(),
                    );
                } else {
                    encoder_stream::write_insert_with_literal_name(
                        &mut instructions,
                        name.as_bytes(),
                        value.as_bytes(),
                    );
                }
            }

            if let Some(static_index) = static_table::find_name(name) {
                prefix_int::encode(&mut field_lines, static_index as u64, 4, 0x50);
                strings::write(&mut field_lines, value.as_bytes(), 7, 0);
            } else if let Some((abs, false)) = self.table.find(name, value, base) {
                prefix_int::encode(&mut field_lines, base - 1 - abs, 4, 0x40);
                strings::write(&mut field_lines, value.as_bytes(), 7, 0);
            } else {
                strings::write(&mut field_lines, name.as_bytes(), 3, 0x20);
                strings::write(&mut field_lines, value.as_bytes(), 7, 0);
            }
        }

        let mut section = Vec::new();
        let encoded_ric = insert_count::encode(base, self.table.capacity());
        prefix_int::encode(&mut section, encoded_ric, 8, 0);
        prefix_int::encode(&mut section, 0, 7, 0); // Base = RIC: sign 0, delta 0
        section.extend_from_slice(&field_lines);

        if !referenced.is_empty() {
            self.outstanding.insert(stream_id, (base, referenced));
        }
        (section, instructions)
    }

    /// RFC 9204 §4.4.1 — the decoder has fully processed `stream_id`'s
    /// field section: release its table references and advance Known
    /// Received Count if this section depended on more insertions than we
    /// already knew were received.
    pub(crate) fn on_section_acknowledgment(&mut self, stream_id: u64) {
        if let Some((ric, refs)) = self.outstanding.remove(&stream_id) {
            for abs in refs {
                self.table.release_ref(abs);
            }
            self.known_received_count = self.known_received_count.max(ric);
        }
    }

    /// RFC 9204 §4.4.2 — `stream_id` was reset/abandoned: release its
    /// table references without advancing Known Received Count.
    pub(crate) fn on_stream_cancellation(&mut self, stream_id: u64) {
        if let Some((_, refs)) = self.outstanding.remove(&stream_id) {
            for abs in refs {
                self.table.release_ref(abs);
            }
        }
    }

    /// RFC 9204 §4.4.3 — advance Known Received Count directly.
    pub(crate) fn on_insert_count_increment(&mut self, increment: u64) {
        self.known_received_count += increment;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::decoder::Decoder;

    #[test]
    fn static_only_fields_need_no_instructions() {
        let mut enc = Encoder::new(4096);
        let (section, instructions) = enc.encode(0, [(":status", "200")]);
        assert!(instructions.is_empty());
        assert_eq!(section, vec![0, 0, 0xc0 | 25]); // RIC=0, Base=0, static index 25
    }

    #[test]
    fn round_trips_through_a_real_decoder_across_multiple_sections() {
        let mut enc = Encoder::new(4096);
        let mut dec = Decoder::new(4096);

        // First section: nothing indexable yet, gets inserted for later.
        let (section1, instr1) = enc.encode(0, [("x-custom", "widget"), (":status", "200")]);
        for instr in split_instructions(&instr1) {
            let ack = dec.apply_encoder_instruction(instr).unwrap();
            for a in split_decoder_acks(&ack) {
                match a {
                    super::super::decoder_stream::DecoderInstruction::InsertCountIncrement { increment } => {
                        enc.on_insert_count_increment(increment);
                    }
                    _ => unreachable!(),
                }
            }
        }
        let (fields1, ack1) = dec.decode(0, &section1).unwrap();
        assert_eq!(fields1, vec![("x-custom".into(), "widget".into()), (":status".into(), "200".into())]);
        if !ack1.is_empty() {
            enc.on_section_acknowledgment(0);
        }

        // Second section: now the dynamic entry from the first section is
        // known-received, so it should be referenced by index, not spelled
        // out again.
        let (section2, instr2) = enc.encode(1, [("x-custom", "widget")]);
        assert!(instr2.is_empty(), "expected a dynamic-table hit, no new insert");
        let (fields2, _ack2) = dec.decode(1, &section2).unwrap();
        assert_eq!(fields2, vec![("x-custom".into(), "widget".into())]);
    }

    fn split_instructions(mut input: &[u8]) -> Vec<super::super::encoder_stream::EncoderInstruction> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let Some((instr, used)) = super::super::encoder_stream::parse_next(input).unwrap() else {
                break;
            };
            out.push(instr);
            input = &input[used..];
        }
        out
    }

    fn split_decoder_acks(mut input: &[u8]) -> Vec<super::super::decoder_stream::DecoderInstruction> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let Some((instr, used)) = super::super::decoder_stream::parse_next(input) else {
                break;
            };
            out.push(instr);
            input = &input[used..];
        }
        out
    }
}
