// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Stateful QPACK field-section encoder (RFC 9204 §4.5), backed by a real
//! dynamic table. Operates in strictly non-blocking mode: it never
//! references an entry the peer decoder hasn't yet acknowledged, so it
//! always emits `Base = Known Received Count`, a Required Insert Count no
//! larger than that, and never uses post-base indexing (§4.5.3/§4.5.5) - a
//! compliant peer never blocks decoding our field sections, which is why
//! hopf's own decoder can safely advertise `SETTINGS_QPACK_BLOCKED_STREAMS
//! = 0`.

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
    /// (RFC 9204 §2.1.4) - our non-blocking policy's Base value.
    known_received_count: u64,
    /// Dynamic-table insertions and duplications sent on the encoder stream
    /// (RFC 9204 §4.4.3 — peer increments must not exceed this).
    sent_insert_count: u64,
    /// Streams whose last encoded field section had a non-zero Required
    /// Insert Count and are still awaiting a Section Acknowledgment
    /// (RFC 9204 §4.4.1).
    pending_section_ack: HashMap<u64, u64>,
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
            sent_insert_count: 0,
            pending_section_ack: HashMap::new(),
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
        let base = self.known_received_count; // non-blocking policy: Base = KRC
        let mut field_lines = Vec::new();
        let mut instructions = Vec::new();
        let mut referenced = Vec::new();
        // One more than the largest absolute index referenced, 0 if none.
        let mut required_insert_count = 0;

        for (name, value) in fields {
            if let Some(index) = static_table::find(name, value) {
                prefix_int::encode(&mut field_lines, index as u64, 6, 0xc0);
                continue;
            }
            if let Some((abs, true)) = self.table.find(name, value, base) {
                self.table.add_ref(abs);
                referenced.push(abs);
                required_insert_count = required_insert_count.max(abs + 1);
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
                self.sent_insert_count += 1;
            }

            if let Some(static_index) = static_table::find_name(name) {
                prefix_int::encode(&mut field_lines, static_index as u64, 4, 0x50);
                strings::write(&mut field_lines, value.as_bytes(), 7, 0);
            } else if let Some((abs, false)) = self.table.find(name, value, base) {
                required_insert_count = required_insert_count.max(abs + 1);
                prefix_int::encode(&mut field_lines, base - 1 - abs, 4, 0x40);
                strings::write(&mut field_lines, value.as_bytes(), 7, 0);
            } else {
                strings::write(&mut field_lines, name.as_bytes(), 3, 0x20);
                strings::write(&mut field_lines, value.as_bytes(), 7, 0);
            }
        }

        // RFC 9204 §2.2.1: the Required Insert Count is the lowest value the
        // section can be decoded with, 0 if it references no dynamic entry;
        // a strict decoder treats a larger one as a decompression failure.
        // Base stays the Known Received Count the relative indices were
        // taken against, so Delta Base (sign 0) is the difference - and 0
        // when the section has no dynamic references (Base is then 0 too).
        let mut section = Vec::new();
        let encoded_ric = insert_count::encode(required_insert_count, self.table.capacity());
        prefix_int::encode(&mut section, encoded_ric, 8, 0);
        let delta_base = if required_insert_count == 0 { 0 } else { base - required_insert_count };
        prefix_int::encode(&mut section, delta_base, 7, 0);
        section.extend_from_slice(&field_lines);

        // The decoder sends a Section Acknowledgment iff the Required
        // Insert Count is above 0, and Known Received Count then rises to it.
        if required_insert_count > 0 {
            self.outstanding.insert(stream_id, (required_insert_count, referenced));
            self.pending_section_ack.insert(stream_id, required_insert_count);
        }
        (section, instructions)
    }

    /// RFC 9204 §4.4.1 — the decoder has fully processed `stream_id`'s
    /// field section: release its table references and advance Known
    /// Received Count if this section depended on more insertions than we
    /// already knew were received.
    pub(crate) fn on_section_acknowledgment(&mut self, stream_id: u64) -> Result<(), ()> {
        // Duplicate or spurious Section Acknowledgment → decoder stream error.
        self.pending_section_ack.remove(&stream_id).ok_or(())?;
        if let Some((ric, refs)) = self.outstanding.remove(&stream_id) {
            for abs in refs {
                self.table.release_ref(abs);
            }
            self.known_received_count = self.known_received_count.max(ric);
        }
        Ok(())
    }

    /// RFC 9204 §4.4.2 — `stream_id` was reset/abandoned: release its
    /// table references without advancing Known Received Count.
    pub(crate) fn on_stream_cancellation(&mut self, stream_id: u64) {
        self.pending_section_ack.remove(&stream_id);
        if let Some((_, refs)) = self.outstanding.remove(&stream_id) {
            for abs in refs {
                self.table.release_ref(abs);
            }
        }
    }

    /// RFC 9204 §4.4.3 — advance Known Received Count directly.
    pub(crate) fn on_insert_count_increment(&mut self, increment: u64) -> Result<(), ()> {
        if increment == 0 {
            return Err(());
        }
        let new_count = self
            .known_received_count
            .checked_add(increment)
            .ok_or(())?;
        if new_count > self.sent_insert_count {
            return Err(());
        }
        self.known_received_count = new_count;
        Ok(())
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
                        enc.on_insert_count_increment(increment).unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        }
        let (fields1, ack1) = dec.decode(0, &section1).unwrap();
        assert_eq!(fields1, vec![("x-custom".into(), "widget".into()), (":status".into(), "200".into())]);
        if !ack1.is_empty() {
            enc.on_section_acknowledgment(0).unwrap();
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
            let Some((instr, used)) = super::super::decoder_stream::parse_next(input).unwrap() else {
                break;
            };
            out.push(instr);
            input = &input[used..];
        }
        out
    }

    /// RFC 9204 section 2.2.1: the Required Insert Count is what the
    /// section needs, not what the peer has acknowledged. A section that
    /// uses only static or literal representations needs nothing from the
    /// dynamic table, so its RIC is 0 even once entries are known-received,
    /// and the decoder sends no Section Acknowledgment for it.
    #[test]
    fn static_only_section_has_zero_required_insert_count_after_dynamic_inserts() {
        let mut enc = Encoder::new(4096);
        let (_, instructions) = enc.encode(0, [("x-custom", "widget")]);
        assert!(!instructions.is_empty(), "expected an insert instruction");
        enc.on_insert_count_increment(1).unwrap(); // KRC = 1

        let (section, instructions) = enc.encode(4, [(":status", "200")]);
        assert!(instructions.is_empty());
        assert_eq!(section, vec![0, 0, 0xc0 | 25], "RIC=0, Base=0, static index 25");
        assert!(
            !enc.pending_section_ack.contains_key(&4),
            "a section with RIC 0 is never acknowledged"
        );
        assert!(enc.on_section_acknowledgment(4).is_err());
    }

    /// A section referencing dynamic absolute index k needs exactly k + 1
    /// insertions, even when more are already known-received; a strict
    /// decoder (lsquic) fails decompression when the RIC is larger.
    #[test]
    fn required_insert_count_is_one_past_largest_referenced_index_not_krc() {
        let mut enc = Encoder::new(4096);
        let mut dec = Decoder::new(4096);
        let (_, instructions) = enc.encode(0, [("x-a", "1"), ("x-b", "2"), ("x-c", "3")]);
        for instr in split_instructions(&instructions) {
            dec.apply_encoder_instruction(instr).unwrap();
        }
        enc.on_insert_count_increment(3).unwrap(); // KRC = 3, abs 0..=2 live

        // Full match on abs 0: RIC = 1 (wire 2), Base = KRC = 3 so
        // Delta Base = 2 with sign 0, relative index = 3 - 1 - 0 = 2.
        let (section, instructions) = enc.encode(4, [("x-a", "1")]);
        assert!(instructions.is_empty());
        assert_eq!(section, vec![2, 2, 0x80 | 2]);
        assert_eq!(enc.pending_section_ack.get(&4), Some(&1));
        assert_eq!(enc.outstanding.get(&4).map(|(ric, _)| *ric), Some(1));
        let (fields, ack) = dec.decode(4, &section).unwrap();
        assert_eq!(fields, vec![("x-a".into(), "1".into())]);
        assert!(!ack.is_empty(), "RIC > 0 is acknowledged");
        enc.on_section_acknowledgment(4).unwrap();
        assert_eq!(enc.known_received_count, 3, "an ack never lowers KRC");

        // Name-only match on abs 1 (x-b): RIC = 2 (wire 3), Delta Base = 1.
        let (section, instructions) = enc.encode(8, [("x-b", "9")]);
        for instr in split_instructions(&instructions) {
            dec.apply_encoder_instruction(instr).unwrap();
        }
        assert_eq!(&section[..3], &[3, 1, 0x40 | 1]);
        assert_eq!(enc.pending_section_ack.get(&8), Some(&2));
        let (fields, _) = dec.decode(8, &section).unwrap();
        assert_eq!(fields, vec![("x-b".into(), "9".into())]);
    }

    #[test]
    fn zero_insert_count_increment_is_rejected() {
        let mut enc = Encoder::new(4096);
        assert!(enc.on_insert_count_increment(0).is_err());
    }

    #[test]
    fn insert_count_increment_beyond_sent_inserts_is_rejected() {
        let mut enc = Encoder::new(4096);
        assert!(enc.on_insert_count_increment(1).is_err());
    }

    #[test]
    fn duplicate_section_acknowledgment_is_rejected() {
        let mut enc = Encoder::new(4096);
        enc.pending_section_ack.insert(4, 1);
        assert!(enc.on_section_acknowledgment(4).is_ok());
        assert!(enc.on_section_acknowledgment(4).is_err());
    }

    #[test]
    fn spurious_section_acknowledgment_is_rejected() {
        let mut enc = Encoder::new(4096);
        assert!(enc.on_section_acknowledgment(0).is_err());
    }
}
