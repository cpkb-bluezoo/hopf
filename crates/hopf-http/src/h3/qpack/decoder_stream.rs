// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QPACK decoder-stream instructions (RFC 9204 §4.4): written by our
//! decoder to acknowledge field sections and dynamic-table growth back to
//! the peer encoder; parsed by our encoder from the peer decoder's stream.

use super::prefix_int;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecoderInstruction {
    /// §4.4.1 — the request/push stream identified has been fully processed.
    SectionAcknowledgment { stream_id: u64 },
    /// §4.4.2 — the request/push stream identified was reset or abandoned
    /// without processing its (possibly still-encoded) field section.
    StreamCancellation { stream_id: u64 },
    /// §4.4.3 — the decoder's Known Received Count has advanced by this
    /// many entries beyond what Section Acknowledgments alone conveyed.
    InsertCountIncrement { increment: u64 },
}

pub(crate) fn write_section_acknowledgment(out: &mut Vec<u8>, stream_id: u64) {
    prefix_int::encode(out, stream_id, 7, 0x80);
}

pub(crate) fn write_stream_cancellation(out: &mut Vec<u8>, stream_id: u64) {
    prefix_int::encode(out, stream_id, 6, 0x40);
}

pub(crate) fn write_insert_count_increment(out: &mut Vec<u8>, increment: u64) {
    prefix_int::encode(out, increment, 6, 0x00);
}

/// Parse the next complete instruction from the start of `input`. Returns
/// `Ok(None)` if `input` doesn't yet hold a full instruction (wait for
/// more bytes from the stream). `Err(())` means a malformed instruction.
pub(crate) fn parse_next(input: &[u8]) -> Result<Option<(DecoderInstruction, usize)>, ()> {
    let Some(&first) = input.first() else {
        return Ok(None);
    };
    if first & 0x80 != 0 {
        match prefix_int::decode_status(input, 7) {
            prefix_int::DecodeStatus::NeedMore => Ok(None),
            prefix_int::DecodeStatus::Invalid => Err(()),
            prefix_int::DecodeStatus::Complete { value: stream_id, used } => Ok(Some((
                DecoderInstruction::SectionAcknowledgment { stream_id },
                used,
            ))),
        }
    } else if first & 0x40 != 0 {
        match prefix_int::decode_status(input, 6) {
            prefix_int::DecodeStatus::NeedMore => Ok(None),
            prefix_int::DecodeStatus::Invalid => Err(()),
            prefix_int::DecodeStatus::Complete { value: stream_id, used } => Ok(Some((
                DecoderInstruction::StreamCancellation { stream_id },
                used,
            ))),
        }
    } else {
        match prefix_int::decode_status(input, 6) {
            prefix_int::DecodeStatus::NeedMore => Ok(None),
            prefix_int::DecodeStatus::Invalid => Err(()),
            prefix_int::DecodeStatus::Complete { value: increment, used } => Ok(Some((
                DecoderInstruction::InsertCountIncrement { increment },
                used,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_acknowledgment_round_trips() {
        let mut out = Vec::new();
        write_section_acknowledgment(&mut out, 4);
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((DecoderInstruction::SectionAcknowledgment { stream_id: 4 }, out.len()))
        );
    }

    #[test]
    fn stream_cancellation_round_trips() {
        let mut out = Vec::new();
        write_stream_cancellation(&mut out, 8);
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((DecoderInstruction::StreamCancellation { stream_id: 8 }, out.len()))
        );
    }

    #[test]
    fn insert_count_increment_round_trips() {
        let mut out = Vec::new();
        write_insert_count_increment(&mut out, 3);
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((DecoderInstruction::InsertCountIncrement { increment: 3 }, out.len()))
        );
    }

    #[test]
    fn large_values_round_trip() {
        let mut out = Vec::new();
        write_section_acknowledgment(&mut out, 100_000);
        assert_eq!(
            parse_next(&out).unwrap(),
            Some((DecoderInstruction::SectionAcknowledgment { stream_id: 100_000 }, out.len()))
        );
    }

    #[test]
    fn truncated_instruction_yields_none() {
        let mut out = Vec::new();
        write_section_acknowledgment(&mut out, 100_000);
        for cut in 1..out.len() {
            assert_eq!(
                parse_next(&out[..cut]).unwrap(),
                None,
                "cut at {cut} should be incomplete"
            );
        }
    }

    #[test]
    fn concatenated_instructions_parse_one_at_a_time() {
        let mut out = Vec::new();
        write_insert_count_increment(&mut out, 5);
        write_stream_cancellation(&mut out, 2);
        let (first, used1) = parse_next(&out).unwrap().unwrap();
        assert_eq!(first, DecoderInstruction::InsertCountIncrement { increment: 5 });
        let (second, used2) = parse_next(&out[used1..]).unwrap().unwrap();
        assert_eq!(second, DecoderInstruction::StreamCancellation { stream_id: 2 });
        assert_eq!(used1 + used2, out.len());
    }

    #[test]
    fn overlong_prefix_integer_is_malformed() {
        let mut out = vec![0x80 | 0x7f];
        out.extend(std::iter::repeat_n(0xff, 12));
        assert!(parse_next(&out).is_err());
    }
}
