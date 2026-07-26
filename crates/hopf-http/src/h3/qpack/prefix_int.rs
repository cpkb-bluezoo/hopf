// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QPACK's N-bit-prefix variable-length integer (RFC 9204 §4.1.1) — the same
//! encoding HPACK uses, shared here across field-line representations and
//! both instruction streams (encoder stream, decoder stream).

/// Append `value` using an `prefix_bits`-bit prefix; `first_byte_bits` are
/// the already-set high bits of the first byte (e.g. a representation-type
/// tag) ORed in below the prefix.
pub(crate) fn encode(out: &mut Vec<u8>, value: u64, prefix_bits: u8, first_byte_bits: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(first_byte_bits | value as u8);
        return;
    }
    out.push(first_byte_bits | max as u8);
    let mut remaining = value - max;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}

/// Decode a prefix integer from the start of `input`. Returns `(value,
/// bytes_consumed)`, or `None` if `input` doesn't yet hold a complete
/// encoding (the caller decides what "incomplete" means: a framing error
/// for an already-fully-buffered block, or "wait for more bytes" for a
/// streaming instruction reader).
pub(crate) fn decode(input: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    let mask = if prefix_bits >= 8 {
        u8::MAX
    } else {
        (1u8 << prefix_bits) - 1
    };
    let mut value = u64::from(*input.first()? & mask);
    if value < u64::from(mask) {
        return Some((value, 1));
    }
    let mut used = 1;
    let mut shift = 0;
    loop {
        let byte = *input.get(used)?;
        used += 1;
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, used));
        }
        shift += 7;
        if shift > 56 {
            // Absurdly long continuation — treat as malformed by refusing
            // to grow further; callers see this as "never completes".
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_small_and_large_values() {
        for &(value, prefix) in &[(5u64, 5u8), (127, 7), (1337, 5), (10_000_000, 8)] {
            let mut out = Vec::new();
            encode(&mut out, value, prefix, 0);
            assert_eq!(decode(&out, prefix), Some((value, out.len())));
        }
    }

    #[test]
    fn first_byte_bits_are_preserved_for_small_values() {
        let mut out = Vec::new();
        encode(&mut out, 5, 5, 0xc0);
        assert_eq!(out, vec![0xc5]);
    }

    #[test]
    fn incomplete_continuation_is_none() {
        let mut out = Vec::new();
        encode(&mut out, 1337, 5, 0);
        assert_eq!(decode(&out[..1], 5), None);
    }
}
