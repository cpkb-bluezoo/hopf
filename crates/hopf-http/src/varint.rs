// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 9000 QUIC variable-length integers.

/// Maximum value representable by a QUIC variable-length integer.
pub const MAX: u64 = (1 << 62) - 1;

/// Append `value` in QUIC variable-length form.
pub fn encode(out: &mut Vec<u8>, value: u64) {
    assert!(value <= MAX, "QUIC varint exceeds 62 bits");
    let (len, tag): (usize, u8) = if value < (1 << 6) {
        (1, 0)
    } else if value < (1 << 14) {
        (2, 0x40)
    } else if value < (1 << 30) {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    let encoded = value | (u64::from(tag) << ((len - 1) * 8));
    for shift in (0..len).rev().map(|n| n * 8) {
        out.push((encoded >> shift) as u8);
    }
}

/// Decode one complete QUIC variable-length integer.
///
/// Returns `None` when more bytes are needed.
pub fn decode(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_lengths() {
        for value in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX] {
            let mut encoded = Vec::new();
            encode(&mut encoded, value);
            assert_eq!(decode(&encoded), Some((value, encoded.len())));
        }
    }
}
