// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT variable-length integer (MQTT 3.1.1 §2.2.3, MQTT 5.0 §1.5.5).
//!
//! Seven bits of value per byte plus a continuation bit; up to 4 bytes.

/// Largest value that fits in 4 encoded bytes.
pub const MAX_VALUE: u32 = 268_435_455;

/// Longest possible encoded form.
pub const MAX_BYTES: usize = 4;

/// Result of [`decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarIntResult {
    /// Decoded `value`, consuming `len` bytes from the front of the input.
    Ok {
        /// Decoded value.
        value: u32,
        /// Bytes consumed (1-4).
        len: usize,
    },
    /// Not enough bytes yet; caller should wait for more input.
    NeedMoreData,
    /// More than 4 continuation bytes (fifth byte still has the high bit set).
    Malformed,
}

/// Decode a variable-length integer from the front of `buf`.
pub fn decode(buf: &[u8]) -> VarIntResult {
    let mut value: u32 = 0;
    let mut multiplier: u32 = 1;
    for (i, &b) in buf.iter().enumerate() {
        if i == MAX_BYTES {
            return VarIntResult::Malformed;
        }
        value += (b & 0x7F) as u32 * multiplier;
        if b & 0x80 == 0 {
            return VarIntResult::Ok { value, len: i + 1 };
        }
        multiplier *= 128;
    }
    VarIntResult::NeedMoreData
}

/// Append the variable-length encoding of `value` to `out`.
///
/// # Panics
///
/// Panics if `value > `[`MAX_VALUE`].
pub fn encode(out: &mut Vec<u8>, mut value: u32) {
    assert!(value <= MAX_VALUE, "varint value out of range: {value}");
    loop {
        let mut byte = (value % 128) as u8;
        value /= 128;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Number of bytes [`encode`] would write for `value`.
pub fn encoded_len(value: u32) -> usize {
    match value {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_boundaries() {
        for &v in &[0u32, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, MAX_VALUE] {
            let mut buf = Vec::new();
            encode(&mut buf, v);
            assert_eq!(buf.len(), encoded_len(v));
            match decode(&buf) {
                VarIntResult::Ok { value, len } => {
                    assert_eq!(value, v);
                    assert_eq!(len, buf.len());
                }
                other => panic!("expected Ok for {v}, got {other:?}"),
            }
        }
    }

    #[test]
    fn needs_more_data_on_truncated_continuation() {
        // 0xFF has the continuation bit set; alone it's incomplete.
        assert_eq!(decode(&[0xFF]), VarIntResult::NeedMoreData);
        assert_eq!(decode(&[0xFF, 0xFF]), VarIntResult::NeedMoreData);
    }

    #[test]
    fn malformed_after_four_continuation_bytes() {
        assert_eq!(decode(&[0xFF, 0xFF, 0xFF, 0xFF, 0x01]), VarIntResult::Malformed);
    }

    #[test]
    fn decode_ignores_trailing_bytes() {
        // A single-byte value followed by unrelated trailing data.
        assert_eq!(decode(&[0x00, 0xAA, 0xBB]), VarIntResult::Ok { value: 0, len: 1 });
    }

    #[test]
    #[should_panic]
    fn encode_panics_over_max() {
        let mut buf = Vec::new();
        encode(&mut buf, MAX_VALUE + 1);
    }
}
