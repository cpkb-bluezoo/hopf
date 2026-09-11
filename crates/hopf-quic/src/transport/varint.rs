// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC variable-length integer encoding (RFC 9000 §16).

/// Largest value representable in a QUIC varint (`2^62 - 1`).
pub const MAX_VALUE: u64 = (1 << 62) - 1;

/// Number of bytes [`encode`] would use for `value`.
pub fn encoded_length(value: u64) -> usize {
    assert!(value <= MAX_VALUE, "varint out of range");
    if value <= 0x3f {
        1
    } else if value <= 0x3fff {
        2
    } else if value <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

/// Peek total encoded length from the first byte alone.
pub fn peek_encoded_length(first: u8) -> usize {
    match (first & 0xc0) >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    }
}

/// Encode `value` with the shortest encoding into `out`.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    match encoded_length(value) {
        1 => out.push(value as u8),
        2 => {
            let v = (value | 0x4000) as u16;
            out.extend_from_slice(&v.to_be_bytes());
        }
        4 => {
            let v = (value | 0x8000_0000) as u32;
            out.extend_from_slice(&v.to_be_bytes());
        }
        _ => {
            let v = value | 0xc000_0000_0000_0000;
            out.extend_from_slice(&v.to_be_bytes());
        }
    }
}

/// Decode a varint from `buf`, advancing the slice past the encoding.
pub fn decode(buf: &mut &[u8]) -> Option<u64> {
    if buf.is_empty() {
        return None;
    }
    let len = peek_encoded_length(buf[0]);
    if buf.len() < len {
        return None;
    }
    let value = match len {
        1 => (buf[0] & 0x3f) as u64,
        2 => {
            let v = u16::from_be_bytes([buf[0], buf[1]]);
            (v & 0x3fff) as u64
        }
        4 => {
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            (v & 0x3fff_ffff) as u64
        }
        _ => {
            let v = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            v & 0x3fff_ffff_ffff_ffff
        }
    };
    *buf = &buf[len..];
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_values() {
        for v in [0u64, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, MAX_VALUE] {
            let mut buf = Vec::new();
            encode(v, &mut buf);
            assert_eq!(buf.len(), encoded_length(v));
            let mut slice = buf.as_slice();
            assert_eq!(decode(&mut slice), Some(v));
            assert!(slice.is_empty());
        }
    }
}
