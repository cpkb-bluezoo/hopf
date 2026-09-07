// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC transport parameters (RFC 9000 §18) — opaque wire codec for TLS extension 0x0039.

use bytes::{Bytes, BytesMut};

/// QUIC varint encode (RFC 9000 §16).
pub fn write_varint(out: &mut BytesMut, mut value: u64) {
    if value <= 63 {
        out.extend_from_slice(&[value as u8]);
    } else if value <= 16_383 {
        value |= 0x4000;
        out.extend_from_slice(&value.to_be_bytes()[6..]);
    } else if value <= 1_073_741_823 {
        value |= 0x8000_0000;
        out.extend_from_slice(&value.to_be_bytes()[4..]);
    } else {
        value |= 0xC000_0000_0000_0000;
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// QUIC varint decode; returns `(value, bytes_consumed)`.
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for b in &buf[1..len] {
        value = (value << 8) | *b as u64;
    }
    Some((value, len))
}

/// RFC 9000 transport parameter id: initial_max_data.
pub const INITIAL_MAX_DATA: u64 = 0x04;

/// Encode a minimal transport-parameters block (one integer parameter) for tests and QUIC wiring.
pub fn encode_initial_max_data(max_data: u64) -> Bytes {
    let mut out = BytesMut::new();
    write_varint(&mut out, INITIAL_MAX_DATA);
    write_varint(&mut out, max_data.size_varint());
    write_varint(&mut out, max_data);
    out.freeze()
}

trait VarintSize {
    fn size_varint(self) -> u64;
}

impl VarintSize for u64 {
    fn size_varint(self) -> u64 {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, self);
        buf.len() as u64
    }
}

/// Find a transport parameter value by id in an encoded block.
pub fn find_parameter<'a>(encoded: &'a [u8], id: u64) -> Option<&'a [u8]> {
    let mut i = 0;
    while i < encoded.len() {
        let (param_id, id_len) = read_varint(&encoded[i..])?;
        i += id_len;
        let (len, len_len) = read_varint(&encoded[i..])?;
        i += len_len;
        let len = len as usize;
        if i + len > encoded.len() {
            return None;
        }
        let value = &encoded[i..i + len];
        i += len;
        if param_id == id {
            return Some(value);
        }
    }
    None
}

/// Decode `initial_max_data` from a transport-parameters block, if present.
pub fn decode_initial_max_data(encoded: &[u8]) -> Option<u64> {
    let value = find_parameter(encoded, INITIAL_MAX_DATA)?;
    let (n, consumed) = read_varint(value)?;
    if consumed == value.len() {
        Some(n)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 63, 64, 16_383, 16_384, 1_048_576] {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, v);
            let (parsed, n) = read_varint(&buf).unwrap();
            assert_eq!(parsed, v, "varint {v}");
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn initial_max_data_roundtrip() {
        let enc = encode_initial_max_data(1_048_576);
        assert_eq!(decode_initial_max_data(&enc), Some(1_048_576));
    }
}
