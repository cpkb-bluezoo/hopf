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
/// initial_max_stream_data_bidi_local
pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
/// initial_max_stream_data_bidi_remote
pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
/// initial_max_stream_data_uni
pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
/// initial_max_streams_bidi
pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
/// initial_max_streams_uni
pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
/// active_connection_id_limit
pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;

/// Server transport limits remembered for 0-RTT (RFC 9000 §7.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RememberedTransportLimits {
    /// active_connection_id_limit
    pub active_connection_id_limit: u64,
    /// initial_max_data
    pub initial_max_data: u64,
    /// initial_max_stream_data_bidi_local
    pub initial_max_stream_data_bidi_local: u64,
    /// initial_max_stream_data_bidi_remote
    pub initial_max_stream_data_bidi_remote: u64,
    /// initial_max_stream_data_uni
    pub initial_max_stream_data_uni: u64,
    /// initial_max_streams_bidi
    pub initial_max_streams_bidi: u64,
    /// initial_max_streams_uni
    pub initial_max_streams_uni: u64,
}

impl RememberedTransportLimits {
    /// RFC 9000 defaults when a parameter is omitted from the blob.
    pub fn default_missing() -> Self {
        Self {
            active_connection_id_limit: 2,
            initial_max_data: 10 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 1 * 1024 * 1024,
            initial_max_stream_data_bidi_remote: 1 * 1024 * 1024,
            initial_max_stream_data_uni: 1 * 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
        }
    }

    /// Decode the rememberable limits from a TLS transport-parameters extension blob.
    pub fn decode_from_tp_blob(encoded: &[u8]) -> Option<Self> {
        let mut limits = Self::default_missing();
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
            let (n, consumed) = read_varint(value)?;
            if consumed != value.len() {
                return None;
            }
            match param_id {
                INITIAL_MAX_DATA => limits.initial_max_data = n,
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    limits.initial_max_stream_data_bidi_local = n;
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    limits.initial_max_stream_data_bidi_remote = n;
                }
                INITIAL_MAX_STREAM_DATA_UNI => limits.initial_max_stream_data_uni = n,
                INITIAL_MAX_STREAMS_BIDI => limits.initial_max_streams_bidi = n,
                INITIAL_MAX_STREAMS_UNI => limits.initial_max_streams_uni = n,
                ACTIVE_CONNECTION_ID_LIMIT => limits.active_connection_id_limit = n,
                _ => {}
            }
        }
        Some(limits)
    }

    /// Fixed 56-byte encoding for sealed tickets (7 × u64 BE).
    pub fn encode_fixed(&self) -> [u8; 56] {
        let mut out = [0u8; 56];
        out[0..8].copy_from_slice(&self.active_connection_id_limit.to_be_bytes());
        out[8..16].copy_from_slice(&self.initial_max_data.to_be_bytes());
        out[16..24].copy_from_slice(&self.initial_max_stream_data_bidi_local.to_be_bytes());
        out[24..32].copy_from_slice(&self.initial_max_stream_data_bidi_remote.to_be_bytes());
        out[32..40].copy_from_slice(&self.initial_max_stream_data_uni.to_be_bytes());
        out[40..48].copy_from_slice(&self.initial_max_streams_bidi.to_be_bytes());
        out[48..56].copy_from_slice(&self.initial_max_streams_uni.to_be_bytes());
        out
    }

    /// Decode [`Self::encode_fixed`].
    pub fn decode_fixed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 56 {
            return None;
        }
        Some(Self {
            active_connection_id_limit: u64::from_be_bytes(bytes[0..8].try_into().ok()?),
            initial_max_data: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            initial_max_stream_data_bidi_local: u64::from_be_bytes(bytes[16..24].try_into().ok()?),
            initial_max_stream_data_bidi_remote: u64::from_be_bytes(bytes[24..32].try_into().ok()?),
            initial_max_stream_data_uni: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            initial_max_streams_bidi: u64::from_be_bytes(bytes[40..48].try_into().ok()?),
            initial_max_streams_uni: u64::from_be_bytes(bytes[48..56].try_into().ok()?),
        })
    }

    /// RFC 9000 §7.4.1: `current` server offer must not be below `remembered`.
    pub fn current_supports_0rtt(&self, current: &Self) -> bool {
        self.active_connection_id_limit <= current.active_connection_id_limit
            && self.initial_max_data <= current.initial_max_data
            && self.initial_max_stream_data_bidi_local <= current.initial_max_stream_data_bidi_local
            && self.initial_max_stream_data_bidi_remote <= current.initial_max_stream_data_bidi_remote
            && self.initial_max_stream_data_uni <= current.initial_max_stream_data_uni
            && self.initial_max_streams_bidi <= current.initial_max_streams_bidi
            && self.initial_max_streams_uni <= current.initial_max_streams_uni
    }
}

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
    fn remembered_limits_roundtrip_and_shrink_rejects() {
        let enc = encode_initial_max_data(2_000_000);
        let remembered = RememberedTransportLimits::decode_from_tp_blob(&enc).unwrap();
        assert_eq!(remembered.initial_max_data, 2_000_000);
        let fixed = remembered.encode_fixed();
        let decoded = RememberedTransportLimits::decode_fixed(&fixed).unwrap();
        assert_eq!(decoded, remembered);
        let mut smaller = remembered;
        smaller.initial_max_data = 1_000_000;
        assert!(!remembered.current_supports_0rtt(&smaller));
        let mut larger = remembered;
        larger.initial_max_data = 3_000_000;
        assert!(remembered.current_supports_0rtt(&larger));
    }
}
