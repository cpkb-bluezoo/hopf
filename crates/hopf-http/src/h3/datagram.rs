// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 Datagrams (RFC 9297 §2.1) over QUIC DATAGRAM (RFC 9221).

use super::varint;

/// `SETTINGS_H3_DATAGRAM` (RFC 9297 §2.1.1) — willingness to receive
/// HTTP/3 Datagrams. Value must be 0 or 1.
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// `H3_DATAGRAM_ERROR` (RFC 9297) — stream or connection error for HTTP
/// Datagram protocol violations. Distinct from the 0x0100-range codes in
/// RFC 9114 §8.1.
pub const H3_DATAGRAM_ERROR: u32 = 0x33;

/// Largest legal quarter-stream-ID (RFC 9297 §2.1): `(2^62 - 1) / 4`.
const MAX_QUARTER_STREAM_ID: u64 = (1u64 << 60) - 1;

/// Encode an HTTP/3 Datagram: quarter-stream-ID varint + payload.
pub fn encode(stream_id: u64, payload: &[u8]) -> Option<Vec<u8>> {
    if stream_id % 4 != 0 {
        return None;
    }
    let quarter = stream_id / 4;
    if quarter > MAX_QUARTER_STREAM_ID {
        return None;
    }
    let mut out = Vec::with_capacity(8 + payload.len());
    varint::encode(&mut out, quarter);
    out.extend_from_slice(payload);
    Some(out)
}

/// Decode an HTTP/3 Datagram into `(stream_id, payload)`.
pub fn decode(data: &[u8]) -> Result<(u64, &[u8]), ()> {
    let (quarter, n) = varint::decode(data).ok_or(())?;
    if quarter > MAX_QUARTER_STREAM_ID {
        return Err(());
    }
    // Client-initiated bidirectional stream IDs are 0 mod 4.
    let stream_id = quarter.checked_mul(4).ok_or(())?;
    Ok((stream_id, &data[n..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_payload() {
        let encoded = encode(0, b"").unwrap();
        let (sid, payload) = decode(&encoded).unwrap();
        assert_eq!(sid, 0);
        assert!(payload.is_empty());
    }

    #[test]
    fn round_trip_with_payload() {
        let encoded = encode(8, b"hello").unwrap();
        let (sid, payload) = decode(&encoded).unwrap();
        assert_eq!(sid, 8);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn rejects_non_client_bi_stream_id() {
        assert!(encode(1, b"x").is_none());
    }

    #[test]
    fn decode_truncated_is_err() {
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn settings_and_error_code_match_rfc() {
        assert_eq!(SETTINGS_H3_DATAGRAM, 0x33);
        assert_eq!(H3_DATAGRAM_ERROR, 0x33);
    }
}

/// Encode and send an HTTP/3 Datagram on `endpoint` for `stream_id`
/// (RFC 9297 §2.1). The peer must have advertised `SETTINGS_H3_DATAGRAM=1`.
pub fn send(
    endpoint: &mut dyn hopf_core::Endpoint,
    stream_id: u64,
    payload: &[u8],
) -> std::io::Result<()> {
    let Some(encoded) = encode(stream_id, payload) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "stream_id must be a client-initiated bidirectional QUIC stream id",
        ));
    };
    endpoint.send_datagram(&encoded)
}
