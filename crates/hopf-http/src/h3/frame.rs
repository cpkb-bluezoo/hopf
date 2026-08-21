// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 frame encoding (RFC 9114 §7.2).

use super::varint;

/// DATA frame type.
pub const DATA: u64 = 0x00;
/// HEADERS frame type.
pub const HEADERS: u64 = 0x01;
/// SETTINGS frame type.
pub const SETTINGS: u64 = 0x04;
/// GOAWAY frame type.
pub const GOAWAY: u64 = 0x07;

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §5) — decoder's advertised
/// dynamic-table capacity ceiling for the peer encoder. Default if absent: 0.
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §5) — how many streams the
/// decoder is willing to block. Default if absent: 0. hopf always sends 0
/// (non-blocking encoder policy).
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` identifier (RFC 9220).
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

// ---------------------------------------------------------------------------
// HTTP/3 application error codes (RFC 9114 §8.1), for QUIC-level
// CONNECT_CLOSE / RESET_STREAM / STOP_SENDING.
// ---------------------------------------------------------------------------

/// A stream required by the connection was closed or reset without
/// warning, or a second control/QPACK critical stream was opened.
pub const H3_STREAM_CREATION_ERROR: u32 = 0x0103;
/// A frame arrived that isn't permitted on the stream it arrived on (e.g.
/// HEADERS/DATA on the control stream).
pub const H3_FRAME_UNEXPECTED: u32 = 0x0105;
/// A frame violated layout or size rules for its type.
pub const H3_FRAME_ERROR: u32 = 0x0106;
/// A malformed request or response message.
pub const H3_MESSAGE_ERROR: u32 = 0x010e;

// ---------------------------------------------------------------------------
// QPACK-specific application error codes (RFC 9204 §3.1).
// ---------------------------------------------------------------------------

/// A field section referenced the dynamic table in a way this decoder
/// can't resolve (unknown index, or would require blocking).
pub const QPACK_DECOMPRESSION_FAILED: u32 = 0x0200;
/// The peer's encoder stream sent a malformed or unresolvable instruction.
pub const QPACK_ENCODER_STREAM_ERROR: u32 = 0x0201;

/// Append an HTTP/3 frame with `payload`.
pub fn write_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    varint::encode(out, frame_type);
    varint::encode(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Append a HEADERS frame.
pub fn write_headers(out: &mut Vec<u8>, block: &[u8]) {
    write_frame(out, HEADERS, block);
}

/// Append a DATA frame.
pub fn write_data(out: &mut Vec<u8>, data: &[u8]) {
    write_frame(out, DATA, data);
}

/// Append a GOAWAY frame carrying `id` — a client-initiated bidirectional
/// stream ID (RFC 9114 §5.2). Only ever sent on the control stream.
pub fn write_goaway(out: &mut Vec<u8>, id: u64) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, id);
    write_frame(out, GOAWAY, &payload);
}

/// Parse a GOAWAY frame's payload (RFC 9114 §5.2): a single varint ID.
pub fn parse_goaway(payload: &[u8]) -> Option<u64> {
    varint::decode(payload).map(|(id, _)| id)
}

/// Append a SETTINGS frame advertising QPACK parameters (RFC 9204 §5) and
/// Extended CONNECT (RFC 9220).
///
/// `qpack_max_table_capacity` is this endpoint's decoder ceiling (what the
/// peer encoder may grow to); `qpack_blocked_streams` is how many streams
/// we are willing to block — hopf always passes `0`.
pub fn write_settings(
    out: &mut Vec<u8>,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    varint::encode(&mut payload, qpack_max_table_capacity);
    varint::encode(&mut payload, SETTINGS_QPACK_BLOCKED_STREAMS);
    varint::encode(&mut payload, qpack_blocked_streams);
    varint::encode(&mut payload, SETTINGS_ENABLE_CONNECT_PROTOCOL);
    varint::encode(&mut payload, 1);
    write_frame(out, SETTINGS, &payload);
}

/// Decode a SETTINGS frame payload into `(identifier, value)` pairs,
/// stopping at the first malformed entry (RFC 9114 §7.2.4).
pub fn parse_settings(payload: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < payload.len() {
        let Some((id, id_len)) = varint::decode(&payload[offset..]) else {
            break;
        };
        let Some((val, val_len)) = varint::decode(&payload[offset + id_len..]) else {
            break;
        };
        out.push((id, val));
        offset += id_len + val_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_settings_round_trips_through_parse_settings() {
        let mut out = Vec::new();
        write_settings(&mut out, 4096, 0);
        // Strip the frame type+length prefix to get just the payload, as a
        // real receiver would after `H3Parser` hands it a SETTINGS frame.
        let (ty, ty_len) = varint::decode(&out).unwrap();
        assert_eq!(ty, SETTINGS);
        let (len, len_len) = varint::decode(&out[ty_len..]).unwrap();
        let payload = &out[ty_len + len_len..ty_len + len_len + len as usize];

        let parsed = parse_settings(payload);
        assert_eq!(
            parsed,
            vec![
                (SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096),
                (SETTINGS_QPACK_BLOCKED_STREAMS, 0),
                (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            ]
        );
    }

    #[test]
    fn parse_settings_multiple_entries_and_truncated_trailer() {
        let mut payload = Vec::new();
        varint::encode(&mut payload, 0x06); // SETTINGS_MAX_FIELD_SECTION_SIZE
        varint::encode(&mut payload, 4096);
        varint::encode(&mut payload, SETTINGS_ENABLE_CONNECT_PROTOCOL);
        varint::encode(&mut payload, 1);
        assert_eq!(parse_settings(&payload), vec![(0x06, 4096), (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)]);

        // A dangling identifier with no value is silently dropped, not a panic.
        let mut truncated = payload.clone();
        varint::encode(&mut truncated, 0x02);
        assert_eq!(parse_settings(&truncated), parse_settings(&payload));
    }

    #[test]
    fn write_goaway_round_trips_through_parse_goaway() {
        let mut out = Vec::new();
        write_goaway(&mut out, 12);
        let (ty, ty_len) = varint::decode(&out).unwrap();
        assert_eq!(ty, GOAWAY);
        let (len, len_len) = varint::decode(&out[ty_len..]).unwrap();
        let payload = &out[ty_len + len_len..ty_len + len_len + len as usize];
        assert_eq!(parse_goaway(payload), Some(12));
    }

    #[test]
    fn parse_goaway_empty_payload_is_none() {
        assert_eq!(parse_goaway(&[]), None);
    }
}
