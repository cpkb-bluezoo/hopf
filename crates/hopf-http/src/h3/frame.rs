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

/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` identifier (RFC 9220).
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

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

/// Append a SETTINGS frame advertising Extended CONNECT (RFC 9220).
pub fn write_settings(out: &mut Vec<u8>) {
    let mut payload = Vec::new();
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
        write_settings(&mut out);
        // Strip the frame type+length prefix to get just the payload, as a
        // real receiver would after `H3Parser` hands it a SETTINGS frame.
        let (ty, ty_len) = varint::decode(&out).unwrap();
        assert_eq!(ty, SETTINGS);
        let (len, len_len) = varint::decode(&out[ty_len..]).unwrap();
        let payload = &out[ty_len + len_len..ty_len + len_len + len as usize];

        let parsed = parse_settings(payload);
        assert_eq!(parsed, vec![(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)]);
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
}
