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
    // SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08 (RFC 9220)
    varint::encode(&mut payload, 0x08);
    varint::encode(&mut payload, 1);
    write_frame(out, SETTINGS, &payload);
}
