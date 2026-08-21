// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/2 frame types, flags, error codes and wire-format helpers (RFC 9113).

// ---------------------------------------------------------------------------
// Frame type constants
// ---------------------------------------------------------------------------

/// DATA frame type.
pub const TYPE_DATA: u8 = 0x00;
/// HEADERS frame type.
pub const TYPE_HEADERS: u8 = 0x01;
/// PRIORITY frame type (deprecated in RFC 9113).
pub const TYPE_PRIORITY: u8 = 0x02;
/// RST_STREAM frame type.
pub const TYPE_RST_STREAM: u8 = 0x03;
/// SETTINGS frame type.
pub const TYPE_SETTINGS: u8 = 0x04;
/// PUSH_PROMISE frame type.
pub const TYPE_PUSH_PROMISE: u8 = 0x05;
/// PING frame type.
pub const TYPE_PING: u8 = 0x06;
/// GOAWAY frame type.
pub const TYPE_GOAWAY: u8 = 0x07;
/// WINDOW_UPDATE frame type.
pub const TYPE_WINDOW_UPDATE: u8 = 0x08;
/// CONTINUATION frame type.
pub const TYPE_CONTINUATION: u8 = 0x09;
/// PRIORITY_UPDATE frame type (RFC 9218 §7.1).
pub const TYPE_PRIORITY_UPDATE: u8 = 0x10;

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// END_STREAM flag (DATA and HEADERS frames).
pub const FLAG_END_STREAM: u8 = 0x01;
/// END_HEADERS flag (HEADERS, PUSH_PROMISE, CONTINUATION).
pub const FLAG_END_HEADERS: u8 = 0x04;
/// PADDED flag (DATA and HEADERS).
pub const FLAG_PADDED: u8 = 0x08;
/// PRIORITY flag (HEADERS only).
pub const FLAG_PRIORITY: u8 = 0x20;
/// ACK flag (SETTINGS and PING).
pub const FLAG_ACK: u8 = 0x01;

// ---------------------------------------------------------------------------
// SETTINGS parameter identifiers
// ---------------------------------------------------------------------------

/// SETTINGS_HEADER_TABLE_SIZE (default 4096).
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x01;
/// SETTINGS_ENABLE_PUSH (default 1; servers set to 0).
pub const SETTINGS_ENABLE_PUSH: u16 = 0x02;
/// SETTINGS_MAX_CONCURRENT_STREAMS (no default; servers should send 100).
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x03;
/// SETTINGS_INITIAL_WINDOW_SIZE (default 65535).
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x04;
/// SETTINGS_MAX_FRAME_SIZE (default 16384).
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x05;
/// SETTINGS_MAX_HEADER_LIST_SIZE (advisory; 8192 recommended).
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x06;
/// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441) — Extended CONNECT / WebSocket.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x08;
/// SETTINGS_NO_RFC7540_PRIORITIES (RFC 9218 §2.1) — ignore HTTP/2 PRIORITY.
pub const SETTINGS_NO_RFC7540_PRIORITIES: u16 = 0x09;

// ---------------------------------------------------------------------------
// Error code constants
// ---------------------------------------------------------------------------

/// No error (graceful shutdown).
pub const ERROR_NO_ERROR: u32 = 0x00;
/// Generic protocol error.
pub const ERROR_PROTOCOL_ERROR: u32 = 0x01;
/// Internal implementation error.
pub const ERROR_INTERNAL_ERROR: u32 = 0x02;
/// Flow-control limit exceeded.
pub const ERROR_FLOW_CONTROL_ERROR: u32 = 0x03;
/// SETTINGS not acknowledged in time.
pub const ERROR_SETTINGS_TIMEOUT: u32 = 0x04;
/// Frame received on half-closed stream.
pub const ERROR_STREAM_CLOSED: u32 = 0x05;
/// Frame too large.
pub const ERROR_FRAME_SIZE_ERROR: u32 = 0x06;
/// Refused stream (server did not process request).
pub const ERROR_REFUSED_STREAM: u32 = 0x07;
/// Stream cancelled by endpoint.
pub const ERROR_CANCEL: u32 = 0x08;
/// HPACK compression error.
pub const ERROR_COMPRESSION_ERROR: u32 = 0x09;
/// TCP connect error (for CONNECT).
pub const ERROR_CONNECT_ERROR: u32 = 0x0a;
/// Processing capacity exceeded.
pub const ERROR_ENHANCE_YOUR_CALM: u32 = 0x0b;
/// Required extension not negotiated.
pub const ERROR_INADEQUATE_SECURITY: u32 = 0x0c;
/// HTTP/1.1 required instead of HTTP/2.
pub const ERROR_HTTP_1_1_REQUIRED: u32 = 0x0d;

// ---------------------------------------------------------------------------
// Frame header
// ---------------------------------------------------------------------------

/// Parsed 9-byte HTTP/2 frame header.
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    /// Payload length in bytes (24-bit unsigned).
    pub length: u32,
    /// Frame type byte.
    pub ty: u8,
    /// Flags byte.
    pub flags: u8,
    /// Stream identifier (reserved bit masked off).
    pub stream_id: u32,
}

/// Parse a 9-byte frame header slice. The slice must be exactly 9 bytes.
pub fn parse_frame_header(bytes: &[u8]) -> FrameHeader {
    debug_assert_eq!(bytes.len(), 9);
    let length = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
    let ty = bytes[3];
    let flags = bytes[4];
    let stream_id = u32::from_be_bytes([bytes[5] & 0x7f, bytes[6], bytes[7], bytes[8]]);
    FrameHeader { length, ty, flags, stream_id }
}

// ---------------------------------------------------------------------------
// Frame writers
// ---------------------------------------------------------------------------

/// Write the 9-byte frame header into `out`.
pub fn write_frame_header(out: &mut Vec<u8>, length: u32, ty: u8, flags: u8, stream_id: u32) {
    out.push((length >> 16) as u8);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    out.push(ty);
    out.push(flags);
    out.push((stream_id >> 24) as u8);
    out.push((stream_id >> 16) as u8);
    out.push((stream_id >> 8) as u8);
    out.push(stream_id as u8);
}

/// Write a SETTINGS frame (stream 0).
///
/// `params` is a slice of `(identifier, value)` pairs. Pass an empty slice for SETTINGS ACK.
pub fn write_settings(out: &mut Vec<u8>, params: &[(u16, u32)], ack: bool) {
    let flags = if ack { FLAG_ACK } else { 0 };
    let len = (params.len() * 6) as u32;
    write_frame_header(out, len, TYPE_SETTINGS, flags, 0);
    for &(id, val) in params {
        out.push((id >> 8) as u8);
        out.push(id as u8);
        out.push((val >> 24) as u8);
        out.push((val >> 16) as u8);
        out.push((val >> 8) as u8);
        out.push(val as u8);
    }
}

/// Write a SETTINGS ACK frame.
pub fn write_settings_ack(out: &mut Vec<u8>) {
    write_settings(out, &[], true);
}

/// Write a PING frame (stream 0). `ack` should be `true` for echo replies.
pub fn write_ping(out: &mut Vec<u8>, payload: &[u8; 8], ack: bool) {
    let flags = if ack { FLAG_ACK } else { 0 };
    write_frame_header(out, 8, TYPE_PING, flags, 0);
    out.extend_from_slice(payload);
}

/// Write a GOAWAY frame (stream 0).
pub fn write_goaway(out: &mut Vec<u8>, last_stream_id: u32, error_code: u32) {
    write_frame_header(out, 8, TYPE_GOAWAY, 0, 0);
    out.push((last_stream_id >> 24) as u8);
    out.push((last_stream_id >> 16) as u8);
    out.push((last_stream_id >> 8) as u8);
    out.push(last_stream_id as u8);
    out.push((error_code >> 24) as u8);
    out.push((error_code >> 16) as u8);
    out.push((error_code >> 8) as u8);
    out.push(error_code as u8);
}

/// Write a WINDOW_UPDATE frame.
pub fn write_window_update(out: &mut Vec<u8>, stream_id: u32, increment: u32) {
    write_frame_header(out, 4, TYPE_WINDOW_UPDATE, 0, stream_id);
    out.push(((increment & 0x7fff_ffff) >> 24) as u8);
    out.push((increment >> 16) as u8);
    out.push((increment >> 8) as u8);
    out.push(increment as u8);
}

/// Write a HEADERS frame (END_HEADERS always set; no padding or priority).
///
/// `block` is a pre-encoded HPACK header block. Additional flags (END_STREAM)
/// can be passed in `extra_flags`.
pub fn write_headers(out: &mut Vec<u8>, block: &[u8], extra_flags: u8, stream_id: u32) {
    let flags = FLAG_END_HEADERS | extra_flags;
    write_frame_header(out, block.len() as u32, TYPE_HEADERS, flags, stream_id);
    out.extend_from_slice(block);
}

/// Write a DATA frame.
///
/// `extra_flags` may include `FLAG_END_STREAM`.
pub fn write_data(out: &mut Vec<u8>, data: &[u8], extra_flags: u8, stream_id: u32) {
    write_frame_header(out, data.len() as u32, TYPE_DATA, extra_flags, stream_id);
    out.extend_from_slice(data);
}

/// Write a RST_STREAM frame.
pub fn write_rst_stream(out: &mut Vec<u8>, stream_id: u32, error_code: u32) {
    write_frame_header(out, 4, TYPE_RST_STREAM, 0, stream_id);
    out.push((error_code >> 24) as u8);
    out.push((error_code >> 16) as u8);
    out.push((error_code >> 8) as u8);
    out.push(error_code as u8);
}

/// Write a PRIORITY_UPDATE frame on the control stream (RFC 9218 §7.1).
pub fn write_priority_update(
    out: &mut Vec<u8>,
    prioritized_stream_id: u32,
    priority_field_value: &str,
) {
    let value = priority_field_value.as_bytes();
    let len = 4 + value.len() as u32;
    write_frame_header(out, len, TYPE_PRIORITY_UPDATE, 0, 0);
    out.extend_from_slice(&(prioritized_stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(value);
}

/// Parse a PRIORITY_UPDATE payload into `(prioritized_stream_id, field_value)`.
pub fn parse_priority_update(payload: &[u8]) -> Option<(u32, &str)> {
    if payload.len() < 4 {
        return None;
    }
    let sid = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
    let value = std::str::from_utf8(&payload[4..]).ok()?;
    Some((sid, value))
}

// ---------------------------------------------------------------------------
// Payload helpers
// ---------------------------------------------------------------------------

/// Strip padding and priority fields from a HEADERS payload, returning the
/// raw HPACK header block fragment.
///
/// `flags` is the frame's flags byte.
pub fn strip_headers_payload<'a>(payload: &'a [u8], flags: u8) -> &'a [u8] {
    let mut pos = 0;
    let padded = flags & FLAG_PADDED != 0;
    let priority = flags & FLAG_PRIORITY != 0;

    let pad_length = if padded {
        if payload.is_empty() {
            return &[];
        }
        let p = payload[0] as usize;
        pos += 1;
        p
    } else {
        0
    };

    if priority {
        pos += 5; // Exclusive(1) + stream dependency(31) + weight(8) = 5 bytes
    }

    let total_len = payload.len();
    if pos + pad_length > total_len {
        return &[];
    }
    &payload[pos..total_len - pad_length]
}

/// Strip the pad-length byte from a DATA payload if PADDED is set.
pub fn strip_data_payload<'a>(payload: &'a [u8], flags: u8) -> &'a [u8] {
    if flags & FLAG_PADDED == 0 {
        return payload;
    }
    if payload.is_empty() {
        return &[];
    }
    let pad = payload[0] as usize;
    let end = payload.len().saturating_sub(pad);
    if end <= 1 {
        &[]
    } else {
        &payload[1..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_frame_roundtrip() {
        let mut buf = Vec::new();
        write_settings(
            &mut buf,
            &[
                (SETTINGS_MAX_CONCURRENT_STREAMS, 100),
                (SETTINGS_INITIAL_WINDOW_SIZE, 65535),
            ],
            false,
        );
        // 9-byte header + 2*6 = 21 bytes
        assert_eq!(buf.len(), 21);
        let hdr = parse_frame_header(&buf[..9]);
        assert_eq!(hdr.ty, TYPE_SETTINGS);
        assert_eq!(hdr.length, 12);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.stream_id, 0);
    }

    #[test]
    fn ping_ack() {
        let mut buf = Vec::new();
        write_ping(&mut buf, b"deadbeef", true);
        assert_eq!(buf.len(), 17);
        let hdr = parse_frame_header(&buf[..9]);
        assert_eq!(hdr.ty, TYPE_PING);
        assert_eq!(hdr.flags, FLAG_ACK);
        assert_eq!(&buf[9..], b"deadbeef");
    }

    #[test]
    fn priority_update_round_trips() {
        let mut out = Vec::new();
        write_priority_update(&mut out, 7, "u=1, i");
        let hdr = parse_frame_header(&out[..9]);
        assert_eq!(hdr.ty, TYPE_PRIORITY_UPDATE);
        assert_eq!(hdr.stream_id, 0);
        let (sid, value) = parse_priority_update(&out[9..]).unwrap();
        assert_eq!(sid, 7);
        assert_eq!(value, "u=1, i");
    }
}
