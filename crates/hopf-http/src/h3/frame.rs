// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 frame encoding (RFC 9114 §7.2).

use super::varint;

/// DATA frame type.
pub const DATA: u64 = 0x00;
/// HEADERS frame type.
pub const HEADERS: u64 = 0x01;
/// CANCEL_PUSH frame type (RFC 9114 §7.2.3) — control stream only.
pub const CANCEL_PUSH: u64 = 0x03;
/// SETTINGS frame type.
pub const SETTINGS: u64 = 0x04;
/// PUSH_PROMISE frame type (RFC 9114 §7.2.5) — request stream, server→client.
pub const PUSH_PROMISE: u64 = 0x05;
/// GOAWAY frame type.
pub const GOAWAY: u64 = 0x07;
/// MAX_PUSH_ID frame type (RFC 9114 §7.2.7) — control stream, client→server.
pub const MAX_PUSH_ID: u64 = 0x0d;
/// PRIORITY_UPDATE for a request stream (RFC 9218 §7.2).
pub const PRIORITY_UPDATE_REQUEST: u64 = 0xF0700;
/// PRIORITY_UPDATE for a push stream (RFC 9218 §7.2).
pub const PRIORITY_UPDATE_PUSH: u64 = 0xF0701;

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §5) — decoder's advertised
/// dynamic-table capacity ceiling for the peer encoder. Default if absent: 0.
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 §5) — how many streams the
/// decoder is willing to block. Default if absent: 0. hopf always sends 0
/// (non-blocking encoder policy).
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §7.2.4.1 / §4.2.2) — advisory
/// ceiling on a decompressed field section, in bytes under the
/// name+value+32 accounting model. Default if absent: unlimited.
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x06;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` identifier (RFC 9220).
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

/// Default / advertised `SETTINGS_MAX_FIELD_SECTION_SIZE` — matches the
/// HTTP/2 `SETTINGS_MAX_HEADER_LIST_SIZE` hopf advertises (8192).
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 8_192;

/// Decompressed field-section size under RFC 7541 §4.1 / RFC 9114 §4.2.2
/// accounting (name length + value length + 32 octets per field line).
pub fn field_section_size<'a, I>(pairs: I) -> usize
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    pairs
        .into_iter()
        .map(|(name, value)| name.len() + value.len() + 32)
        .sum()
}

/// Same as [`field_section_size`] for owned decoded pairs.
pub fn field_section_size_owned(pairs: &[(String, String)]) -> usize {
    field_section_size(pairs.iter().map(|(n, v)| (n.as_str(), v.as_str())))
}

// ---------------------------------------------------------------------------
// HTTP/3 application error codes (RFC 9114 §8.1), for QUIC-level
// CONNECTION_CLOSE / RESET_STREAM / STOP_SENDING.
// ---------------------------------------------------------------------------

/// No error — used when the connection or stream needs to be closed without
/// signalling a fault (RFC 9114 §8.1).
pub const H3_NO_ERROR: u32 = 0x0100;
/// Peer violated protocol requirements in a way that does not match a more
/// specific code, or the endpoint declines to use a more specific code.
pub const H3_GENERAL_PROTOCOL_ERROR: u32 = 0x0101;
/// An internal error occurred in the HTTP stack.
pub const H3_INTERNAL_ERROR: u32 = 0x0102;
/// The peer created a stream that this endpoint will not accept (e.g. a
/// second control or QPACK critical stream).
pub const H3_STREAM_CREATION_ERROR: u32 = 0x0103;
/// A stream required by the HTTP/3 connection was closed or reset.
pub const H3_CLOSED_CRITICAL_STREAM: u32 = 0x0104;
/// A frame arrived that isn't permitted in the current state or on the
/// stream it arrived on (e.g. HEADERS/DATA on the control stream).
pub const H3_FRAME_UNEXPECTED: u32 = 0x0105;
/// A frame violated layout or size rules for its type.
pub const H3_FRAME_ERROR: u32 = 0x0106;
/// The peer is exhibiting behaviour that might generate excessive load.
pub const H3_EXCESSIVE_LOAD: u32 = 0x0107;
/// A stream ID or push ID was used incorrectly (exceeding a limit, reducing
/// a limit, or being reused).
pub const H3_ID_ERROR: u32 = 0x0108;
/// An error was detected in the payload of a SETTINGS frame.
pub const H3_SETTINGS_ERROR: u32 = 0x0109;
/// No SETTINGS frame was received at the beginning of the control stream.
pub const H3_MISSING_SETTINGS: u32 = 0x010a;
/// A server rejected a request without performing any application processing.
pub const H3_REQUEST_REJECTED: u32 = 0x010b;
/// The request or its response (including a pushed response) is cancelled.
pub const H3_REQUEST_CANCELLED: u32 = 0x010c;
/// The client's stream terminated without containing a fully formed request.
pub const H3_REQUEST_INCOMPLETE: u32 = 0x010d;
/// A malformed request or response message.
pub const H3_MESSAGE_ERROR: u32 = 0x010e;
/// The TCP connection established for a CONNECT request was reset or
/// abnormally closed.
pub const H3_CONNECT_ERROR: u32 = 0x010f;
/// The requested operation cannot be served over HTTP/3; the peer should
/// retry over HTTP/1.1.
pub const H3_VERSION_FALLBACK: u32 = 0x0110;

// ---------------------------------------------------------------------------
// QPACK-specific application error codes (RFC 9204 §6 / §8).
// ---------------------------------------------------------------------------

/// A field section could not be decoded (unknown index, would require
/// blocking, etc.).
pub const QPACK_DECOMPRESSION_FAILED: u32 = 0x0200;
/// The peer's encoder stream sent a malformed or unresolvable instruction.
pub const QPACK_ENCODER_STREAM_ERROR: u32 = 0x0201;
/// The peer's decoder stream sent a malformed or unresolvable instruction.
pub const QPACK_DECODER_STREAM_ERROR: u32 = 0x0202;

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

/// Append a PRIORITY_UPDATE frame for a request stream (RFC 9218 §7.2).
pub fn write_priority_update_request(out: &mut Vec<u8>, stream_id: u64, field_value: &str) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, stream_id);
    payload.extend_from_slice(field_value.as_bytes());
    write_frame(out, PRIORITY_UPDATE_REQUEST, &payload);
}

/// Decode a request-stream PRIORITY_UPDATE payload.
pub fn parse_priority_update_request(payload: &[u8]) -> Option<(u64, &str)> {
    let (stream_id, n) = varint::decode(payload)?;
    let value = std::str::from_utf8(&payload[n..]).ok()?;
    Some((stream_id, value))
}

/// Append a CANCEL_PUSH frame (RFC 9114 §7.2.3).
pub fn write_cancel_push(out: &mut Vec<u8>, push_id: u64) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, push_id);
    write_frame(out, CANCEL_PUSH, &payload);
}

/// Append a PUSH_PROMISE frame (RFC 9114 §7.2.5).
pub fn write_push_promise(out: &mut Vec<u8>, push_id: u64, headers_block: &[u8]) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, push_id);
    payload.extend_from_slice(headers_block);
    write_frame(out, PUSH_PROMISE, &payload);
}

/// Append a MAX_PUSH_ID frame (RFC 9114 §7.2.7).
pub fn write_max_push_id(out: &mut Vec<u8>, max_push_id: u64) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, max_push_id);
    write_frame(out, MAX_PUSH_ID, &payload);
}

/// Parse a GOAWAY frame's payload (RFC 9114 §5.2): a single varint ID.
pub fn parse_goaway(payload: &[u8]) -> Option<u64> {
    varint::decode(payload).map(|(id, _)| id)
}

/// Append a SETTINGS frame advertising QPACK parameters (RFC 9204 §5),
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §7.2.4.1), Extended
/// CONNECT (RFC 9220), and `SETTINGS_H3_DATAGRAM=1` (RFC 9297 §2.1.1).
///
/// `qpack_max_table_capacity` is this endpoint's decoder ceiling (what the
/// peer encoder may grow to); `qpack_blocked_streams` is how many streams
/// we are willing to block — hopf always passes `0`.
/// `max_field_section_size` is the decompressed field-section byte ceiling
/// we will enforce on inbound HEADERS (see [`DEFAULT_MAX_FIELD_SECTION_SIZE`]).
pub fn write_settings(
    out: &mut Vec<u8>,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
    max_field_section_size: u64,
) {
    let mut payload = Vec::new();
    varint::encode(&mut payload, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
    varint::encode(&mut payload, qpack_max_table_capacity);
    varint::encode(&mut payload, SETTINGS_QPACK_BLOCKED_STREAMS);
    varint::encode(&mut payload, qpack_blocked_streams);
    varint::encode(&mut payload, SETTINGS_MAX_FIELD_SECTION_SIZE);
    varint::encode(&mut payload, max_field_section_size);
    varint::encode(&mut payload, SETTINGS_ENABLE_CONNECT_PROTOCOL);
    varint::encode(&mut payload, 1);
    // RFC 9297 §2.1.1 / §4: always advertise to avoid "sticking out".
    varint::encode(&mut payload, super::datagram::SETTINGS_H3_DATAGRAM);
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
        write_settings(&mut out, 4096, 0, DEFAULT_MAX_FIELD_SECTION_SIZE);
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
                (SETTINGS_MAX_FIELD_SECTION_SIZE, DEFAULT_MAX_FIELD_SECTION_SIZE),
                (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
                (super::super::datagram::SETTINGS_H3_DATAGRAM, 1),
            ]
        );
    }

    #[test]
    fn parse_settings_multiple_entries_and_truncated_trailer() {
        let mut payload = Vec::new();
        varint::encode(&mut payload, SETTINGS_MAX_FIELD_SECTION_SIZE);
        varint::encode(&mut payload, 4096);
        varint::encode(&mut payload, SETTINGS_ENABLE_CONNECT_PROTOCOL);
        varint::encode(&mut payload, 1);
        assert_eq!(
            parse_settings(&payload),
            vec![
                (SETTINGS_MAX_FIELD_SECTION_SIZE, 4096),
                (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)
            ]
        );

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
    fn priority_update_request_round_trips() {
        let mut out = Vec::new();
        write_priority_update_request(&mut out, 8, "u=0");
        let (ty, ty_len) = varint::decode(&out).unwrap();
        assert_eq!(ty, PRIORITY_UPDATE_REQUEST);
        let (len, len_len) = varint::decode(&out[ty_len..]).unwrap();
        let payload = &out[ty_len + len_len..ty_len + len_len + len as usize];
        let (sid, value) = parse_priority_update_request(payload).unwrap();
        assert_eq!(sid, 8);
        assert_eq!(value, "u=0");
    }

    #[test]
    fn parse_goaway_empty_payload_is_none() {
        assert_eq!(parse_goaway(&[]), None);
    }

    /// Every RFC 9114 §8.1 / RFC 9204 §6 application error code hopf
    /// exposes must keep its registered numeric value — later issues
    /// (SETTINGS, critical-stream close, push, …) signal with these.
    #[test]
    fn h3_and_qpack_error_codes_match_rfc_registry() {
        assert_eq!(H3_NO_ERROR, 0x0100);
        assert_eq!(H3_GENERAL_PROTOCOL_ERROR, 0x0101);
        assert_eq!(H3_INTERNAL_ERROR, 0x0102);
        assert_eq!(H3_STREAM_CREATION_ERROR, 0x0103);
        assert_eq!(H3_CLOSED_CRITICAL_STREAM, 0x0104);
        assert_eq!(H3_FRAME_UNEXPECTED, 0x0105);
        assert_eq!(H3_FRAME_ERROR, 0x0106);
        assert_eq!(H3_EXCESSIVE_LOAD, 0x0107);
        assert_eq!(H3_ID_ERROR, 0x0108);
        assert_eq!(H3_SETTINGS_ERROR, 0x0109);
        assert_eq!(H3_MISSING_SETTINGS, 0x010a);
        assert_eq!(H3_REQUEST_REJECTED, 0x010b);
        assert_eq!(H3_REQUEST_CANCELLED, 0x010c);
        assert_eq!(H3_REQUEST_INCOMPLETE, 0x010d);
        assert_eq!(H3_MESSAGE_ERROR, 0x010e);
        assert_eq!(H3_CONNECT_ERROR, 0x010f);
        assert_eq!(H3_VERSION_FALLBACK, 0x0110);
        assert_eq!(QPACK_DECOMPRESSION_FAILED, 0x0200);
        assert_eq!(QPACK_ENCODER_STREAM_ERROR, 0x0201);
        assert_eq!(QPACK_DECODER_STREAM_ERROR, 0x0202);
        assert_eq!(crate::h3::datagram::H3_DATAGRAM_ERROR, 0x33);
    }
}
