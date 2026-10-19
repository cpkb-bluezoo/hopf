// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC frame encode helpers.

use crate::transport::frame::parser::ty;
use crate::transport::types::{ConnectionId, StreamId};
use crate::transport::varint;

/// Encode CRYPTO frame.
pub fn crypto(out: &mut Vec<u8>, offset: u64, data: &[u8]) {
    varint::encode(ty::CRYPTO, out);
    varint::encode(offset, out);
    varint::encode(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Encode STREAM frame (always with OFF + LEN bits set).
pub fn stream(out: &mut Vec<u8>, id: StreamId, offset: u64, data: &[u8], fin: bool) {
    let mut t = ty::STREAM_MIN | 0x04 | 0x02; // OFF + LEN
    if fin {
        t |= 0x01;
    }
    varint::encode(t, out);
    varint::encode(id.as_u64(), out);
    varint::encode(offset, out);
    varint::encode(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Encode a single-range ACK for `pn`.
pub fn ack_single(out: &mut Vec<u8>, pn: u64) {
    ack(out, 0, &[(pn, pn)]);
}

/// Encode an ACK (RFC 9000 section 19.3) over `ranges`, each `(low, high)`
/// inclusive, in descending order with the largest first, and the given
/// already-scaled ACK Delay. `ranges` must not be empty.
pub fn ack(out: &mut Vec<u8>, delay: u64, ranges: &[(u64, u64)]) {
    let (first_low, largest) = ranges[0];
    varint::encode(ty::ACK, out);
    varint::encode(largest, out);
    varint::encode(delay, out);
    varint::encode(ranges.len() as u64 - 1, out);
    varint::encode(largest - first_low, out);
    let mut prev_low = first_low;
    for &(low, high) in &ranges[1..] {
        // Gap: packets between this range and the previous one, minus 2.
        varint::encode(prev_low - high - 2, out);
        varint::encode(high - low, out);
        prev_low = low;
    }
}

/// Encode HANDSHAKE_DONE.
pub fn handshake_done(out: &mut Vec<u8>) {
    varint::encode(ty::HANDSHAKE_DONE, out);
}

/// Encode PING.
pub fn ping(out: &mut Vec<u8>) {
    varint::encode(ty::PING, out);
}

/// Encode CONNECTION_CLOSE (transport, type 0x1c).
pub fn connection_close(out: &mut Vec<u8>, error_code: u64, reason: &[u8]) {
    varint::encode(ty::CONNECTION_CLOSE, out);
    varint::encode(error_code, out);
    varint::encode(0, out); // frame type
    varint::encode(reason.len() as u64, out);
    out.extend_from_slice(reason);
}

/// Encode CONNECTION_CLOSE (application, type 0x1d) — no frame_type field.
pub fn connection_close_app(out: &mut Vec<u8>, error_code: u64, reason: &[u8]) {
    varint::encode(ty::CONNECTION_CLOSE_APP, out);
    varint::encode(error_code, out);
    varint::encode(reason.len() as u64, out);
    out.extend_from_slice(reason);
}

/// Encode MAX_STREAMS for bidirectional streams (type 0x12).
pub fn max_streams_bidi(out: &mut Vec<u8>, max: u64) {
    varint::encode(ty::MAX_STREAMS_BIDI, out);
    varint::encode(max, out);
}

/// Encode MAX_DATA (type 0x10).
pub fn max_data(out: &mut Vec<u8>, max: u64) {
    varint::encode(ty::MAX_DATA, out);
    varint::encode(max, out);
}

/// Encode MAX_STREAM_DATA (type 0x11).
pub fn max_stream_data(out: &mut Vec<u8>, id: StreamId, max: u64) {
    varint::encode(ty::MAX_STREAM_DATA, out);
    varint::encode(id.as_u64(), out);
    varint::encode(max, out);
}

/// Encode DATA_BLOCKED (type 0x14).
pub fn data_blocked(out: &mut Vec<u8>, max: u64) {
    varint::encode(ty::DATA_BLOCKED, out);
    varint::encode(max, out);
}

/// Encode STREAM_DATA_BLOCKED (type 0x15).
pub fn stream_data_blocked(out: &mut Vec<u8>, id: StreamId, max: u64) {
    varint::encode(ty::STREAM_DATA_BLOCKED, out);
    varint::encode(id.as_u64(), out);
    varint::encode(max, out);
}

/// Encode RESET_STREAM (type 0x04).
pub fn reset_stream(out: &mut Vec<u8>, id: StreamId, error_code: u64, final_size: u64) {
    varint::encode(ty::RESET_STREAM, out);
    varint::encode(id.as_u64(), out);
    varint::encode(error_code, out);
    varint::encode(final_size, out);
}

/// Encode STOP_SENDING (type 0x05).
pub fn stop_sending(out: &mut Vec<u8>, id: StreamId, error_code: u64) {
    varint::encode(ty::STOP_SENDING, out);
    varint::encode(id.as_u64(), out);
    varint::encode(error_code, out);
}

/// Encode NEW_TOKEN (type 0x07).
pub fn new_token(out: &mut Vec<u8>, token: &[u8]) {
    varint::encode(ty::NEW_TOKEN, out);
    varint::encode(token.len() as u64, out);
    out.extend_from_slice(token);
}

/// Encode MAX_STREAMS for unidirectional streams (type 0x13).
pub fn max_streams_uni(out: &mut Vec<u8>, max: u64) {
    varint::encode(ty::MAX_STREAMS_UNI, out);
    varint::encode(max, out);
}

/// Encode STREAMS_BLOCKED (type 0x16 bidirectional, 0x17 unidirectional).
pub fn streams_blocked(out: &mut Vec<u8>, bidi: bool, max: u64) {
    varint::encode(if bidi { ty::STREAMS_BLOCKED_BIDI } else { ty::STREAMS_BLOCKED_UNI }, out);
    varint::encode(max, out);
}

/// Encode NEW_CONNECTION_ID (type 0x18).
pub fn new_connection_id(
    out: &mut Vec<u8>,
    seq: u64,
    retire_prior_to: u64,
    cid: &ConnectionId,
    reset_token: &[u8; 16],
) {
    varint::encode(ty::NEW_CONNECTION_ID, out);
    varint::encode(seq, out);
    varint::encode(retire_prior_to, out);
    out.push(cid.len() as u8);
    out.extend_from_slice(cid.as_slice());
    out.extend_from_slice(reset_token);
}

/// Encode RETIRE_CONNECTION_ID (type 0x19).
pub fn retire_connection_id(out: &mut Vec<u8>, seq: u64) {
    varint::encode(ty::RETIRE_CONNECTION_ID, out);
    varint::encode(seq, out);
}

/// Encode PATH_CHALLENGE (type 0x1a).
pub fn path_challenge(out: &mut Vec<u8>, data: &[u8; 8]) {
    varint::encode(ty::PATH_CHALLENGE, out);
    out.extend_from_slice(data);
}

/// Encode PATH_RESPONSE (type 0x1b).
pub fn path_response(out: &mut Vec<u8>, data: &[u8; 8]) {
    varint::encode(ty::PATH_RESPONSE, out);
    out.extend_from_slice(data);
}

/// Encode DATAGRAM with length (type 0x31).
pub fn datagram(out: &mut Vec<u8>, data: &[u8]) {
    varint::encode(ty::DATAGRAM_LEN, out);
    varint::encode(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Pad to at least `min_len` total length with PADDING bytes.
pub fn pad_to(out: &mut Vec<u8>, min_len: usize) {
    while out.len() < min_len {
        out.push(0);
    }
}
