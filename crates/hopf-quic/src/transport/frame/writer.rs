// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! QUIC frame encode helpers.

use crate::transport::frame::parser::ty;
use crate::transport::types::StreamId;
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
    varint::encode(id.0, out);
    varint::encode(offset, out);
    varint::encode(data.len() as u64, out);
    out.extend_from_slice(data);
}

/// Encode a single-range ACK for `pn`.
pub fn ack_single(out: &mut Vec<u8>, pn: u64) {
    varint::encode(ty::ACK, out);
    varint::encode(pn, out); // largest
    varint::encode(0, out); // delay
    varint::encode(0, out); // ACK Range Count
    varint::encode(0, out); // First ACK Range (just `pn`)
}

/// Encode HANDSHAKE_DONE.
pub fn handshake_done(out: &mut Vec<u8>) {
    varint::encode(ty::HANDSHAKE_DONE, out);
}

/// Encode PING.
pub fn ping(out: &mut Vec<u8>) {
    varint::encode(ty::PING, out);
}

/// Encode CONNECTION_CLOSE (transport).
pub fn connection_close(out: &mut Vec<u8>, error_code: u64, reason: &[u8]) {
    varint::encode(ty::CONNECTION_CLOSE, out);
    varint::encode(error_code, out);
    varint::encode(0, out); // frame type
    varint::encode(reason.len() as u64, out);
    out.extend_from_slice(reason);
}

/// Pad to at least `min_len` total length with PADDING bytes.
pub fn pad_to(out: &mut Vec<u8>, min_len: usize) {
    while out.len() < min_len {
        out.push(0);
    }
}
