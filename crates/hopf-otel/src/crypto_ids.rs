// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Random id generation for traces/spans.

use getrandom::getrandom;

/// Trace id length (16 bytes).
pub const TRACE_ID_LEN: usize = 16;
/// Span id length (8 bytes).
pub const SPAN_ID_LEN: usize = 8;

/// Lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn fill_nonzero(buf: &mut [u8]) {
    loop {
        getrandom(buf).expect("OS RNG");
        if buf.iter().any(|&b| b != 0) {
            return;
        }
    }
}

/// Fresh 16-byte trace id.
pub fn generate_trace_id() -> [u8; TRACE_ID_LEN] {
    let mut id = [0u8; TRACE_ID_LEN];
    fill_nonzero(&mut id);
    id
}

/// Fresh 8-byte span id.
pub fn generate_span_id() -> [u8; SPAN_ID_LEN] {
    let mut id = [0u8; SPAN_ID_LEN];
    fill_nonzero(&mut id);
    id
}
