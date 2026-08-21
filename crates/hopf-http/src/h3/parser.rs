// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental, zero-copy HTTP/3 frame parser.

use std::mem;

use super::{frame, varint};

/// Sink for complete HTTP/3 frames. Payloads are valid only during the call.
pub trait H3FrameHandler {
    /// A DATA frame.
    fn data_frame(&mut self, payload: &[u8]);
    /// A HEADERS frame.
    fn headers_frame(&mut self, payload: &[u8]);
    /// A CANCEL_PUSH frame (RFC 9114 §7.2.3).
    fn cancel_push_frame(&mut self, payload: &[u8]);
    /// A SETTINGS frame.
    fn settings_frame(&mut self, payload: &[u8]);
    /// A PUSH_PROMISE frame (RFC 9114 §7.2.5).
    fn push_promise_frame(&mut self, payload: &[u8]);
    /// A GOAWAY frame.
    fn goaway_frame(&mut self, payload: &[u8]);
    /// A MAX_PUSH_ID frame (RFC 9114 §7.2.7).
    fn max_push_id_frame(&mut self, payload: &[u8]);
    /// A PRIORITY_UPDATE frame for a request stream (RFC 9218 §7.2).
    fn priority_update_request_frame(&mut self, _payload: &[u8]) {}
    /// A PRIORITY_UPDATE frame for a push stream (RFC 9218 §7.2).
    fn priority_update_push_frame(&mut self, _payload: &[u8]) {}
    /// An unknown or reserved (GREASE) frame type — ignored after SETTINGS
    /// on the control stream (RFC 9114 §9), but must not count as the
    /// required first SETTINGS frame (§6.2.1 / §7.2.4).
    fn unknown_frame(&mut self, _frame_type: u64) {}
    /// A malformed frame was received.
    fn frame_error(&mut self, message: &str);
}

/// Push-incremental HTTP/3 frame parser.
pub struct H3Parser {
    buf: Vec<u8>,
    max_frame_size: usize,
}

impl Default for H3Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl H3Parser {
    /// Create with a 16 MiB payload limit.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            max_frame_size: 16 * 1024 * 1024,
        }
    }

    /// Append bytes and dispatch every complete frame.
    pub fn push(&mut self, data: &[u8], handler: &mut dyn H3FrameHandler) {
        self.buf.extend_from_slice(data);
        self.drain(handler);
    }

    /// Drain complete frames into `handler`.
    pub fn drain(&mut self, handler: &mut dyn H3FrameHandler) {
        let mut buf = mem::take(&mut self.buf);
        let mut offset = 0;
        while offset < buf.len() {
            let Some((ty, ty_len)) = varint::decode(&buf[offset..]) else {
                break;
            };
            let Some((len, len_len)) = varint::decode(&buf[offset + ty_len..]) else {
                break;
            };
            let Ok(payload_len) = usize::try_from(len) else {
                handler.frame_error("frame length overflows usize");
                offset = buf.len();
                break;
            };
            if payload_len > self.max_frame_size {
                handler.frame_error("frame exceeds maximum size");
                offset = buf.len();
                break;
            }
            let payload_start = offset + ty_len + len_len;
            let Some(end) = payload_start.checked_add(payload_len) else {
                handler.frame_error("frame length overflow");
                offset = buf.len();
                break;
            };
            if end > buf.len() {
                break;
            }
            let payload = &buf[payload_start..end];
            match ty {
                frame::DATA => handler.data_frame(payload),
                frame::HEADERS => handler.headers_frame(payload),
                frame::CANCEL_PUSH => handler.cancel_push_frame(payload),
                frame::SETTINGS => handler.settings_frame(payload),
                frame::PUSH_PROMISE => handler.push_promise_frame(payload),
                frame::GOAWAY => handler.goaway_frame(payload),
                frame::MAX_PUSH_ID => handler.max_push_id_frame(payload),
                frame::PRIORITY_UPDATE_REQUEST => {
                    handler.priority_update_request_frame(payload)
                }
                frame::PRIORITY_UPDATE_PUSH => handler.priority_update_push_frame(payload),
                // Unknown / reserved (GREASE) — notify so the control stream
                // can enforce SETTINGS-first; otherwise ignore per §9.
                other => handler.unknown_frame(other),
            }
            offset = end;
        }
        if offset > 0 {
            buf.drain(..offset);
        }
        self.buf = buf;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect(Vec<u8>);
    impl H3FrameHandler for Collect {
        fn data_frame(&mut self, payload: &[u8]) {
            self.0.extend_from_slice(payload);
        }
        fn headers_frame(&mut self, _: &[u8]) {}
        fn cancel_push_frame(&mut self, _: &[u8]) {}
        fn settings_frame(&mut self, _: &[u8]) {}
        fn push_promise_frame(&mut self, _: &[u8]) {}
        fn goaway_frame(&mut self, _: &[u8]) {}
        fn max_push_id_frame(&mut self, _: &[u8]) {}
        fn frame_error(&mut self, _: &str) {}
    }

    #[test]
    fn parses_frame_split_at_every_boundary() {
        let mut bytes = Vec::new();
        frame::write_data(&mut bytes, b"hello");
        for split in 0..bytes.len() {
            let mut parser = H3Parser::new();
            let mut collect = Collect::default();
            parser.push(&bytes[..split], &mut collect);
            assert!(collect.0.is_empty());
            parser.push(&bytes[split..], &mut collect);
            assert_eq!(collect.0, b"hello");
        }
    }
}
