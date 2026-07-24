// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push-parser for HTTP/2 frames (RFC 9113 §4) — Gumdrop `H2Parser` shape.
//!
//! Feed arbitrary byte slices; incomplete frames stay buffered. Complete frames
//! are delivered as typed callbacks with **zero-copy** payload slices into the
//! parser buffer (consume or copy before returning). No intermediate `Frame`
//! objects are allocated.

use std::mem;

use super::frame::{self, FrameHeader, FLAG_END_HEADERS};

/// Callback sink for frames emitted by [`H2Parser`].
///
/// Payload slices are views into the parser input buffer and are only valid for
/// the duration of the callback.
pub trait H2FrameHandler {
    /// DATA frame.
    fn data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]);
    /// HEADERS frame (`payload` is the raw frame payload including pad/priority).
    fn headers_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]);
    /// PRIORITY frame (deprecated; may be ignored).
    fn priority_frame(&mut self, stream_id: u32, payload: &[u8]);
    /// RST_STREAM frame.
    fn rst_stream_frame(&mut self, stream_id: u32, payload: &[u8]);
    /// SETTINGS frame.
    fn settings_frame(&mut self, flags: u8, payload: &[u8]);
    /// PUSH_PROMISE frame.
    fn push_promise_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]);
    /// PING frame.
    fn ping_frame(&mut self, flags: u8, payload: &[u8]);
    /// GOAWAY frame.
    fn goaway_frame(&mut self, payload: &[u8]);
    /// WINDOW_UPDATE frame.
    fn window_update_frame(&mut self, stream_id: u32, payload: &[u8]);
    /// CONTINUATION frame.
    fn continuation_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]);
    /// Parser detected a connection error (e.g. frame too large).
    fn frame_error(&mut self, error_code: u32, stream_id: u32, message: &str);
}

/// Incremental HTTP/2 frame parser.
pub struct H2Parser {
    buf: Vec<u8>,
    max_frame_size: usize,
    /// When `Some`, only CONTINUATION for this stream is allowed (RFC 9113 §4.3).
    continuation_expected: Option<u32>,
}

impl Default for H2Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl H2Parser {
    /// Create a parser with the default max frame size (16 KiB).
    pub fn new() -> Self {
        Self::with_max_frame_size(16_384)
    }

    /// Create a parser with an explicit max frame size.
    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_frame_size,
            continuation_expected: None,
        }
    }

    /// Update the maximum accepted frame payload size (from SETTINGS).
    pub fn set_max_frame_size(&mut self, max_frame_size: usize) {
        self.max_frame_size = max_frame_size;
    }

    /// Bytes still buffered (incomplete frame).
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Append `data` and dispatch every complete frame to `handler`.
    pub fn push(&mut self, data: &[u8], handler: &mut dyn H2FrameHandler) {
        self.buf.extend_from_slice(data);
        self.drain(handler);
    }

    /// Take ownership of the internal buffer (e.g. for preface sniffing).
    pub fn take_buf(&mut self) -> Vec<u8> {
        mem::take(&mut self.buf)
    }

    /// Restore a buffer previously taken with [`take_buf`](Self::take_buf).
    pub fn set_buf(&mut self, buf: Vec<u8>) {
        self.buf = buf;
    }

    /// Drain complete frames from the current buffer into `handler`.
    pub fn drain(&mut self, handler: &mut dyn H2FrameHandler) {
        let mut buf = mem::take(&mut self.buf);
        let mut offset = 0usize;

        loop {
            if buf.len() - offset < 9 {
                break;
            }
            let hdr = frame::parse_frame_header(&buf[offset..offset + 9]);
            let total = 9 + hdr.length as usize;

            // SETTINGS may exceed peer max before the peer's SETTINGS is applied.
            if hdr.ty != frame::TYPE_SETTINGS && hdr.length as usize > self.max_frame_size {
                handler.frame_error(
                    frame::ERROR_FRAME_SIZE_ERROR,
                    hdr.stream_id,
                    "frame size exceeds maximum",
                );
                offset = buf.len();
                break;
            }

            if buf.len() - offset < total {
                break;
            }

            if let Some(expected) = self.continuation_expected {
                if hdr.ty != frame::TYPE_CONTINUATION || hdr.stream_id != expected {
                    handler.frame_error(
                        frame::ERROR_PROTOCOL_ERROR,
                        hdr.stream_id,
                        "expected CONTINUATION",
                    );
                    offset = buf.len();
                    break;
                }
            }

            let payload = &buf[offset + 9..offset + total];
            self.dispatch(handler, hdr, payload);
            offset += total;
        }

        if offset > 0 {
            buf.drain(..offset);
        }
        self.buf = buf;
    }

    fn dispatch(&mut self, handler: &mut dyn H2FrameHandler, hdr: FrameHeader, payload: &[u8]) {
        match hdr.ty {
            frame::TYPE_DATA => {
                handler.data_frame(hdr.stream_id, hdr.flags, payload);
            }
            frame::TYPE_HEADERS => {
                let end_headers = hdr.flags & FLAG_END_HEADERS != 0;
                if !end_headers {
                    self.continuation_expected = Some(hdr.stream_id);
                } else {
                    self.continuation_expected = None;
                }
                handler.headers_frame(hdr.stream_id, hdr.flags, payload);
            }
            frame::TYPE_PRIORITY => {
                handler.priority_frame(hdr.stream_id, payload);
            }
            frame::TYPE_RST_STREAM => {
                handler.rst_stream_frame(hdr.stream_id, payload);
            }
            frame::TYPE_SETTINGS => {
                handler.settings_frame(hdr.flags, payload);
            }
            frame::TYPE_PUSH_PROMISE => {
                let end_headers = hdr.flags & FLAG_END_HEADERS != 0;
                if !end_headers {
                    self.continuation_expected = Some(hdr.stream_id);
                } else {
                    self.continuation_expected = None;
                }
                handler.push_promise_frame(hdr.stream_id, hdr.flags, payload);
            }
            frame::TYPE_PING => {
                handler.ping_frame(hdr.flags, payload);
            }
            frame::TYPE_GOAWAY => {
                handler.goaway_frame(payload);
            }
            frame::TYPE_WINDOW_UPDATE => {
                handler.window_update_frame(hdr.stream_id, payload);
            }
            frame::TYPE_CONTINUATION => {
                let end_headers = hdr.flags & FLAG_END_HEADERS != 0;
                if end_headers {
                    self.continuation_expected = None;
                }
                handler.continuation_frame(hdr.stream_id, hdr.flags, payload);
            }
            _ => {
                // Unknown frame types are ignored (RFC 9113 §5.1).
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::frame::{write_data, write_ping, FLAG_END_STREAM, TYPE_DATA};

    struct Collect {
        data: Vec<(u32, bool, Vec<u8>)>,
        pings: usize,
    }

    impl H2FrameHandler for Collect {
        fn data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
            self.data
                .push((stream_id, flags & FLAG_END_STREAM != 0, payload.to_vec()));
        }
        fn headers_frame(&mut self, _: u32, _: u8, _: &[u8]) {}
        fn priority_frame(&mut self, _: u32, _: &[u8]) {}
        fn rst_stream_frame(&mut self, _: u32, _: &[u8]) {}
        fn settings_frame(&mut self, _: u8, _: &[u8]) {}
        fn push_promise_frame(&mut self, _: u32, _: u8, _: &[u8]) {}
        fn ping_frame(&mut self, _: u8, _: &[u8]) {
            self.pings += 1;
        }
        fn goaway_frame(&mut self, _: &[u8]) {}
        fn window_update_frame(&mut self, _: u32, _: &[u8]) {}
        fn continuation_frame(&mut self, _: u32, _: u8, _: &[u8]) {}
        fn frame_error(&mut self, _: u32, _: u32, _: &str) {}
    }

    #[test]
    fn incremental_data_and_ping() {
        let mut out = Vec::new();
        write_data(&mut out, b"hello", FLAG_END_STREAM, 1);
        write_ping(&mut out, &[1, 2, 3, 4, 5, 6, 7, 8], false);

        let mut p = H2Parser::with_max_frame_size(16_384);
        let mut c = Collect {
            data: Vec::new(),
            pings: 0,
        };

        // Split mid-frame.
        p.push(&out[..4], &mut c);
        assert!(c.data.is_empty());
        p.push(&out[4..], &mut c);
        assert_eq!(c.data.len(), 1);
        assert_eq!(c.data[0].2, b"hello");
        assert_eq!(c.pings, 1);
        assert_eq!(TYPE_DATA, 0);
    }
}
