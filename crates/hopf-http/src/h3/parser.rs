// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental HTTP/3 frame parser over the stream's inbound [`LoopBuf`].
//!
//! The parser holds none of the stream. A frame other than DATA is consumed
//! once the whole of it is in the ring and delivered as a slice of the ring
//! (copied to a scratch buffer only if it wraps the ring's end). A DATA frame
//! is streamed: its payload goes to the handler in the pieces the ring holds,
//! so a frame of any size passes through a ring of any size.

use hopf_core::LoopBuf;

use super::{frame, varint};

/// Sink for HTTP/3 frames. Payloads are valid only during the call.
pub trait H3FrameHandler {
    /// A piece of a DATA frame's payload, in order: a frame arrives as one or
    /// more pieces, and a frame with no payload as one empty piece.
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
    ///
    /// Must not be used for the HTTP/2 leftovers in
    /// [`frame::is_reserved_http2_frame_type`] — those go through
    /// [`Self::reserved_http2_frame`].
    fn unknown_frame(&mut self, _frame_type: u64) {}
    /// A reserved HTTP/2 frame type (`0x02` / `0x06` / `0x08` / `0x09`) —
    /// RFC 9114 §7.2.8 requires a connection error of type
    /// `H3_FRAME_UNEXPECTED`.
    fn reserved_http2_frame(&mut self, _frame_type: u64) {}
    /// A malformed frame was received.
    fn frame_error(&mut self, message: &str);
}

/// Incremental HTTP/3 frame parser.
pub struct H3Parser {
    max_frame_size: usize,
    /// Payload bytes of the DATA frame in progress still to pass on.
    data_remaining: u64,
    /// A frame that wraps the ring's end, copied to be seen as one slice.
    scratch: Vec<u8>,
}

impl Default for H3Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl H3Parser {
    /// Create with a 16 MiB payload limit (a frame other than DATA must
    /// also fit the ring it is read from).
    pub fn new() -> Self {
        Self {
            max_frame_size: 16 * 1024 * 1024,
            data_remaining: 0,
            scratch: Vec::new(),
        }
    }

    /// Dispatches every frame `buf` holds to `handler`, consuming from it. A
    /// frame that is not all there yet stays in `buf` (a DATA frame's payload
    /// goes through as it arrives). A frame that could never fit `buf` is a
    /// frame error.
    pub fn receive(&mut self, buf: &mut LoopBuf, handler: &mut dyn H3FrameHandler) {
        loop {
            if self.data_remaining > 0 {
                if buf.is_empty() {
                    return;
                }
                let take = self.data_remaining.min(buf.len() as u64) as usize;
                let (first, second) = buf.readable_spans();
                let first_len = first.len().min(take);
                handler.data_frame(&first[..first_len]);
                if take > first_len {
                    handler.data_frame(&second[..take - first_len]);
                }
                buf.advance(take);
                self.data_remaining -= take as u64;
                continue;
            }

            // Type and length are varints of up to 8 bytes each.
            let mut head = [0u8; 16];
            let have = buf.len().min(head.len());
            copy_front(buf, &mut head[..have]);
            let Some((ty, ty_len)) = varint::decode(&head[..have]) else {
                return;
            };
            let Some((len, len_len)) = varint::decode(&head[ty_len..have]) else {
                return;
            };
            let header_len = ty_len + len_len;
            let Ok(payload_len) = usize::try_from(len) else {
                handler.frame_error("frame length overflows usize");
                buf.advance(buf.len());
                return;
            };

            if payload_len > self.max_frame_size {
                handler.frame_error("frame exceeds maximum size");
                buf.advance(buf.len());
                return;
            }

            if ty == frame::DATA {
                buf.advance(header_len);
                if payload_len == 0 {
                    handler.data_frame(&[]);
                }
                self.data_remaining = len;
                continue;
            }

            // Held whole, so it must fit the ring.
            let Some(total) = header_len.checked_add(payload_len) else {
                handler.frame_error("frame length overflow");
                buf.advance(buf.len());
                return;
            };
            if total > buf.capacity() {
                handler.frame_error("frame exceeds the receive buffer");
                buf.advance(buf.len());
                return;
            }
            if buf.len() < total {
                return;
            }
            self.with_payload(buf, header_len, payload_len, |_, payload| {
                Self::dispatch(handler, ty, payload)
            });
            buf.advance(total);
        }
    }

    /// Runs `f` with the payload of the frame at the front of `buf` (after
    /// its `header_len` bytes of type and length) as one slice.
    fn with_payload(
        &mut self,
        buf: &LoopBuf,
        header_len: usize,
        payload_len: usize,
        f: impl FnOnce(&mut Self, &[u8]),
    ) {
        let (first, second) = buf.readable_spans();
        if first.len() >= header_len + payload_len {
            f(self, &first[header_len..header_len + payload_len]);
        } else {
            let mut scratch = std::mem::take(&mut self.scratch);
            scratch.clear();
            scratch.extend_from_slice(first);
            scratch.extend_from_slice(second);
            f(self, &scratch[header_len..header_len + payload_len]);
            self.scratch = scratch;
        }
    }

    fn dispatch(handler: &mut dyn H3FrameHandler, ty: u64, payload: &[u8]) {
        match ty {
            frame::HEADERS => handler.headers_frame(payload),
            frame::CANCEL_PUSH => handler.cancel_push_frame(payload),
            frame::SETTINGS => handler.settings_frame(payload),
            frame::PUSH_PROMISE => handler.push_promise_frame(payload),
            frame::GOAWAY => handler.goaway_frame(payload),
            frame::MAX_PUSH_ID => handler.max_push_id_frame(payload),
            frame::PRIORITY_UPDATE_REQUEST => handler.priority_update_request_frame(payload),
            frame::PRIORITY_UPDATE_PUSH => handler.priority_update_push_frame(payload),
            // HTTP/2 leftovers (RFC 9114 §7.2.8 / §11.2.1) - never GREASE.
            other if frame::is_reserved_http2_frame_type(other) => {
                handler.reserved_http2_frame(other);
            }
            // Unknown / reserved (GREASE) - notify so the control stream
            // can enforce SETTINGS-first; otherwise ignore per §9.
            other => handler.unknown_frame(other),
        }
    }
}

/// Copies the first `out.len()` bytes of `buf` into `out`, which the caller
/// has checked it holds.
pub(super) fn copy_front(buf: &LoopBuf, out: &mut [u8]) {
    let (first, second) = buf.readable_spans();
    let n = first.len().min(out.len());
    out[..n].copy_from_slice(&first[..n]);
    let rest = out.len() - n;
    out[n..].copy_from_slice(&second[..rest]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Collect {
        data: Vec<u8>,
        pieces: usize,
        headers: Vec<Vec<u8>>,
        errors: Vec<String>,
    }
    impl H3FrameHandler for Collect {
        fn data_frame(&mut self, payload: &[u8]) {
            self.data.extend_from_slice(payload);
            self.pieces += 1;
        }
        fn headers_frame(&mut self, payload: &[u8]) {
            self.headers.push(payload.to_vec());
        }
        fn cancel_push_frame(&mut self, _: &[u8]) {}
        fn settings_frame(&mut self, _: &[u8]) {}
        fn push_promise_frame(&mut self, _: &[u8]) {}
        fn goaway_frame(&mut self, _: &[u8]) {}
        fn max_push_id_frame(&mut self, _: &[u8]) {}
        fn frame_error(&mut self, message: &str) {
            self.errors.push(message.to_string());
        }
    }

    fn headers(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode(&mut out, frame::HEADERS);
        varint::encode(&mut out, payload.len() as u64);
        out.extend_from_slice(payload);
        out
    }

    /// Feeds `bytes` in chunks through a ring of `ring` bytes.
    fn feed(p: &mut H3Parser, c: &mut Collect, bytes: &[u8], chunk: usize, ring: usize) -> LoopBuf {
        let mut buf = LoopBuf::with_capacity(ring);
        let mut rest = bytes;
        while !rest.is_empty() {
            let taken = buf.extend_from_slice(&rest[..chunk.min(rest.len())]);
            rest = &rest[taken..];
            let before = buf.len();
            p.receive(&mut buf, c);
            if taken == 0 && buf.len() == before {
                break;
            }
        }
        buf
    }

    #[test]
    fn parses_frame_split_at_every_boundary() {
        let mut bytes = Vec::new();
        frame::write_data(&mut bytes, b"hello");
        for split in 0..bytes.len() {
            let mut parser = H3Parser::new();
            let mut collect = Collect::default();
            let mut buf = LoopBuf::with_capacity(64);
            buf.extend_from_slice(&bytes[..split]);
            parser.receive(&mut buf, &mut collect);
            // A DATA frame's payload passes through as it arrives.
            assert!(b"hello".starts_with(&collect.data));
            buf.extend_from_slice(&bytes[split..]);
            parser.receive(&mut buf, &mut collect);
            assert_eq!(collect.data, b"hello");
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn every_chunking_gives_the_same_frames() {
        let mut bytes = Vec::new();
        frame::write_data(&mut bytes, b"first");
        bytes.extend(headers(b"block"));
        frame::write_data(&mut bytes, b"");
        frame::write_data(&mut bytes, b"second");
        for chunk in [1, 2, 3, 5, 9, 64, 1000] {
            let mut p = H3Parser::new();
            let mut c = Collect::default();
            let buf = feed(&mut p, &mut c, &bytes, chunk, 4096);
            assert!(buf.is_empty(), "chunk={chunk}");
            assert_eq!(c.data, b"firstsecond", "chunk={chunk}");
            assert_eq!(c.headers, vec![b"block".to_vec()], "chunk={chunk}");
        }
    }

    #[test]
    fn a_data_frame_streams_through_a_ring_smaller_than_it() {
        let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut bytes = Vec::new();
        frame::write_data(&mut bytes, &content);
        let mut p = H3Parser::new();
        let mut c = Collect::default();
        let buf = feed(&mut p, &mut c, &bytes, 40, 64);
        assert!(buf.is_empty());
        assert_eq!(c.data, content);
        assert!(c.pieces > 10, "delivered in pieces");
        assert!(c.errors.is_empty());
    }

    #[test]
    fn a_frame_that_wraps_the_ring_is_delivered_whole() {
        let mut p = H3Parser::new();
        let mut c = Collect::default();
        let mut buf = LoopBuf::with_capacity(32);
        buf.extend_from_slice(&[0u8; 25]);
        buf.advance(25);
        let frame = headers(b"0123456789abcdef");
        assert_eq!(buf.extend_from_slice(&frame), frame.len());
        assert!(!buf.readable_spans().1.is_empty(), "the frame wraps");
        p.receive(&mut buf, &mut c);
        assert_eq!(c.headers, vec![b"0123456789abcdef".to_vec()]);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_frame_too_big_for_the_ring_is_a_frame_error() {
        let bytes = headers(&[7u8; 100]);
        let mut p = H3Parser::new();
        let mut c = Collect::default();
        feed(&mut p, &mut c, &bytes, 30, 64);
        assert_eq!(c.errors, vec!["frame exceeds the receive buffer".to_string()]);
        assert!(c.headers.is_empty());
    }
}
