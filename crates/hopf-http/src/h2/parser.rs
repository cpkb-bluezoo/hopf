// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Push-parser for HTTP/2 frames (RFC 9113 §4) - Gumdrop `H2Parser` shape.
//!
//! The parser reads the connection's inbound [`LoopBuf`] and holds none of the
//! stream itself. A frame other than DATA is consumed only once the whole of it
//! is in the ring, and delivered as a typed callback with its payload as a
//! slice of the ring (copied to a scratch buffer only if the frame wraps the
//! ring's end). A DATA frame is streamed: its payload goes to the handler in
//! whatever pieces the ring holds, so a frame of any size passes through a ring
//! of any size. No intermediate `Frame` objects are allocated.

use hopf_core::LoopBuf;

use super::frame::{self, FrameHeader, FLAG_END_HEADERS, FLAG_END_STREAM, FLAG_PADDED};

/// Callback sink for frames emitted by [`H2Parser`].
///
/// Payload slices are only valid for the duration of the callback.
pub trait H2FrameHandler {
    /// A DATA frame begins. `length` is its whole payload, padding included.
    /// The content follows as [`Self::data_frame`] calls. Default: ignore.
    fn data_start(&mut self, stream_id: u32, flags: u8, length: u32) {
        let _ = (stream_id, flags, length);
    }
    /// A piece of a DATA frame's content, in order, with padding removed.
    /// `flags` has `END_STREAM` only on the last piece, and `PADDED` never. A
    /// frame without content is delivered as one empty piece, so that the
    /// handler sees its flags.
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
    /// PRIORITY_UPDATE frame (RFC 9218 §7.1). Default: ignore.
    fn priority_update_frame(&mut self, stream_id: u32, payload: &[u8]) {
        let _ = (stream_id, payload);
    }
    /// Parser detected a connection error (e.g. frame too large).
    fn frame_error(&mut self, error_code: u32, stream_id: u32, message: &str);
}

/// A DATA frame whose content is passing through.
struct DataInProgress {
    stream_id: u32,
    /// The frame's flags without `PADDED`.
    flags: u8,
    /// Content bytes still to deliver.
    content: u32,
    /// Padding bytes still to skip.
    padding: u32,
}

/// Incremental HTTP/2 frame parser.
pub struct H2Parser {
    max_frame_size: usize,
    /// When `Some`, only CONTINUATION for this stream is allowed (RFC 9113 §4.3).
    continuation_expected: Option<u32>,
    data: Option<DataInProgress>,
    /// A frame that wraps the ring's end, copied to be seen as one slice.
    scratch: Vec<u8>,
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
            max_frame_size,
            continuation_expected: None,
            data: None,
            scratch: Vec::new(),
        }
    }

    /// Update the maximum accepted frame payload size (from SETTINGS).
    pub fn set_max_frame_size(&mut self, max_frame_size: usize) {
        self.max_frame_size = max_frame_size;
    }

    /// Dispatches every frame `buf` holds to `handler`, consuming from it. A
    /// frame that is not all there yet stays in `buf` (a DATA frame's content
    /// goes through as it arrives). A frame that could never fit `buf` is a
    /// connection error.
    pub fn receive(&mut self, buf: &mut LoopBuf, handler: &mut dyn H2FrameHandler) {
        loop {
            if self.data.is_some() {
                if !self.pass_data(buf, handler) {
                    break;
                }
                continue;
            }
            if buf.len() < 9 {
                break;
            }
            let mut header = [0u8; 9];
            copy_front(buf, &mut header);
            let hdr = frame::parse_frame_header(&header);
            let length = hdr.length as usize;

            // A frame other than DATA is held whole, so it must fit the ring.
            // SETTINGS may exceed peer max before the peer's SETTINGS is applied.
            let holdable = buf.capacity() - 9;
            let too_big = (hdr.ty != frame::TYPE_SETTINGS && length > self.max_frame_size)
                || (hdr.ty != frame::TYPE_DATA && length > holdable);
            if too_big {
                handler.frame_error(
                    frame::ERROR_FRAME_SIZE_ERROR,
                    hdr.stream_id,
                    "frame size exceeds maximum",
                );
                buf.advance(buf.len());
                break;
            }

            if let Some(expected) = self.continuation_expected {
                if hdr.ty != frame::TYPE_CONTINUATION || hdr.stream_id != expected {
                    handler.frame_error(
                        frame::ERROR_PROTOCOL_ERROR,
                        hdr.stream_id,
                        "expected CONTINUATION",
                    );
                    buf.advance(buf.len());
                    break;
                }
            }

            if hdr.ty == frame::TYPE_DATA {
                if !self.start_data(buf, handler, hdr) {
                    break;
                }
                continue;
            }

            let total = 9 + length;
            if buf.len() < total {
                break;
            }
            self.with_payload(buf, length, |this, payload| this.dispatch(handler, hdr, payload));
            buf.advance(total);
        }
    }

    /// Begins a DATA frame whose header is at the front of `buf`. False if
    /// more must arrive first (the pad length is not there yet).
    fn start_data(&mut self, buf: &mut LoopBuf, handler: &mut dyn H2FrameHandler, hdr: FrameHeader) -> bool {
        let padded = hdr.flags & FLAG_PADDED != 0;
        let mut head = 9;
        let mut content = hdr.length;
        let mut padding = 0;
        if padded && hdr.length > 0 {
            if buf.len() < 10 {
                return false;
            }
            let mut two = [0u8; 10];
            copy_front(buf, &mut two);
            let pad = two[9] as u32;
            head = 10;
            // A pad length that leaves no content is read as no content.
            content = (hdr.length - 1).saturating_sub(pad);
            padding = hdr.length - 1 - content;
        }
        buf.advance(head);
        handler.data_start(hdr.stream_id, hdr.flags, hdr.length);
        let flags = hdr.flags & !FLAG_PADDED;
        if content == 0 {
            // Nothing to pass on but the flags.
            handler.data_frame(hdr.stream_id, flags, &[]);
        }
        self.data = Some(DataInProgress {
            stream_id: hdr.stream_id,
            flags,
            content,
            padding,
        });
        if content == 0 && padding == 0 {
            self.data = None;
        }
        true
    }

    /// Passes on the content and skips the padding of the DATA frame in
    /// progress as far as `buf` goes. False if `buf` ran out first.
    fn pass_data(&mut self, buf: &mut LoopBuf, handler: &mut dyn H2FrameHandler) -> bool {
        let d = self.data.as_mut().expect("a DATA frame in progress");
        while d.content > 0 {
            if buf.is_empty() {
                return false;
            }
            let take = (d.content as usize).min(buf.len());
            let last_of_frame = take == d.content as usize;
            let (first, second) = buf.readable_spans();
            let first_len = first.len().min(take);
            let second_len = take - first_len;
            let end = |last: bool| if last { d.flags } else { d.flags & !FLAG_END_STREAM };
            if second_len == 0 {
                handler.data_frame(d.stream_id, end(last_of_frame), &first[..first_len]);
            } else {
                handler.data_frame(d.stream_id, end(false), first);
                handler.data_frame(d.stream_id, end(last_of_frame), &second[..second_len]);
            }
            d.content -= take as u32;
            buf.advance(take);
        }
        if d.padding > 0 {
            let skip = (d.padding as usize).min(buf.len());
            buf.advance(skip);
            d.padding -= skip as u32;
            if d.padding > 0 {
                return false;
            }
        }
        self.data = None;
        true
    }

    /// Runs `f` with the payload of the frame at the front of `buf` (after
    /// its 9-byte header) as one slice.
    fn with_payload(&mut self, buf: &LoopBuf, length: usize, f: impl FnOnce(&mut Self, &[u8])) {
        let (first, second) = buf.readable_spans();
        if first.len() >= 9 + length {
            f(self, &first[9..9 + length]);
        } else {
            let mut scratch = std::mem::take(&mut self.scratch);
            scratch.clear();
            scratch.extend_from_slice(first);
            scratch.extend_from_slice(second);
            f(self, &scratch[9..9 + length]);
            self.scratch = scratch;
        }
    }

    fn dispatch(&mut self, handler: &mut dyn H2FrameHandler, hdr: FrameHeader, payload: &[u8]) {
        match hdr.ty {
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
            frame::TYPE_PRIORITY_UPDATE => {
                handler.priority_update_frame(hdr.stream_id, payload);
            }
            _ => {
                // Unknown frame types are ignored (RFC 9113 §5.1).
            }
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
    use crate::h2::frame::{write_data, write_frame_header, write_ping, ERROR_FRAME_SIZE_ERROR};

    #[derive(Default)]
    struct Collect {
        /// (stream, end_stream, bytes) of every DATA piece.
        data: Vec<(u32, bool, Vec<u8>)>,
        starts: Vec<(u32, u32)>,
        frames: Vec<(u32, bool, Vec<u8>)>,
        pings: usize,
        headers: Vec<Vec<u8>>,
        errors: Vec<u32>,
    }

    impl Collect {
        /// The content of each DATA frame, its pieces joined, with whether
        /// END_STREAM came on its last piece and on no other.
        fn frames(&self) -> Vec<(u32, bool, Vec<u8>)> {
            self.frames.clone()
        }
    }

    impl H2FrameHandler for Collect {
        fn data_start(&mut self, stream_id: u32, _flags: u8, length: u32) {
            self.starts.push((stream_id, length));
            self.frames.push((stream_id, false, Vec::new()));
        }
        fn data_frame(&mut self, stream_id: u32, flags: u8, payload: &[u8]) {
            assert_eq!(flags & FLAG_PADDED, 0, "padding is the parser's");
            let end = flags & FLAG_END_STREAM != 0;
            let frame = self.frames.last_mut().expect("data_start came first");
            assert!(!frame.1, "no piece after END_STREAM");
            frame.2.extend_from_slice(payload);
            frame.1 = end;
            self.data.push((stream_id, end, payload.to_vec()));
        }
        fn headers_frame(&mut self, _: u32, _: u8, payload: &[u8]) {
            self.headers.push(payload.to_vec());
        }
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
        fn frame_error(&mut self, code: u32, _: u32, _: &str) {
            self.errors.push(code);
        }
    }

    /// Feeds `bytes` in chunks of `chunk` through a ring of `ring` bytes.
    fn feed(p: &mut H2Parser, c: &mut Collect, bytes: &[u8], chunk: usize, ring: usize) -> LoopBuf {
        let mut buf = LoopBuf::with_capacity(ring);
        let mut rest = bytes;
        while !rest.is_empty() {
            let piece = &rest[..chunk.min(rest.len())];
            let taken = buf.extend_from_slice(piece);
            rest = &rest[taken..];
            let before = buf.len();
            p.receive(&mut buf, c);
            if taken == 0 && buf.len() == before {
                break;
            }
        }
        buf
    }

    fn padded_data(content: &[u8], pad: u8, flags: u8, stream: u32) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame_header(
            &mut out,
            1 + content.len() as u32 + pad as u32,
            frame::TYPE_DATA,
            flags | FLAG_PADDED,
            stream,
        );
        out.push(pad);
        out.extend_from_slice(content);
        out.extend(std::iter::repeat(0).take(pad as usize));
        out
    }

    #[test]
    fn incremental_data_and_ping() {
        let mut out = Vec::new();
        write_data(&mut out, b"hello", FLAG_END_STREAM, 1);
        write_ping(&mut out, &[1, 2, 3, 4, 5, 6, 7, 8], false);

        let mut p = H2Parser::new();
        let mut c = Collect::default();
        let buf = feed(&mut p, &mut c, &out[..4], 4, 64);
        assert!(c.data.is_empty());
        assert_eq!(buf.len(), 4, "a partial header stays in the ring");
        let mut buf = buf;
        buf.extend_from_slice(&out[4..]);
        p.receive(&mut buf, &mut c);
        assert_eq!(c.frames(), vec![(1, true, b"hello".to_vec())]);
        assert_eq!(c.pings, 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn every_chunking_gives_the_same_frames() {
        let mut out = Vec::new();
        write_data(&mut out, b"first", 0, 1);
        write_ping(&mut out, &[9; 8], false);
        out.extend(padded_data(b"padded", 7, FLAG_END_STREAM, 3));
        write_data(&mut out, b"", FLAG_END_STREAM, 5);
        for chunk in [1, 2, 3, 7, 10, 64, 1000] {
            let mut p = H2Parser::new();
            let mut c = Collect::default();
            let buf = feed(&mut p, &mut c, &out, chunk, 4096);
            assert!(buf.is_empty(), "chunk={chunk}");
            assert_eq!(
                c.frames(),
                vec![
                    (1, false, b"first".to_vec()),
                    (3, true, b"padded".to_vec()),
                    (5, true, Vec::new()),
                ],
                "chunk={chunk}"
            );
            assert_eq!(c.pings, 1, "chunk={chunk}");
            assert_eq!(c.starts, vec![(1, 5), (3, 14), (5, 0)], "chunk={chunk}");
        }
    }

    #[test]
    fn a_data_frame_streams_through_a_ring_smaller_than_it() {
        let content: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let mut out = Vec::new();
        write_data(&mut out, &content, FLAG_END_STREAM, 1);
        let mut p = H2Parser::new();
        let mut c = Collect::default();
        // 64 bytes of ring for a 5000 byte frame.
        let buf = feed(&mut p, &mut c, &out, 40, 64);
        assert!(buf.is_empty());
        assert_eq!(c.frames(), vec![(1, true, content)]);
        assert!(c.data.len() > 10, "delivered in pieces");
        assert!(c.errors.is_empty());
    }

    #[test]
    fn padding_is_skipped_even_when_it_spans_chunks() {
        let out = padded_data(b"abc", 200, FLAG_END_STREAM, 1);
        let mut following = out.clone();
        write_ping(&mut following, &[0; 8], false);
        let mut p = H2Parser::new();
        let mut c = Collect::default();
        let buf = feed(&mut p, &mut c, &following, 13, 64);
        assert!(buf.is_empty());
        assert_eq!(c.frames(), vec![(1, true, b"abc".to_vec())]);
        assert_eq!(c.pings, 1);
    }

    #[test]
    fn a_frame_that_wraps_the_ring_is_delivered_whole() {
        let mut p = H2Parser::new();
        let mut c = Collect::default();
        let mut buf = LoopBuf::with_capacity(64);
        // Move the read position near the end so the next frame wraps.
        buf.extend_from_slice(&[0u8; 50]);
        buf.advance(50);
        let mut out = Vec::new();
        write_frame_header(&mut out, 20, frame::TYPE_HEADERS, FLAG_END_HEADERS, 1);
        out.extend((0..20u8).collect::<Vec<_>>());
        assert_eq!(buf.extend_from_slice(&out), out.len());
        assert!(!buf.readable_spans().1.is_empty(), "the frame wraps");
        p.receive(&mut buf, &mut c);
        assert_eq!(c.headers, vec![(0..20u8).collect::<Vec<_>>()]);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_frame_too_big_for_the_ring_is_a_frame_size_error() {
        let mut out = Vec::new();
        write_frame_header(&mut out, 100, frame::TYPE_HEADERS, FLAG_END_HEADERS, 1);
        out.extend([0u8; 100]);
        let mut p = H2Parser::new();
        let mut c = Collect::default();
        feed(&mut p, &mut c, &out, 30, 64);
        assert_eq!(c.errors, vec![ERROR_FRAME_SIZE_ERROR]);
        assert!(c.headers.is_empty());
    }

    #[test]
    fn a_frame_over_the_maximum_is_a_frame_size_error_before_it_arrives() {
        let mut out = Vec::new();
        write_frame_header(&mut out, 16_385, frame::TYPE_DATA, 0, 1);
        let mut p = H2Parser::new();
        let mut c = Collect::default();
        feed(&mut p, &mut c, &out, 9, 64 * 1024);
        assert_eq!(c.errors, vec![ERROR_FRAME_SIZE_ERROR]);
    }

    #[test]
    fn only_continuation_may_follow_headers_without_end_headers() {
        let mut out = Vec::new();
        write_frame_header(&mut out, 0, frame::TYPE_HEADERS, 0, 1);
        write_ping(&mut out, &[0; 8], false);
        let mut p = H2Parser::new();
        let mut c = Collect::default();
        feed(&mut p, &mut c, &out, 100, 4096);
        assert_eq!(c.errors, vec![frame::ERROR_PROTOCOL_ERROR]);
        assert_eq!(c.pings, 0);
    }
}
