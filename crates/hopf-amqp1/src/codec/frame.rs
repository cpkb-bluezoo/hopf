// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental push parser for the AMQP 1.0 frame layer (core spec section
//! 2.3) and the protocol header exchange (section 2.2) shared by the SASL
//! and AMQP sub-protocols.
//!
//! Frame layout: a 4-byte size (whole frame, header included), a 1-byte
//! data offset (`DOFF`, in 4-byte words, minimum 2), a 1-byte frame type
//! (`0x00` AMQP, `0x01` SASL), a 2-byte channel, any extended-header bytes
//! (`DOFF*4 - 8`, always skipped per spec), then the frame body. A frame
//! with an empty body is a heartbeat (or, on channel 0, a SASL/AMQP
//! keep-alive) rather than an error.
//!
//! Like [`crate::codec::types`], this parser only ever hands a **complete**
//! frame body to its handler — bytes accumulate in an internal buffer until
//! a whole frame (bounded by the negotiated max-frame-size) is present,
//! then that buffer is drained. This mirrors this workspace's existing
//! AMQP 0-9-1 and MQTT frame parsers rather than the zero-copy, per-chunk
//! body forwarding an implementation streaming *unbounded* frame bodies
//! would need — AMQP 1.0 frames are capped by max-frame-size, so buffering
//! one is bounded the same way buffering one HTTP/2 or MQTT frame is.
//! A *message* spanning many `transfer` frames is never buffered as a
//! whole, though: [`crate::codec::message::MessageParser`] streams each
//! transfer's payload to the application as that frame arrives.

use super::Amqp1Error;

/// Minimum max-frame-size a peer may advertise (core spec 2.7.1).
pub const MIN_MAX_FRAME_SIZE: u32 = 512;

/// This client's own default max-frame-size, advertised in `open` until
/// overridden.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 1_048_576;

/// AMQP frame type octet (core spec 2.3.2).
pub const FRAME_TYPE_AMQP: u8 = 0x00;
/// SASL frame type octet (SASL spec 5.3.2).
pub const FRAME_TYPE_SASL: u8 = 0x01;

/// Protocol id octet identifying which header/sub-protocol is being
/// negotiated (core spec 2.2, SASL spec 5.2.1).
pub const PROTOCOL_ID_AMQP: u8 = 0x00;
/// TLS protocol id. Never sent or expected by this client: TLS here is
/// applied at the transport layer before any AMQP bytes are exchanged
/// (implicit TLS on `amqps://`), not negotiated via this header exchange.
pub const PROTOCOL_ID_TLS: u8 = 0x02;
/// SASL protocol id.
pub const PROTOCOL_ID_SASL: u8 = 0x03;

const FRAME_HEADER_LEN: usize = 8;
const PROTOCOL_HEADER_LEN: usize = 8;

/// Signals the parser needs to act on immediately after a `frame`/
/// `empty_frame` callback returns — before its own loop moves on to
/// whatever bytes follow in the same buffer.
///
/// This exists because a handler cannot safely reconfigure the very
/// [`Amqp1FrameParser`] instance mid-`feed()` (it would need a second
/// `&mut` reference to a value `feed` already holds `&mut self` on).
/// Returning the requested change instead lets `feed`'s own loop apply it
/// to its own state before deciding how to interpret the next bytes —
/// which matters because those next bytes can already be sitting in the
/// same buffer as the frame that requested the change (e.g. a peer that
/// pipelines its `sasl-outcome` frame immediately followed by its AMQP
/// protocol header, both landing in one `feed()` call: without applying
/// [`Self::expect_protocol_header`] before the loop continues, those
/// header bytes would be misread as a frame's size field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameOutcome {
    /// Re-arm the parser to expect a fresh protocol header next, instead of
    /// a frame — the SASL-header-then-AMQP-header handoff.
    pub expect_protocol_header: bool,
    /// Change the accepted max frame size effective immediately (e.g. once
    /// this client's own negotiated `open.max-frame-size` is decided).
    pub max_frame_size: Option<u32>,
}

impl FrameOutcome {
    /// Nothing to change — continue parsing normally.
    pub const NONE: FrameOutcome = FrameOutcome { expect_protocol_header: false, max_frame_size: None };
}

/// Callbacks from [`Amqp1FrameParser`].
pub trait Amqp1FrameHandler {
    /// An 8-byte protocol header arrived (`"AMQP"` + protocol id + version).
    /// Fires once at connection start, and again after a `frame`/
    /// `empty_frame` callback returns [`FrameOutcome::expect_protocol_header`]
    /// — the SASL-to-AMQP header handoff.
    fn protocol_header(&mut self, protocol_id: u8, major: u8, minor: u8, revision: u8);
    /// A complete frame with a non-empty body. `body` excludes the fixed
    /// frame header and any extended header, and is valid for this call only.
    fn frame(&mut self, frame_type: u8, channel: u16, body: &[u8]) -> FrameOutcome;
    /// A frame with an empty body (heartbeat / keep-alive).
    fn empty_frame(&mut self, frame_type: u8, channel: u16) -> FrameOutcome;
    /// Fatal parse error; no further bytes are processed after this.
    fn error(&mut self, err: Amqp1Error);
}

/// Incremental AMQP 1.0 frame-layer parser.
pub struct Amqp1FrameParser {
    buf: Vec<u8>,
    max_frame_size: u32,
    expect_header: bool,
    failed: bool,
}

impl Amqp1FrameParser {
    /// Create a parser. `max_frame_size` is the size this side will accept
    /// (`0` uses [`DEFAULT_MAX_FRAME_SIZE`]); update it via
    /// [`Self::set_max_frame_size`] if it changes after construction.
    pub fn new(max_frame_size: u32) -> Self {
        Self {
            buf: Vec::new(),
            max_frame_size: if max_frame_size == 0 {
                DEFAULT_MAX_FRAME_SIZE
            } else {
                max_frame_size
            },
            expect_header: true,
            failed: false,
        }
    }

    /// Update the accepted max frame size (e.g. once this client's own
    /// `open.max-frame-size` is decided; this parser only enforces the
    /// receive-side cap, per core spec 2.7.1 — it does not read the peer's
    /// advertised value itself).
    pub fn set_max_frame_size(&mut self, max_frame_size: u32) {
        self.max_frame_size = if max_frame_size == 0 {
            DEFAULT_MAX_FRAME_SIZE
        } else {
            max_frame_size
        };
    }

    /// Re-arm the parser to expect a fresh 8-byte protocol header next,
    /// instead of a frame — used for the SASL-header-then-AMQP-header
    /// handoff once a SASL exchange concludes.
    pub fn expect_protocol_header(&mut self) {
        self.expect_header = true;
    }

    /// Feed inbound bytes; invokes handler callbacks as headers/frames complete.
    pub fn feed(&mut self, data: &[u8], handler: &mut dyn Amqp1FrameHandler) {
        if self.failed {
            return;
        }
        self.buf.extend_from_slice(data);
        loop {
            if self.expect_header {
                if self.buf.len() < PROTOCOL_HEADER_LEN {
                    return;
                }
                if &self.buf[0..4] != b"AMQP" {
                    self.fail(handler, Amqp1Error::Malformed("bad protocol header magic"));
                    return;
                }
                let (protocol_id, major, minor, revision) =
                    (self.buf[4], self.buf[5], self.buf[6], self.buf[7]);
                self.buf.drain(..PROTOCOL_HEADER_LEN);
                self.expect_header = false;
                handler.protocol_header(protocol_id, major, minor, revision);
                continue;
            }

            if self.buf.len() < FRAME_HEADER_LEN {
                return;
            }
            let size = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
            let doff = self.buf[4];
            let frame_type = self.buf[5];
            let channel = u16::from_be_bytes([self.buf[6], self.buf[7]]);

            if (size as usize) < FRAME_HEADER_LEN {
                self.fail(handler, Amqp1Error::Malformed("frame size below header size"));
                return;
            }
            if size > self.max_frame_size {
                self.fail(
                    handler,
                    Amqp1Error::FrameTooLarge {
                        size,
                        max: self.max_frame_size,
                    },
                );
                return;
            }
            let doff_bytes = (doff as usize) * 4;
            if doff < 2 || doff_bytes > size as usize {
                self.fail(handler, Amqp1Error::Malformed("invalid data offset"));
                return;
            }

            let total = size as usize;
            if self.buf.len() < total {
                return; // wait for the rest of this frame
            }

            let body_start = doff_bytes;
            if body_start > total {
                self.fail(handler, Amqp1Error::Malformed("invalid data offset"));
                return;
            }
            let outcome = if body_start == total {
                handler.empty_frame(frame_type, channel)
            } else {
                handler.frame(frame_type, channel, &self.buf[body_start..total])
            };
            self.buf.drain(..total);
            if outcome.expect_protocol_header {
                self.expect_header = true;
            }
            if let Some(max) = outcome.max_frame_size {
                self.set_max_frame_size(max);
            }
        }
    }

    fn fail(&mut self, handler: &mut dyn Amqp1FrameHandler, err: Amqp1Error) {
        self.failed = true;
        self.buf.clear();
        handler.error(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protocol_header(protocol_id: u8) -> Vec<u8> {
        let mut v = b"AMQP".to_vec();
        v.push(protocol_id);
        v.extend_from_slice(&[1, 0, 0]);
        v
    }

    fn frame(frame_type: u8, channel: u16, body: &[u8]) -> Vec<u8> {
        let size = (FRAME_HEADER_LEN + body.len()) as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&size.to_be_bytes());
        v.push(2); // doff
        v.push(frame_type);
        v.extend_from_slice(&channel.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    #[derive(Default)]
    struct Collect {
        headers: Vec<(u8, u8, u8, u8)>,
        frames: Vec<(u8, u16, Vec<u8>)>,
        empties: Vec<(u8, u16)>,
        errors: Vec<Amqp1Error>,
        /// When set, the next SASL-type frame handled requests
        /// [`FrameOutcome::expect_protocol_header`] — lets tests simulate a
        /// handler that reacts to (e.g.) a `sasl-outcome` frame the same way
        /// `Amqp1ClientEndpoint` does.
        rearm_after_next_sasl_frame: bool,
    }

    impl Amqp1FrameHandler for Collect {
        fn protocol_header(&mut self, protocol_id: u8, major: u8, minor: u8, revision: u8) {
            self.headers.push((protocol_id, major, minor, revision));
        }
        fn frame(&mut self, frame_type: u8, channel: u16, body: &[u8]) -> FrameOutcome {
            self.frames.push((frame_type, channel, body.to_vec()));
            if frame_type == FRAME_TYPE_SASL && self.rearm_after_next_sasl_frame {
                self.rearm_after_next_sasl_frame = false;
                return FrameOutcome { expect_protocol_header: true, ..FrameOutcome::NONE };
            }
            FrameOutcome::NONE
        }
        fn empty_frame(&mut self, frame_type: u8, channel: u16) -> FrameOutcome {
            self.empties.push((frame_type, channel));
            FrameOutcome::NONE
        }
        fn error(&mut self, err: Amqp1Error) {
            self.errors.push(err);
        }
    }

    #[test]
    fn header_then_frame_whole_buffer() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect::default();
        let mut data = protocol_header(PROTOCOL_ID_SASL);
        data.extend_from_slice(&frame(FRAME_TYPE_SASL, 0, b"hello"));
        parser.feed(&data, &mut h);
        assert_eq!(h.headers, vec![(PROTOCOL_ID_SASL, 1, 0, 0)]);
        assert_eq!(h.frames, vec![(FRAME_TYPE_SASL, 0, b"hello".to_vec())]);
        assert!(h.errors.is_empty());
    }

    #[test]
    fn tiny_chunks() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect::default();
        let mut data = protocol_header(PROTOCOL_ID_AMQP);
        data.extend_from_slice(&frame(FRAME_TYPE_AMQP, 3, b"performative-bytes"));
        for chunk in data.chunks(3) {
            parser.feed(chunk, &mut h);
        }
        assert_eq!(h.headers, vec![(PROTOCOL_ID_AMQP, 1, 0, 0)]);
        assert_eq!(h.frames, vec![(FRAME_TYPE_AMQP, 3, b"performative-bytes".to_vec())]);
        assert!(h.errors.is_empty());
    }

    /// Proves correctness at every possible split point, not just a couple
    /// of hand-picked chunk sizes.
    #[test]
    fn split_at_every_byte_boundary() {
        let mut data = protocol_header(PROTOCOL_ID_AMQP);
        data.extend_from_slice(&frame(FRAME_TYPE_AMQP, 7, b"split-me-anywhere"));
        data.extend_from_slice(&frame(FRAME_TYPE_AMQP, 7, &[])); // heartbeat

        for split in 1..=data.len() {
            let mut parser = Amqp1FrameParser::new(0);
            let mut h = Collect::default();
            let mut off = 0;
            while off < data.len() {
                let len = split.min(data.len() - off);
                parser.feed(&data[off..off + len], &mut h);
                off += len;
            }
            assert_eq!(h.headers, vec![(PROTOCOL_ID_AMQP, 1, 0, 0)], "split={split}");
            assert_eq!(
                h.frames,
                vec![(FRAME_TYPE_AMQP, 7, b"split-me-anywhere".to_vec())],
                "split={split}"
            );
            assert_eq!(h.empties, vec![(FRAME_TYPE_AMQP, 7)], "split={split}");
            assert!(h.errors.is_empty(), "split={split}: {:?}", h.errors);
        }
    }

    #[test]
    fn header_rearm_after_sasl_outcome() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect::default();
        let mut data = protocol_header(PROTOCOL_ID_SASL);
        data.extend_from_slice(&frame(FRAME_TYPE_SASL, 0, b"outcome"));
        parser.feed(&data, &mut h);
        assert_eq!(h.frames.len(), 1);

        parser.expect_protocol_header();
        let mut data2 = protocol_header(PROTOCOL_ID_AMQP);
        data2.extend_from_slice(&frame(FRAME_TYPE_AMQP, 0, b"open"));
        parser.feed(&data2, &mut h);

        assert_eq!(h.headers, vec![(PROTOCOL_ID_SASL, 1, 0, 0), (PROTOCOL_ID_AMQP, 1, 0, 0)]);
        assert_eq!(h.frames[1], (FRAME_TYPE_AMQP, 0, b"open".to_vec()));
    }

    /// Regression test for a real bug: a peer that pipelines its
    /// `sasl-outcome` frame immediately followed by its AMQP protocol
    /// header (both landing in the client's inbound buffer before the
    /// client's reactor even gets a chance to react to the first one) must
    /// still have the header bytes recognized as a protocol header, not
    /// misread as the next frame's size field. This only reproduces when
    /// both arrive in the *same* `feed()` call — calling
    /// [`Amqp1FrameParser::expect_protocol_header`] between two separate
    /// `feed()` calls (as [`header_rearm_after_sasl_outcome`] does) always
    /// worked and never exercised this path.
    #[test]
    fn header_rearm_takes_effect_within_a_single_feed_call() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect { rearm_after_next_sasl_frame: true, ..Default::default() };

        let mut data = protocol_header(PROTOCOL_ID_SASL);
        data.extend_from_slice(&frame(FRAME_TYPE_SASL, 0, b"outcome"));
        // The AMQP header + a frame, appended to the *same* buffer as the
        // SASL outcome above, delivered in one `feed()` call — simulating
        // both arriving in a single TCP read.
        data.extend_from_slice(&protocol_header(PROTOCOL_ID_AMQP));
        data.extend_from_slice(&frame(FRAME_TYPE_AMQP, 0, b"open"));

        parser.feed(&data, &mut h);

        assert!(h.errors.is_empty(), "unexpected errors: {:?}", h.errors);
        assert_eq!(h.headers, vec![(PROTOCOL_ID_SASL, 1, 0, 0), (PROTOCOL_ID_AMQP, 1, 0, 0)]);
        assert_eq!(h.frames, vec![
            (FRAME_TYPE_SASL, 0, b"outcome".to_vec()),
            (FRAME_TYPE_AMQP, 0, b"open".to_vec()),
        ]);
    }

    #[test]
    fn oversize_frame_is_rejected_before_body_buffering() {
        let mut parser = Amqp1FrameParser::new(64);
        let mut h = Collect::default();
        let mut data = protocol_header(PROTOCOL_ID_AMQP);
        data.extend_from_slice(&frame(FRAME_TYPE_AMQP, 0, &[0u8; 200]));
        parser.feed(&data, &mut h);
        assert_eq!(h.errors.len(), 1);
        assert!(matches!(h.errors[0], Amqp1Error::FrameTooLarge { .. }));
    }

    #[test]
    fn bad_protocol_header_magic_errors() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect::default();
        parser.feed(b"XXXX\x00\x01\x00\x00", &mut h);
        assert_eq!(h.errors.len(), 1);
    }

    #[test]
    fn invalid_doff_errors() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect::default();
        let mut data = protocol_header(PROTOCOL_ID_AMQP);
        // doff = 1 (< 2) is invalid.
        data.extend_from_slice(&[0, 0, 0, 8, 1, FRAME_TYPE_AMQP, 0, 0]);
        parser.feed(&data, &mut h);
        assert_eq!(h.errors.len(), 1);
    }

    #[test]
    fn byte_by_byte_delivery() {
        let mut parser = Amqp1FrameParser::new(0);
        let mut h = Collect::default();
        let mut data = protocol_header(PROTOCOL_ID_AMQP);
        data.extend_from_slice(&frame(FRAME_TYPE_AMQP, 1, b"x"));
        for b in &data {
            parser.feed(std::slice::from_ref(b), &mut h);
        }
        assert_eq!(h.headers.len(), 1);
        assert_eq!(h.frames, vec![(FRAME_TYPE_AMQP, 1, b"x".to_vec())]);
    }
}
