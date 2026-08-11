// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Incremental push AMQP frame parser.

use std::collections::HashMap;

use super::methods::MethodFrame;
use super::properties::BasicProperties;
use super::types::{FRAME_BODY, FRAME_END, FRAME_HEADER, FRAME_HEARTBEAT, FRAME_METHOD};
use super::AmqpError;

/// Default max frame size accepted before negotiation completes.
pub const DEFAULT_MAX_FRAME: u32 = 131_072;

/// Callbacks from [`AmqpFrameParser`].
pub trait AmqpFrameHandler {
    /// Complete method frame.
    fn method(&mut self, frame: MethodFrame);
    /// Content header (start of a content-bearing method's body).
    fn content_header(
        &mut self,
        channel: u16,
        class_id: u16,
        body_size: u64,
        properties: BasicProperties,
    );
    /// Chunk of content body (`data` valid for this call only).
    fn content_body(&mut self, channel: u16, data: &[u8]);
    /// Heartbeat received.
    fn heartbeat(&mut self);
    /// Parse / protocol error.
    fn error(&mut self, err: AmqpError);
}

/// Incremental frame parser.
pub struct AmqpFrameParser {
    buf: Vec<u8>,
    max_frame: u32,
    /// Remaining body bytes expected for the current content, per channel
    /// (absent once that channel has no content in flight). Keyed by
    /// channel rather than a single scalar because AMQP 0-9-1 permits the
    /// broker to interleave content frames from *different* channels on
    /// one connection — only same-channel content must be contiguous
    /// (issue #180).
    body_remaining: HashMap<u16, u64>,
}

impl AmqpFrameParser {
    /// Create a parser with the given max frame size.
    pub fn new(max_frame: u32) -> Self {
        Self {
            buf: Vec::new(),
            max_frame: if max_frame == 0 {
                DEFAULT_MAX_FRAME
            } else {
                max_frame
            },
            body_remaining: HashMap::new(),
        }
    }

    /// Update max frame after tune negotiation.
    pub fn set_max_frame(&mut self, max_frame: u32) {
        self.max_frame = if max_frame == 0 {
            DEFAULT_FRAME_MAX_FALLBACK
        } else {
            max_frame
        };
    }

    /// Feed inbound bytes; invokes handler callbacks as frames complete.
    pub fn feed(&mut self, data: &[u8], handler: &mut dyn AmqpFrameHandler) {
        self.buf.extend_from_slice(data);
        loop {
            if self.buf.len() < 7 {
                return;
            }
            let frame_type = self.buf[0];
            let channel = u16::from_be_bytes([self.buf[1], self.buf[2]]);
            let size = u32::from_be_bytes([self.buf[3], self.buf[4], self.buf[5], self.buf[6]]);
            if size > self.max_frame.saturating_sub(8).max(self.max_frame) && size > self.max_frame {
                // Allow size up to max_frame payload; frame total is size+8.
                if size > self.max_frame {
                    handler.error(AmqpError::FrameTooLarge {
                        size,
                        max: self.max_frame,
                    });
                    self.buf.clear();
                    return;
                }
            }
            let total = 7 + size as usize + 1;
            if self.buf.len() < total {
                return;
            }
            if self.buf[total - 1] != FRAME_END {
                handler.error(AmqpError::Malformed("bad frame end"));
                self.buf.clear();
                return;
            }
            let payload = self.buf[7..total - 1].to_vec();
            self.buf.drain(..total);

            match frame_type {
                FRAME_METHOD => {
                    if payload.len() < 4 {
                        handler.error(AmqpError::Malformed("truncated method ids"));
                        continue;
                    }
                    let class_id = u16::from_be_bytes([payload[0], payload[1]]);
                    let method_id = u16::from_be_bytes([payload[2], payload[3]]);
                    let args = payload[4..].to_vec();
                    handler.method(MethodFrame {
                        channel,
                        class_id,
                        method_id,
                        args,
                    });
                }
                FRAME_HEADER => {
                    if payload.len() < 14 {
                        handler.error(AmqpError::Malformed("truncated content header"));
                        continue;
                    }
                    let class_id = u16::from_be_bytes([payload[0], payload[1]]);
                    // weight at [2..4]
                    let body_size = u64::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7], payload[8], payload[9],
                        payload[10], payload[11],
                    ]);
                    let mut prop_data: &[u8] = &payload[12..];
                    match BasicProperties::decode(&mut prop_data) {
                        Ok(properties) => {
                            if body_size == 0 {
                                self.body_remaining.remove(&channel);
                            } else {
                                self.body_remaining.insert(channel, body_size);
                            }
                            handler.content_header(channel, class_id, body_size, properties);
                        }
                        Err(e) => handler.error(e),
                    }
                }
                FRAME_BODY => {
                    let n = payload.len() as u64;
                    let remaining = self.body_remaining.get(&channel).copied().unwrap_or(0);
                    if n > remaining {
                        handler.error(AmqpError::Malformed("content body exceeds declared size"));
                        self.body_remaining.remove(&channel);
                        continue;
                    }
                    handler.content_body(channel, &payload);
                    let left = remaining - n;
                    if left == 0 {
                        self.body_remaining.remove(&channel);
                    } else {
                        self.body_remaining.insert(channel, left);
                    }
                }
                FRAME_HEARTBEAT => {
                    if channel != 0 || !payload.is_empty() {
                        handler.error(AmqpError::Malformed("invalid heartbeat frame"));
                    } else {
                        handler.heartbeat();
                    }
                }
                other => handler.error(AmqpError::UnknownFrameType(other)),
            }
        }
    }
}

const DEFAULT_FRAME_MAX_FALLBACK: u32 = DEFAULT_MAX_FRAME;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode::{encode_content, encode_content_header, encode_heartbeat, encode_method};
    use crate::codec::types::class;

    struct Collect {
        methods: Vec<(u16, u16, u16)>,
        heartbeats: u32,
        body_bytes: usize,
        headers: u32,
        errors: Vec<AmqpError>,
        /// Body bytes received per channel, in arrival order — lets
        /// interleaving tests check attribution, not just totals.
        body_by_channel: HashMap<u16, Vec<u8>>,
    }

    impl AmqpFrameHandler for Collect {
        fn method(&mut self, frame: MethodFrame) {
            self.methods
                .push((frame.channel, frame.class_id, frame.method_id));
        }
        fn content_header(
            &mut self,
            _channel: u16,
            _class_id: u16,
            _body_size: u64,
            _properties: BasicProperties,
        ) {
            self.headers += 1;
        }
        fn content_body(&mut self, channel: u16, data: &[u8]) {
            self.body_bytes += data.len();
            self.body_by_channel.entry(channel).or_default().extend_from_slice(data);
        }
        fn heartbeat(&mut self) {
            self.heartbeats += 1;
        }
        fn error(&mut self, err: AmqpError) {
            self.errors.push(err);
        }
    }

    impl Collect {
        fn new() -> Self {
            Self {
                methods: vec![],
                heartbeats: 0,
                body_bytes: 0,
                headers: 0,
                errors: vec![],
                body_by_channel: HashMap::new(),
            }
        }
    }

    #[test]
    fn parse_method_and_heartbeat() {
        let mut parser = AmqpFrameParser::new(131_072);
        let mut h = Collect::new();
        let mut data = encode_method(1, class::CHANNEL, 10, &[0]);
        data.extend_from_slice(&encode_heartbeat());
        // feed in tiny chunks
        for chunk in data.chunks(3) {
            parser.feed(chunk, &mut h);
        }
        assert_eq!(h.methods.len(), 1);
        assert_eq!(h.heartbeats, 1);
        assert!(h.errors.is_empty());
    }

    #[test]
    fn parse_content_stream() {
        let mut parser = AmqpFrameParser::new(131_072);
        let mut h = Collect::new();
        let props = BasicProperties::new();
        let body = b"hello amqp body";
        let data = encode_content(1, &props, body, 131_072).unwrap();
        parser.feed(&data, &mut h);
        assert_eq!(h.headers, 1);
        assert_eq!(h.body_bytes, body.len());
        assert!(h.errors.is_empty());
    }

    /// AMQP 0-9-1 permits the broker to interleave content frames from
    /// *different* channels on one connection (only same-channel content
    /// must be contiguous). Two channels' headers and bodies arriving
    /// interleaved — header 1, header 2, body 1, body 2 — must reassemble
    /// each channel's content independently, not corrupt or cross-attribute
    /// bytes between them (issue #180).
    #[test]
    fn interleaved_channel_content_reassembles_independently() {
        let mut parser = AmqpFrameParser::new(131_072);
        let mut h = Collect::new();
        let props = BasicProperties::new();

        let header1 = encode_content_header(1, 5, &props).unwrap();
        let header2 = encode_content_header(2, 6, &props).unwrap();
        let body1 = crate::codec::encode::encode_content_body(1, b"one-A");
        let body2 = crate::codec::encode::encode_content_body(2, b"two-AB");

        // Interleave: both headers open before either body frame arrives.
        let mut data = Vec::new();
        data.extend_from_slice(&header1);
        data.extend_from_slice(&header2);
        data.extend_from_slice(&body1);
        data.extend_from_slice(&body2);
        parser.feed(&data, &mut h);

        assert!(h.errors.is_empty(), "unexpected errors: {:?}", h.errors);
        assert_eq!(h.headers, 2);
        assert_eq!(h.body_by_channel.get(&1).map(Vec::as_slice), Some(&b"one-A"[..]));
        assert_eq!(h.body_by_channel.get(&2).map(Vec::as_slice), Some(&b"two-AB"[..]));
    }
}
