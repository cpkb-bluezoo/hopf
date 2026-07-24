// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! gRPC message framing (5-byte prefix) and push frame parser.
//!
//! Each gRPC message is prefixed with:
//! - 1 byte: compressed flag (0 = uncompressed, 1 = compressed)
//! - 4 bytes: message length (big-endian)

use std::error::Error;
use std::fmt;

/// Default maximum gRPC message payload size: 4 MiB (common gRPC default).
pub const DEFAULT_MAX_MESSAGE_SIZE: u64 = 4 * 1024 * 1024;

const HEADER_SIZE: usize = 5;
const UNCOMPRESSED: u8 = 0;

/// Error from gRPC framing helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcFramingError {
    message: String,
}

impl GrpcFramingError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for GrpcFramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for GrpcFramingError {}

/// Static helpers for the gRPC 5-byte length prefix (Gumdrop `GrpcFraming`).
pub struct GrpcFraming;

impl GrpcFraming {
    /// Wraps a message with the gRPC 5-byte prefix (uncompressed).
    pub fn frame(message: &[u8]) -> Vec<u8> {
        frame(message)
    }

    /// Returns the total size of a framed message (header + payload).
    pub fn framed_size(payload_length: usize) -> usize {
        framed_size(payload_length)
    }

    /// Parses the gRPC frame header with no payload-size limit
    /// (except `u32::MAX`).
    ///
    /// Returns `Ok(None)` if the header is incomplete.
    pub fn read_header(data: &[u8]) -> Result<Option<u32>, GrpcFramingError> {
        Self::read_header_limited(data, u64::MAX)
    }

    /// Parses the gRPC frame header.
    ///
    /// `max_message_length` of `0` or `u64::MAX` means no limit except `u32::MAX`.
    /// Returns `Ok(None)` if the header is incomplete.
    pub fn read_header_limited(
        data: &[u8],
        max_message_length: u64,
    ) -> Result<Option<u32>, GrpcFramingError> {
        if data.len() < HEADER_SIZE {
            return Ok(None);
        }
        // compressed flag at data[0] — consumed but unused here (parser rejects non-zero)
        let _flag = data[0];
        let length = ((data[1] as u64) << 24)
            | ((data[2] as u64) << 16)
            | ((data[3] as u64) << 8)
            | (data[4] as u64);
        if length > u32::MAX as u64 {
            return Err(GrpcFramingError::new(format!(
                "gRPC message length exceeds maximum {}",
                u32::MAX
            )));
        }
        let message_length = length as u32;
        if max_message_length > 0 && message_length as u64 > max_message_length {
            return Err(GrpcFramingError::new(format!(
                "gRPC message length {message_length} exceeds maximum {max_message_length}"
            )));
        }
        Ok(Some(message_length))
    }

    /// Number of header bytes to skip when positioned at frame start.
    pub fn header_size() -> usize {
        HEADER_SIZE
    }
}

/// Frame a protobuf message with the gRPC 5-byte prefix (uncompressed).
pub fn frame(message: &[u8]) -> Vec<u8> {
    let length = message.len();
    let mut out = Vec::with_capacity(HEADER_SIZE + length);
    out.push(UNCOMPRESSED);
    out.push((length >> 24) as u8);
    out.push((length >> 16) as u8);
    out.push((length >> 8) as u8);
    out.push(length as u8);
    out.extend_from_slice(message);
    out
}

/// Total framed size for a payload of `payload_length` bytes.
pub fn framed_size(payload_length: usize) -> usize {
    HEADER_SIZE + payload_length
}

/// Push events for length-prefixed gRPC frames (`GrpcEventHandler`).
pub trait GrpcEventHandler {
    /// Called when a complete frame header has been parsed.
    ///
    /// `compression_flag`: 0 = uncompressed, 1 = compressed.
    fn start_message(&mut self, compression_flag: u8, length: u32);

    /// Delivers a chunk of frame payload data.
    fn message_data(&mut self, data: &[u8]);

    /// Called when the frame payload has been fully delivered.
    fn end_message(&mut self);

    /// Called when a framing error is detected.
    fn parse_error(&mut self, message: &str);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Payload,
}

/// Push-parser for gRPC length-prefixed message frames (`GrpcFrameParser`).
pub struct GrpcFrameParser<H: GrpcEventHandler> {
    handler: H,
    max_message_size: u64,
    state: State,
    header_buf: [u8; HEADER_SIZE],
    header_len: usize,
    payload_remaining: u32,
    message_completed: bool,
}

impl<H: GrpcEventHandler> GrpcFrameParser<H> {
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            state: State::Header,
            header_buf: [0; HEADER_SIZE],
            header_len: 0,
            payload_remaining: 0,
            message_completed: false,
        }
    }

    pub fn max_message_size(&self) -> u64 {
        self.max_message_size
    }

    /// Sets the maximum permitted frame payload size (`0` = unlimited).
    pub fn set_max_message_size(&mut self, max_message_size: u64) {
        self.max_message_size = max_message_size;
    }

    /// Returns true if at least one complete message frame was delivered.
    pub fn is_message_completed(&self) -> bool {
        self.message_completed
    }

    /// Returns true if a frame is partially received.
    pub fn has_partial_frame(&self) -> bool {
        self.header_len > 0 || self.state == State::Payload
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn into_handler(self) -> H {
        self.handler
    }

    /// Parses as many complete frames as possible from `data`.
    pub fn receive(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.state {
                State::Header => {
                    if !self.process_header(&mut data) {
                        return;
                    }
                }
                State::Payload => {
                    self.process_payload(&mut data);
                    if self.state == State::Header && data.is_empty() {
                        return;
                    }
                }
            }
        }
    }

    fn process_header(&mut self, data: &mut &[u8]) -> bool {
        while self.header_len < HEADER_SIZE && !data.is_empty() {
            self.header_buf[self.header_len] = data[0];
            self.header_len += 1;
            *data = &data[1..];
        }
        if self.header_len < HEADER_SIZE {
            return false;
        }

        let compression_flag = self.header_buf[0];
        if compression_flag != 0 {
            self.reset();
            self.handler
                .parse_error("Compressed gRPC frames are not supported");
            return false;
        }

        let length = ((self.header_buf[1] as u64) << 24)
            | ((self.header_buf[2] as u64) << 16)
            | ((self.header_buf[3] as u64) << 8)
            | (self.header_buf[4] as u64);
        if length > u32::MAX as u64 {
            self.reset();
            self.handler
                .parse_error(&format!("gRPC frame length too large: {length}"));
            return false;
        }
        let payload_length = length as u32;
        if self.max_message_size > 0 && payload_length as u64 > self.max_message_size {
            self.reset();
            self.handler.parse_error(&format!(
                "gRPC frame length {payload_length} exceeds maximum {}",
                self.max_message_size
            ));
            return false;
        }

        self.header_len = 0;
        self.payload_remaining = payload_length;
        self.state = State::Payload;
        self.handler
            .start_message(compression_flag, payload_length);
        true
    }

    fn process_payload(&mut self, data: &mut &[u8]) {
        let to_deliver = (*data).len().min(self.payload_remaining as usize);
        if to_deliver > 0 {
            let chunk = &data[..to_deliver];
            self.handler.message_data(chunk);
            *data = &data[to_deliver..];
            self.payload_remaining -= to_deliver as u32;
        }

        if self.payload_remaining == 0 {
            self.handler.end_message();
            self.message_completed = true;
            self.state = State::Header;
        }
    }

    fn reset(&mut self) {
        self.state = State::Header;
        self.header_len = 0;
        self.payload_remaining = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Collect {
        starts: Vec<(u8, u32)>,
        chunks: Vec<Vec<u8>>,
        ends: usize,
        errors: Vec<String>,
    }

    impl GrpcEventHandler for Collect {
        fn start_message(&mut self, compression_flag: u8, length: u32) {
            self.starts.push((compression_flag, length));
        }
        fn message_data(&mut self, data: &[u8]) {
            self.chunks.push(data.to_vec());
        }
        fn end_message(&mut self) {
            self.ends += 1;
        }
        fn parse_error(&mut self, message: &str) {
            self.errors.push(message.to_string());
        }
    }

    #[test]
    fn frame_and_parse_split() {
        let payload = b"hello";
        let framed = GrpcFraming::frame(payload);
        let mut p = GrpcFrameParser::new(Collect {
            starts: vec![],
            chunks: vec![],
            ends: 0,
            errors: vec![],
        });
        p.receive(&framed[..3]);
        assert!(p.has_partial_frame());
        p.receive(&framed[3..]);
        assert!(p.is_message_completed());
        let h = p.into_handler();
        assert_eq!(h.starts, vec![(0, 5)]);
        assert_eq!(h.chunks.concat(), payload);
        assert_eq!(h.ends, 1);
        assert!(h.errors.is_empty());
    }

    #[test]
    fn reject_compression() {
        let mut framed = frame(b"x");
        framed[0] = 1;
        let mut p = GrpcFrameParser::new(Collect {
            starts: vec![],
            chunks: vec![],
            ends: 0,
            errors: vec![],
        });
        p.receive(&framed);
        assert!(!p.into_handler().errors.is_empty());
    }

    #[test]
    fn read_header_incomplete() {
        assert_eq!(GrpcFraming::read_header(&[0, 0, 0]).unwrap(), None);
    }
}
