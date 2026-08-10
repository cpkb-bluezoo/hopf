// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Streaming BER (Basic Encoding Rules) decoder for ASN.1 data (ITU-T X.690).
//!
//! Designed for non-blocking I/O: accept data incrementally via [`BerDecoder::receive`]
//! and retrieve complete elements via [`BerDecoder::next`].

use super::element::Asn1Element;
use super::error::Asn1Error;
use super::types::Asn1Type;
use std::collections::VecDeque;

const STATE_TAG: u8 = 0;
const STATE_TAG_MULTI: u8 = 1;
const STATE_LENGTH: u8 = 2;
const STATE_LENGTH_MULTI: u8 = 3;
const STATE_VALUE: u8 = 4;

const DEFAULT_CAPACITY: usize = 8192;
const MAX_VALUE_SIZE: usize = 10 * 1024 * 1024;
/// Matches `BerEncoder`'s `MAX_DEPTH` — the write side already enforces
/// this; a message with deeper nesting than the encoder could ever produce
/// is necessarily hostile.
const MAX_DEPTH: usize = 32;

/// Streaming BER decoder (definite-length only).
#[derive(Debug)]
pub struct BerDecoder {
    /// Accumulated unread input.
    buffer: Vec<u8>,
    /// Read cursor into `buffer`.
    pos: usize,
    state: u8,
    tag: u32,
    length: usize,
    length_bytes_remaining: usize,
    value_buffer: Option<Vec<u8>>,
    value_offset: usize,
    completed: VecDeque<Asn1Element>,
    /// Nesting depth of this decoder: 0 for a top-level decoder, N+1 for a
    /// child decoder created by `parse_children` to decode a constructed
    /// element's contents at depth N.
    depth: usize,
}

impl Default for BerDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl BerDecoder {
    /// Creates a new BER decoder with default buffer size (8KB).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Creates a new BER decoder with the specified initial buffer capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_depth(capacity, 0)
    }

    fn with_capacity_and_depth(capacity: usize, depth: usize) -> Self {
        let mut decoder = Self {
            buffer: Vec::with_capacity(capacity),
            pos: 0,
            state: STATE_TAG,
            tag: 0,
            length: 0,
            length_bytes_remaining: 0,
            value_buffer: None,
            value_offset: 0,
            completed: VecDeque::new(),
            depth,
        };
        decoder.reset();
        decoder
    }

    /// Resets the decoder state, discarding any partial data.
    pub fn reset(&mut self) {
        self.state = STATE_TAG;
        self.tag = 0;
        self.length = 0;
        self.length_bytes_remaining = 0;
        self.value_buffer = None;
        self.value_offset = 0;
        self.buffer.clear();
        self.pos = 0;
        self.completed.clear();
    }

    /// Receives data for decoding.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), Asn1Error> {
        self.compact_if_needed();
        self.buffer.extend_from_slice(data);
        self.decode()
    }

    /// Returns the next complete element, or `None` if none available.
    pub fn next(&mut self) -> Option<Asn1Element> {
        self.completed.pop_front()
    }

    /// Returns whether there is data still being accumulated.
    pub fn has_partial_data(&self) -> bool {
        self.state != STATE_TAG || self.pos < self.buffer.len()
    }

    fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.pos)
    }

    fn compact_if_needed(&mut self) {
        if self.pos > 0 && self.pos == self.buffer.len() {
            self.buffer.clear();
            self.pos = 0;
        } else if self.pos > 0 && self.pos > self.buffer.capacity() / 2 {
            self.buffer.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.pos < self.buffer.len() {
            let b = self.buffer[self.pos];
            self.pos += 1;
            Some(b)
        } else {
            None
        }
    }

    fn decode(&mut self) -> Result<(), Asn1Error> {
        loop {
            if self.remaining() == 0 && self.state == STATE_TAG {
                break;
            }
            if self.remaining() == 0 {
                // Need more data for current state
                break;
            }

            let progressed = match self.state {
                STATE_TAG => self.decode_tag()?,
                STATE_TAG_MULTI => self.decode_tag_multi()?,
                STATE_LENGTH => self.decode_length()?,
                STATE_LENGTH_MULTI => self.decode_length_multi()?,
                STATE_VALUE => self.decode_value()?,
                _ => unreachable!(),
            };

            if !progressed {
                break;
            }

            if self.state == STATE_TAG && self.remaining() == 0 {
                break;
            }
        }

        // Compact consumed prefix (mirrors Java ByteBuffer.compact)
        if self.pos > 0 {
            self.buffer.drain(..self.pos);
            self.pos = 0;
        }
        Ok(())
    }

    fn decode_tag(&mut self) -> Result<bool, Asn1Error> {
        let Some(b) = self.read_u8() else {
            return Ok(false);
        };
        if (b & 0x1F) == 0x1F {
            self.tag = u32::from(b);
            self.state = STATE_TAG_MULTI;
        } else {
            self.tag = u32::from(b);
            self.state = STATE_LENGTH;
        }
        Ok(true)
    }

    fn decode_tag_multi(&mut self) -> Result<bool, Asn1Error> {
        let mut any = false;
        while let Some(b) = self.read_u8() {
            any = true;
            self.tag = (self.tag << 8) | u32::from(b);
            if (b & 0x80) == 0 {
                self.state = STATE_LENGTH;
                return Ok(true);
            }
        }
        Ok(any)
    }

    fn decode_length(&mut self) -> Result<bool, Asn1Error> {
        let Some(b) = self.read_u8() else {
            return Ok(false);
        };
        if b == 0x80 {
            return Err(Asn1Error::new(
                "Indefinite length encoding not supported",
            ));
        } else if (b & 0x80) == 0 {
            self.length = usize::from(b);
            self.start_value()?;
        } else {
            self.length_bytes_remaining = usize::from(b & 0x7F);
            if self.length_bytes_remaining > 4 {
                return Err(Asn1Error::new(format!(
                    "Length too large: {} bytes",
                    self.length_bytes_remaining
                )));
            }
            self.length = 0;
            self.state = STATE_LENGTH_MULTI;
        }
        Ok(true)
    }

    fn decode_length_multi(&mut self) -> Result<bool, Asn1Error> {
        let mut any = false;
        while self.remaining() > 0 && self.length_bytes_remaining > 0 {
            let b = self.read_u8().unwrap();
            any = true;
            self.length = (self.length << 8) | usize::from(b);
            self.length_bytes_remaining -= 1;
        }
        if self.length_bytes_remaining == 0 {
            self.start_value()?;
            Ok(true)
        } else {
            Ok(any)
        }
    }

    fn start_value(&mut self) -> Result<(), Asn1Error> {
        if self.length == 0 {
            self.complete_element(Vec::new())?;
        } else if self.length > MAX_VALUE_SIZE {
            return Err(Asn1Error::new(format!(
                "Value too large: {} bytes",
                self.length
            )));
        } else {
            self.value_buffer = Some(vec![0u8; self.length]);
            self.value_offset = 0;
            self.state = STATE_VALUE;
        }
        Ok(())
    }

    fn decode_value(&mut self) -> Result<bool, Asn1Error> {
        let needed = self.length - self.value_offset;
        let available = self.remaining();
        let to_copy = available.min(needed);
        if to_copy == 0 {
            return Ok(false);
        }

        {
            let buf = self.value_buffer.as_mut().unwrap();
            buf[self.value_offset..self.value_offset + to_copy]
                .copy_from_slice(&self.buffer[self.pos..self.pos + to_copy]);
        }
        self.pos += to_copy;
        self.value_offset += to_copy;

        if self.value_offset == self.length {
            let value = self.value_buffer.take().unwrap();
            self.complete_element(value)?;
            Ok(true)
        } else {
            Ok(true)
        }
    }

    fn complete_element(&mut self, value: Vec<u8>) -> Result<(), Asn1Error> {
        // LDAP tags fit in one byte; multi-byte tags are rare.
        let tag_byte = (self.tag & 0xFF) as u8;
        let element = if Asn1Type::is_constructed(tag_byte) {
            let children = parse_children(&value, self.depth)?;
            Asn1Element::constructed(tag_byte, children)
        } else {
            Asn1Element::primitive(tag_byte, value)
        };

        self.completed.push_back(element);

        self.state = STATE_TAG;
        self.tag = 0;
        self.length = 0;
        self.value_buffer = None;
        self.value_offset = 0;
        Ok(())
    }
}

fn parse_children(data: &[u8], depth: usize) -> Result<Vec<Asn1Element>, Asn1Error> {
    if depth >= MAX_DEPTH {
        return Err(Asn1Error::new(format!(
            "Nesting depth exceeds maximum of {}",
            MAX_DEPTH
        )));
    }
    let mut child_decoder = BerDecoder::with_capacity_and_depth(data.len().max(1), depth + 1);
    child_decoder.receive(data)?;

    let mut children = Vec::new();
    while let Some(child) = child_decoder.next() {
        children.push(child);
    }

    if child_decoder.has_partial_data() {
        return Err(Asn1Error::new(
            "Incomplete child element in constructed type",
        ));
    }

    Ok(children)
}

#[cfg(test)]
mod tests {
    use super::BerDecoder;
    use crate::asn1::encoder::BerEncoder;
    use crate::asn1::types::Asn1Type;

    #[test]
    fn decode_boolean() {
        let data = [0x01, 0x01, 0xFF];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag(), Asn1Type::BOOLEAN);
        assert!(element.as_bool().unwrap());
    }

    #[test]
    fn decode_boolean_false() {
        let data = [0x01, 0x01, 0x00];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert!(!element.as_bool().unwrap());
    }

    #[test]
    fn decode_integer_small() {
        let data = [0x02, 0x01, 0x2A];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag(), Asn1Type::INTEGER);
        assert_eq!(element.as_i32().unwrap(), 42);
    }

    #[test]
    fn decode_integer_negative() {
        let data = [0x02, 0x01, 0xFF];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        assert_eq!(decoder.next().unwrap().as_i32().unwrap(), -1);
    }

    #[test]
    fn decode_integer_two_bytes() {
        let data = [0x02, 0x02, 0x01, 0x00];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        assert_eq!(decoder.next().unwrap().as_i32().unwrap(), 256);
    }

    #[test]
    fn decode_octet_string() {
        let data = [0x04, 0x04, 0x74, 0x65, 0x73, 0x74];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag(), Asn1Type::OCTET_STRING);
        assert_eq!(element.as_string().as_deref(), Some("test"));
    }

    #[test]
    fn decode_null() {
        let data = [0x05, 0x00];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag(), Asn1Type::NULL);
        assert_eq!(element.value().unwrap().len(), 0);
    }

    #[test]
    fn decode_enumerated() {
        let data = [0x0A, 0x01, 0x02];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag(), Asn1Type::ENUMERATED);
        assert_eq!(element.as_i32().unwrap(), 2);
    }

    #[test]
    fn decode_sequence() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag(), Asn1Type::SEQUENCE);
        assert!(element.is_constructed());
        assert_eq!(element.child_count(), 1);
        assert_eq!(element.child(0).as_i32().unwrap(), 1);
    }

    #[test]
    fn decode_nested_sequence() {
        let data = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let outer = decoder.next().unwrap();
        assert_eq!(outer.child_count(), 1);
        let inner = outer.child(0);
        assert_eq!(inner.tag(), Asn1Type::SEQUENCE);
        assert_eq!(inner.child_count(), 1);
        assert_eq!(inner.child(0).as_i32().unwrap(), 2);
    }

    #[test]
    fn decode_long_form_length_one_byte() {
        let mut data = vec![0u8; 3 + 200];
        data[0] = 0x04;
        data[1] = 0x81;
        data[2] = 200;
        for i in 0..200 {
            data[3 + i] = i as u8;
        }
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.value().unwrap().len(), 200);
    }

    #[test]
    fn decode_long_form_length_two_bytes() {
        let mut data = vec![0u8; 4 + 1000];
        data[0] = 0x04;
        data[1] = 0x82;
        data[2] = 0x03;
        data[3] = 0xE8;
        for i in 0..1000 {
            data[4 + i] = i as u8;
        }
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.value().unwrap().len(), 1000);
    }

    #[test]
    fn incremental_decode() {
        let data = [0x02, 0x01, 0x2A];
        let mut decoder = BerDecoder::new();

        decoder.receive(&data[0..1]).unwrap();
        assert!(decoder.next().is_none());
        assert!(decoder.has_partial_data());

        decoder.receive(&data[1..2]).unwrap();
        assert!(decoder.next().is_none());

        decoder.receive(&data[2..3]).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.as_i32().unwrap(), 42);
        assert!(!decoder.has_partial_data());
    }

    #[test]
    fn multiple_elements() {
        let data = [0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        assert_eq!(decoder.next().unwrap().as_i32().unwrap(), 1);
        assert_eq!(decoder.next().unwrap().as_i32().unwrap(), 2);
        assert!(decoder.next().is_none());
    }

    #[test]
    fn decode_context_primitive() {
        let data = [0x80, 0x02, 0x01, 0x02];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag_class(), Asn1Type::CLASS_CONTEXT);
        assert_eq!(element.tag_number(), 0);
        assert!(!element.is_constructed());
        assert_eq!(element.value().unwrap().len(), 2);
    }

    #[test]
    fn decode_context_constructed() {
        let data = [0xA3, 0x03, 0x02, 0x01, 0x01];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag_class(), Asn1Type::CLASS_CONTEXT);
        assert_eq!(element.tag_number(), 3);
        assert!(element.is_constructed());
        assert_eq!(element.child_count(), 1);
    }

    #[test]
    fn decode_application_tag() {
        let data = [0x60, 0x03, 0x02, 0x01, 0x03];
        let mut decoder = BerDecoder::new();
        decoder.receive(&data).unwrap();
        let element = decoder.next().unwrap();
        assert_eq!(element.tag_class(), Asn1Type::CLASS_APPLICATION);
        assert_eq!(element.tag_number(), 0);
        assert!(element.is_constructed());
    }

    #[test]
    fn reset() {
        let mut decoder = BerDecoder::new();
        decoder.receive(&[0x02, 0x01]).unwrap();
        assert!(decoder.has_partial_data());

        decoder.reset();
        assert!(!decoder.has_partial_data());

        decoder.receive(&[0x02, 0x01, 0x2A]).unwrap();
        assert_eq!(decoder.next().unwrap().as_i32().unwrap(), 42);
    }

    #[test]
    fn deeply_nested_sequences_within_limit_decode_successfully() {
        // 32 nested SEQUENCEs (matching BerEncoder's own MAX_DEPTH) via the
        // encoder, so the fix doesn't reject anything the encoder can
        // legitimately produce.
        let mut encoder = BerEncoder::new();
        for _ in 0..32 {
            encoder.begin_sequence();
        }
        encoder.write_integer_i32(7);
        for _ in 0..32 {
            encoder.end_sequence();
        }
        let encoded = encoder.to_bytes();

        let mut decoder = BerDecoder::new();
        decoder.receive(&encoded).unwrap();
        let mut current = decoder.next().unwrap();
        for _ in 0..31 {
            assert_eq!(current.child_count(), 1);
            current = current.child(0).clone();
        }
        assert_eq!(current.child(0).as_i32().unwrap(), 7);
    }

    #[test]
    fn excessively_nested_sequences_are_rejected_not_stack_overflowed() {
        // One nesting level beyond what the encoder itself will produce —
        // must be rejected with an error, not recursed into.
        let depth = 10_000;
        let mut data = Vec::new();
        for _ in 0..depth {
            data.push(0x30); // SEQUENCE, constructed
        }
        // Build lengths from the innermost element outward so every
        // declared length is correct definite-length BER (long-form once
        // nesting pushes the content past 127 bytes).
        fn ber_length(len: usize) -> Vec<u8> {
            if len < 0x80 {
                vec![len as u8]
            } else {
                let bytes = len.to_be_bytes();
                let significant: Vec<u8> = bytes
                    .iter()
                    .copied()
                    .skip_while(|&b| b == 0)
                    .collect();
                let mut out = vec![0x80 | significant.len() as u8];
                out.extend_from_slice(&significant);
                out
            }
        }

        let mut body: Vec<u8> = vec![0x02, 0x01, 0x00]; // INTEGER 0
        for _ in 0..depth {
            let mut wrapped = vec![0x30];
            wrapped.extend_from_slice(&ber_length(body.len()));
            wrapped.extend_from_slice(&body);
            body = wrapped;
        }

        let mut decoder = BerDecoder::new();
        let err = decoder.receive(&body).unwrap_err();
        assert!(err.message().contains("depth"), "{}", err.message());
    }

    #[test]
    fn indefinite_length_rejected() {
        let data = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00];
        let mut decoder = BerDecoder::new();
        let err = decoder.receive(&data).unwrap_err();
        assert!(err.message().contains("Indefinite length"));
    }

    #[test]
    fn round_trip() {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(42);
        encoder.write_octet_string_str("hello");
        encoder.write_boolean(true);
        encoder.end_sequence();
        let encoded = encoder.to_bytes();

        let mut decoder = BerDecoder::new();
        decoder.receive(&encoded).unwrap();
        let seq = decoder.next().unwrap();
        assert_eq!(seq.tag(), Asn1Type::SEQUENCE);
        assert_eq!(seq.child_count(), 3);
        assert_eq!(seq.child(0).as_i32().unwrap(), 42);
        assert_eq!(seq.child(1).as_string().as_deref(), Some("hello"));
        assert!(seq.child(2).as_bool().unwrap());
    }

    #[test]
    fn round_trip_nested_structure() {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(1);
        encoder.begin_sequence();
        encoder.write_integer_i32(2);
        encoder.write_integer_i32(3);
        encoder.end_sequence();
        encoder.end_sequence();
        let encoded = encoder.to_bytes();

        let mut decoder = BerDecoder::new();
        decoder.receive(&encoded).unwrap();
        let outer = decoder.next().unwrap();
        assert_eq!(outer.child_count(), 2);
        assert_eq!(outer.child(0).as_i32().unwrap(), 1);
        let inner = outer.child(1);
        assert_eq!(inner.child_count(), 2);
        assert_eq!(inner.child(0).as_i32().unwrap(), 2);
        assert_eq!(inner.child(1).as_i32().unwrap(), 3);
    }

    #[test]
    fn ldap_bind_request_round_trip() {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(1);
        encoder.begin_application(0, true);
        encoder.write_integer_i32(3);
        encoder.write_octet_string_str("cn=admin,dc=example,dc=com");
        encoder.write_context(0, b"secret");
        encoder.end_application();
        encoder.end_sequence();
        let encoded = encoder.to_bytes();

        let mut decoder = BerDecoder::new();
        decoder.receive(&encoded).unwrap();
        let msg = decoder.next().unwrap();
        assert_eq!(msg.tag(), Asn1Type::SEQUENCE);
        assert_eq!(msg.child(0).as_i32().unwrap(), 1);
        let bind = msg.child(1);
        assert_eq!(bind.tag_class(), Asn1Type::CLASS_APPLICATION);
        assert_eq!(bind.tag_number(), 0);
        assert_eq!(bind.child(0).as_i32().unwrap(), 3);
        assert_eq!(
            bind.child(1).as_string().as_deref(),
            Some("cn=admin,dc=example,dc=com")
        );
        assert_eq!(bind.child(2).value(), Some(b"secret".as_slice()));
    }
}
