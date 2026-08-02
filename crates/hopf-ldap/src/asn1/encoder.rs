// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! BER (Basic Encoding Rules) encoder for ASN.1 data (ITU-T X.690).
//!
//! This encoder produces BER-encoded data suitable for LDAP protocol
//! messages (RFC 4511 section 5.1). It uses definite-length encoding
//! for all elements.

use super::element::Asn1Element;
use super::types::Asn1Type;

const MAX_DEPTH: usize = 32;

/// BER encoder producing definite-length TLV encodings.
#[derive(Debug)]
pub struct BerEncoder {
    output: Vec<u8>,
    stack: Vec<Vec<u8>>,
}

impl Default for BerEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl BerEncoder {
    /// Creates a new BER encoder.
    pub fn new() -> Self {
        Self {
            output: Vec::new(),
            stack: Vec::new(),
        }
    }

    /// Resets the encoder for reuse.
    pub fn reset(&mut self) {
        self.output.clear();
        self.stack.clear();
    }

    /// Returns the encoded data as a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.output.clone()
    }

    /// Returns a reference to the encoded data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.output
    }

    /// Consumes the encoder and returns the encoded data.
    pub fn into_bytes(self) -> Vec<u8> {
        self.output
    }

    /// Writes a complete [`Asn1Element`] to the output.
    pub fn write_element(&mut self, element: &Asn1Element) {
        if element.is_constructed() {
            self.begin_construct(element.tag());
            if let Some(children) = element.children() {
                for child in children {
                    self.write_element(child);
                }
            }
            self.end_construct();
        } else {
            let value = element.value().unwrap_or(&[]);
            self.write_raw(u32::from(element.tag()), value);
        }
    }

    /// Writes a boolean value.
    pub fn write_boolean(&mut self, value: bool) {
        self.write_raw(
            u32::from(Asn1Type::BOOLEAN),
            &[if value { 0xFF } else { 0x00 }],
        );
    }

    /// Writes a 32-bit integer value.
    pub fn write_integer_i32(&mut self, value: i32) {
        let bytes = encode_integer(value);
        self.write_raw(u32::from(Asn1Type::INTEGER), &bytes);
    }

    /// Writes a 64-bit integer value.
    pub fn write_integer_i64(&mut self, value: i64) {
        let bytes = encode_long(value);
        self.write_raw(u32::from(Asn1Type::INTEGER), &bytes);
    }

    /// Writes an enumerated value.
    pub fn write_enumerated(&mut self, value: i32) {
        let bytes = encode_integer(value);
        self.write_raw(u32::from(Asn1Type::ENUMERATED), &bytes);
    }

    /// Writes an octet string from a byte slice.
    pub fn write_octet_string(&mut self, value: &[u8]) {
        self.write_raw(u32::from(Asn1Type::OCTET_STRING), value);
    }

    /// Writes an octet string from a UTF-8 string.
    pub fn write_octet_string_str(&mut self, value: &str) {
        self.write_octet_string(value.as_bytes());
    }

    /// Writes a null value.
    pub fn write_null(&mut self) {
        self.write_raw(u32::from(Asn1Type::NULL), &[]);
    }

    /// Begins a SEQUENCE.
    pub fn begin_sequence(&mut self) {
        self.begin_construct(Asn1Type::SEQUENCE);
    }

    /// Ends a SEQUENCE.
    pub fn end_sequence(&mut self) {
        self.end_construct();
    }

    /// Begins a SET.
    pub fn begin_set(&mut self) {
        self.begin_construct(Asn1Type::SET);
    }

    /// Ends a SET.
    pub fn end_set(&mut self) {
        self.end_construct();
    }

    /// Begins a context-specific tagged element.
    pub fn begin_context(&mut self, tag_number: u8, constructed: bool) {
        let tag = Asn1Type::context_tag(tag_number, constructed);
        self.begin_construct(tag);
    }

    /// Ends a context-specific tagged element.
    pub fn end_context(&mut self) {
        self.end_construct();
    }

    /// Begins an application-specific tagged element.
    pub fn begin_application(&mut self, tag_number: u8, constructed: bool) {
        let tag = Asn1Type::application_tag(tag_number, constructed);
        self.begin_construct(tag);
    }

    /// Ends an application-specific tagged element.
    pub fn end_application(&mut self) {
        self.end_construct();
    }

    /// Writes an application-specific primitive value.
    pub fn write_application(&mut self, tag_number: u8, value: &[u8]) {
        let tag = Asn1Type::application_tag(tag_number, false);
        self.write_raw(u32::from(tag), value);
    }

    /// Writes a context-specific primitive value.
    pub fn write_context(&mut self, tag_number: u8, value: &[u8]) {
        let tag = Asn1Type::context_tag(tag_number, false);
        self.write_raw(u32::from(tag), value);
    }

    /// Writes a context-specific primitive string value (UTF-8).
    pub fn write_context_str(&mut self, tag_number: u8, value: &str) {
        self.write_context(tag_number, value.as_bytes());
    }

    fn begin_construct(&mut self, tag: u8) {
        if self.stack.len() >= MAX_DEPTH {
            panic!("Nesting too deep");
        }
        // Push a new buffer; tag is written first, length prepended on end.
        let mut buf = Vec::new();
        buf.push(tag);
        self.stack.push(buf);
    }

    fn end_construct(&mut self) {
        let construct = self
            .stack
            .pop()
            .expect("No construct to end");
        // data[0] is the tag, data[1:] is the content
        let tag = u32::from(construct[0]);
        let content = &construct[1..];
        self.write_raw(tag, content);
    }

    fn write_raw(&mut self, tag: u32, value: &[u8]) {
        let out = self.current_output();

        // Write tag
        if tag <= 0xFF {
            out.push(tag as u8);
        } else {
            // Multi-byte tag (rare in LDAP)
            out.push(((tag >> 24) & 0xFF) as u8);
            out.push(((tag >> 16) & 0xFF) as u8);
            out.push(((tag >> 8) & 0xFF) as u8);
            out.push((tag & 0xFF) as u8);
        }

        write_length(out, value.len());
        out.extend_from_slice(value);
    }

    fn current_output(&mut self) -> &mut Vec<u8> {
        if let Some(top) = self.stack.last_mut() {
            top
        } else {
            &mut self.output
        }
    }
}

fn write_length(out: &mut Vec<u8>, length: usize) {
    if length < 128 {
        out.push(length as u8);
    } else if length < 256 {
        out.push(0x81);
        out.push(length as u8);
    } else if length < 65536 {
        out.push(0x82);
        out.push(((length >> 8) & 0xFF) as u8);
        out.push((length & 0xFF) as u8);
    } else if length < 16_777_216 {
        out.push(0x83);
        out.push(((length >> 16) & 0xFF) as u8);
        out.push(((length >> 8) & 0xFF) as u8);
        out.push((length & 0xFF) as u8);
    } else {
        out.push(0x84);
        out.push(((length >> 24) & 0xFF) as u8);
        out.push(((length >> 16) & 0xFF) as u8);
        out.push(((length >> 8) & 0xFF) as u8);
        out.push((length & 0xFF) as u8);
    }
}

fn encode_integer(value: i32) -> Vec<u8> {
    if (-128..=127).contains(&value) {
        vec![value as u8]
    } else if (-32768..=32767).contains(&value) {
        vec![(value >> 8) as u8, value as u8]
    } else if (-8_388_608..=8_388_607).contains(&value) {
        vec![(value >> 16) as u8, (value >> 8) as u8, value as u8]
    } else {
        vec![
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]
    }
}

fn encode_long(mut value: i64) -> Vec<u8> {
    // Find minimum bytes needed (matches Gumdrop BEREncoder.encodeLong)
    let mut bytes = 8;
    let original = value;
    let mut test = value;
    for i in 0..7 {
        let high = test >> 8;
        if (test >= -128 && test <= 127)
            && ((original >= 0 && (test & 0x80) == 0) || (original < 0 && (test & 0x80) != 0))
        {
            bytes = i + 1;
            break;
        }
        test = high;
    }

    let mut result = vec![0u8; bytes];
    for i in (0..bytes).rev() {
        result[i] = value as u8;
        value >>= 8;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::BerEncoder;
    use crate::asn1::types::Asn1Type;

    #[test]
    fn write_boolean() {
        let mut encoder = BerEncoder::new();
        encoder.write_boolean(true);
        let data = encoder.to_bytes();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], Asn1Type::BOOLEAN);
        assert_eq!(data[1], 1);
        assert_eq!(data[2], 0xFF);

        encoder.reset();
        encoder.write_boolean(false);
        let data = encoder.to_bytes();
        assert_eq!(data.len(), 3);
        assert_eq!(data[2], 0x00);
    }

    #[test]
    fn write_integer_small() {
        let mut encoder = BerEncoder::new();
        encoder.write_integer_i32(127);
        let data = encoder.to_bytes();
        assert_eq!(data, vec![Asn1Type::INTEGER, 1, 127]);
    }

    #[test]
    fn write_integer_negative() {
        let mut encoder = BerEncoder::new();
        encoder.write_integer_i32(-1);
        let data = encoder.to_bytes();
        assert_eq!(data, vec![Asn1Type::INTEGER, 1, 0xFF]);
    }

    #[test]
    fn write_integer_two_bytes() {
        let mut encoder = BerEncoder::new();
        encoder.write_integer_i32(256);
        let data = encoder.to_bytes();
        assert_eq!(data, vec![Asn1Type::INTEGER, 2, 0x01, 0x00]);
    }

    #[test]
    fn write_integer_four_bytes() {
        let mut encoder = BerEncoder::new();
        encoder.write_integer_i32(0x1234_5678);
        let data = encoder.to_bytes();
        assert_eq!(
            data,
            vec![Asn1Type::INTEGER, 4, 0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn write_enumerated() {
        let mut encoder = BerEncoder::new();
        encoder.write_enumerated(2);
        let data = encoder.to_bytes();
        assert_eq!(data, vec![Asn1Type::ENUMERATED, 1, 2]);
    }

    #[test]
    fn write_octet_string_bytes() {
        let mut encoder = BerEncoder::new();
        encoder.write_octet_string(&[0x01, 0x02, 0x03, 0x04]);
        let data = encoder.to_bytes();
        assert_eq!(
            data,
            vec![Asn1Type::OCTET_STRING, 4, 0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn write_octet_string_string() {
        let mut encoder = BerEncoder::new();
        encoder.write_octet_string_str("test");
        let data = encoder.to_bytes();
        assert_eq!(
            data,
            vec![Asn1Type::OCTET_STRING, 4, b't', b'e', b's', b't']
        );
    }

    #[test]
    fn write_null() {
        let mut encoder = BerEncoder::new();
        encoder.write_null();
        let data = encoder.to_bytes();
        assert_eq!(data, vec![Asn1Type::NULL, 0]);
    }

    #[test]
    fn length_encoding_short_form() {
        let mut encoder = BerEncoder::new();
        encoder.write_octet_string(&[0u8; 127]);
        let data = encoder.to_bytes();
        assert_eq!(data[1], 127);
    }

    #[test]
    fn length_encoding_long_form_one_byte() {
        let mut encoder = BerEncoder::new();
        encoder.write_octet_string(&[0u8; 200]);
        let data = encoder.to_bytes();
        assert_eq!(data[1], 0x81);
        assert_eq!(data[2], 200);
    }

    #[test]
    fn length_encoding_long_form_two_bytes() {
        let mut encoder = BerEncoder::new();
        encoder.write_octet_string(&[0u8; 1000]);
        let data = encoder.to_bytes();
        assert_eq!(data[1], 0x82);
        assert_eq!(data[2], 0x03);
        assert_eq!(data[3], 0xE8);
    }

    #[test]
    fn sequence() {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(1);
        encoder.write_octet_string_str("test");
        encoder.end_sequence();
        let data = encoder.to_bytes();
        assert_eq!(data[0], Asn1Type::SEQUENCE);
        assert_eq!(data[1], 9);
    }

    #[test]
    fn nested_sequences() {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(1);
        encoder.begin_sequence();
        encoder.write_integer_i32(2);
        encoder.end_sequence();
        encoder.end_sequence();
        let data = encoder.to_bytes();
        assert_eq!(data[0], Asn1Type::SEQUENCE);
        // Outer: integer(3) + inner sequence(5) = 8 content bytes
        assert_eq!(data[1], 8);
    }

    #[test]
    fn set() {
        let mut encoder = BerEncoder::new();
        encoder.begin_set();
        encoder.write_boolean(true);
        encoder.end_set();
        let data = encoder.to_bytes();
        assert_eq!(data[0], Asn1Type::SET);
    }

    #[test]
    fn context_primitive() {
        let mut encoder = BerEncoder::new();
        encoder.write_context(0, &[0x01, 0x02]);
        let data = encoder.to_bytes();
        assert_eq!(data, vec![0x80, 2, 0x01, 0x02]);
    }

    #[test]
    fn context_constructed() {
        let mut encoder = BerEncoder::new();
        encoder.begin_context(3, true);
        encoder.write_integer_i32(42);
        encoder.end_context();
        let data = encoder.to_bytes();
        assert_eq!(data[0], 0xA3);
    }

    #[test]
    fn application_tag() {
        let mut encoder = BerEncoder::new();
        encoder.begin_application(0, true);
        encoder.write_integer_i32(3);
        encoder.end_application();
        let data = encoder.to_bytes();
        assert_eq!(data[0], 0x60);
    }

    #[test]
    fn reset() {
        let mut encoder = BerEncoder::new();
        encoder.write_integer_i32(1);
        assert_eq!(encoder.to_bytes().len(), 3);

        encoder.reset();
        encoder.write_boolean(false);
        let data = encoder.to_bytes();
        assert_eq!(data.len(), 3);
        assert_eq!(data[0], Asn1Type::BOOLEAN);
    }

    #[test]
    fn ldap_bind_request() {
        let mut encoder = BerEncoder::new();
        encoder.begin_sequence();
        encoder.write_integer_i32(1);
        encoder.begin_application(0, true);
        encoder.write_integer_i32(3);
        encoder.write_octet_string_str("cn=admin,dc=example,dc=com");
        encoder.write_context(0, b"secret");
        encoder.end_application();
        encoder.end_sequence();
        let data = encoder.to_bytes();
        assert_eq!(data[0], Asn1Type::SEQUENCE);
        assert!(data.len() > 10);
    }
}
