// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serializes protobuf messages from event-driven input using a Proto model.

use std::collections::VecDeque;
use loopbuf::LoopBuf;
use rprotobuf::{WriteError, Writer};

use super::{FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ScalarValue};

/// Serializes protobuf messages from event-driven input using a Proto model.
///
/// The application drives the serializer with events (`start_message`, `field`,
/// `start_field`, `end_field`, `end_message`). The serializer uses the model to
/// map field names to numbers and types, writing the correct wire format.
pub struct ProtoModelSerializer {
    proto_file: ProtoFile,
    message_stack: VecDeque<MessageDescriptor>,
}

impl ProtoModelSerializer {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file,
            message_stack: VecDeque::new(),
        }
    }

    /// Starts a message (root or nested).
    pub fn start_message(&mut self, type_name: &str) -> Result<(), std::io::Error> {
        let mut msg = self.proto_file.message(type_name);
        if msg.is_none() && type_name.starts_with('.') {
            msg = self.proto_file.message(&type_name[1..]);
        }
        let msg = msg.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unknown message type: {type_name}"),
            )
        })?;
        self.message_stack.push_front(msg.clone());
        Ok(())
    }

    /// Ends the current message.
    pub fn end_message(&mut self) {
        let _ = self.message_stack.pop_front();
    }

    /// Writes a scalar field in the wire type the protobuf encoding gives its
    /// type (varint, zigzag varint, 4-byte, 8-byte or length-delimited), so
    /// any other implementation can read it.
    pub fn field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        value: ScalarValue,
    ) -> Result<(), WriteError> {
        let fd = match self.current_field(name) {
            Some(fd) => fd.clone(),
            None => return Ok(()),
        };
        let num = fd.number as u32;
        match fd.field_type {
            FieldType::Double => {
                writer.write_double_field(ring, num, as_f64(&value))?;
            }
            FieldType::Float => {
                writer.write_float_field(ring, num, as_f32(&value))?;
            }
            FieldType::Int32
            | FieldType::Uint32
            | FieldType::Enum
            | FieldType::Int64
            | FieldType::Uint64 => {
                writer.write_varint_field(ring, num, as_u64(&value))?;
            }
            FieldType::Fixed32 => {
                writer.write_fixed32_field(ring, num, as_u64(&value) as u32)?;
            }
            FieldType::Fixed64 => {
                writer.write_fixed64_field(ring, num, as_u64(&value))?;
            }
            FieldType::Sint32 => {
                writer.write_svarint_field(ring, num, as_i64(&value))?;
            }
            FieldType::Sint64 => {
                writer.write_svarint_field(ring, num, as_i64(&value))?;
            }
            FieldType::Sfixed32 => {
                writer.write_fixed32_field(ring, num, as_i64(&value) as u32)?;
            }
            FieldType::Sfixed64 => {
                writer.write_fixed64_field(ring, num, as_u64(&value))?;
            }
            FieldType::Bool => {
                let b = matches!(value, ScalarValue::Bool(true))
                    || matches!(value, ScalarValue::U64(v) if v != 0)
                    || matches!(value, ScalarValue::I32(v) if v != 0)
                    || matches!(value, ScalarValue::I64(v) if v != 0);
                writer.write_bool_field(ring, num, b)?;
            }
            FieldType::String => {
                let s = match &value {
                    ScalarValue::String(s) => s.as_str(),
                    _ => return Ok(()),
                };
                writer.write_string_field(ring, num, s)?;
            }
            FieldType::Bytes => {
                match &value {
                    ScalarValue::Bytes(b) => writer.write_bytes_field(ring, num, b)?,
                    ScalarValue::String(s) => writer.write_bytes_field(ring, num, s.as_bytes())?,
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Starts a nested message field context. Used with start_message/field/end_message.
    pub fn start_field(&mut self, name: &str, type_name: &str) {
        if self.current_field(name).is_none() {
            return;
        }
        let mut nested = self.proto_file.message(type_name);
        if nested.is_none() && type_name.starts_with('.') {
            nested = self.proto_file.message(&type_name[1..]);
        }
        if let Some(nested) = nested {
            self.message_stack.push_front(nested.clone());
        }
    }

    /// Ends a nested message field context.
    pub fn end_field(&mut self) {
        let _ = self.message_stack.pop_front();
    }

    /// Writes an embedded message. The content is written via the callback.
    pub fn message_field<F>(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        type_name: &str,
        content: F,
    ) -> Result<(), WriteError>
    where
        F: FnOnce(&mut ProtoModelSerializer, &mut Writer, &mut LoopBuf) -> Result<(), WriteError>,
    {
        let fd = match self.current_field(name) {
            Some(fd) => fd.clone(),
            None => return Ok(()),
        };

        let mut nested = self.proto_file.message(type_name);
        if nested.is_none() && type_name.starts_with('.') {
            nested = self.proto_file.message(&type_name[1..]);
        }
        let nested = match nested {
            Some(n) => n.clone(),
            None => return Ok(()),
        };

        self.message_stack.push_front(nested);
        let result = writer.write_message_field(ring, fd.number as u32, |w, ring| content(self, w, ring));
        self.message_stack.pop_front();
        result
    }

    fn current_field(&self, name: &str) -> Option<&FieldDescriptor> {
        let msg = self.message_stack.front()?;
        msg.fields.iter().find(|fd| fd.name == name)
    }
}

fn as_u64(value: &ScalarValue) -> u64 {
    match value {
        ScalarValue::Bool(b) => u64::from(*b),
        ScalarValue::I32(v) => *v as u64,
        ScalarValue::I64(v) => *v as u64,
        ScalarValue::U64(v) => *v,
        ScalarValue::F32(v) => *v as u64,
        ScalarValue::F64(v) => *v as u64,
        ScalarValue::String(_) | ScalarValue::Bytes(_) => 0,
    }
}

fn as_i64(value: &ScalarValue) -> i64 {
    match value {
        ScalarValue::Bool(b) => i64::from(*b),
        ScalarValue::I32(v) => i64::from(*v),
        ScalarValue::I64(v) => *v,
        ScalarValue::U64(v) => *v as i64,
        ScalarValue::F32(v) => *v as i64,
        ScalarValue::F64(v) => *v as i64,
        ScalarValue::String(_) | ScalarValue::Bytes(_) => 0,
    }
}

fn as_f64(value: &ScalarValue) -> f64 {
    match value {
        ScalarValue::F64(v) => *v,
        ScalarValue::F32(v) => f64::from(*v),
        ScalarValue::I32(v) => f64::from(*v),
        ScalarValue::I64(v) => *v as f64,
        ScalarValue::U64(v) => *v as f64,
        ScalarValue::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        ScalarValue::String(_) | ScalarValue::Bytes(_) => 0.0,
    }
}

fn as_f32(value: &ScalarValue) -> f32 {
    match value {
        ScalarValue::F32(v) => *v,
        ScalarValue::F64(v) => *v as f32,
        ScalarValue::I32(v) => *v as f32,
        ScalarValue::I64(v) => *v as f32,
        ScalarValue::U64(v) => *v as f32,
        ScalarValue::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        ScalarValue::String(_) | ScalarValue::Bytes(_) => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ProtoFileParser;

    const SRC: &str = r#"
        syntax = "proto3";
        package demo;
        enum Color { RED = 0; GREEN = 1; }
        message M {
            int32 i32 = 1; int64 i64 = 2; uint32 u32 = 3; uint64 u64 = 4;
            sint32 s32 = 5; sint64 s64 = 6; fixed32 f32 = 7; fixed64 f64 = 8;
            sfixed32 sf32 = 9; sfixed64 sf64 = 10; float fl = 11; double db = 12;
            bool b = 13; string s = 14; bytes by = 15; Color color = 16;
        }
    "#;

    /// The wire bytes for one `field` call on `demo.M`.
    fn wire(name: &str, value: ScalarValue) -> Vec<u8> {
        let mut ser = ProtoModelSerializer::new(ProtoFileParser::parse(SRC).unwrap());
        let mut w = Writer::new();
        let mut ring = LoopBuf::with_capacity(256);
        ser.start_message("demo.M").unwrap();
        ser.field(&mut w, &mut ring, name, value).unwrap();
        ser.end_message();
        let mut out = Vec::new();
        w.drain_to(&mut ring, &mut out).unwrap();
        out
    }

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    fn tagged(field: u32, wire: u32, body: &[u8]) -> Vec<u8> {
        [varint(u64::from(field << 3 | wire)), body.to_vec()].concat()
    }

    #[test]
    fn varint_types_use_the_varint_wire_type() {
        assert_eq!(wire("i32", ScalarValue::I32(300)), tagged(1, 0, &varint(300)));
        assert_eq!(wire("i32", ScalarValue::I32(-1)), tagged(1, 0, &varint(u64::MAX)), "negative: ten bytes");
        assert_eq!(wire("i64", ScalarValue::I64(-2)), tagged(2, 0, &varint((-2i64) as u64)));
        assert_eq!(wire("u32", ScalarValue::U64(4_000_000_000)), tagged(3, 0, &varint(4_000_000_000)));
        assert_eq!(wire("u64", ScalarValue::U64(u64::MAX)), tagged(4, 0, &varint(u64::MAX)));
        assert_eq!(wire("b", ScalarValue::Bool(true)), tagged(13, 0, &[1]));
        assert_eq!(wire("b", ScalarValue::Bool(false)), tagged(13, 0, &[0]));
        assert_eq!(wire("color", ScalarValue::U64(1)), tagged(16, 0, &[1]));
    }

    #[test]
    fn signed_types_are_zigzag_encoded() {
        assert_eq!(wire("s32", ScalarValue::I32(-3)), tagged(5, 0, &varint(5)));
        assert_eq!(wire("s32", ScalarValue::I32(i32::MIN)), tagged(5, 0, &varint(u64::from(u32::MAX))));
        assert_eq!(wire("s64", ScalarValue::I64(-3)), tagged(6, 0, &varint(5)));
        assert_eq!(wire("s64", ScalarValue::I64(i64::MIN)), tagged(6, 0, &varint(u64::MAX)));
    }

    #[test]
    fn fixed_width_types_use_the_fixed_wire_types() {
        // Wire type 5 (4 bytes) and 1 (8 bytes), little-endian: what any other
        // protobuf implementation sends and expects for fixed32/fixed64.
        assert_eq!(wire("f32", ScalarValue::U64(7)), tagged(7, 5, &7u32.to_le_bytes()));
        assert_eq!(wire("f32", ScalarValue::U64(4_000_000_000)), tagged(7, 5, &4_000_000_000u32.to_le_bytes()));
        assert_eq!(wire("f64", ScalarValue::U64(u64::MAX)), tagged(8, 1, &u64::MAX.to_le_bytes()));
        assert_eq!(wire("sf32", ScalarValue::I32(-7)), tagged(9, 5, &(-7i32).to_le_bytes()));
        assert_eq!(wire("sf64", ScalarValue::I64(-7)), tagged(10, 1, &(-7i64).to_le_bytes()));
        assert_eq!(wire("fl", ScalarValue::F32(1.5)), tagged(11, 5, &1.5f32.to_le_bytes()));
        assert_eq!(wire("db", ScalarValue::F64(-2.5)), tagged(12, 1, &(-2.5f64).to_le_bytes()));
    }

    #[test]
    fn strings_and_bytes_are_length_delimited() {
        assert_eq!(wire("s", ScalarValue::String("héllo".into())), tagged(14, 2, &[varint(6), "héllo".as_bytes().to_vec()].concat()));
        assert_eq!(wire("by", ScalarValue::Bytes(vec![0, 255])), tagged(15, 2, &[2, 0, 255]));
        assert_eq!(wire("s", ScalarValue::String(String::new())), tagged(14, 2, &[0]));
    }

    #[test]
    fn a_field_the_message_does_not_have_writes_nothing() {
        assert!(wire("nope", ScalarValue::I32(1)).is_empty());
    }

    #[test]
    fn a_value_of_the_wrong_kind_for_a_string_writes_nothing() {
        assert!(wire("s", ScalarValue::I32(1)).is_empty());
    }
}
