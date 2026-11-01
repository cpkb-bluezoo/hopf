// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serializes protobuf messages as proto3 JSON using a Proto model.

use std::collections::VecDeque;

use loopbuf::LoopBuf;
use rjsonparser::{WriteError, WriteResult, Writer};

use super::base64;
use super::json_names::proto_json_name;
use super::{FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ScalarValue};

/// Serializes messages to proto3 JSON from event-driven input.
pub struct JsonModelSerializer {
    proto_file: ProtoFile,
    message_stack: VecDeque<MessageDescriptor>,
    /// Whether `start_message` has opened a JSON object for the current frame.
    object_open: VecDeque<bool>,
}

impl JsonModelSerializer {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file,
            message_stack: VecDeque::new(),
            object_open: VecDeque::new(),
        }
    }

    /// Starts a message (root or nested). Writes `{`.
    pub fn start_message(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        type_name: &str,
    ) -> WriteResult<()> {
        let msg = resolve_message(&self.proto_file, type_name).map_err(|e| {
            WriteError::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        self.message_stack.push_front(msg);
        writer.write_start_object(ring)?;
        self.object_open.push_front(true);
        Ok(())
    }

    /// Ends the current message. Writes `}`.
    pub fn end_message(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
    ) -> WriteResult<()> {
        let _ = self.message_stack.pop_front();
        if self.object_open.pop_front().unwrap_or(false) {
            writer.write_end_object(ring)?;
        }
        Ok(())
    }

    /// Writes a scalar field using the proto3 JSON mapping.
    pub fn field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        value: ScalarValue,
    ) -> WriteResult<()> {
        let fd = match self.current_field(name) {
            Some(fd) => fd.clone(),
            None => return Ok(()),
        };
        let key = proto_json_name(&fd.name);
        writer.write_key(ring, &key)?;
        write_scalar(writer, ring, &fd, &self.proto_file, &value)
    }

    /// Starts a nested message field: writes the key and opens `{` via `start_message`.
    pub fn start_field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        type_name: &str,
    ) -> WriteResult<()> {
        if self.current_field(name).is_none() {
            return Ok(());
        }
        writer.write_key(ring, &proto_json_name(name))?;
        self.start_message(writer, ring, type_name)
    }

    /// Ends a nested message field (closes the object opened by [`start_field`]).
    pub fn end_field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
    ) -> WriteResult<()> {
        self.end_message(writer, ring)
    }

    fn current_field(&self, name: &str) -> Option<&FieldDescriptor> {
        let msg = self.message_stack.front()?;
        msg.fields.iter().find(|fd| fd.name == name)
    }
}

fn resolve_message(proto: &ProtoFile, name: &str) -> Result<MessageDescriptor, String> {
    let mut msg = proto.message(name);
    if msg.is_none() && name.starts_with('.') {
        msg = proto.message(&name[1..]);
    }
    msg.cloned()
        .ok_or_else(|| format!("Unknown message type: {name}"))
}

fn write_scalar(
    writer: &mut Writer,
    ring: &mut LoopBuf,
    fd: &FieldDescriptor,
    proto: &ProtoFile,
    value: &ScalarValue,
) -> WriteResult<()> {
    match fd.field_type {
        FieldType::Bool => {
            let b = matches!(value, ScalarValue::Bool(true))
                || matches!(value, ScalarValue::U64(v) if *v != 0)
                || matches!(value, ScalarValue::I32(v) if *v != 0)
                || matches!(value, ScalarValue::I64(v) if *v != 0);
            writer.write_boolean(ring, b)
        }
        FieldType::String => match value {
            ScalarValue::String(s) => writer.write_string(ring, s),
            _ => writer.write_string(ring, ""),
        },
        FieldType::Bytes => {
            let bytes = match value {
                ScalarValue::Bytes(b) => b.as_slice(),
                ScalarValue::String(s) => s.as_bytes(),
                _ => &[],
            };
            writer.write_string(ring, &base64::encode(bytes))
        }
        FieldType::Enum => {
            let num = as_i64(value) as i32;
            if let Some(ref ename) = fd.enum_type_name {
                if let Some(enm) = proto.enum_type(ename) {
                    if let Some(name) = enm.value_name(num) {
                        return writer.write_string(ring, name);
                    }
                }
            }
            writer.write_i32(ring, num)
        }
        // NaN and the infinities are strings in proto3 JSON; a number is the
        // value the field has, not the double it widens to (0.1f32 is 0.1).
        FieldType::Float => {
            let f = match value {
                ScalarValue::F32(v) => *v,
                other => as_f64(other) as f32,
            };
            match non_finite(f64::from(f)) {
                Some(text) => writer.write_string(ring, text),
                None => writer.write_f64(ring, format!("{f}").parse().unwrap_or(f64::from(f))),
            }
        }
        FieldType::Double => {
            let d = as_f64(value);
            match non_finite(d) {
                Some(text) => writer.write_string(ring, text),
                None => writer.write_f64(ring, d),
            }
        }
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => {
            writer.write_i32(ring, as_i64(value) as i32)
        }
        FieldType::Uint32 | FieldType::Fixed32 => writer.write_i64(ring, i64::from(as_u64(value) as u32)),
        // 64-bit integers are JSON strings in proto3 JSON mapping.
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
            writer.write_string(ring, &as_i64(value).to_string())
        }
        FieldType::Uint64 | FieldType::Fixed64 => {
            writer.write_string(ring, &as_u64(value).to_string())
        }
        FieldType::Message | FieldType::Map => Ok(()),
    }
}

/// The proto3 JSON spelling of a non-finite floating point value.
fn non_finite(v: f64) -> Option<&'static str> {
    if v.is_nan() {
        Some("NaN")
    } else if v == f64::INFINITY {
        Some("Infinity")
    } else if v == f64::NEG_INFINITY {
        Some("-Infinity")
    } else {
        None
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ProtoFileParser;

    #[test]
    fn writes_camel_case_json() {
        let proto = ProtoFileParser::parse(
            r#"
            syntax = "proto3";
            package demo;
            message Echo { string text = 1; int32 foo_bar = 2; }
            "#,
        )
        .unwrap();
        let mut ser = JsonModelSerializer::new(proto);
        let mut w = Writer::new();
        let mut ring = LoopBuf::with_capacity(64);
        ser.start_message(&mut w, &mut ring, "demo.Echo").unwrap();
        ser.field(&mut w, &mut ring, "text", ScalarValue::String("hi".into()))
            .unwrap();
        ser.field(&mut w, &mut ring, "foo_bar", ScalarValue::I32(7))
            .unwrap();
        ser.end_message(&mut w, &mut ring).unwrap();
        let (a, b) = ring.readable_spans();
        let s = String::from_utf8([a, b].concat()).unwrap();
        assert_eq!(s, r#"{"text":"hi","fooBar":7}"#);
    }

    const SRC: &str = r#"
        syntax = "proto3";
        package demo;
        enum Color { RED = 0; GREEN = 1; }
        message Inner { int32 v = 1; }
        message M {
            int32 i32 = 1; int64 i64 = 2; uint32 u32 = 3; uint64 u64 = 4;
            sint32 s32 = 5; sint64 s64 = 6; fixed32 f32 = 7; fixed64 f64 = 8;
            sfixed32 sf32 = 9; sfixed64 sf64 = 10; float fl = 11; double db = 12;
            bool b = 13; string s = 14; bytes by = 15; Color color = 16;
            Inner one = 17;
        }
    "#;

    /// The JSON for one `field` call on `demo.M`.
    fn json(name: &str, value: ScalarValue) -> Result<String, String> {
        let mut ser = JsonModelSerializer::new(ProtoFileParser::parse(SRC).unwrap());
        let mut w = Writer::new();
        let mut ring = LoopBuf::with_capacity(512);
        ser.start_message(&mut w, &mut ring, "demo.M").unwrap();
        ser.field(&mut w, &mut ring, name, value).map_err(|e| e.to_string())?;
        ser.end_message(&mut w, &mut ring).unwrap();
        let (a, b) = ring.readable_spans();
        Ok(String::from_utf8([a, b].concat()).unwrap())
    }

    #[test]
    fn integers_follow_the_proto3_json_mapping() {
        assert_eq!(json("i32", ScalarValue::I32(-5)).unwrap(), r#"{"i32":-5}"#);
        assert_eq!(json("s32", ScalarValue::I32(-5)).unwrap(), r#"{"s32":-5}"#);
        assert_eq!(json("sf32", ScalarValue::I32(i32::MIN)).unwrap(), r#"{"sf32":-2147483648}"#);
        assert_eq!(json("u32", ScalarValue::U64(4_000_000_000)).unwrap(), r#"{"u32":4000000000}"#);
        assert_eq!(json("f32", ScalarValue::U64(4_294_967_295)).unwrap(), r#"{"f32":4294967295}"#);
        // 64-bit integers are strings
        assert_eq!(json("i64", ScalarValue::I64(-9)).unwrap(), r#"{"i64":"-9"}"#);
        assert_eq!(json("s64", ScalarValue::I64(i64::MIN)).unwrap(), r#"{"s64":"-9223372036854775808"}"#);
        assert_eq!(json("sf64", ScalarValue::I64(-1)).unwrap(), r#"{"sf64":"-1"}"#);
        assert_eq!(json("u64", ScalarValue::U64(u64::MAX)).unwrap(), r#"{"u64":"18446744073709551615"}"#);
        assert_eq!(json("f64", ScalarValue::U64(u64::MAX)).unwrap(), r#"{"f64":"18446744073709551615"}"#);
    }

    #[test]
    fn a_value_arriving_as_the_other_integer_kind_still_prints_correctly() {
        // The wire decoder may deliver a 64-bit value as I64 or U64.
        assert_eq!(json("i64", ScalarValue::U64((-3i64) as u64)).unwrap(), r#"{"i64":"-3"}"#);
        assert_eq!(json("u64", ScalarValue::I64(5)).unwrap(), r#"{"u64":"5"}"#);
        assert_eq!(json("u32", ScalarValue::I32(-294_967_296)).unwrap(), r#"{"u32":4000000000}"#);
    }

    #[test]
    fn floats_follow_the_proto3_json_mapping() {
        assert_eq!(json("db", ScalarValue::F64(1.5)).unwrap(), r#"{"db":1.5}"#);
        assert_eq!(json("db", ScalarValue::F64(-0.25)).unwrap(), r#"{"db":-0.25}"#);
        assert_eq!(json("db", ScalarValue::F64(f64::NAN)).unwrap(), r#"{"db":"NaN"}"#);
        assert_eq!(json("db", ScalarValue::F64(f64::INFINITY)).unwrap(), r#"{"db":"Infinity"}"#);
        assert_eq!(json("db", ScalarValue::F64(f64::NEG_INFINITY)).unwrap(), r#"{"db":"-Infinity"}"#);
        assert_eq!(json("fl", ScalarValue::F32(f32::NAN)).unwrap(), r#"{"fl":"NaN"}"#);
        assert_eq!(json("fl", ScalarValue::F32(f32::INFINITY)).unwrap(), r#"{"fl":"Infinity"}"#);
    }

    #[test]
    fn a_float_prints_as_the_float_it_is() {
        // 0.1f32 is not 0.10000000149011612 to anyone reading the JSON.
        assert_eq!(json("fl", ScalarValue::F32(0.1)).unwrap(), r#"{"fl":0.1}"#);
        assert_eq!(json("fl", ScalarValue::F32(3.5)).unwrap(), r#"{"fl":3.5}"#);
    }

    #[test]
    fn bytes_enums_booleans_and_strings() {
        assert_eq!(json("by", ScalarValue::Bytes(vec![0xfb, 0xff])).unwrap(), r#"{"by":"+/8="}"#);
        assert_eq!(json("by", ScalarValue::Bytes(vec![])).unwrap(), r#"{"by":""}"#);
        assert_eq!(json("color", ScalarValue::U64(1)).unwrap(), r#"{"color":"GREEN"}"#);
        assert_eq!(json("color", ScalarValue::U64(0)).unwrap(), r#"{"color":"RED"}"#);
        assert_eq!(json("color", ScalarValue::U64(7)).unwrap(), r#"{"color":7}"#, "an unknown number stays a number");
        assert_eq!(json("b", ScalarValue::Bool(true)).unwrap(), r#"{"b":true}"#);
        assert_eq!(json("b", ScalarValue::Bool(false)).unwrap(), r#"{"b":false}"#);
        assert_eq!(json("s", ScalarValue::String("a\"b\\c\n☃".into())).unwrap(), r#"{"s":"a\"b\\c\n☃"}"#);
    }

    #[test]
    fn unknown_fields_are_not_written() {
        assert_eq!(json("nope", ScalarValue::I32(1)).unwrap(), "{}");
    }

    #[test]
    fn nested_messages_become_nested_objects() {
        let mut ser = JsonModelSerializer::new(ProtoFileParser::parse(SRC).unwrap());
        let mut w = Writer::new();
        let mut ring = LoopBuf::with_capacity(512);
        ser.start_message(&mut w, &mut ring, "demo.M").unwrap();
        ser.field(&mut w, &mut ring, "i32", ScalarValue::I32(1)).unwrap();
        ser.start_field(&mut w, &mut ring, "one", "demo.Inner").unwrap();
        ser.field(&mut w, &mut ring, "v", ScalarValue::I32(2)).unwrap();
        ser.end_field(&mut w, &mut ring).unwrap();
        ser.end_message(&mut w, &mut ring).unwrap();
        let (a, b) = ring.readable_spans();
        assert_eq!(String::from_utf8([a, b].concat()).unwrap(), r#"{"i32":1,"one":{"v":2}}"#);
    }

    #[test]
    fn an_unknown_message_type_is_an_error() {
        let mut ser = JsonModelSerializer::new(ProtoFileParser::parse(SRC).unwrap());
        let mut w = Writer::new();
        let mut ring = LoopBuf::with_capacity(64);
        assert!(ser.start_message(&mut w, &mut ring, "demo.Missing").is_err());
        assert!(ser.start_message(&mut w, &mut ring, ".demo.M").is_ok(), "a leading dot is allowed");
    }
}
