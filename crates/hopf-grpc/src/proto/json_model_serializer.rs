// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serializes protobuf messages as proto3 JSON using a Proto model.

use std::collections::VecDeque;

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
    pub fn start_message<W: std::io::Write>(
        &mut self,
        writer: &mut Writer<W>,
        type_name: &str,
    ) -> WriteResult<()> {
        let msg = resolve_message(&self.proto_file, type_name).map_err(|e| {
            WriteError::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        self.message_stack.push_front(msg);
        writer.write_start_object()?;
        self.object_open.push_front(true);
        Ok(())
    }

    /// Ends the current message. Writes `}`.
    pub fn end_message<W: std::io::Write>(
        &mut self,
        writer: &mut Writer<W>,
    ) -> WriteResult<()> {
        let _ = self.message_stack.pop_front();
        if self.object_open.pop_front().unwrap_or(false) {
            writer.write_end_object()?;
        }
        Ok(())
    }

    /// Writes a scalar field using the proto3 JSON mapping.
    pub fn field<W: std::io::Write>(
        &mut self,
        writer: &mut Writer<W>,
        name: &str,
        value: ScalarValue,
    ) -> WriteResult<()> {
        let fd = match self.current_field(name) {
            Some(fd) => fd.clone(),
            None => return Ok(()),
        };
        let key = proto_json_name(&fd.name);
        writer.write_key(&key)?;
        write_scalar(writer, &fd, &self.proto_file, &value)
    }

    /// Starts a nested message field: writes the key and opens `{` via `start_message`.
    pub fn start_field<W: std::io::Write>(
        &mut self,
        writer: &mut Writer<W>,
        name: &str,
        type_name: &str,
    ) -> WriteResult<()> {
        if self.current_field(name).is_none() {
            return Ok(());
        }
        writer.write_key(&proto_json_name(name))?;
        self.start_message(writer, type_name)
    }

    /// Ends a nested message field (closes the object opened by [`start_field`]).
    pub fn end_field<W: std::io::Write>(
        &mut self,
        writer: &mut Writer<W>,
    ) -> WriteResult<()> {
        self.end_message(writer)
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

fn write_scalar<W: std::io::Write>(
    writer: &mut Writer<W>,
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
            writer.write_boolean(b)
        }
        FieldType::String => match value {
            ScalarValue::String(s) => writer.write_string(s),
            _ => writer.write_string(""),
        },
        FieldType::Bytes => {
            let bytes = match value {
                ScalarValue::Bytes(b) => b.as_slice(),
                ScalarValue::String(s) => s.as_bytes(),
                _ => &[],
            };
            writer.write_string(&base64::encode(bytes))
        }
        FieldType::Enum => {
            let num = as_i64(value) as i32;
            if let Some(ref ename) = fd.enum_type_name {
                if let Some(enm) = proto.enum_type(ename) {
                    if let Some(name) = enm.value_name(num) {
                        return writer.write_string(name);
                    }
                }
            }
            writer.write_i32(num)
        }
        FieldType::Float => writer.write_f64(as_f64(value)),
        FieldType::Double => writer.write_f64(as_f64(value)),
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => {
            writer.write_i32(as_i64(value) as i32)
        }
        FieldType::Uint32 | FieldType::Fixed32 => writer.write_i64(as_u64(value) as i64),
        // 64-bit integers are JSON strings in proto3 JSON mapping.
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
            writer.write_string(&as_i64(value).to_string())
        }
        FieldType::Uint64 | FieldType::Fixed64 => {
            writer.write_string(&as_u64(value).to_string())
        }
        FieldType::Message | FieldType::Map => Ok(()),
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
        let mut w = Writer::buffer(64);
        ser.start_message(&mut w, "demo.Echo").unwrap();
        ser.field(&mut w, "text", ScalarValue::String("hi".into()))
            .unwrap();
        ser.field(&mut w, "foo_bar", ScalarValue::I32(7))
            .unwrap();
        ser.end_message(&mut w).unwrap();
        let bytes = w.finish().unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert_eq!(s, r#"{"text":"hi","fooBar":7}"#);
    }
}
