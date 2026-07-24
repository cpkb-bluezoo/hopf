// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serializes protobuf messages from event-driven input using a Proto model.

use std::collections::VecDeque;
use std::io::Write;

use rprotobuf::{Buffer, WriteError, Writer};

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

    /// Writes a scalar field.
    ///
    /// Gumdrop quirks preserved: `Fixed32` / `Fixed64` / `Enum` are written as
    /// varint fields (not fixed wire types).
    pub fn field<W: Write>(
        &mut self,
        writer: &mut Writer<W>,
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
                writer.write_double_field(num, as_f64(&value))?;
            }
            FieldType::Float => {
                writer.write_float_field(num, as_f32(&value))?;
            }
            FieldType::Int32
            | FieldType::Uint32
            | FieldType::Fixed32
            | FieldType::Enum
            | FieldType::Int64
            | FieldType::Uint64
            | FieldType::Fixed64 => {
                writer.write_varint_field(num, as_u64(&value))?;
            }
            FieldType::Sint32 => {
                writer.write_svarint_field(num, as_i64(&value))?;
            }
            FieldType::Sint64 => {
                writer.write_svarint_field(num, as_i64(&value))?;
            }
            FieldType::Sfixed32 => {
                writer.write_fixed32_field(num, as_i64(&value) as u32)?;
            }
            FieldType::Sfixed64 => {
                writer.write_fixed64_field(num, as_u64(&value))?;
            }
            FieldType::Bool => {
                let b = matches!(value, ScalarValue::Bool(true))
                    || matches!(value, ScalarValue::U64(v) if v != 0)
                    || matches!(value, ScalarValue::I32(v) if v != 0)
                    || matches!(value, ScalarValue::I64(v) if v != 0);
                writer.write_bool_field(num, b)?;
            }
            FieldType::String => {
                let s = match &value {
                    ScalarValue::String(s) => s.as_str(),
                    _ => return Ok(()),
                };
                writer.write_string_field(num, s)?;
            }
            FieldType::Bytes => {
                match &value {
                    ScalarValue::Bytes(b) => writer.write_bytes_field(num, b)?,
                    ScalarValue::String(s) => writer.write_bytes_field(num, s.as_bytes())?,
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
    pub fn message_field<W, F>(
        &mut self,
        writer: &mut Writer<W>,
        name: &str,
        type_name: &str,
        content: F,
    ) -> Result<(), WriteError>
    where
        W: Write,
        F: FnOnce(&mut ProtoModelSerializer, &mut Writer<Buffer>) -> Result<(), WriteError>,
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
        let result = writer.write_message_field(fd.number as u32, |w| content(self, w));
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
