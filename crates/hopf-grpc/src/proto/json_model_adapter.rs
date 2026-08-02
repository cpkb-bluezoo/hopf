// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Bridges `rjsonparser::ContentHandler` events to [`ProtoMessageHandler`]
//! using proto3 JSON mapping.

use std::collections::VecDeque;

use rjsonparser::{ContentHandler, Number, ParseError, ParseResult};

use super::base64;
use super::{
    FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ProtoMessageHandler, ProtoParseError,
    ScalarValue,
};

struct MessageContext {
    message: MessageDescriptor,
    field_name: Option<String>,
}

#[derive(Clone)]
enum Pending {
    Field(FieldDescriptor),
    Array(FieldDescriptor),
    Map(FieldDescriptor),
    MapValue {
        field: FieldDescriptor,
        key: ScalarValue,
    },
}

enum AfterNested {
    RestoreArray(FieldDescriptor),
    CloseMapEntry(FieldDescriptor),
}

/// Adapter: JSON parse events → [`ProtoMessageHandler`] semantic events.
pub struct JsonModelAdapter<H: ProtoMessageHandler> {
    proto_file: ProtoFile,
    handler: H,
    message_stack: VecDeque<MessageContext>,
    pending: Option<Pending>,
    after_nested: Vec<AfterNested>,
    /// When true, the next complete JSON value (scalar or tree) is ignored.
    skip_value: bool,
    /// Nesting depth while skipping a structured value (`0` = not inside one).
    skip_depth: u32,
    root_started: bool,
    root_object_open: bool,
    pub last_error: Option<ProtoParseError>,
}

impl<H: ProtoMessageHandler> JsonModelAdapter<H> {
    pub fn new(proto_file: ProtoFile, handler: H) -> Self {
        Self {
            proto_file,
            handler,
            message_stack: VecDeque::new(),
            pending: None,
            after_nested: Vec::new(),
            skip_value: false,
            skip_depth: 0,
            root_started: false,
            root_object_open: false,
            last_error: None,
        }
    }

    pub fn into_handler(self) -> H {
        self.handler
    }

    pub fn start_root_message(&mut self, message_type_name: &str) -> Result<(), ProtoParseError> {
        if self.root_started {
            panic!("Root message already started");
        }
        let msg = resolve_message(&self.proto_file, message_type_name)?;
        self.handler.start_message(message_type_name)?;
        self.message_stack.push_front(MessageContext {
            message: msg,
            field_name: None,
        });
        self.root_started = true;
        Ok(())
    }

    pub fn end_root_message(&mut self) -> Result<(), ProtoParseError> {
        if !self.message_stack.is_empty() {
            self.message_stack.pop_front();
            self.handler.end_message()?;
        }
        Ok(())
    }

    fn map_err(&mut self, e: ProtoParseError) -> ParseError {
        let msg = e.message().to_string();
        self.last_error = Some(e);
        ParseError::new(msg)
    }

    fn emit_field(&mut self, name: &str, value: ScalarValue) -> ParseResult<()> {
        self.handler
            .field(name, value)
            .map_err(|e| self.map_err(e))
    }

    fn lookup_field(&self, key: &str) -> Option<FieldDescriptor> {
        self.message_stack
            .front()
            .and_then(|ctx| ctx.message.field_by_json_key(key))
            .cloned()
    }

    fn begin_nested(&mut self, fd: &FieldDescriptor) -> ParseResult<()> {
        let type_name = fd
            .message_type_name
            .as_deref()
            .ok_or_else(|| ParseError::new(format!("field {} is not a message", fd.name)))?;
        let nested = resolve_message(&self.proto_file, type_name)
            .map_err(|e| ParseError::new(e.message().to_string()))?;
        self.handler
            .start_field(&fd.name, type_name)
            .map_err(|e| self.map_err(e))?;
        self.handler
            .start_message(type_name)
            .map_err(|e| self.map_err(e))?;
        self.message_stack.push_front(MessageContext {
            message: nested,
            field_name: Some(fd.name.clone()),
        });
        Ok(())
    }

    fn finish_nested(&mut self) -> ParseResult<()> {
        let ctx = self
            .message_stack
            .pop_front()
            .ok_or_else(|| ParseError::new("unexpected end of object"))?;
        self.handler
            .end_message()
            .map_err(|e| self.map_err(e))?;
        if ctx.field_name.is_some() {
            self.handler.end_field().map_err(|e| self.map_err(e))?;
        }
        match self.after_nested.pop() {
            Some(AfterNested::RestoreArray(fd)) => {
                self.pending = Some(Pending::Array(fd));
            }
            Some(AfterNested::CloseMapEntry(fd)) => {
                self.handler
                    .end_message()
                    .map_err(|e| self.map_err(e))?;
                self.handler.end_field().map_err(|e| self.map_err(e))?;
                self.pending = Some(Pending::Map(fd));
            }
            None => {}
        }
        Ok(())
    }

    fn convert_string(&self, fd: &FieldDescriptor, s: &str) -> ParseResult<ScalarValue> {
        match fd.field_type {
            FieldType::String => Ok(ScalarValue::String(s.to_string())),
            FieldType::Bytes => {
                let bytes =
                    base64::decode(s).ok_or_else(|| ParseError::new("invalid base64 bytes"))?;
                Ok(ScalarValue::Bytes(bytes))
            }
            FieldType::Enum => {
                if let Some(ref enum_name) = fd.enum_type_name {
                    if let Some(enm) = self.proto_file.enum_type(enum_name) {
                        if let Some(num) = enm.value_number(s) {
                            return Ok(ScalarValue::U64(num as u64));
                        }
                    }
                }
                if let Ok(n) = s.parse::<i32>() {
                    return Ok(ScalarValue::U64(n as u64));
                }
                Err(ParseError::new(format!("unknown enum value {s}")))
            }
            FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
                let v: i64 = s
                    .parse()
                    .map_err(|_| ParseError::new("invalid int64 string"))?;
                Ok(ScalarValue::I64(v))
            }
            FieldType::Uint64 | FieldType::Fixed64 => {
                let v: u64 = s
                    .parse()
                    .map_err(|_| ParseError::new("invalid uint64 string"))?;
                Ok(ScalarValue::U64(v))
            }
            FieldType::Int32
            | FieldType::Sint32
            | FieldType::Sfixed32
            | FieldType::Uint32
            | FieldType::Fixed32 => {
                let v: i64 = s
                    .parse()
                    .map_err(|_| ParseError::new("invalid integer string"))?;
                if matches!(fd.field_type, FieldType::Uint32 | FieldType::Fixed32) {
                    Ok(ScalarValue::U64(v as u64))
                } else {
                    Ok(ScalarValue::I32(v as i32))
                }
            }
            FieldType::Float | FieldType::Double => {
                let v: f64 = s
                    .parse()
                    .map_err(|_| ParseError::new("invalid float string"))?;
                if fd.field_type == FieldType::Float {
                    Ok(ScalarValue::F32(v as f32))
                } else {
                    Ok(ScalarValue::F64(v))
                }
            }
            FieldType::Bool => match s {
                "true" => Ok(ScalarValue::Bool(true)),
                "false" => Ok(ScalarValue::Bool(false)),
                _ => Err(ParseError::new("invalid bool string")),
            },
            FieldType::Message | FieldType::Map => Err(ParseError::new(format!(
                "unexpected string for field {}",
                fd.name
            ))),
        }
    }

    fn finish_scalar(&mut self, value: ScalarValue) -> ParseResult<()> {
        match self.pending.take() {
            Some(Pending::Field(fd)) => self.emit_field(&fd.name, value),
            Some(Pending::Array(fd)) => {
                self.emit_field(&fd.name, value)?;
                self.pending = Some(Pending::Array(fd));
                Ok(())
            }
            Some(Pending::MapValue { field, key }) => {
                let entry_type = map_entry_type_name(&field);
                self.handler
                    .start_field(&field.name, &entry_type)
                    .map_err(|e| self.map_err(e))?;
                self.handler
                    .start_message(&entry_type)
                    .map_err(|e| self.map_err(e))?;
                self.emit_field("key", key)?;
                self.emit_field("value", value)?;
                self.handler
                    .end_message()
                    .map_err(|e| self.map_err(e))?;
                self.handler.end_field().map_err(|e| self.map_err(e))?;
                self.pending = Some(Pending::Map(field));
                Ok(())
            }
            Some(Pending::Map(_)) => Err(ParseError::new("expected string map key")),
            None => Err(ParseError::new("unexpected scalar")),
        }
    }

    fn skip_scalar(&mut self) {
        if self.skip_value && self.skip_depth == 0 {
            self.skip_value = false;
        }
    }
}

fn convert_number(fd: &FieldDescriptor, n: &Number) -> ParseResult<ScalarValue> {
    match fd.field_type {
        FieldType::Double => Ok(ScalarValue::F64(
            n.as_f64()
                .ok_or_else(|| ParseError::new("invalid double"))?,
        )),
        FieldType::Float => Ok(ScalarValue::F32(
            n.as_f64()
                .ok_or_else(|| ParseError::new("invalid float"))? as f32,
        )),
        FieldType::Bool => Err(ParseError::new("expected boolean for bool field")),
        FieldType::String | FieldType::Bytes | FieldType::Message | FieldType::Map => Err(
            ParseError::new(format!("unexpected number for field {}", fd.name)),
        ),
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 | FieldType::Enum => {
            if let Some(v) = n.as_i32() {
                Ok(ScalarValue::I32(v))
            } else if let Some(v) = n.as_i64() {
                Ok(ScalarValue::I32(v as i32))
            } else {
                Err(ParseError::new("invalid int32"))
            }
        }
        FieldType::Uint32 | FieldType::Fixed32 => {
            let v = n
                .as_i64()
                .ok_or_else(|| ParseError::new("invalid uint32"))?;
            Ok(ScalarValue::U64(v as u64))
        }
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
            let v = n
                .as_i64()
                .ok_or_else(|| ParseError::new("invalid int64"))?;
            Ok(ScalarValue::I64(v))
        }
        FieldType::Uint64 | FieldType::Fixed64 => {
            if let Some(v) = n.as_i64() {
                Ok(ScalarValue::U64(v as u64))
            } else if let Number::BigInt(s) = n {
                let v: u64 = s.parse().map_err(|_| ParseError::new("invalid uint64"))?;
                Ok(ScalarValue::U64(v))
            } else {
                Err(ParseError::new("invalid uint64"))
            }
        }
    }
}

fn resolve_message(proto: &ProtoFile, name: &str) -> Result<MessageDescriptor, ProtoParseError> {
    let mut msg = proto.message(name);
    if msg.is_none() && name.starts_with('.') {
        msg = proto.message(&name[1..]);
    }
    msg.cloned()
        .ok_or_else(|| ProtoParseError::new(format!("Unknown message type: {name}")))
}

fn map_entry_type_name(fd: &FieldDescriptor) -> String {
    format!("{}.MapEntry", fd.name)
}

fn map_key_from_string(fd: &FieldDescriptor, s: &str) -> ParseResult<ScalarValue> {
    let key_ty = fd.key_type_name.as_deref().unwrap_or("string");
    match key_ty {
        "string" => Ok(ScalarValue::String(s.to_string())),
        "bool" => match s {
            "true" => Ok(ScalarValue::Bool(true)),
            "false" => Ok(ScalarValue::Bool(false)),
            _ => Err(ParseError::new("invalid bool map key")),
        },
        "int32" | "sint32" | "sfixed32" => {
            let v: i32 = s.parse().map_err(|_| ParseError::new("invalid int map key"))?;
            Ok(ScalarValue::I32(v))
        }
        "int64" | "sint64" | "sfixed64" => {
            let v: i64 = s.parse().map_err(|_| ParseError::new("invalid int map key"))?;
            Ok(ScalarValue::I64(v))
        }
        "uint32" | "fixed32" => {
            let v: u32 = s
                .parse()
                .map_err(|_| ParseError::new("invalid uint map key"))?;
            Ok(ScalarValue::U64(u64::from(v)))
        }
        "uint64" | "fixed64" => {
            let v: u64 = s
                .parse()
                .map_err(|_| ParseError::new("invalid uint map key"))?;
            Ok(ScalarValue::U64(v))
        }
        _ => Ok(ScalarValue::String(s.to_string())),
    }
}

fn map_value_from_string(fd: &FieldDescriptor, s: &str) -> ParseResult<ScalarValue> {
    let vty = fd.value_type_name.as_deref().unwrap_or("string");
    match vty {
        "string" => Ok(ScalarValue::String(s.to_string())),
        "bytes" => {
            let b = base64::decode(s).ok_or_else(|| ParseError::new("invalid base64"))?;
            Ok(ScalarValue::Bytes(b))
        }
        "int64" | "sint64" | "sfixed64" => Ok(ScalarValue::I64(
            s.parse().map_err(|_| ParseError::new("bad int64"))?,
        )),
        "uint64" | "fixed64" => Ok(ScalarValue::U64(
            s.parse().map_err(|_| ParseError::new("bad uint64"))?,
        )),
        "int32" | "sint32" | "sfixed32" => Ok(ScalarValue::I32(
            s.parse().map_err(|_| ParseError::new("bad int32"))?,
        )),
        "uint32" | "fixed32" => Ok(ScalarValue::U64(u64::from(
            s.parse::<u32>()
                .map_err(|_| ParseError::new("bad uint32"))?,
        ))),
        "float" => Ok(ScalarValue::F32(
            s.parse().map_err(|_| ParseError::new("bad float"))?,
        )),
        "double" => Ok(ScalarValue::F64(
            s.parse().map_err(|_| ParseError::new("bad double"))?,
        )),
        "bool" => match s {
            "true" => Ok(ScalarValue::Bool(true)),
            "false" => Ok(ScalarValue::Bool(false)),
            _ => Err(ParseError::new("bad bool")),
        },
        _ => Ok(ScalarValue::String(s.to_string())),
    }
}

fn is_message_value_type(name: &str) -> bool {
    !matches!(
        name,
        "double"
            | "float"
            | "int32"
            | "int64"
            | "uint32"
            | "uint64"
            | "sint32"
            | "sint64"
            | "fixed32"
            | "fixed64"
            | "sfixed32"
            | "sfixed64"
            | "bool"
            | "string"
            | "bytes"
    )
}

impl<H: ProtoMessageHandler> ContentHandler for JsonModelAdapter<H> {
    fn start_object(&mut self) -> ParseResult<()> {
        if self.skip_value {
            self.skip_depth += 1;
            return Ok(());
        }
        if matches!(self.pending, Some(Pending::Field(ref fd)) if fd.field_type == FieldType::Map)
        {
            if let Some(Pending::Field(fd)) = self.pending.take() {
                self.pending = Some(Pending::Map(fd));
                return Ok(());
            }
        }
        match self.pending.take() {
            Some(Pending::Field(fd)) => {
                if fd.field_type != FieldType::Message {
                    return Err(ParseError::new(format!(
                        "expected message for field {}",
                        fd.name
                    )));
                }
                self.begin_nested(&fd)
            }
            Some(Pending::Array(fd)) => {
                if fd.field_type != FieldType::Message {
                    return Err(ParseError::new(format!(
                        "expected message for field {}",
                        fd.name
                    )));
                }
                self.after_nested
                    .push(AfterNested::RestoreArray(fd.clone()));
                self.begin_nested(&fd)
            }
            Some(Pending::MapValue { field, key }) => {
                let value_type = field
                    .value_type_name
                    .clone()
                    .ok_or_else(|| ParseError::new("map missing value type"))?;
                if !is_message_value_type(&value_type) {
                    return Err(ParseError::new("expected scalar map value"));
                }
                let entry_type = map_entry_type_name(&field);
                self.handler
                    .start_field(&field.name, &entry_type)
                    .map_err(|e| self.map_err(e))?;
                self.handler
                    .start_message(&entry_type)
                    .map_err(|e| self.map_err(e))?;
                self.emit_field("key", key)?;
                let nested = resolve_message(&self.proto_file, &value_type)
                    .map_err(|e| ParseError::new(e.message().to_string()))?;
                self.handler
                    .start_field("value", &value_type)
                    .map_err(|e| self.map_err(e))?;
                self.handler
                    .start_message(&value_type)
                    .map_err(|e| self.map_err(e))?;
                self.message_stack.push_front(MessageContext {
                    message: nested,
                    field_name: Some("value".into()),
                });
                self.after_nested
                    .push(AfterNested::CloseMapEntry(field));
                Ok(())
            }
            Some(Pending::Map(_)) => Err(ParseError::new("expected string map key")),
            None => {
                if self.root_started && !self.root_object_open && self.message_stack.len() == 1 {
                    self.root_object_open = true;
                    Ok(())
                } else {
                    Err(ParseError::new("unexpected object"))
                }
            }
        }
    }

    fn end_object(&mut self) -> ParseResult<()> {
        if self.skip_value {
            self.skip_depth = self.skip_depth.saturating_sub(1);
            if self.skip_depth == 0 {
                self.skip_value = false;
            }
            return Ok(());
        }
        if matches!(self.pending, Some(Pending::Map(_))) {
            self.pending = None;
            return Ok(());
        }
        if self.message_stack.len() > 1 {
            return self.finish_nested();
        }
        if self.root_object_open {
            self.root_object_open = false;
            return Ok(());
        }
        Err(ParseError::new("unexpected end of object"))
    }

    fn start_array(&mut self) -> ParseResult<()> {
        if self.skip_value {
            self.skip_depth += 1;
            return Ok(());
        }
        match self.pending.take() {
            Some(Pending::Field(fd)) if fd.repeated => {
                self.pending = Some(Pending::Array(fd));
                Ok(())
            }
            Some(other) => {
                self.pending = Some(other);
                Err(ParseError::new("unexpected array"))
            }
            None => Err(ParseError::new("unexpected array")),
        }
    }

    fn end_array(&mut self) -> ParseResult<()> {
        if self.skip_value {
            self.skip_depth = self.skip_depth.saturating_sub(1);
            if self.skip_depth == 0 {
                self.skip_value = false;
            }
            return Ok(());
        }
        match self.pending.take() {
            Some(Pending::Array(_)) => Ok(()),
            other => {
                self.pending = other;
                Err(ParseError::new("unexpected end of array"))
            }
        }
    }

    fn key(&mut self, key: &str) -> ParseResult<()> {
        if self.skip_value {
            return Ok(());
        }
        if let Some(Pending::Map(fd)) = self.pending.take() {
            let map_key = map_key_from_string(&fd, key)?;
            self.pending = Some(Pending::MapValue {
                field: fd,
                key: map_key,
            });
            return Ok(());
        }
        match self.lookup_field(key) {
            Some(fd) => {
                self.pending = Some(Pending::Field(fd));
                Ok(())
            }
            None => {
                self.skip_value = true;
                Ok(())
            }
        }
    }

    fn number_value(&mut self, value: &Number) -> ParseResult<()> {
        if self.skip_value {
            self.skip_scalar();
            return Ok(());
        }
        let fd = match &self.pending {
            Some(Pending::Field(fd) | Pending::Array(fd)) => fd.clone(),
            Some(Pending::MapValue { field, .. }) => field.clone(),
            _ => return Err(ParseError::new("unexpected number")),
        };
        let scalar = if matches!(self.pending, Some(Pending::MapValue { .. })) {
            map_value_from_number(&fd, value)?
        } else if fd.field_type == FieldType::Enum {
            let v = value
                .as_i64()
                .ok_or_else(|| ParseError::new("invalid enum number"))?;
            ScalarValue::U64(v as u64)
        } else {
            convert_number(&fd, value)?
        };
        self.finish_scalar(scalar)
    }

    fn string_value(&mut self, value: &str) -> ParseResult<()> {
        if self.skip_value {
            self.skip_scalar();
            return Ok(());
        }
        let fd = match &self.pending {
            Some(Pending::Field(fd) | Pending::Array(fd)) => fd.clone(),
            Some(Pending::MapValue { field, .. }) => field.clone(),
            _ => return Err(ParseError::new("unexpected string")),
        };
        let scalar = if matches!(self.pending, Some(Pending::MapValue { .. })) {
            map_value_from_string(&fd, value)?
        } else {
            self.convert_string(&fd, value)?
        };
        self.finish_scalar(scalar)
    }

    fn boolean_value(&mut self, value: bool) -> ParseResult<()> {
        if self.skip_value {
            self.skip_scalar();
            return Ok(());
        }
        match &self.pending {
            Some(Pending::Field(fd) | Pending::Array(fd)) => {
                if fd.field_type != FieldType::Bool {
                    return Err(ParseError::new(format!(
                        "unexpected boolean for field {}",
                        fd.name
                    )));
                }
            }
            Some(Pending::MapValue { field, .. }) => {
                if field.value_type_name.as_deref() != Some("bool") {
                    return Err(ParseError::new("unexpected boolean map value"));
                }
            }
            _ => return Err(ParseError::new("unexpected boolean")),
        }
        self.finish_scalar(ScalarValue::Bool(value))
    }

    fn null_value(&mut self) -> ParseResult<()> {
        if self.skip_value {
            self.skip_scalar();
            return Ok(());
        }
        self.pending = None;
        Ok(())
    }
}

fn map_value_from_number(fd: &FieldDescriptor, n: &Number) -> ParseResult<ScalarValue> {
    let vty = fd.value_type_name.as_deref().unwrap_or("");
    // Reuse FieldDescriptor-shaped conversion via a temporary type tag.
    let mut tmp = fd.clone();
    tmp.field_type = match vty {
        "double" => FieldType::Double,
        "float" => FieldType::Float,
        "int32" | "sint32" | "sfixed32" => FieldType::Int32,
        "int64" | "sint64" | "sfixed64" => FieldType::Int64,
        "uint32" | "fixed32" => FieldType::Uint32,
        "uint64" | "fixed64" => FieldType::Uint64,
        "bool" => FieldType::Bool,
        _ => {
            return Err(ParseError::new(format!(
                "unexpected number for map value type {vty}"
            )))
        }
    };
    convert_number(&tmp, n)
}

#[cfg(test)]
mod tests {
    use rjsonparser::{Parser, Writer};

    use super::*;
    use crate::proto::{JsonModelSerializer, ProtoFileParser};

    struct Collect {
        events: Vec<String>,
    }

    impl ProtoMessageHandler for Collect {
        fn start_message(&mut self, t: &str) -> Result<(), ProtoParseError> {
            self.events.push(format!("start:{t}"));
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            self.events.push("end".into());
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
            self.events.push(format!("field:{name}={value:?}"));
            Ok(())
        }
        fn start_field(&mut self, name: &str, t: &str) -> Result<(), ProtoParseError> {
            self.events.push(format!("start_field:{name}:{t}"));
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            self.events.push("end_field".into());
            Ok(())
        }
    }

    #[test]
    fn parses_camel_case_and_snake() {
        let proto = ProtoFileParser::parse(
            r#"
            syntax = "proto3";
            package demo;
            message Echo { string text = 1; int32 foo_bar = 2; bytes data = 3; }
            "#,
        )
        .unwrap();
        let collect = Collect { events: vec![] };
        let mut adapter = JsonModelAdapter::new(proto, collect);
        adapter.start_root_message("demo.Echo").unwrap();
        let json = br#"{"text":"hi","fooBar":7,"data":"Zm9v"}"#;
        {
            let mut input = &json[..];
            let mut p = Parser::new(&mut adapter);
            p.receive(&mut input).unwrap();
            p.close().unwrap();
        }
        adapter.end_root_message().unwrap();
        let ev = adapter.into_handler().events;
        assert!(ev.iter().any(|e| e.contains(r#"field:text=String("hi")"#)));
        assert!(ev.iter().any(|e| e.contains("field:foo_bar=I32(7)")));
        assert!(ev.iter().any(|e| e.contains("field:data=Bytes")));
    }

    #[test]
    fn serialize_then_adapt_roundtrip() {
        let proto = ProtoFileParser::parse(
            r#"
            syntax = "proto3";
            package demo;
            message Echo { string text = 1; int32 n = 2; }
            "#,
        )
        .unwrap();
        let mut ser = JsonModelSerializer::new(proto.clone());
        let mut w = Writer::buffer(64);
        ser.start_message(&mut w, "demo.Echo").unwrap();
        ser.field(&mut w, "text", ScalarValue::String("hi".into()))
            .unwrap();
        ser.field(&mut w, "n", ScalarValue::I32(7)).unwrap();
        ser.end_message(&mut w).unwrap();
        let bytes = w.finish().unwrap();

        let collect = Collect { events: vec![] };
        let mut adapter = JsonModelAdapter::new(proto, collect);
        adapter.start_root_message("demo.Echo").unwrap();
        {
            let mut input = bytes.as_slice();
            let mut p = Parser::new(&mut adapter);
            p.receive(&mut input).unwrap();
            p.close().unwrap();
        }
        adapter.end_root_message().unwrap();
        let ev = adapter.into_handler().events;
        assert!(ev.iter().any(|e| e.contains(r#"field:text=String("hi")"#)));
        assert!(ev.iter().any(|e| e.contains("field:n=I32(7)")));
    }
}
