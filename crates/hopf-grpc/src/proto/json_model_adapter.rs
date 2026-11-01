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
    /// The string value being read, gathered from the chunks the parser
    /// delivers: converting it to a field needs the whole of it.
    string: String,
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
            string: String::new(),
        }
    }

    pub fn into_handler(self) -> H {
        self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
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
        // A further root message (the next one of a stream) may follow.
        self.root_started = false;
        self.root_object_open = false;
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

    /// An enum value given by name (or as a number in a string).
    fn enum_from_string(&self, enum_name: Option<&str>, s: &str) -> ParseResult<ScalarValue> {
        if let Some(enm) = enum_name.and_then(|n| self.proto_file.enum_type(n)) {
            if let Some(num) = enm.value_number(s) {
                return Ok(ScalarValue::U64(num as u64));
            }
        }
        if let Ok(n) = s.parse::<i32>() {
            return Ok(ScalarValue::U64(n as u64));
        }
        Err(ParseError::new(format!("unknown enum value {s}")))
    }

    /// The enum a map field's values are of, if they are enums.
    fn map_value_enum(&self, fd: &FieldDescriptor) -> Option<String> {
        let name = fd.value_type_name.as_deref()?;
        self.proto_file.enum_type(name).map(|_| name.to_string())
    }

    fn convert_string(&self, fd: &FieldDescriptor, s: &str) -> ParseResult<ScalarValue> {
        match fd.field_type {
            FieldType::String => Ok(ScalarValue::String(s.to_string())),
            FieldType::Bytes => {
                let bytes =
                    base64::decode(s).ok_or_else(|| ParseError::new("invalid base64 bytes"))?;
                Ok(ScalarValue::Bytes(bytes))
            }
            FieldType::Enum => self.enum_from_string(fd.enum_type_name.as_deref(), s),
            FieldType::Int32
            | FieldType::Sint32
            | FieldType::Sfixed32
            | FieldType::Uint32
            | FieldType::Fixed32
            | FieldType::Int64
            | FieldType::Sint64
            | FieldType::Sfixed64
            | FieldType::Uint64
            | FieldType::Fixed64 => {
                let v: i128 = s
                    .parse()
                    .map_err(|_| ParseError::new(format!("invalid integer string for field {}", fd.name)))?;
                integer_scalar(&fd.field_type, v, &fd.name)
            }
            FieldType::Float | FieldType::Double => {
                // Only the three spelled-out non-finite values; "inf", "nan"
                // and numbers too big for a double are not proto3 JSON.
                let v: f64 = match s {
                    "NaN" => f64::NAN,
                    "Infinity" => f64::INFINITY,
                    "-Infinity" => f64::NEG_INFINITY,
                    _ => {
                        let v: f64 = s.parse().map_err(|_| ParseError::new("invalid float string"))?;
                        if !v.is_finite() {
                            return Err(ParseError::new("float string out of range"));
                        }
                        v
                    }
                };
                float_scalar(&fd.field_type, v, &fd.name)
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

/// The integer a JSON number stands for: whole numbers however they are
/// written (`1`, `1.0`, `1e2`), as proto3 JSON allows; `None` for anything else.
fn whole_number(n: &Number) -> Option<i128> {
    match n {
        Number::I32(v) => Some(i128::from(*v)),
        Number::I64(v) => Some(i128::from(*v)),
        Number::BigInt(s) => s.parse().ok(),
        Number::F64(f) if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e20 => Some(*f as i128),
        Number::F64(_) => None,
    }
}

/// `v` as the scalar for an integer field of type `ty`, or an error if it
/// does not fit: a value is never truncated or wrapped into range.
fn integer_scalar(ty: &FieldType, v: i128, name: &str) -> ParseResult<ScalarValue> {
    let out = |lo: i128, hi: i128, wrap: fn(i128) -> ScalarValue| {
        if (lo..=hi).contains(&v) {
            Ok(wrap(v))
        } else {
            Err(ParseError::new(format!("value {v} out of range for field {name}")))
        }
    };
    match ty {
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => {
            out(i128::from(i32::MIN), i128::from(i32::MAX), |v| ScalarValue::I32(v as i32))
        }
        FieldType::Uint32 | FieldType::Fixed32 => out(0, i128::from(u32::MAX), |v| ScalarValue::U64(v as u64)),
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => {
            out(i128::from(i64::MIN), i128::from(i64::MAX), |v| ScalarValue::I64(v as i64))
        }
        FieldType::Uint64 | FieldType::Fixed64 => out(0, i128::from(u64::MAX), |v| ScalarValue::U64(v as u64)),
        _ => Err(ParseError::new(format!("not an integer field: {name}"))),
    }
}

/// `v` as the scalar for a float or double field; a finite value too big
/// for a `float` is an error rather than infinity.
fn float_scalar(ty: &FieldType, v: f64, name: &str) -> ParseResult<ScalarValue> {
    if *ty == FieldType::Float {
        if v.is_finite() && v.abs() > f64::from(f32::MAX) {
            return Err(ParseError::new(format!("value out of range for float field {name}")));
        }
        Ok(ScalarValue::F32(v as f32))
    } else {
        Ok(ScalarValue::F64(v))
    }
}

fn convert_number(fd: &FieldDescriptor, n: &Number) -> ParseResult<ScalarValue> {
    match fd.field_type {
        FieldType::Double | FieldType::Float => {
            let v = match n {
                Number::BigInt(s) => s.parse::<f64>().ok(),
                other => other.as_f64(),
            }
            .ok_or_else(|| ParseError::new("invalid floating point number"))?;
            float_scalar(&fd.field_type, v, &fd.name)
        }
        FieldType::Bool => Err(ParseError::new("expected boolean for bool field")),
        FieldType::String | FieldType::Bytes | FieldType::Message | FieldType::Map => Err(
            ParseError::new(format!("unexpected number for field {}", fd.name)),
        ),
        FieldType::Enum => {
            let v = whole_number(n).ok_or_else(|| ParseError::new("invalid enum number"))?;
            integer_scalar(&FieldType::Int32, v, &fd.name)
        }
        _ => {
            let v = whole_number(n)
                .ok_or_else(|| ParseError::new(format!("invalid integer for field {}", fd.name)))?;
            integer_scalar(&fd.field_type, v, &fd.name)
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
                if !is_message_value_type(&value_type) || self.proto_file.enum_type(&value_type).is_some() {
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
            if self.map_value_enum(&fd).is_some() {
                let v = whole_number(value).ok_or_else(|| ParseError::new("invalid enum number"))?;
                match integer_scalar(&FieldType::Int32, v, &fd.name)? {
                    ScalarValue::I32(n) => ScalarValue::U64(n as u64),
                    other => other,
                }
            } else {
                map_value_from_number(&fd, value)?
            }
        } else if fd.field_type == FieldType::Enum {
            let v = whole_number(value).ok_or_else(|| ParseError::new("invalid enum number"))?;
            match integer_scalar(&FieldType::Int32, v, &fd.name)? {
                ScalarValue::I32(n) => ScalarValue::U64(n as u64),
                other => other,
            }
        } else {
            convert_number(&fd, value)?
        };
        self.finish_scalar(scalar)
    }

    fn start_string_value(&mut self) -> ParseResult<()> {
        self.string.clear();
        Ok(())
    }

    fn string_value_content(&mut self, chunk: &str) -> ParseResult<()> {
        if !self.skip_value {
            self.string.push_str(chunk);
        }
        Ok(())
    }

    fn end_string_value(&mut self) -> ParseResult<()> {
        let value = std::mem::take(&mut self.string);
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
            match self.map_value_enum(&fd) {
                Some(enum_name) => self.enum_from_string(Some(&enum_name), &value)?,
                None => map_value_from_string(&fd, &value)?,
            }
        } else {
            self.convert_string(&fd, &value)?
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
            let mut p = Parser::new(&mut adapter);
            p.parse(&json[..]).unwrap();
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
        let mut w = Writer::new();
        let mut ring = loopbuf::LoopBuf::with_capacity(64);
        ser.start_message(&mut w, &mut ring, "demo.Echo").unwrap();
        ser.field(&mut w, &mut ring, "text", ScalarValue::String("hi".into()))
            .unwrap();
        ser.field(&mut w, &mut ring, "n", ScalarValue::I32(7)).unwrap();
        ser.end_message(&mut w, &mut ring).unwrap();
        let (a, b) = ring.readable_spans();
        let bytes = [a, b].concat();

        let collect = Collect { events: vec![] };
        let mut adapter = JsonModelAdapter::new(proto, collect);
        adapter.start_root_message("demo.Echo").unwrap();
        {
            let mut p = Parser::new(&mut adapter);
            p.parse(bytes.as_slice()).unwrap();
        }
        adapter.end_root_message().unwrap();
        let ev = adapter.into_handler().events;
        assert!(ev.iter().any(|e| e.contains(r#"field:text=String("hi")"#)));
        assert!(ev.iter().any(|e| e.contains("field:n=I32(7)")));
    }

    const SCALARS: &str = r#"
        syntax = "proto3";
        package demo;
        enum Color { RED = 0; GREEN = 1; BLUE = 2; }
        message Scalars {
            int32 i32 = 1; uint32 u32 = 2; int64 i64 = 3; uint64 u64 = 4;
            sint32 s32 = 5; fixed32 f32 = 6; sfixed64 sf64 = 7;
            float fl = 8; double db = 9; bool b = 10; string s = 11; bytes by = 12;
            Color color = 13;
            repeated int32 nums = 14;
            map<string, int32> counts = 15;
            map<int32, string> names = 16;
            map<bool, string> flags = 17;
        }
    "#;

    /// The events the adapter produces for `json` as a `demo.Scalars`, or the error message.
    fn adapt(json: &str) -> Result<Vec<String>, String> {
        let proto = ProtoFileParser::parse(SCALARS).unwrap();
        let mut adapter = JsonModelAdapter::new(proto, Collect { events: vec![] });
        adapter.start_root_message("demo.Scalars").unwrap();
        let result = {
            let mut p = Parser::new(&mut adapter);
            p.parse(json.as_bytes())
        };
        match result {
            Ok(_) => {
                adapter.end_root_message().unwrap();
                Ok(adapter.into_handler().events)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn fields(json: &str) -> Vec<String> {
        adapt(json).unwrap_or_else(|e| panic!("{json}: {e}")).into_iter().filter(|e| e.starts_with("field:")).collect()
    }

    #[test]
    fn integers_in_range_are_accepted_as_numbers_and_as_strings() {
        assert_eq!(fields(r#"{"i32":-2147483648}"#), ["field:i32=I32(-2147483648)"]);
        assert_eq!(fields(r#"{"i32":2147483647}"#), ["field:i32=I32(2147483647)"]);
        assert_eq!(fields(r#"{"i32":"-7"}"#), ["field:i32=I32(-7)"]);
        assert_eq!(fields(r#"{"u32":4294967295}"#), ["field:u32=U64(4294967295)"]);
        assert_eq!(fields(r#"{"u32":"4294967295"}"#), ["field:u32=U64(4294967295)"]);
        assert_eq!(fields(r#"{"i64":"-9223372036854775808"}"#), ["field:i64=I64(-9223372036854775808)"]);
        assert_eq!(fields(r#"{"i64":9223372036854775807}"#), ["field:i64=I64(9223372036854775807)"]);
        assert_eq!(fields(r#"{"u64":"18446744073709551615"}"#), ["field:u64=U64(18446744073709551615)"]);
        assert_eq!(fields(r#"{"u64":18446744073709551615}"#), ["field:u64=U64(18446744073709551615)"]);
        assert_eq!(fields(r#"{"s32":-1,"f32":5,"sf64":"-5"}"#).len(), 3);
    }

    #[test]
    fn integers_out_of_range_are_errors_not_wrapped() {
        for json in [
            r#"{"i32":2147483648}"#,
            r#"{"i32":-2147483649}"#,
            r#"{"i32":"4294967297"}"#,
            r#"{"i32":"-2147483649"}"#,
            r#"{"s32":3000000000}"#,
            r#"{"u32":4294967296}"#,
            r#"{"u32":-1}"#,
            r#"{"u32":"-1"}"#,
            r#"{"u32":"4294967296"}"#,
            r#"{"f32":-5}"#,
            r#"{"i64":9223372036854775808}"#,
            r#"{"i64":"9223372036854775808"}"#,
            r#"{"u64":-1}"#,
            r#"{"u64":"-1"}"#,
            r#"{"u64":18446744073709551616}"#,
            r#"{"u64":"18446744073709551616"}"#,
            r#"{"i32":"abc"}"#,
            r#"{"i32":""}"#,
            r#"{"i64":"1.5"}"#,
        ] {
            assert!(adapt(json).is_err(), "{json} should be refused, got {:?}", adapt(json));
        }
    }

    #[test]
    fn an_integer_written_with_a_fraction_or_exponent_is_accepted_when_it_is_whole() {
        // proto3 JSON: 1.0 and 1e2 are valid for integer fields; 1.5 is not.
        assert_eq!(fields(r#"{"i32":1.0}"#), ["field:i32=I32(1)"]);
        assert_eq!(fields(r#"{"i32":1e2}"#), ["field:i32=I32(100)"]);
        assert_eq!(fields(r#"{"i64":2.0}"#), ["field:i64=I64(2)"]);
        assert_eq!(fields(r#"{"u32":3.0}"#), ["field:u32=U64(3)"]);
        assert!(adapt(r#"{"i32":1.5}"#).is_err());
        assert!(adapt(r#"{"u64":0.5}"#).is_err());
    }

    #[test]
    fn floats_and_doubles() {
        assert_eq!(fields(r#"{"db":1.5}"#), ["field:db=F64(1.5)"]);
        assert_eq!(fields(r#"{"fl":2}"#), ["field:fl=F32(2.0)"]);
        assert_eq!(fields(r#"{"db":"-Infinity"}"#), ["field:db=F64(-inf)"]);
        assert_eq!(fields(r#"{"db":"Infinity"}"#), ["field:db=F64(inf)"]);
        assert_eq!(fields(r#"{"fl":"NaN"}"#), ["field:fl=F32(NaN)"]);
        assert_eq!(fields(r#"{"db":"1.25"}"#), ["field:db=F64(1.25)"]);
        assert!(adapt(r#"{"db":"abc"}"#).is_err());
        // out of range for a float is an error, not infinity
        assert!(adapt(r#"{"fl":1e39}"#).is_err());
        assert!(adapt(r#"{"fl":-1e39}"#).is_err());
        assert_eq!(fields(r#"{"fl":3.4e38}"#).len(), 1);
    }

    #[test]
    fn booleans_strings_and_enums() {
        assert_eq!(fields(r#"{"b":true}"#), ["field:b=Bool(true)"]);
        assert!(adapt(r#"{"b":1}"#).is_err());
        assert!(adapt(r#"{"s":5}"#).is_err());
        assert!(adapt(r#"{"s":true}"#).is_err());
        assert_eq!(fields(r#"{"s":"héllo ☃"}"#).len(), 1);
        assert_eq!(fields(r#"{"color":"GREEN"}"#), ["field:color=U64(1)"]);
        assert_eq!(fields(r#"{"color":2}"#), ["field:color=U64(2)"]);
        assert!(adapt(r#"{"color":"PURPLE"}"#).is_err());
        assert!(adapt(r#"{"color":2147483648}"#).is_err());
    }

    #[test]
    fn bytes_take_both_base64_alphabets_and_reject_malformed_input() {
        assert_eq!(fields(r#"{"by":"Zm9v"}"#), ["field:by=Bytes([102, 111, 111])"]);
        assert_eq!(fields(r#"{"by":"Zg=="}"#), ["field:by=Bytes([102])"]);
        assert_eq!(fields(r#"{"by":"Zg"}"#), ["field:by=Bytes([102])"], "padding is optional");
        // URL-safe alphabet: 0xfb 0xff -> "-_8" ("+/8" in the standard one)
        assert_eq!(fields(r#"{"by":"-_8"}"#), ["field:by=Bytes([251, 255])"]);
        assert_eq!(fields(r#"{"by":"+/8="}"#), ["field:by=Bytes([251, 255])"]);
        assert_eq!(fields(r#"{"by":""}"#), ["field:by=Bytes([])"]);
        for bad in [r#"{"by":"Zm9v="}"#, r#"{"by":"Z"}"#, r#"{"by":"Zm=v"}"#, r#"{"by":"Zg==Zg=="}"#, r#"{"by":"Zm9v!"}"#, r#"{"by":"Zg==="}"#] {
            assert!(adapt(bad).is_err(), "{bad} should be refused, got {:?}", adapt(bad));
        }
    }

    #[test]
    fn repeated_fields_maps_and_nulls() {
        assert_eq!(fields(r#"{"nums":[1,2,3]}"#), ["field:nums=I32(1)", "field:nums=I32(2)", "field:nums=I32(3)"]);
        assert!(adapt(r#"{"nums":[1,"x"]}"#).is_err());
        assert!(adapt(r#"{"nums":[1,2147483648]}"#).is_err());
        assert_eq!(fields(r#"{"nums":[]}"#), Vec::<String>::new());
        // null means "not set"
        assert_eq!(fields(r#"{"nums":null,"s":null,"i32":null}"#), Vec::<String>::new());
        let m = adapt(r#"{"counts":{"a":1,"b":2}}"#).unwrap();
        assert_eq!(m.iter().filter(|e| e.starts_with("field:key=")).count(), 2);
        assert!(m.iter().any(|e| e == "field:key=String(\"a\")") && m.iter().any(|e| e == "field:value=I32(2)"));
        let n = adapt(r#"{"names":{"7":"seven","-3":"minus"}}"#).unwrap();
        assert!(n.iter().any(|e| e == "field:key=I32(7)") && n.iter().any(|e| e == "field:key=I32(-3)"));
        let f = adapt(r#"{"flags":{"true":"yes","false":"no"}}"#).unwrap();
        assert!(f.iter().any(|e| e == "field:key=Bool(true)"));
        assert!(adapt(r#"{"names":{"x":"bad key"}}"#).is_err());
        assert!(adapt(r#"{"names":{"2147483648":"too big"}}"#).is_err());
        assert!(adapt(r#"{"counts":{"a":2147483648}}"#).is_err());
        assert!(adapt(r#"{"counts":[1]}"#).is_err());
    }

    #[test]
    fn unknown_fields_are_skipped_whatever_they_hold() {
        let ev = fields(r#"{"nope":{"a":[1,{"b":null}],"c":"d"},"also":[1,2,[3]],"x":1,"i32":5,"y":"s","z":true,"n":null}"#);
        assert_eq!(ev, ["field:i32=I32(5)"]);
    }

    #[test]
    fn both_json_and_proto_names_are_accepted() {
        let proto = ProtoFileParser::parse("syntax = \"proto3\"; package demo; message M { int32 foo_bar = 1; string long_name_x = 2; }").unwrap();
        let mut a = JsonModelAdapter::new(proto, Collect { events: vec![] });
        a.start_root_message("demo.M").unwrap();
        {
            let mut p = Parser::new(&mut a);
            p.parse(&br#"{"fooBar":1,"long_name_x":"a"}"#[..]).unwrap();
        }
        a.end_root_message().unwrap();
        let ev = a.into_handler().events;
        assert!(ev.iter().any(|e| e == "field:foo_bar=I32(1)") && ev.iter().any(|e| e.starts_with("field:long_name_x=")));
    }

    #[test]
    fn nested_messages_and_repeated_messages() {
        let proto = ProtoFileParser::parse(
            "syntax = \"proto3\"; package demo; message Inner { int32 v = 1; } message Outer { Inner one = 1; repeated Inner many = 2; map<string, Inner> by = 3; }",
        )
        .unwrap();
        let mut a = JsonModelAdapter::new(proto, Collect { events: vec![] });
        a.start_root_message("demo.Outer").unwrap();
        {
            let mut p = Parser::new(&mut a);
            p.parse(&br#"{"one":{"v":1},"many":[{"v":2},{"v":3}],"by":{"k":{"v":4}}}"#[..]).unwrap();
        }
        a.end_root_message().unwrap();
        let ev = a.into_handler().events;
        let vs: Vec<_> = ev.iter().filter(|e| e.starts_with("field:v=")).cloned().collect();
        assert_eq!(vs, ["field:v=I32(1)", "field:v=I32(2)", "field:v=I32(3)", "field:v=I32(4)"]);
        let starts = ev.iter().filter(|e| e.starts_with("start:")).count();
        let ends = ev.iter().filter(|e| *e == "end").count();
        assert_eq!(starts, ends, "{ev:?}");
    }

    #[test]
    fn structural_errors() {
        assert!(adapt(r#"{"nums":{"a":1}}"#).is_err(), "object for a repeated scalar");
        assert!(adapt(r#"{"i32":{"a":1}}"#).is_err());
        assert!(adapt(r#"{"i32":[1]}"#).is_err());
        assert!(adapt(r#"[1]"#).is_err(), "the root must be an object");
    }

    #[test]
    fn an_unknown_root_message_is_an_error() {
        let proto = ProtoFileParser::parse(SCALARS).unwrap();
        let mut a = JsonModelAdapter::new(proto, Collect { events: vec![] });
        assert!(a.start_root_message("demo.Missing").is_err());
        assert!(a.start_root_message(".demo.Scalars").is_ok(), "a leading dot is allowed");
    }

    #[test]
    fn enum_values_in_a_map() {
        let proto = ProtoFileParser::parse(
            "syntax = \"proto3\"; package demo; enum Color { RED = 0; GREEN = 1; } message M { map<string, Color> shades = 1; }",
        )
        .unwrap();
        let mut a = JsonModelAdapter::new(proto, Collect { events: vec![] });
        a.start_root_message("demo.M").unwrap();
        {
            let mut p = Parser::new(&mut a);
            p.parse(&br#"{"shades":{"a":"GREEN","b":0}}"#[..]).unwrap();
        }
        a.end_root_message().unwrap();
        let ev = a.into_handler().events;
        let vals: Vec<_> = ev.iter().filter(|e| e.starts_with("field:value=")).cloned().collect();
        assert_eq!(vals, ["field:value=U64(1)", "field:value=U64(0)"]);
    }
}
