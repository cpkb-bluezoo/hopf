// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serializes protobuf messages as proto3 JSON using a Proto model.

use std::collections::HashSet;

use loopbuf::LoopBuf;
use rjsonparser::{WriteError, WriteResult, Writer};

use super::base64;
use super::well_known::{self, WellKnown};
use super::{FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ScalarValue};

/// A JSON array or object the current message has open for one of its fields.
enum Open {
    /// The elements of a repeated field.
    Array(String),
    /// The entries of a map field.
    Map(String),
}

impl Open {
    fn field(&self) -> &str {
        match self {
            Self::Array(name) | Self::Map(name) => name,
        }
    }
}

/// A message being written: the object it opened, and the repeated field or
/// map whose array or object is open inside it.
struct MessageFrame {
    desc: MessageDescriptor,
    open: Option<Open>,
    /// Repeated fields and maps already written and closed, so that one
    /// coming back is refused instead of repeating its key.
    closed: HashSet<String>,
}

/// One entry of a map being written. Nothing is written for the entry itself:
/// its key becomes the JSON key, and its value the JSON value.
struct EntryFrame {
    key: FieldDescriptor,
    value: FieldDescriptor,
    key_written: bool,
    value_written: bool,
    /// A scalar value that arrived ahead of its key (the wire allows any
    /// order, JSON needs the key first).
    held: Option<ScalarValue>,
}

/// A well-known type whose JSON form is a bare value (a `Timestamp`, a
/// wrapper, ...). Its fields are collected, and the value is written when it
/// ends.
struct BareFrame {
    kind: WellKnown,
    seconds: i64,
    nanos: i32,
    paths: Vec<String>,
    value: Option<ScalarValue>,
}

impl BareFrame {
    fn set(&mut self, name: &str, value: ScalarValue) {
        match (self.kind, name) {
            (WellKnown::Timestamp | WellKnown::Duration, "seconds") => self.seconds = as_i64(&value),
            (WellKnown::Timestamp | WellKnown::Duration, "nanos") => self.nanos = as_i64(&value) as i32,
            (WellKnown::FieldMask, "paths") => {
                if let ScalarValue::String(path) = value {
                    self.paths.push(path);
                }
            }
            (WellKnown::Wrapper(_), "value") => self.value = Some(value),
            _ => {}
        }
    }
}

enum Frame {
    Message(MessageFrame),
    Entry(EntryFrame),
    Bare(BareFrame),
    /// A field the message does not have, and everything inside it.
    Skipped,
}

/// Serializes messages to proto3 JSON from event-driven input.
///
/// The events are those of [`super::ProtoModelSerializer`]: `start_message`
/// for the root, `field` for a scalar, and `start_field` / `end_field` around
/// a nested message (the pair also opens and closes its object, so no
/// `start_message` / `end_message` is needed inside). On top of that:
///
/// - **repeated fields** are one `field` (or `start_field` / `end_field`)
///   per element, all together, and come out as one JSON array;
/// - **maps** are one `start_field(map, ..)` / `end_field` per entry, around
///   a `field("key", ..)` and either a `field("value", ..)` or a
///   `start_field("value", message_type)` / `end_field`. The type name given
///   for the entry itself is not used. The entries come out as one JSON
///   object, with each key as a string.
///
/// The elements of a repeated field, and the entries of a map, must not be
/// separated by other fields: the array or object is written as it goes, and
/// a field that comes back after something else is an error.
pub struct JsonModelSerializer {
    proto_file: ProtoFile,
    stack: Vec<Frame>,
}

fn invalid(message: impl Into<String>) -> WriteError {
    WriteError::new(std::io::Error::new(std::io::ErrorKind::InvalidData, message.into()))
}

impl JsonModelSerializer {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file,
            stack: Vec::new(),
        }
    }

    /// Starts a message (root or nested). Writes `{`.
    pub fn start_message(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        type_name: &str,
    ) -> WriteResult<()> {
        let desc = resolve_message(&self.proto_file, type_name).map_err(invalid)?;
        if let Some(kind) = well_known::classify(&desc.full_name) {
            // Written as one value, when it ends.
            self.stack.push(Frame::Bare(BareFrame { kind, seconds: 0, nanos: 0, paths: Vec::new(), value: None }));
            return Ok(());
        }
        writer.write_start_object(ring)?;
        self.stack.push(Frame::Message(MessageFrame { desc, open: None, closed: HashSet::new() }));
        Ok(())
    }

    /// Ends the current message (or map entry, or skipped field). Writes `}`
    /// for a message, closing the array or map still open inside it first.
    pub fn end_message(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
    ) -> WriteResult<()> {
        match self.stack.pop() {
            Some(Frame::Message(mut frame)) => {
                close_open(writer, ring, &mut frame)?;
                writer.write_end_object(ring)?;
                // A message that was a map entry's value completes the entry.
                if let Some(Frame::Entry(entry)) = self.stack.last_mut() {
                    entry.value_written = true;
                }
                Ok(())
            }
            Some(Frame::Bare(frame)) => {
                write_bare(writer, ring, &self.proto_file, frame)?;
                if let Some(Frame::Entry(entry)) = self.stack.last_mut() {
                    entry.value_written = true;
                }
                Ok(())
            }
            Some(Frame::Entry(entry)) => finish_entry(writer, ring, &self.proto_file, entry),
            Some(Frame::Skipped) | None => Ok(()),
        }
    }

    /// Writes a scalar field using the proto3 JSON mapping: under its key, or,
    /// for an element of a repeated field, into the array.
    pub fn field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        value: ScalarValue,
    ) -> WriteResult<()> {
        let proto = &self.proto_file;
        match self.stack.last_mut() {
            None | Some(Frame::Skipped) => Ok(()),
            Some(Frame::Bare(frame)) => {
                frame.set(name, value);
                Ok(())
            }
            Some(Frame::Entry(entry)) => entry_field(writer, ring, proto, entry, name, &value),
            Some(Frame::Message(frame)) => {
                let Some(fd) = frame.desc.fields.iter().find(|fd| fd.name == name).cloned() else {
                    return Ok(());
                };
                if matches!(fd.field_type, FieldType::Message | FieldType::Map) {
                    return Err(invalid(format!("field {name} holds messages: write it with start_field")));
                }
                enter_field(writer, ring, frame, &fd)?;
                if fd.repeated {
                    open_container(writer, ring, frame, &fd, true)?;
                } else {
                    writer.write_key(ring, &fd.json_key())?;
                }
                write_scalar(writer, ring, &fd, proto, &value)
            }
        }
    }

    /// Starts a nested message field: its key (or, for a repeated field, the
    /// next place in the array; for a map, the next entry) and then `{`.
    /// Closed by [`Self::end_field`].
    pub fn start_field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        type_name: &str,
    ) -> WriteResult<()> {
        let value_type = match self.stack.last_mut() {
            None => return Ok(()),
            Some(Frame::Skipped) => {
                self.stack.push(Frame::Skipped);
                return Ok(());
            }
            Some(Frame::Bare(_)) => {
                return Err(invalid(format!("{name}: a well-known type written as a bare value has no message fields")));
            }
            Some(Frame::Entry(entry)) => {
                if name != "value" || entry.value.field_type != FieldType::Message {
                    return Err(invalid(format!("{name} cannot hold a message in a map entry")));
                }
                write_key_if_missing(writer, ring, &self.proto_file, entry)?;
                entry.value.message_type_name.clone().unwrap_or_else(|| type_name.to_string())
            }
            Some(Frame::Message(frame)) => {
                let Some(fd) = frame.desc.fields.iter().find(|fd| fd.name == name).cloned() else {
                    self.stack.push(Frame::Skipped);
                    return Ok(());
                };
                match fd.field_type {
                    FieldType::Map => {
                        enter_field(writer, ring, frame, &fd)?;
                        open_container(writer, ring, frame, &fd, false)?;
                        let entry = entry_frame(&self.proto_file, &fd).map_err(invalid)?;
                        self.stack.push(Frame::Entry(entry));
                        return Ok(());
                    }
                    FieldType::Message => {
                        enter_field(writer, ring, frame, &fd)?;
                        if fd.repeated {
                            open_container(writer, ring, frame, &fd, true)?;
                        } else {
                            writer.write_key(ring, &fd.json_key())?;
                        }
                        type_name.to_string()
                    }
                    _ => return Err(invalid(format!("field {name} is not a message: write it with field"))),
                }
            }
        };
        self.start_message(writer, ring, &value_type)
    }

    /// Ends a nested message field, or a map entry (what [`Self::start_field`]
    /// began).
    pub fn end_field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
    ) -> WriteResult<()> {
        self.end_message(writer, ring)
    }
}

/// Before writing `fd` in `frame`: close the array or map of another field
/// that is still open, and refuse a repeated field or map that was already
/// written and closed.
fn enter_field(writer: &mut Writer, ring: &mut LoopBuf, frame: &mut MessageFrame, fd: &FieldDescriptor) -> WriteResult<()> {
    if frame.open.as_ref().is_some_and(|open| open.field() != fd.name) {
        close_open(writer, ring, frame)?;
    }
    if frame.closed.contains(&fd.name) {
        return Err(invalid(format!(
            "{} is written again after other fields: its elements must be together",
            fd.name
        )));
    }
    Ok(())
}

/// Open the JSON array (`array`) or object (a map) for `fd`, unless it is open.
fn open_container(
    writer: &mut Writer,
    ring: &mut LoopBuf,
    frame: &mut MessageFrame,
    fd: &FieldDescriptor,
    array: bool,
) -> WriteResult<()> {
    if frame.open.is_some() {
        return Ok(());
    }
    writer.write_key(ring, &fd.json_key())?;
    if array {
        writer.write_start_array(ring)?;
        frame.open = Some(Open::Array(fd.name.clone()));
    } else {
        writer.write_start_object(ring)?;
        frame.open = Some(Open::Map(fd.name.clone()));
    }
    Ok(())
}

fn close_open(writer: &mut Writer, ring: &mut LoopBuf, frame: &mut MessageFrame) -> WriteResult<()> {
    match frame.open.take() {
        Some(open) => {
            match open {
                Open::Array(_) => writer.write_end_array(ring)?,
                Open::Map(_) => writer.write_end_object(ring)?,
            }
            frame.closed.insert(open.field().to_string());
            Ok(())
        }
        None => Ok(()),
    }
}

/// The key and value descriptors of one entry of map field `fd`.
fn entry_frame(proto: &ProtoFile, fd: &FieldDescriptor) -> Result<EntryFrame, String> {
    let key_type = fd
        .key_type_name
        .as_deref()
        .and_then(FieldType::from_scalar_name)
        .filter(|t| !matches!(t, FieldType::Double | FieldType::Float | FieldType::Bytes))
        .ok_or_else(|| format!("map {} has a key type that is not an integer, bool or string", fd.name))?;
    let value_name = fd.value_type_name.clone().unwrap_or_default();
    let value = FieldDescriptor::builder().number(2).name("value");
    let value = if let Some(t) = FieldType::from_scalar_name(&value_name) {
        value.field_type(t)
    } else if proto.enum_type(&value_name).is_some() {
        value.field_type(FieldType::Enum).enum_type_name(value_name)
    } else {
        value.field_type(FieldType::Message).message_type_name(value_name)
    };
    Ok(EntryFrame {
        key: FieldDescriptor::builder().number(1).name("key").field_type(key_type).build(),
        value: value.build(),
        key_written: false,
        value_written: false,
        held: None,
    })
}

/// A `field` inside a map entry: its key or its (scalar) value.
fn entry_field(
    writer: &mut Writer,
    ring: &mut LoopBuf,
    proto: &ProtoFile,
    entry: &mut EntryFrame,
    name: &str,
    value: &ScalarValue,
) -> WriteResult<()> {
    match name {
        "key" => {
            if entry.key_written {
                return Err(invalid("a map entry has two keys"));
            }
            writer.write_key(ring, &key_text(&entry.key, value))?;
            entry.key_written = true;
            if let Some(held) = entry.held.take() {
                write_scalar(writer, ring, &entry.value, proto, &held)?;
                entry.value_written = true;
            }
            Ok(())
        }
        "value" => {
            if entry.value.field_type == FieldType::Message {
                return Err(invalid("a map entry's value is a message: write it with start_field"));
            }
            if entry.value_written || entry.held.is_some() {
                return Err(invalid("a map entry has two values"));
            }
            if entry.key_written {
                write_scalar(writer, ring, &entry.value, proto, value)?;
                entry.value_written = true;
            } else {
                entry.held = Some(value.clone());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// A map key as a JSON object key: always text, whatever its type.
fn key_text(fd: &FieldDescriptor, value: &ScalarValue) -> String {
    match fd.field_type {
        FieldType::String => match value {
            ScalarValue::String(s) => s.clone(),
            _ => String::new(),
        },
        FieldType::Bool => {
            let b = matches!(value, ScalarValue::Bool(true))
                || matches!(value, ScalarValue::U64(v) if *v != 0)
                || matches!(value, ScalarValue::I32(v) if *v != 0)
                || matches!(value, ScalarValue::I64(v) if *v != 0);
            b.to_string()
        }
        FieldType::Int32 | FieldType::Sint32 | FieldType::Sfixed32 => (as_i64(value) as i32).to_string(),
        FieldType::Uint32 | FieldType::Fixed32 => (as_u64(value) as u32).to_string(),
        FieldType::Int64 | FieldType::Sint64 | FieldType::Sfixed64 => as_i64(value).to_string(),
        _ => as_u64(value).to_string(),
    }
}

/// A key the entry never had is the default for its type (what the wire
/// leaves out).
fn write_key_if_missing(writer: &mut Writer, ring: &mut LoopBuf, proto: &ProtoFile, entry: &mut EntryFrame) -> WriteResult<()> {
    if !entry.key_written {
        let default = if entry.key.field_type == FieldType::String { ScalarValue::String(String::new()) } else { ScalarValue::I32(0) };
        entry_field(writer, ring, proto, entry, "key", &default)?;
    }
    Ok(())
}

/// The end of a map entry: whatever it never had is the default for its type.
fn finish_entry(writer: &mut Writer, ring: &mut LoopBuf, proto: &ProtoFile, mut entry: EntryFrame) -> WriteResult<()> {
    write_key_if_missing(writer, ring, proto, &mut entry)?;
    if !entry.value_written {
        if entry.value.field_type == FieldType::Message {
            writer.write_start_object(ring)?;
            writer.write_end_object(ring)
        } else {
            write_scalar(writer, ring, &entry.value, proto, &ScalarValue::I32(0))
        }
    } else {
        Ok(())
    }
}

/// The bare JSON value of a finished well-known message.
fn write_bare(writer: &mut Writer, ring: &mut LoopBuf, proto: &ProtoFile, frame: BareFrame) -> WriteResult<()> {
    match frame.kind {
        WellKnown::Timestamp => {
            writer.write_string(ring, &well_known::format_timestamp(frame.seconds, frame.nanos).map_err(invalid)?)
        }
        WellKnown::Duration => {
            writer.write_string(ring, &well_known::format_duration(frame.seconds, frame.nanos).map_err(invalid)?)
        }
        WellKnown::FieldMask => writer.write_string(ring, &well_known::field_mask_to_json(&frame.paths).map_err(invalid)?),
        WellKnown::Wrapper(field_type) => {
            // Nothing set is the default of the wrapped type.
            let fd = FieldDescriptor::builder().number(1).name("value").field_type(field_type).build();
            let value = frame.value.unwrap_or(ScalarValue::I32(0));
            write_scalar(writer, ring, &fd, proto, &value)
        }
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

    // -- repeated fields and maps (issue #513) ----------------------------------

    const REPEATED: &str = r#"
        syntax = "proto3";
        package demo;
        enum Color { RED = 0; GREEN = 1; BLUE = 2; }
        message Inner { int32 v = 1; repeated string tags = 2; }
        message R {
            repeated int32 nums = 1; repeated int64 big = 2; repeated string names = 3;
            repeated Color colors = 4; repeated bytes blobs = 5; repeated double ds = 6;
            repeated bool flags = 7; repeated Inner inners = 8;
            map<string, int32> counts = 9; map<int32, string> by_id = 10;
            map<bool, string> by_flag = 11; map<uint64, string> by_big = 12;
            map<string, Inner> inner_by_name = 13; map<string, Color> shades = 14;
            map<string, int64> longs = 15; map<string, bytes> raw = 16;
            string s = 17; Inner one = 18;
            repeated int32 snake_nums = 19 [json_name = "customNums"];
            map<string, int32> snake_map = 20 [json_name = "customMap"];
            map<sint64, string> signed_keys = 21;
        }
    "#;

    /// A serializer and its output, driven by the tests below.
    struct Out {
        ser: JsonModelSerializer,
        w: Writer,
        ring: LoopBuf,
    }

    impl Out {
        fn new() -> Self {
            let mut out = Self {
                ser: JsonModelSerializer::new(ProtoFileParser::parse(REPEATED).unwrap()),
                w: Writer::new(),
                ring: LoopBuf::with_capacity(4096),
            };
            out.ser.start_message(&mut out.w, &mut out.ring, "demo.R").unwrap();
            out
        }

        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), String> {
            self.ser.field(&mut self.w, &mut self.ring, name, value).map_err(|e| e.to_string())
        }

        fn start(&mut self, name: &str, type_name: &str) -> Result<(), String> {
            self.ser.start_field(&mut self.w, &mut self.ring, name, type_name).map_err(|e| e.to_string())
        }

        fn end(&mut self) {
            self.ser.end_field(&mut self.w, &mut self.ring).unwrap();
        }

        /// Closes the root message and returns the JSON.
        fn finish(mut self) -> String {
            self.ser.end_message(&mut self.w, &mut self.ring).unwrap();
            let (a, b) = self.ring.readable_spans();
            String::from_utf8([a, b].concat()).unwrap()
        }

        fn ints(&mut self, name: &str, values: &[i32]) {
            for v in values {
                self.field(name, ScalarValue::I32(*v)).unwrap();
            }
        }

        /// One map entry with a scalar value, key first.
        fn entry(&mut self, map: &str, key: ScalarValue, value: ScalarValue) {
            self.start(map, &format!("{map}.MapEntry")).unwrap();
            self.field("key", key).unwrap();
            self.field("value", value).unwrap();
            self.end();
        }
    }

    fn text(s: &str) -> ScalarValue {
        ScalarValue::String(s.into())
    }

    #[test]
    fn a_repeated_scalar_is_a_json_array() {
        let mut o = Out::new();
        o.ints("nums", &[1, -2, 300]);
        assert_eq!(o.finish(), r#"{"nums":[1,-2,300]}"#);
    }

    #[test]
    fn a_single_element_is_still_an_array() {
        let mut o = Out::new();
        o.ints("nums", &[7]);
        assert_eq!(o.finish(), r#"{"nums":[7]}"#);
    }

    #[test]
    fn the_array_ends_where_the_next_field_begins() {
        let mut o = Out::new();
        o.ints("nums", &[1, 2]);
        o.field("s", text("x")).unwrap();
        assert_eq!(o.finish(), r#"{"nums":[1,2],"s":"x"}"#);
    }

    #[test]
    fn two_repeated_fields_one_after_the_other() {
        let mut o = Out::new();
        o.ints("nums", &[1]);
        o.field("names", text("a")).unwrap();
        o.field("names", text("b")).unwrap();
        assert_eq!(o.finish(), r#"{"nums":[1],"names":["a","b"]}"#);
    }

    #[test]
    fn elements_follow_the_scalar_mapping_of_their_type() {
        let mut o = Out::new();
        o.field("big", ScalarValue::I64(-9)).unwrap();
        o.field("big", ScalarValue::I64(i64::MAX)).unwrap();
        o.field("colors", ScalarValue::U64(1)).unwrap();
        o.field("colors", ScalarValue::U64(9)).unwrap();
        o.field("blobs", ScalarValue::Bytes(vec![0xfb, 0xff])).unwrap();
        o.field("ds", ScalarValue::F64(0.5)).unwrap();
        o.field("ds", ScalarValue::F64(f64::NAN)).unwrap();
        o.field("flags", ScalarValue::Bool(true)).unwrap();
        o.field("flags", ScalarValue::Bool(false)).unwrap();
        assert_eq!(
            o.finish(),
            r#"{"big":["-9","9223372036854775807"],"colors":["GREEN",9],"blobs":["+/8="],"ds":[0.5,"NaN"],"flags":[true,false]}"#
        );
    }

    #[test]
    fn a_repeated_field_is_written_under_its_json_name() {
        let mut o = Out::new();
        o.ints("snake_nums", &[1, 2]);
        assert_eq!(o.finish(), r#"{"customNums":[1,2]}"#);
    }

    #[test]
    fn repeated_messages_are_an_array_of_objects() {
        let mut o = Out::new();
        for v in [1, 2] {
            o.start("inners", "demo.Inner").unwrap();
            o.field("v", ScalarValue::I32(v)).unwrap();
            o.end();
        }
        o.field("s", text("after")).unwrap();
        assert_eq!(o.finish(), r#"{"inners":[{"v":1},{"v":2}],"s":"after"}"#);
    }

    #[test]
    fn a_repeated_field_inside_a_repeated_message() {
        let mut o = Out::new();
        o.start("inners", "demo.Inner").unwrap();
        o.field("tags", text("a")).unwrap();
        o.field("tags", text("b")).unwrap();
        o.field("v", ScalarValue::I32(5)).unwrap();
        o.end();
        o.start("inners", "demo.Inner").unwrap();
        o.end();
        o.start("one", "demo.Inner").unwrap();
        o.field("tags", text("c")).unwrap();
        o.end();
        assert_eq!(o.finish(), r#"{"inners":[{"tags":["a","b"],"v":5},{}],"one":{"tags":["c"]}}"#);
    }

    #[test]
    fn a_repeated_field_that_comes_back_after_other_fields_is_an_error_not_a_second_key() {
        // The first array is already written and closed; a second "nums" key
        // would be an object JSON readers disagree about.
        let mut o = Out::new();
        o.ints("nums", &[1]);
        o.field("s", text("x")).unwrap();
        let err = o.field("nums", ScalarValue::I32(2)).unwrap_err();
        assert!(err.contains("nums"), "{err}");
    }

    #[test]
    fn a_message_field_given_a_scalar_is_an_error_not_a_dangling_key() {
        let mut o = Out::new();
        assert!(o.field("one", ScalarValue::I32(1)).is_err());
        assert!(o.field("counts", ScalarValue::I32(1)).is_err());
        assert!(o.start("s", "demo.Inner").is_err(), "a string is not a message");
        assert_eq!(o.finish(), "{}", "nothing was left half written");
    }

    #[test]
    fn a_map_is_a_json_object() {
        let mut o = Out::new();
        o.entry("counts", text("a"), ScalarValue::I32(1));
        o.entry("counts", text("b"), ScalarValue::I32(-2));
        assert_eq!(o.finish(), r#"{"counts":{"a":1,"b":-2}}"#);
    }

    #[test]
    fn map_keys_of_every_scalar_kind_are_strings() {
        let mut o = Out::new();
        o.entry("by_id", ScalarValue::I32(-4), text("minus four"));
        o.entry("by_id", ScalarValue::I32(10), text("ten"));
        o.entry("by_flag", ScalarValue::Bool(true), text("yes"));
        o.entry("by_flag", ScalarValue::Bool(false), text("no"));
        o.entry("by_big", ScalarValue::U64(u64::MAX), text("max"));
        o.entry("signed_keys", ScalarValue::I64(i64::MIN), text("min"));
        assert_eq!(
            o.finish(),
            r#"{"byId":{"-4":"minus four","10":"ten"},"byFlag":{"true":"yes","false":"no"},"byBig":{"18446744073709551615":"max"},"signedKeys":{"-9223372036854775808":"min"}}"#
        );
    }

    #[test]
    fn map_values_follow_the_scalar_mapping_of_their_type() {
        let mut o = Out::new();
        o.entry("shades", text("a"), ScalarValue::U64(2));
        o.entry("shades", text("b"), ScalarValue::U64(7));
        o.entry("longs", text("n"), ScalarValue::I64(-1));
        o.entry("raw", text("r"), ScalarValue::Bytes(b"foo".to_vec()));
        assert_eq!(
            o.finish(),
            r#"{"shades":{"a":"BLUE","b":7},"longs":{"n":"-1"},"raw":{"r":"Zm9v"}}"#
        );
    }

    #[test]
    fn map_values_that_are_messages() {
        let mut o = Out::new();
        for (k, v) in [("x", 1), ("y", 2)] {
            o.start("inner_by_name", "inner_by_name.MapEntry").unwrap();
            o.field("key", text(k)).unwrap();
            o.start("value", "demo.Inner").unwrap();
            o.field("v", ScalarValue::I32(v)).unwrap();
            o.end();
            o.end();
        }
        assert_eq!(o.finish(), r#"{"innerByName":{"x":{"v":1},"y":{"v":2}}}"#);
    }

    #[test]
    fn a_map_is_written_under_its_json_name_and_ends_where_the_next_field_begins() {
        let mut o = Out::new();
        o.entry("snake_map", text("k"), ScalarValue::I32(1));
        o.field("s", text("x")).unwrap();
        o.ints("nums", &[3]);
        o.entry("counts", text("c"), ScalarValue::I32(2));
        assert_eq!(o.finish(), r#"{"customMap":{"k":1},"s":"x","nums":[3],"counts":{"c":2}}"#);
    }

    #[test]
    fn an_entry_without_a_key_or_value_takes_the_defaults() {
        let mut o = Out::new();
        o.start("counts", "counts.MapEntry").unwrap();
        o.field("key", text("only-key")).unwrap();
        o.end();
        o.start("counts", "counts.MapEntry").unwrap();
        o.field("value", ScalarValue::I32(9)).unwrap();
        o.end();
        o.start("by_id", "by_id.MapEntry").unwrap();
        o.end();
        o.start("inner_by_name", "inner_by_name.MapEntry").unwrap();
        o.field("key", text("k")).unwrap();
        o.end();
        assert_eq!(
            o.finish(),
            r#"{"counts":{"only-key":0,"":9},"byId":{"0":""},"innerByName":{"k":{}}}"#
        );
    }

    #[test]
    fn a_value_that_arrives_before_its_key_is_held_until_the_key_does() {
        // Wire order is the encoder's choice; JSON needs the key first.
        let mut o = Out::new();
        o.start("counts", "counts.MapEntry").unwrap();
        o.field("value", ScalarValue::I32(5)).unwrap();
        o.field("key", text("late")).unwrap();
        o.end();
        assert_eq!(o.finish(), r#"{"counts":{"late":5}}"#);
    }

    #[test]
    fn fields_the_message_does_not_have_are_skipped_with_everything_inside_them() {
        let mut o = Out::new();
        o.ints("nums", &[1]);
        o.start("nope", "demo.Inner").unwrap();
        o.field("v", ScalarValue::I32(2)).unwrap();
        o.start("deeper", "demo.Inner").unwrap();
        o.end();
        o.end();
        o.field("s", text("x")).unwrap();
        assert_eq!(o.finish(), r#"{"nums":[1],"s":"x"}"#, "the skipped field's end did not close the real message");
    }

    // -- round trips through the adapters ------------------------------------------

    /// Feeds a serializer from the events an adapter produces. The adapters
    /// report a nested message as `start_field` then `start_message`, and its
    /// end as `end_message` then `end_field`; the serializer takes each pair
    /// as one call.
    struct Replay {
        out: Out,
        /// `start_message` right after a `start_field` is the same message.
        just_started_field: bool,
        depth: u32,
        error: Option<String>,
    }

    impl Replay {
        fn new() -> Self {
            Self::over(Out::new())
        }

        fn over(out: Out) -> Self {
            Self { out, just_started_field: false, depth: 0, error: None }
        }

        fn note(&mut self, r: Result<(), String>) -> Result<(), crate::proto::ProtoParseError> {
            if let Err(e) = r {
                self.error.get_or_insert(e.clone());
                return Err(crate::proto::ProtoParseError::new(e));
            }
            Ok(())
        }
    }

    impl crate::proto::ProtoMessageHandler for Replay {
        fn start_message(&mut self, _type_name: &str) -> Result<(), crate::proto::ProtoParseError> {
            // the root was started by `Out::new`
            self.just_started_field = false;
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), crate::proto::ProtoParseError> {
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), crate::proto::ProtoParseError> {
            let r = self.out.field(name, value);
            self.note(r)
        }
        fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), crate::proto::ProtoParseError> {
            self.just_started_field = true;
            self.depth += 1;
            let r = self.out.start(name, type_name);
            self.note(r)
        }
        fn end_field(&mut self) -> Result<(), crate::proto::ProtoParseError> {
            self.depth -= 1;
            let r = self.out.ser.end_field(&mut self.out.w, &mut self.out.ring).map_err(|e| e.to_string());
            self.note(r)
        }
    }

    /// `json` read by the adapter and written again by the serializer.
    fn json_round_trip(json: &str) -> String {
        use crate::proto::JsonModelAdapter;
        use rjsonparser::Parser;
        let proto = ProtoFileParser::parse(REPEATED).unwrap();
        let mut adapter = JsonModelAdapter::new(proto, Replay::new());
        adapter.start_root_message("demo.R").unwrap();
        {
            let mut p = Parser::new(&mut adapter);
            p.parse(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"));
        }
        adapter.end_root_message().unwrap();
        let replay = adapter.into_handler();
        assert_eq!(replay.error, None);
        replay.out.finish()
    }

    #[test]
    fn json_read_by_the_adapter_is_written_back_as_it_was() {
        for json in [
            r#"{"nums":[1,-2,300]}"#,
            r#"{"nums":[1,2],"s":"x"}"#,
            r#"{"names":["a","b"],"big":["-9","9223372036854775807"],"colors":["GREEN","BLUE"]}"#,
            r#"{"inners":[{"v":1},{"v":2,"tags":["a","b"]}],"one":{"tags":["c"]}}"#,
            r#"{"counts":{"a":1,"b":-2},"s":"x"}"#,
            r#"{"byId":{"-4":"minus four","10":"ten"},"byFlag":{"true":"yes","false":"no"},"byBig":{"18446744073709551615":"max"}}"#,
            r#"{"innerByName":{"x":{"v":1},"y":{"v":2,"tags":["t"]}},"shades":{"a":"BLUE"},"longs":{"n":"-1"},"raw":{"r":"Zm9v"}}"#,
            r#"{"customNums":[1,2],"customMap":{"k":1}}"#,
        ] {
            assert_eq!(json_round_trip(json), json);
        }
    }

    #[test]
    fn protobuf_bytes_become_json_through_the_proto_adapter() {
        // What a standard encoder sends: packed repeated numbers, unpacked
        // strings, and map entries, in one message.
        use crate::proto::ProtoModelAdapter;
        use rprotobuf::Parser;
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
        fn len(field: u32, body: &[u8]) -> Vec<u8> {
            [varint(u64::from(field << 3 | 2)), varint(body.len() as u64), body.to_vec()].concat()
        }
        fn vint(field: u32, v: u64) -> Vec<u8> {
            [varint(u64::from(field << 3)), varint(v)].concat()
        }
        let wire = [
            len(1, &[1, 172, 2]),                                          // nums = [1, 300] (packed)
            len(3, b"a"),
            len(3, b"b"),                                                 // names
            len(9, &[len(1, b"k"), vint(2, 5)].concat()),                  // counts["k"] = 5
            len(13, &[len(1, b"x"), len(2, &vint(1, 7))].concat()),        // inner_by_name["x"].v = 7
        ]
        .concat();
        let proto = ProtoFileParser::parse(REPEATED).unwrap();
        let mut adapter = ProtoModelAdapter::new(proto, Replay::new());
        adapter.start_root_message("demo.R").unwrap();
        {
            let mut pb = Parser::new(&mut adapter);
            pb.parse(wire.as_slice()).unwrap();
        }
        adapter.end_root_message().unwrap();
        let replay = adapter.into_handler();
        assert_eq!(replay.error, None);
        assert_eq!(
            replay.out.finish(),
            r#"{"nums":[1,300],"names":["a","b"],"counts":{"k":5},"innerByName":{"x":{"v":7}}}"#
        );
    }

    // -- one script, both encodings ----------------------------------------------------

    /// An event for a serializer: a scalar field, the start of a nested
    /// message (or map entry, or the value of one), or its end.
    enum Ev {
        F(&'static str, ScalarValue),
        S(&'static str, &'static str),
        E,
    }

    /// The JSON the serializer writes for `script`.
    fn json_of(script: &[Ev]) -> String {
        json_of_in(REPEATED, "demo.R", script)
    }

    fn json_of_in(src: &str, root: &str, script: &[Ev]) -> String {
        let mut o = Out::of(src, root);
        for ev in script {
            match ev {
                Ev::F(name, v) => o.field(name, v.clone()).unwrap(),
                Ev::S(name, t) => o.start(name, t).unwrap(),
                Ev::E => o.end(),
            }
        }
        o.finish()
    }

    /// The JSON for `script` written as protobuf, read back and written as JSON.
    fn json_via_protobuf(script: &[Ev]) -> String {
        json_via_protobuf_in(REPEATED, "demo.R", script)
    }

    fn json_via_protobuf_in(src: &str, root: &str, script: &[Ev]) -> String {
        use crate::proto::{ProtoModelAdapter, ProtoModelSerializer};
        use rprotobuf::Parser;
        let proto = ProtoFileParser::parse(src).unwrap();
        let mut ser = ProtoModelSerializer::new(proto.clone());
        let mut w = rprotobuf::Writer::new();
        let mut ring = LoopBuf::with_capacity(4096);
        ser.start_message(root).unwrap();
        for ev in script {
            match ev {
                Ev::F(name, v) => ser.field(&mut w, &mut ring, name, v.clone()).unwrap(),
                Ev::S(name, t) => ser.start_field(name, t).unwrap(),
                Ev::E => ser.end_field(&mut w, &mut ring).unwrap(),
            }
        }
        ser.end_message();
        let mut wire = Vec::new();
        w.drain_to(&mut ring, &mut wire).unwrap();

        let mut adapter = ProtoModelAdapter::new(proto, Replay::over(Out::of(src, root)));
        adapter.start_root_message(root).unwrap();
        {
            let mut pb = Parser::new(&mut adapter);
            pb.parse(wire.as_slice()).unwrap();
        }
        adapter.end_root_message().unwrap();
        let replay = adapter.into_handler();
        assert_eq!(replay.error, None);
        replay.out.finish()
    }

    #[test]
    fn a_handler_gets_the_same_message_in_either_encoding() {
        use Ev::{E, F, S};
        let script = [
            F("nums", ScalarValue::I32(1)),
            F("nums", ScalarValue::I32(-300)),
            F("names", text("a")),
            F("names", text("b")),
            F("big", ScalarValue::I64(-9)),
            F("colors", ScalarValue::U64(1)),
            F("blobs", ScalarValue::Bytes(vec![0xfb, 0xff])),
            F("ds", ScalarValue::F64(0.5)),
            F("flags", ScalarValue::Bool(true)),
            S("inners", "demo.Inner"),
            F("v", ScalarValue::I32(5)),
            F("tags", text("t1")),
            F("tags", text("t2")),
            E,
            S("inners", "demo.Inner"),
            E,
            S("counts", "counts.MapEntry"),
            F("key", text("a")),
            F("value", ScalarValue::I32(1)),
            E,
            S("counts", "counts.MapEntry"),
            F("key", text("b")),
            F("value", ScalarValue::I32(-2)),
            E,
            S("by_id", "by_id.MapEntry"),
            F("key", ScalarValue::I32(-4)),
            F("value", text("minus four")),
            E,
            S("by_flag", "by_flag.MapEntry"),
            F("key", ScalarValue::Bool(true)),
            F("value", text("yes")),
            E,
            S("by_big", "by_big.MapEntry"),
            F("key", ScalarValue::U64(u64::MAX)),
            F("value", text("max")),
            E,
            S("inner_by_name", "inner_by_name.MapEntry"),
            F("key", text("x")),
            S("value", "demo.Inner"),
            F("v", ScalarValue::I32(7)),
            E,
            E,
            S("shades", "shades.MapEntry"),
            F("key", text("s")),
            F("value", ScalarValue::U64(2)),
            E,
            S("longs", "longs.MapEntry"),
            F("key", text("n")),
            F("value", ScalarValue::I64(-1)),
            E,
            S("raw", "raw.MapEntry"),
            F("key", text("r")),
            F("value", ScalarValue::Bytes(b"foo".to_vec())),
            E,
            F("s", text("x")),
            S("one", "demo.Inner"),
            F("tags", text("c")),
            E,
        ];
        let json = json_of(&script);
        assert!(json.contains(r#""counts":{"a":1,"b":-2}"#) && json.contains(r#""one":{"tags":["c"]}"#), "{json}");
        assert_eq!(json_via_protobuf(&script), json);
    }

    #[test]
    fn defaults_in_a_map_entry_come_out_the_same_in_either_encoding() {
        use Ev::{E, F, S};
        let script = [
            S("counts", "counts.MapEntry"),
            F("key", text("only-key")),
            E,
            S("counts", "counts.MapEntry"),
            F("value", ScalarValue::I32(9)),
            E,
            S("by_id", "by_id.MapEntry"),
            E,
            S("inner_by_name", "inner_by_name.MapEntry"),
            F("key", text("k")),
            E,
        ];
        assert_eq!(json_via_protobuf(&script), json_of(&script));
    }

    // -- well-known types with a bare JSON form (issue #514) ----------------------------

    const WKT: &str = r#"
        syntax = "proto3";
        package demo;
        message W {
            google.protobuf.Timestamp at = 1; google.protobuf.Duration d = 2;
            google.protobuf.FieldMask mask = 3; google.protobuf.Int64Value i64v = 4;
            google.protobuf.StringValue sv = 5; google.protobuf.BoolValue bv = 6;
            google.protobuf.BytesValue bytes_v = 7; google.protobuf.DoubleValue dv = 8;
            google.protobuf.UInt32Value u32v = 9; repeated google.protobuf.Timestamp times = 10;
            map<string, google.protobuf.Duration> deadlines = 11; google.protobuf.Empty nothing = 12;
            repeated google.protobuf.StringValue svs = 13; google.protobuf.FloatValue fv = 14;
            google.protobuf.Int32Value i32v = 15; google.protobuf.UInt64Value u64v = 16;
        }
    "#;

    impl Out {
        /// A serializer over `src`, with a `root` message started.
        fn of(src: &str, root: &str) -> Self {
            let mut out = Self {
                ser: JsonModelSerializer::new(ProtoFileParser::parse(src).unwrap()),
                w: Writer::new(),
                ring: LoopBuf::with_capacity(4096),
            };
            out.ser.start_message(&mut out.w, &mut out.ring, root).unwrap();
            out
        }

        /// `type_name` as field `name`, with `fields` in it.
        fn message(&mut self, name: &str, type_name: &str, fields: &[(&str, ScalarValue)]) -> Result<(), String> {
            self.start(name, type_name)?;
            for (n, v) in fields {
                self.field(n, v.clone())?;
            }
            self.ser.end_field(&mut self.w, &mut self.ring).map_err(|e| e.to_string())
        }
    }

    const TS: &str = "google.protobuf.Timestamp";
    const DUR: &str = "google.protobuf.Duration";

    fn secs_nanos(s: i64, n: i32) -> Vec<(&'static str, ScalarValue)> {
        vec![("seconds", ScalarValue::I64(s)), ("nanos", ScalarValue::I32(n))]
    }

    fn wkt_json(build: impl FnOnce(&mut Out) -> Result<(), String>) -> Result<String, String> {
        let mut o = Out::of(WKT, "demo.W");
        build(&mut o)?;
        Ok(o.finish())
    }

    #[test]
    fn a_timestamp_is_an_rfc_3339_string() {
        let json = wkt_json(|o| o.message("at", TS, &secs_nanos(63_108_020, 21_000_000))).unwrap();
        assert_eq!(json, r#"{"at":"1972-01-01T10:00:20.021Z"}"#);
    }

    #[test]
    fn a_timestamp_with_no_fields_is_the_epoch() {
        assert_eq!(wkt_json(|o| o.message("at", TS, &[])).unwrap(), r#"{"at":"1970-01-01T00:00:00Z"}"#);
        assert_eq!(wkt_json(|o| o.message("at", TS, &[("seconds", ScalarValue::I64(60))])).unwrap(), r#"{"at":"1970-01-01T00:01:00Z"}"#);
    }

    #[test]
    fn a_duration_is_seconds_with_an_s() {
        assert_eq!(wkt_json(|o| o.message("d", DUR, &secs_nanos(1, 500_000_000))).unwrap(), r#"{"d":"1.500s"}"#);
        assert_eq!(wkt_json(|o| o.message("d", DUR, &secs_nanos(-3, -1000))).unwrap(), r#"{"d":"-3.000001s"}"#);
        assert_eq!(wkt_json(|o| o.message("d", DUR, &[])).unwrap(), r#"{"d":"0s"}"#);
    }

    #[test]
    fn a_field_mask_is_its_paths_in_camel_case_joined_by_commas() {
        let paths = [("paths", text("foo_bar.baz")), ("paths", text("qux"))];
        assert_eq!(wkt_json(|o| o.message("mask", "google.protobuf.FieldMask", &paths)).unwrap(), r#"{"mask":"fooBar.baz,qux"}"#);
        assert_eq!(wkt_json(|o| o.message("mask", "google.protobuf.FieldMask", &[])).unwrap(), r#"{"mask":""}"#);
    }

    #[test]
    fn a_wrapper_is_the_value_it_wraps_in_that_values_json_form() {
        let w = |name: &str, ty: &str, v: ScalarValue| wkt_json(|o| o.message(name, ty, &[("value", v)])).unwrap();
        assert_eq!(w("i64v", "google.protobuf.Int64Value", ScalarValue::I64(5)), r#"{"i64v":"5"}"#, "64-bit integers are strings");
        assert_eq!(w("u64v", "google.protobuf.UInt64Value", ScalarValue::U64(u64::MAX)), r#"{"u64v":"18446744073709551615"}"#);
        assert_eq!(w("i32v", "google.protobuf.Int32Value", ScalarValue::I32(-7)), r#"{"i32v":-7}"#);
        assert_eq!(w("u32v", "google.protobuf.UInt32Value", ScalarValue::U64(4_000_000_000)), r#"{"u32v":4000000000}"#);
        assert_eq!(w("sv", "google.protobuf.StringValue", text("hi \"there\"")), r#"{"sv":"hi \"there\""}"#);
        assert_eq!(w("bv", "google.protobuf.BoolValue", ScalarValue::Bool(true)), r#"{"bv":true}"#);
        assert_eq!(w("bytes_v", "google.protobuf.BytesValue", ScalarValue::Bytes(b"foo".to_vec())), r#"{"bytesV":"Zm9v"}"#);
        assert_eq!(w("dv", "google.protobuf.DoubleValue", ScalarValue::F64(1.5)), r#"{"dv":1.5}"#);
        assert_eq!(w("dv", "google.protobuf.DoubleValue", ScalarValue::F64(f64::NAN)), r#"{"dv":"NaN"}"#);
        assert_eq!(w("fv", "google.protobuf.FloatValue", ScalarValue::F32(0.1)), r#"{"fv":0.1}"#);
    }

    #[test]
    fn a_wrapper_with_nothing_in_it_is_the_default_of_its_type() {
        let empty = |name: &str, ty: &str| wkt_json(|o| o.message(name, ty, &[])).unwrap();
        assert_eq!(empty("i64v", "google.protobuf.Int64Value"), r#"{"i64v":"0"}"#);
        assert_eq!(empty("i32v", "google.protobuf.Int32Value"), r#"{"i32v":0}"#);
        assert_eq!(empty("sv", "google.protobuf.StringValue"), r#"{"sv":""}"#);
        assert_eq!(empty("bv", "google.protobuf.BoolValue"), r#"{"bv":false}"#);
        assert_eq!(empty("bytes_v", "google.protobuf.BytesValue"), r#"{"bytesV":""}"#);
        assert_eq!(empty("dv", "google.protobuf.DoubleValue"), r#"{"dv":0}"#);
    }

    #[test]
    fn empty_is_an_empty_object() {
        assert_eq!(wkt_json(|o| o.message("nothing", "google.protobuf.Empty", &[])).unwrap(), r#"{"nothing":{}}"#);
    }

    #[test]
    fn elements_of_a_repeated_field_and_values_of_a_map_are_bare_too() {
        let json = wkt_json(|o| {
            o.message("times", TS, &secs_nanos(0, 0))?;
            o.message("times", TS, &secs_nanos(63_108_020, 0))?;
            o.message("svs", "google.protobuf.StringValue", &[("value", text("a"))])?;
            o.message("svs", "google.protobuf.StringValue", &[("value", text("b"))])?;
            o.start("deadlines", "deadlines.MapEntry")?;
            o.field("key", text("short"))?;
            o.message("value", DUR, &secs_nanos(1, 0))?;
            o.ser.end_field(&mut o.w, &mut o.ring).map_err(|e| e.to_string())?;
            o.start("deadlines", "deadlines.MapEntry")?;
            o.field("key", text("long"))?;
            o.message("value", DUR, &secs_nanos(3600, 0))?;
            o.ser.end_field(&mut o.w, &mut o.ring).map_err(|e| e.to_string())
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"times":["1970-01-01T00:00:00Z","1972-01-01T10:00:20Z"],"svs":["a","b"],"deadlines":{"short":"1s","long":"3600s"}}"#
        );
    }

    #[test]
    fn a_message_that_is_itself_a_timestamp_is_the_whole_document() {
        let mut o = Out::of(WKT, TS);
        o.field("seconds", ScalarValue::I64(63_108_020)).unwrap();
        assert_eq!(o.finish(), r#""1972-01-01T10:00:20Z""#);
    }

    #[test]
    fn a_value_that_cannot_be_written_in_the_json_form_is_an_error() {
        let ts = |s, n| wkt_json(|o| o.message("at", TS, &secs_nanos(s, n)));
        assert!(ts(300_000_000_000, 0).is_err(), "past year 9999");
        assert!(ts(0, -1).is_err(), "negative nanos");
        assert!(wkt_json(|o| o.message("d", DUR, &secs_nanos(1, -1))).is_err(), "signs differ");
        assert!(wkt_json(|o| o.message("mask", "google.protobuf.FieldMask", &[("paths", text("fooBar"))])).is_err());
        let err = wkt_json(|o| o.message("at", TS, &secs_nanos(300_000_000_000, 0))).unwrap_err();
        assert!(err.contains("9999"), "{err}");
    }

    #[test]
    fn fields_a_bare_type_does_not_have_are_ignored_and_a_nested_message_in_one_is_refused() {
        let json = wkt_json(|o| o.message("at", TS, &[("seconds", ScalarValue::I64(0)), ("bogus", ScalarValue::I32(1))])).unwrap();
        assert_eq!(json, r#"{"at":"1970-01-01T00:00:00Z"}"#);
        let mut o = Out::of(WKT, "demo.W");
        o.start("at", TS).unwrap();
        assert!(o.start("seconds", DUR).is_err(), "nothing nests inside a timestamp");
    }

    #[test]
    fn well_known_json_read_by_the_adapter_is_written_back_normalised() {
        use crate::proto::JsonModelAdapter;
        use rjsonparser::Parser;
        let round = |json: &str| {
            let proto = ProtoFileParser::parse(WKT).unwrap();
            let mut adapter = JsonModelAdapter::new(proto, Replay::over(Out::of(WKT, "demo.W")));
            adapter.start_root_message("demo.W").unwrap();
            {
                let mut p = Parser::new(&mut adapter);
                p.parse(json.as_bytes()).unwrap_or_else(|e| panic!("{json}: {e}"));
            }
            adapter.end_root_message().unwrap();
            let replay = adapter.into_handler();
            assert_eq!(replay.error, None);
            replay.out.finish()
        };
        assert_eq!(
            round(r#"{"at":"1972-01-01T10:00:20.021Z","d":"1.5s","mask":"fooBar,baz.qux","i64v":"5","sv":"hi","bv":true,"bytesV":"Zm9v","dv":1.5,"u32v":7}"#),
            r#"{"at":"1972-01-01T10:00:20.021Z","d":"1.500s","mask":"fooBar,baz.qux","i64v":"5","sv":"hi","bv":true,"bytesV":"Zm9v","dv":1.5,"u32v":7}"#
        );
        assert_eq!(round(r#"{"at":"1972-01-01T02:00:20-08:00"}"#), r#"{"at":"1972-01-01T10:00:20Z"}"#, "an offset becomes Z");
        assert_eq!(round(r#"{"i64v":5,"u64v":"18446744073709551615"}"#), r#"{"i64v":"5","u64v":"18446744073709551615"}"#);
        assert_eq!(
            round(r#"{"times":["1970-01-01T00:00:00Z","1972-01-01T10:00:20Z"],"svs":["a","b"],"deadlines":{"s":"1s","l":"1h"}}"#.replace("1h", "3600s").as_str()),
            r#"{"times":["1970-01-01T00:00:00Z","1972-01-01T10:00:20Z"],"svs":["a","b"],"deadlines":{"s":"1s","l":"3600s"}}"#
        );
        assert_eq!(round(r#"{"at":null,"d":null,"sv":null}"#), "{}", "null is absent");
        assert_eq!(round(r#"{"nothing":{}}"#), r#"{"nothing":{}}"#);
    }

    #[test]
    fn well_known_messages_come_out_the_same_through_protobuf() {
        use Ev::{E, F, S};
        let script = [
            S("at", TS),
            F("seconds", ScalarValue::I64(63_108_020)),
            F("nanos", ScalarValue::I32(21_000_000)),
            E,
            S("d", DUR),
            F("seconds", ScalarValue::I64(-3)),
            F("nanos", ScalarValue::I32(-1000)),
            E,
            S("mask", "google.protobuf.FieldMask"),
            F("paths", text("foo_bar")),
            F("paths", text("baz")),
            E,
            S("i64v", "google.protobuf.Int64Value"),
            F("value", ScalarValue::I64(5)),
            E,
            S("sv", "google.protobuf.StringValue"),
            F("value", text("hi")),
            E,
            S("times", TS),
            F("seconds", ScalarValue::I64(0)),
            E,
            S("times", TS),
            F("seconds", ScalarValue::I64(86_400)),
            E,
            S("deadlines", "deadlines.MapEntry"),
            F("key", text("k")),
            S("value", DUR),
            F("seconds", ScalarValue::I64(2)),
            E,
            E,
        ];
        let expected = r#"{"at":"1972-01-01T10:00:20.021Z","d":"-3.000001s","mask":"fooBar,baz","i64v":"5","sv":"hi","times":["1970-01-01T00:00:00Z","1970-01-02T00:00:00Z"],"deadlines":{"k":"2s"}}"#;
        let direct = json_of_in(WKT, "demo.W", &script);
        assert_eq!(direct, expected);
        assert_eq!(json_via_protobuf_in(WKT, "demo.W", &script), expected);
    }
}
