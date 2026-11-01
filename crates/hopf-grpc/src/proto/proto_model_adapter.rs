// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Adapter that bridges low-level `rprotobuf::Handler` events to high-level
//! [`ProtoMessageHandler`] events using a Proto model.

use std::collections::VecDeque;

use loopbuf::LoopBuf;
use rprotobuf::decode_helpers::BytesCollector;
use rprotobuf::{Handler, ParseError, ParseResult};

use super::{
    FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ProtoMessageHandler, ProtoParseError,
    ScalarValue,
};

struct MessageContext {
    message: MessageDescriptor,
    field_name: Option<String>,
}

/// Bridges `rprotobuf::Handler` wire events to [`ProtoMessageHandler`] semantic events.
pub struct ProtoModelAdapter<H: ProtoMessageHandler> {
    proto_file: ProtoFile,
    handler: H,
    message_stack: VecDeque<MessageContext>,
    root_started: bool,
    /// Last error from the high-level handler (Gumdrop wraps these in RuntimeException).
    pub last_error: Option<ProtoParseError>,
    /// The field whose bytes are arriving, if the model knows it.
    bytes_field: Option<String>,
    bytes: BytesCollector,
}

impl<H: ProtoMessageHandler> ProtoModelAdapter<H> {
    pub fn new(proto_file: ProtoFile, handler: H) -> Self {
        Self {
            proto_file,
            handler,
            message_stack: VecDeque::new(),
            root_started: false,
            last_error: None,
            bytes_field: None,
            bytes: BytesCollector::default(),
        }
    }

    pub fn handler(&self) -> &H {
        &self.handler
    }

    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    pub fn into_handler(self) -> H {
        self.handler
    }

    /// Initializes parsing for a root message. Must be called before feeding
    /// data to the protobuf parser.
    pub fn start_root_message(&mut self, message_type_name: &str) -> Result<(), ProtoParseError> {
        if self.root_started {
            panic!("Root message already started");
        }
        let mut msg = self.proto_file.message(message_type_name);
        if msg.is_none() && message_type_name.starts_with('.') {
            msg = self.proto_file.message(&message_type_name[1..]);
        }
        let msg = msg
            .cloned()
            .ok_or_else(|| ProtoParseError::new(format!("Unknown message type: {message_type_name}")))?;
        self.handler.start_message(message_type_name)?;
        self.message_stack.push_front(MessageContext {
            message: msg,
            field_name: None,
        });
        self.root_started = true;
        Ok(())
    }

    /// Call when the root message parsing is complete.
    pub fn end_root_message(&mut self) -> Result<(), ProtoParseError> {
        if !self.message_stack.is_empty() {
            self.message_stack.pop_front();
            self.handler.end_message()?;
        }
        // A further root message (the next one of a stream) may follow.
        self.root_started = false;
        Ok(())
    }

    fn current_field(&self, field_number: u32) -> Option<&FieldDescriptor> {
        self.message_stack
            .front()
            .and_then(|ctx| ctx.message.field_by_number(field_number as i32))
    }

    /// Remembers `e` as the last error and stops the parse with it.
    fn map_err(&mut self, e: ProtoParseError) -> ParseError {
        let msg = e.message().to_string();
        self.last_error = Some(e);
        ParseError::new(msg)
    }

    fn emit_field(&mut self, name: &str, value: ScalarValue) -> ParseResult<()> {
        self.handler.field(name, value).map_err(|e| self.map_err(e))
    }
}

impl<H: ProtoMessageHandler> Handler for ProtoModelAdapter<H> {
    fn handle_varint(&mut self, field_number: u32, value: u64) -> ParseResult<()> {
        let fd = match self.current_field(field_number) {
            Some(fd) => fd,
            None => return Ok(()),
        };
        let name = fd.name.clone();
        let val = varint_scalar(fd.field_type, value);
        self.emit_field(&name, val)
    }

    fn handle_fixed64(&mut self, field_number: u32, value: u64) -> ParseResult<()> {
        let fd = match self.current_field(field_number) {
            Some(fd) => fd,
            None => return Ok(()),
        };
        let name = fd.name.clone();
        let val = fixed64_scalar(fd.field_type, value);
        self.emit_field(&name, val)
    }

    fn handle_fixed32(&mut self, field_number: u32, value: u32) -> ParseResult<()> {
        let fd = match self.current_field(field_number) {
            Some(fd) => fd,
            None => return Ok(()),
        };
        let name = fd.name.clone();
        let val = fixed32_scalar(fd.field_type, value);
        self.emit_field(&name, val)
    }

    fn start_bytes(&mut self, field_number: u32, length: u64) -> ParseResult<()> {
        // A field the model does not know is skipped, not gathered.
        self.bytes_field = self.current_field(field_number).map(|fd| fd.name.clone());
        if self.bytes_field.is_some() {
            self.bytes.start(length);
        }
        Ok(())
    }

    fn bytes_content(&mut self, data: &mut LoopBuf) -> ParseResult<()> {
        if self.bytes_field.is_some() {
            self.bytes.push(data);
        } else {
            data.advance(data.len());
        }
        Ok(())
    }

    fn end_bytes(&mut self) -> ParseResult<()> {
        let Some(name) = self.bytes_field.take() else {
            return Ok(());
        };
        let data = self.bytes.take();
        let fd = self
            .message_stack
            .front()
            .and_then(|ctx| ctx.message.fields.iter().find(|fd| fd.name == name))
            .cloned();
        let Some(fd) = fd else {
            return Ok(());
        };
        let proto = self.proto_file.clone();
        let result = decode_len_field(&proto, &mut self.handler, &fd, &data, 0);
        result.map_err(|e| self.map_err(e))
    }

    fn is_message(&self, field_number: u32) -> bool {
        self.current_field(field_number)
            .map(|fd| fd.field_type == FieldType::Message)
            .unwrap_or(false)
    }

    fn start_message(&mut self, field_number: u32) -> ParseResult<()> {
        let (fd_name, type_name) = {
            let ctx = match self.message_stack.front() {
                Some(ctx) => ctx,
                None => return Ok(()),
            };
            let fd = match ctx.message.field_by_number(field_number as i32) {
                Some(fd) => fd,
                None => return Ok(()),
            };
            let type_name = match &fd.message_type_name {
                Some(t) => t.clone(),
                None => return Ok(()),
            };
            (fd.name.clone(), type_name)
        };

        let nested = match self.proto_file.message(&type_name) {
            Some(m) => m.clone(),
            None => return Ok(()),
        };

        self.handler
            .start_field(&fd_name, &type_name)
            .map_err(|e| self.map_err(e))?;
        self.handler
            .start_message(&type_name)
            .map_err(|e| self.map_err(e))?;
        self.message_stack.push_front(MessageContext {
            message: nested,
            field_name: Some(fd_name),
        });
        Ok(())
    }

    fn end_message(&mut self) -> ParseResult<()> {
        let ctx = match self.message_stack.pop_front() {
            Some(ctx) => ctx,
            None => return Ok(()),
        };
        self.handler.end_message().map_err(|e| self.map_err(e))?;
        if ctx.field_name.is_some() {
            self.handler.end_field().map_err(|e| self.map_err(e))?;
        }
        Ok(())
    }
}

/// How deeply nested messages inside a map value are followed.
const MAX_DEPTH: u32 = 64;

/// The scalar a varint stands for in a field of type `ft`.
fn varint_scalar(ft: FieldType, v: u64) -> ScalarValue {
    match ft {
        FieldType::Bool => ScalarValue::Bool(v != 0),
        FieldType::Int32 | FieldType::Sfixed32 => ScalarValue::I32(v as i32),
        FieldType::Uint32 | FieldType::Fixed32 => ScalarValue::U64(u64::from(v as u32)),
        FieldType::Sint32 => {
            let n = v as u32;
            ScalarValue::I32(((n >> 1) as i32) ^ (-((n & 1) as i32)))
        }
        FieldType::Sint64 => ScalarValue::I64(((v >> 1) as i64) ^ (-((v & 1) as i64))),
        FieldType::Int64 | FieldType::Sfixed64 => ScalarValue::I64(v as i64),
        // Enum (a negative value arrives sign-extended), Uint64, Fixed64.
        _ => ScalarValue::U64(v),
    }
}

/// The scalar a 4-byte value stands for in a field of type `ft`.
fn fixed32_scalar(ft: FieldType, v: u32) -> ScalarValue {
    match ft {
        FieldType::Float => ScalarValue::F32(f32::from_bits(v)),
        FieldType::Fixed32 | FieldType::Uint32 => ScalarValue::U64(u64::from(v)),
        _ => ScalarValue::I32(v as i32),
    }
}

/// The scalar an 8-byte value stands for in a field of type `ft`.
fn fixed64_scalar(ft: FieldType, v: u64) -> ScalarValue {
    match ft {
        FieldType::Double => ScalarValue::F64(f64::from_bits(v)),
        FieldType::Sfixed64 | FieldType::Int64 => ScalarValue::I64(v as i64),
        _ => ScalarValue::U64(v),
    }
}

/// Numeric scalar types, which a repeated field may send packed.
fn is_packable(ft: FieldType) -> bool {
    !matches!(ft, FieldType::String | FieldType::Bytes | FieldType::Message | FieldType::Map)
}

/// 4 and 8 byte fields; every other packable type is a varint.
fn fixed_width(ft: FieldType) -> Option<usize> {
    match ft {
        FieldType::Fixed32 | FieldType::Sfixed32 | FieldType::Float => Some(4),
        FieldType::Fixed64 | FieldType::Sfixed64 | FieldType::Double => Some(8),
        _ => None,
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, ProtoParseError> {
    let mut v = 0u64;
    for shift in (0..70).step_by(7) {
        let b = *data.get(*pos).ok_or_else(|| ProtoParseError::new("truncated varint"))?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return Err(ProtoParseError::new("varint too long"));
        }
        v |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(ProtoParseError::new("varint too long"))
}

fn scalar_type(name: &str) -> Option<FieldType> {
    Some(match name {
        "double" => FieldType::Double,
        "float" => FieldType::Float,
        "int32" => FieldType::Int32,
        "int64" => FieldType::Int64,
        "uint32" => FieldType::Uint32,
        "uint64" => FieldType::Uint64,
        "sint32" => FieldType::Sint32,
        "sint64" => FieldType::Sint64,
        "fixed32" => FieldType::Fixed32,
        "fixed64" => FieldType::Fixed64,
        "sfixed32" => FieldType::Sfixed32,
        "sfixed64" => FieldType::Sfixed64,
        "bool" => FieldType::Bool,
        "string" => FieldType::String,
        "bytes" => FieldType::Bytes,
        _ => return None,
    })
}

/// A length-delimited string or bytes value as the scalar of type `ft`.
fn len_scalar(ft: FieldType, data: &[u8]) -> ScalarValue {
    if ft == FieldType::String {
        ScalarValue::String(String::from_utf8_lossy(data).into_owned())
    } else {
        ScalarValue::Bytes(data.to_vec())
    }
}

/// What a field's length-delimited payload means, as events: a string or
/// bytes value, a packed run of numbers, or a map entry. (An embedded
/// message is delivered through the streaming `start_message` path, and
/// only reaches here as a map entry's value.)
fn decode_len_field<H: ProtoMessageHandler>(
    proto: &ProtoFile,
    h: &mut H,
    fd: &FieldDescriptor,
    data: &[u8],
    depth: u32,
) -> Result<(), ProtoParseError> {
    match fd.field_type {
        FieldType::Map => decode_map_entry(proto, h, fd, data, depth),
        FieldType::Message => decode_message_field(proto, h, fd, data, depth),
        ft if fd.repeated && is_packable(ft) => {
            let mut pos = 0;
            match fixed_width(ft) {
                Some(4) => {
                    if data.len() % 4 != 0 {
                        return Err(ProtoParseError::new("packed field is not a whole number of 4-byte values"));
                    }
                    for c in data.chunks_exact(4) {
                        h.field(&fd.name, fixed32_scalar(ft, u32::from_le_bytes([c[0], c[1], c[2], c[3]])))?;
                    }
                }
                Some(_) => {
                    if data.len() % 8 != 0 {
                        return Err(ProtoParseError::new("packed field is not a whole number of 8-byte values"));
                    }
                    for c in data.chunks_exact(8) {
                        let mut b = [0u8; 8];
                        b.copy_from_slice(c);
                        h.field(&fd.name, fixed64_scalar(ft, u64::from_le_bytes(b)))?;
                    }
                }
                None => {
                    while pos < data.len() {
                        let v = read_varint(data, &mut pos)?;
                        h.field(&fd.name, varint_scalar(ft, v))?;
                    }
                }
            }
            Ok(())
        }
        ft => h.field(&fd.name, len_scalar(ft, data)),
    }
}

/// An embedded message inside a decoded payload (a map value).
fn decode_message_field<H: ProtoMessageHandler>(
    proto: &ProtoFile,
    h: &mut H,
    fd: &FieldDescriptor,
    data: &[u8],
    depth: u32,
) -> Result<(), ProtoParseError> {
    let type_name = fd
        .message_type_name
        .as_deref()
        .ok_or_else(|| ProtoParseError::new("message field without a type"))?;
    h.start_field(&fd.name, type_name)?;
    walk_message(proto, h, type_name, data, depth + 1)?;
    h.end_field()
}

/// One map entry: `key = 1`, `value = 2`, each possibly absent (then the
/// type's default, which an absent field is not given an event for).
fn decode_map_entry<H: ProtoMessageHandler>(
    proto: &ProtoFile,
    h: &mut H,
    fd: &FieldDescriptor,
    data: &[u8],
    depth: u32,
) -> Result<(), ProtoParseError> {
    let key_ft = fd
        .key_type_name
        .as_deref()
        .and_then(scalar_type)
        .ok_or_else(|| ProtoParseError::new("map with a key type that is not a scalar"))?;
    let value_name = fd.value_type_name.clone().unwrap_or_default();
    let entry_type = format!("{}.MapEntry", fd.name);
    h.start_field(&fd.name, &entry_type)?;
    h.start_message(&entry_type)?;
    let mut pos = 0;
    while pos < data.len() {
        let t = read_varint(data, &mut pos)?;
        let (num, wire) = ((t >> 3) as u32, (t & 7) as u8);
        match (num, wire) {
            (1, _) => {
                match wire {
                    0 => h.field("key", varint_scalar(key_ft, read_varint(data, &mut pos)?))?,
                    2 => {
                        let body = take_len(data, &mut pos)?;
                        h.field("key", len_scalar(key_ft, body))?;
                    }
                    5 => h.field("key", fixed32_scalar(key_ft, take_fixed32(data, &mut pos)?))?,
                    1 => h.field("key", fixed64_scalar(key_ft, take_fixed64(data, &mut pos)?))?,
                    _ => return Err(ProtoParseError::new("unsupported wire type in a map entry")),
                };
            }
            (2, _) => {
                if let Some(vt) = scalar_type(&value_name) {
                    match wire {
                        0 => h.field("value", varint_scalar(vt, read_varint(data, &mut pos)?))?,
                        2 => {
                            let body = take_len(data, &mut pos)?;
                            h.field("value", len_scalar(vt, body))?;
                        }
                        5 => h.field("value", fixed32_scalar(vt, take_fixed32(data, &mut pos)?))?,
                        1 => h.field("value", fixed64_scalar(vt, take_fixed64(data, &mut pos)?))?,
                        _ => return Err(ProtoParseError::new("unsupported wire type in a map entry")),
                    };
                } else if proto.enum_type(&value_name).is_some() {
                    if wire != 0 {
                        return Err(ProtoParseError::new("an enum map value must be a varint"));
                    }
                    h.field("value", ScalarValue::U64(read_varint(data, &mut pos)?))?;
                } else {
                    if wire != 2 {
                        return Err(ProtoParseError::new("a message map value must be length-delimited"));
                    }
                    let body = take_len(data, &mut pos)?;
                    h.start_field("value", &value_name)?;
                    walk_message(proto, h, &value_name, body, depth + 1)?;
                    h.end_field()?;
                }
            }
            _ => skip_field(data, &mut pos, wire)?,
        }
    }
    h.end_message()?;
    h.end_field()
}

fn take_len<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ProtoParseError> {
    let len = usize::try_from(read_varint(data, pos)?).map_err(|_| ProtoParseError::new("length too large"))?;
    let end = pos.checked_add(len).filter(|&e| e <= data.len()).ok_or_else(|| ProtoParseError::new("truncated field"))?;
    let body = &data[*pos..end];
    *pos = end;
    Ok(body)
}

fn take_fixed32(data: &[u8], pos: &mut usize) -> Result<u32, ProtoParseError> {
    let b = data.get(*pos..*pos + 4).ok_or_else(|| ProtoParseError::new("truncated fixed32"))?;
    *pos += 4;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn take_fixed64(data: &[u8], pos: &mut usize) -> Result<u64, ProtoParseError> {
    let b = data.get(*pos..*pos + 8).ok_or_else(|| ProtoParseError::new("truncated fixed64"))?;
    *pos += 8;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_le_bytes(a))
}

fn skip_field(data: &[u8], pos: &mut usize, wire: u8) -> Result<(), ProtoParseError> {
    match wire {
        0 => {
            read_varint(data, pos)?;
        }
        1 => {
            take_fixed64(data, pos)?;
        }
        2 => {
            take_len(data, pos)?;
        }
        5 => {
            take_fixed32(data, pos)?;
        }
        _ => return Err(ProtoParseError::new("unsupported wire type")),
    }
    Ok(())
}

/// A whole message from its bytes, as events (used below a map value, where
/// the streaming parser does not descend). Fields the model does not know
/// are skipped.
fn walk_message<H: ProtoMessageHandler>(
    proto: &ProtoFile,
    h: &mut H,
    type_name: &str,
    data: &[u8],
    depth: u32,
) -> Result<(), ProtoParseError> {
    if depth > MAX_DEPTH {
        return Err(ProtoParseError::new("messages nested too deeply"));
    }
    let msg = proto
        .message(type_name)
        .or_else(|| type_name.strip_prefix('.').and_then(|n| proto.message(n)))
        .ok_or_else(|| ProtoParseError::new(format!("Unknown message type: {type_name}")))?
        .clone();
    h.start_message(type_name)?;
    let mut pos = 0;
    while pos < data.len() {
        let t = read_varint(data, &mut pos)?;
        let (num, wire) = ((t >> 3) as i32, (t & 7) as u8);
        let Some(fd) = msg.field_by_number(num) else {
            skip_field(data, &mut pos, wire)?;
            continue;
        };
        match wire {
            0 => h.field(&fd.name, varint_scalar(fd.field_type, read_varint(data, &mut pos)?))?,
            1 => h.field(&fd.name, fixed64_scalar(fd.field_type, take_fixed64(data, &mut pos)?))?,
            5 => h.field(&fd.name, fixed32_scalar(fd.field_type, take_fixed32(data, &mut pos)?))?,
            2 => {
                let body = take_len(data, &mut pos)?;
                decode_len_field(proto, h, fd, body, depth)?;
            }
            _ => return Err(ProtoParseError::new("unsupported wire type")),
        }
    }
    h.end_message()
}

#[cfg(test)]
mod tests {
    use loopbuf::LoopBuf;
    use rprotobuf::{Parser, Writer};

    use super::*;
    use crate::proto::{ProtoFileParser, ProtoModelSerializer, ScalarValue};

    struct Collect {
        fields: Vec<(String, ScalarValue)>,
    }

    impl ProtoMessageHandler for Collect {
        fn start_message(&mut self, _: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
            self.fields.push((name.to_string(), value));
            Ok(())
        }
        fn start_field(&mut self, _: &str, _: &str) -> Result<(), ProtoParseError> {
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            Ok(())
        }
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
        let mut ser = ProtoModelSerializer::new(proto.clone());
        let mut w = Writer::new();
        let mut ring = LoopBuf::with_capacity(64);
        ser.start_message("demo.Echo").unwrap();
        ser.field(&mut w, &mut ring, "text", ScalarValue::String("hi".into()))
            .unwrap();
        ser.field(&mut w, &mut ring, "n", ScalarValue::I32(7))
            .unwrap();
        ser.end_message();
        let mut bytes = Vec::new();
        w.drain_to(&mut ring, &mut bytes).unwrap();

        let collect = Collect { fields: vec![] };
        let mut adapter = ProtoModelAdapter::new(proto, collect);
        adapter.start_root_message("demo.Echo").unwrap();
        {
            let mut pb = Parser::new(&mut adapter);
            pb.parse(bytes.as_slice()).unwrap();
        }
        adapter.end_root_message().unwrap();
        let fields = adapter.into_handler().fields;
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "text");
        assert_eq!(fields[0].1, ScalarValue::String("hi".into()));
        assert_eq!(fields[1].0, "n");
        assert_eq!(fields[1].1, ScalarValue::I32(7));
    }

    // -- decoding what a standard protobuf encoder sends ---------------------

    const WIRE: &str = r#"
        syntax = "proto3";
        package demo;
        enum Color { RED = 0; GREEN = 1; BLUE = 2; }
        message Inner { int32 v = 1; string s = 2; }
        message W {
            int32 i32 = 1; int64 i64 = 2; uint32 u32 = 3; uint64 u64 = 4;
            sint32 s32 = 5; sint64 s64 = 6; fixed32 f32 = 7; fixed64 f64 = 8;
            sfixed32 sf32 = 9; sfixed64 sf64 = 10; float fl = 11; double db = 12;
            bool b = 13; string s = 14; bytes by = 15; Color color = 16;
            repeated int32 packed_i32 = 17; repeated sint64 packed_s64 = 18;
            repeated fixed32 packed_f32 = 19; repeated double packed_db = 20;
            repeated bool packed_b = 21; repeated Color packed_color = 22;
            repeated string names = 23; repeated Inner inners = 24;
            map<string, int32> counts = 25; map<int32, string> by_id = 26;
            map<string, Inner> inner_by_name = 27; map<string, Color> shades = 28;
            Inner one = 29;
        }
    "#;

    /// Bytes for a varint.
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

    fn tag(field: u32, wire: u32) -> Vec<u8> {
        varint(u64::from(field << 3 | wire))
    }

    fn f_varint(field: u32, v: u64) -> Vec<u8> {
        [tag(field, 0), varint(v)].concat()
    }

    fn f_fixed32(field: u32, v: u32) -> Vec<u8> {
        [tag(field, 5), v.to_le_bytes().to_vec()].concat()
    }

    fn f_fixed64(field: u32, v: u64) -> Vec<u8> {
        [tag(field, 1), v.to_le_bytes().to_vec()].concat()
    }

    fn f_len(field: u32, body: &[u8]) -> Vec<u8> {
        [tag(field, 2), varint(body.len() as u64), body.to_vec()].concat()
    }

    fn zigzag(v: i64) -> u64 {
        ((v << 1) ^ (v >> 63)) as u64
    }

    struct Events(Vec<String>);

    impl ProtoMessageHandler for Events {
        fn start_message(&mut self, t: &str) -> Result<(), ProtoParseError> {
            self.0.push(format!("start:{t}"));
            Ok(())
        }
        fn end_message(&mut self) -> Result<(), ProtoParseError> {
            self.0.push("end".into());
            Ok(())
        }
        fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
            self.0.push(format!("{name}={value:?}"));
            Ok(())
        }
        fn start_field(&mut self, name: &str, t: &str) -> Result<(), ProtoParseError> {
            self.0.push(format!("start_field:{name}:{t}"));
            Ok(())
        }
        fn end_field(&mut self) -> Result<(), ProtoParseError> {
            self.0.push("end_field".into());
            Ok(())
        }
    }

    /// The events for `wire` decoded as a `demo.W`, or the error.
    fn decode(wire: &[u8]) -> Result<Vec<String>, String> {
        let proto = ProtoFileParser::parse(WIRE).unwrap();
        let mut adapter = ProtoModelAdapter::new(proto, Events(vec![]));
        adapter.start_root_message("demo.W").unwrap();
        let result = {
            let mut pb = Parser::new(&mut adapter);
            pb.parse(wire)
        };
        match result {
            Ok(_) => {
                adapter.end_root_message().unwrap();
                Ok(adapter.into_handler().0)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// The events between the root message's start and end.
    fn only(wire: &[u8]) -> Vec<String> {
        let mut ev = decode(wire).unwrap();
        assert_eq!(ev.first().map(String::as_str), Some("start:demo.W"));
        assert_eq!(ev.last().map(String::as_str), Some("end"));
        ev.pop();
        ev.remove(0);
        ev
    }

    #[test]
    fn every_scalar_type_keeps_its_sign_and_width() {
        assert_eq!(only(&f_varint(1, (-5i64) as u64)), ["i32=I32(-5)"]);
        assert_eq!(only(&f_varint(2, (-5i64) as u64)), ["i64=I64(-5)"]);
        assert_eq!(only(&f_varint(2, i64::MAX as u64)), ["i64=I64(9223372036854775807)"]);
        assert_eq!(only(&f_varint(3, 4_000_000_000)), ["u32=U64(4000000000)"]);
        assert_eq!(only(&f_varint(4, u64::MAX)), ["u64=U64(18446744073709551615)"]);
        assert_eq!(only(&f_varint(5, zigzag(-3))), ["s32=I32(-3)"]);
        assert_eq!(only(&f_varint(6, zigzag(i64::MIN))), ["s64=I64(-9223372036854775808)"]);
        assert_eq!(only(&f_fixed32(7, 4_000_000_000)), ["f32=U64(4000000000)"]);
        assert_eq!(only(&f_fixed64(8, u64::MAX)), ["f64=U64(18446744073709551615)"]);
        assert_eq!(only(&f_fixed32(9, (-7i32) as u32)), ["sf32=I32(-7)"]);
        assert_eq!(only(&f_fixed64(10, (-7i64) as u64)), ["sf64=I64(-7)"]);
        assert_eq!(only(&f_fixed32(11, 1.5f32.to_bits())), ["fl=F32(1.5)"]);
        assert_eq!(only(&f_fixed64(12, (-2.25f64).to_bits())), ["db=F64(-2.25)"]);
        assert_eq!(only(&f_varint(13, 1)), ["b=Bool(true)"]);
        assert_eq!(only(&f_varint(13, 0)), ["b=Bool(false)"]);
        assert_eq!(only(&f_len(14, "héllo".as_bytes())), ["s=String(\"héllo\")"]);
        assert_eq!(only(&f_len(15, &[0, 1, 255])), ["by=Bytes([0, 1, 255])"]);
        assert_eq!(only(&f_varint(16, 2)), ["color=U64(2)"]);
    }

    #[test]
    fn a_negative_enum_value_survives() {
        assert_eq!(only(&f_varint(16, (-1i64) as u64)), [format!("color=U64({})", (-1i64) as u64)]);
    }

    #[test]
    fn packed_repeated_scalars_arrive_one_element_at_a_time() {
        // proto3 encoders pack repeated numeric fields by default.
        let ints = [varint(1), varint(300), varint((-2i64) as u64)].concat();
        assert_eq!(only(&f_len(17, &ints)), ["packed_i32=I32(1)", "packed_i32=I32(300)", "packed_i32=I32(-2)"]);
        let s64 = [varint(zigzag(-1)), varint(zigzag(5))].concat();
        assert_eq!(only(&f_len(18, &s64)), ["packed_s64=I64(-1)", "packed_s64=I64(5)"]);
        let f32s = [1u32.to_le_bytes(), 4_000_000_000u32.to_le_bytes()].concat();
        assert_eq!(only(&f_len(19, &f32s)), ["packed_f32=U64(1)", "packed_f32=U64(4000000000)"]);
        let dbs = [0.5f64.to_le_bytes(), (-1.0f64).to_le_bytes()].concat();
        assert_eq!(only(&f_len(20, &dbs)), ["packed_db=F64(0.5)", "packed_db=F64(-1.0)"]);
        assert_eq!(only(&f_len(21, &[1, 0, 1])), ["packed_b=Bool(true)", "packed_b=Bool(false)", "packed_b=Bool(true)"]);
        assert_eq!(only(&f_len(22, &[1, 2])), ["packed_color=U64(1)", "packed_color=U64(2)"]);
        assert!(only(&f_len(17, &[])).is_empty(), "an empty packed field has no elements");
    }

    #[test]
    fn repeated_scalars_sent_unpacked_are_accepted_too() {
        let wire = [f_varint(17, 1), f_varint(17, 2)].concat();
        assert_eq!(only(&wire), ["packed_i32=I32(1)", "packed_i32=I32(2)"]);
    }

    #[test]
    fn a_packed_field_that_does_not_end_cleanly_is_an_error() {
        assert!(decode(&f_len(17, &[0x80])).is_err(), "varint cut short");
        assert!(decode(&f_len(19, &[1, 0, 0])).is_err(), "a fixed32 of three bytes");
        assert!(decode(&f_len(20, &[0; 9])).is_err(), "a double of nine bytes");
        assert!(decode(&f_len(17, &[0xff; 11])).is_err(), "a varint of eleven bytes");
    }

    #[test]
    fn repeated_strings_and_messages() {
        let wire = [f_len(23, b"a"), f_len(23, b"b")].concat();
        assert_eq!(only(&wire), ["names=String(\"a\")", "names=String(\"b\")"]);
        let wire = [f_len(24, &f_varint(1, 1)), f_len(24, &f_varint(1, 2))].concat();
        let ev = only(&wire);
        assert_eq!(
            ev,
            [
                "start_field:inners:demo.Inner", "start:demo.Inner", "v=I32(1)", "end", "end_field",
                "start_field:inners:demo.Inner", "start:demo.Inner", "v=I32(2)", "end", "end_field",
            ]
        );
    }

    #[test]
    fn maps_arrive_as_key_value_entries() {
        let entry = |k: &str, v: u64| f_len(25, &[f_len(1, k.as_bytes()), f_varint(2, v)].concat());
        let ev = only(&[entry("a", 1), entry("b", 2)].concat());
        assert_eq!(
            ev,
            [
                "start_field:counts:counts.MapEntry", "start:counts.MapEntry", "key=String(\"a\")", "value=I32(1)", "end", "end_field",
                "start_field:counts:counts.MapEntry", "start:counts.MapEntry", "key=String(\"b\")", "value=I32(2)", "end", "end_field",
            ]
        );
        let by_id = f_len(26, &[f_varint(1, (-4i64) as u64), f_len(2, b"minus four")].concat());
        let ev = only(&by_id);
        assert!(ev.contains(&"key=I32(-4)".to_string()) && ev.contains(&"value=String(\"minus four\")".to_string()), "{ev:?}");
    }

    #[test]
    fn a_map_entry_with_a_missing_key_or_value_takes_the_defaults() {
        let ev = only(&f_len(25, &f_len(1, b"only-key")));
        assert!(ev.contains(&"key=String(\"only-key\")".to_string()), "{ev:?}");
        let ev = only(&f_len(25, &f_varint(2, 9)));
        assert!(ev.contains(&"value=I32(9)".to_string()), "{ev:?}");
    }

    #[test]
    fn map_values_that_are_messages_and_enums() {
        let inner = f_len(27, &[f_len(1, b"k"), f_len(2, &f_varint(1, 7))].concat());
        let ev = only(&inner);
        assert_eq!(
            ev,
            [
                "start_field:inner_by_name:inner_by_name.MapEntry", "start:inner_by_name.MapEntry", "key=String(\"k\")",
                "start_field:value:demo.Inner", "start:demo.Inner", "v=I32(7)", "end", "end_field",
                "end", "end_field",
            ]
        );
        let shade = f_len(28, &[f_len(1, b"x"), f_varint(2, 1)].concat());
        assert!(only(&shade).contains(&"value=U64(1)".to_string()));
    }

    #[test]
    fn nested_messages_start_and_end_in_order() {
        let ev = only(&f_len(29, &[f_varint(1, 3), f_len(2, b"hi")].concat()));
        assert_eq!(ev, ["start_field:one:demo.Inner", "start:demo.Inner", "v=I32(3)", "s=String(\"hi\")", "end", "end_field"]);
    }

    #[test]
    fn unknown_fields_of_every_wire_type_are_skipped() {
        let wire = [
            f_varint(100, 5),
            f_fixed64(101, 1),
            f_fixed32(102, 1),
            f_len(103, b"unknown"),
            f_varint(1, 42),
        ]
        .concat();
        assert_eq!(only(&wire), ["i32=I32(42)"]);
    }

    #[test]
    fn truncated_input_is_an_error() {
        let wire = f_len(14, b"hello world");
        for cut in 1..wire.len() {
            let r = decode(&wire[..cut]);
            assert!(r.is_err(), "cut at {cut} should be an error, got {r:?}");
        }
    }

    #[test]
    fn deeply_nested_input_does_not_overflow_the_stack() {
        // A map value that nests a message thousands deep must be refused, not recursed into.
        let mut body = f_varint(1, 1);
        for _ in 0..5000 {
            body = f_len(29, &body);
        }
        let wire = f_len(27, &[f_len(1, b"k"), f_len(2, &body)].concat());
        let _ = decode(&wire); // any outcome but a crash
    }
}
