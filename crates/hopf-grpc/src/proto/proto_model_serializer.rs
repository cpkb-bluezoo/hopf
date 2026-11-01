// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Serializes protobuf messages from event-driven input using a Proto model.

use loopbuf::LoopBuf;
use rprotobuf::{WriteError, Writer};

use super::{FieldDescriptor, FieldType, MessageDescriptor, ProtoFile, ScalarValue};

/// A message being written.
enum Frame {
    Message {
        desc: MessageDescriptor,
        /// `None` for the message `start_message` began, which is written
        /// straight to the caller's writer. A nested message is written into
        /// `bytes` and put in its parent, with its length, by `end_field`:
        /// `number` is the field it goes in.
        nested: Option<Nested>,
    },
    /// A field the message does not have, and everything inside it.
    Skipped,
}

#[derive(Default)]
struct Nested {
    number: u32,
    bytes: Vec<u8>,
}

/// Serializes protobuf messages from event-driven input using a Proto model.
///
/// The application drives the serializer with events (`start_message`, `field`,
/// `start_field`, `end_field`, `end_message`). The serializer uses the model to
/// map field names to numbers and types, writing the correct wire format.
///
/// - A **repeated** field is one `field` (or `start_field` / `end_field`) per
///   element, written unpacked, which every reader accepts.
/// - A **map** is one `start_field(map, ..)` / `end_field` per entry, around a
///   `field("key", ..)` and either a `field("value", ..)` or a
///   `start_field("value", message_type)` / `end_field`: an entry is a message
///   with the key as field 1 and the value as field 2. The type name given for
///   the entry itself is not used.
///
/// These are the same events [`super::JsonModelSerializer`] takes, so a
/// handler can write either encoding.
pub struct ProtoModelSerializer {
    proto_file: ProtoFile,
    stack: Vec<Frame>,
}

fn invalid(message: impl Into<String>) -> WriteError {
    WriteError::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()))
}

impl ProtoModelSerializer {
    pub fn new(proto_file: ProtoFile) -> Self {
        Self {
            proto_file,
            stack: Vec::new(),
        }
    }

    fn resolve(&self, type_name: &str) -> Result<MessageDescriptor, std::io::Error> {
        let mut msg = self.proto_file.message(type_name);
        if msg.is_none() && type_name.starts_with('.') {
            msg = self.proto_file.message(&type_name[1..]);
        }
        msg.cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unknown message type: {type_name}"),
            )
        })
    }

    /// Starts a message (root or nested).
    pub fn start_message(&mut self, type_name: &str) -> Result<(), std::io::Error> {
        let desc = self.resolve(type_name)?;
        self.stack.push(Frame::Message { desc, nested: None });
        Ok(())
    }

    /// Ends the current message.
    pub fn end_message(&mut self) {
        let _ = self.stack.pop();
    }

    /// Writes a scalar field in the wire type the protobuf encoding gives its
    /// type (varint, zigzag varint, 4-byte, 8-byte or length-delimited), so
    /// any other implementation can read it. Inside a nested message it goes
    /// into that message, not to `writer`.
    pub fn field(
        &mut self,
        writer: &mut Writer,
        ring: &mut LoopBuf,
        name: &str,
        value: ScalarValue,
    ) -> Result<(), WriteError> {
        let (fd, nested) = match self.stack.last_mut() {
            Some(Frame::Message { desc, nested }) => match desc.fields.iter().find(|fd| fd.name == name) {
                Some(fd) => (fd.clone(), nested),
                None => return Ok(()),
            },
            _ => return Ok(()),
        };
        if matches!(fd.field_type, FieldType::Message | FieldType::Map) {
            return Err(invalid(format!("field {name} holds messages: write it with start_field")));
        }
        match nested {
            None => encode_field(&fd, &value, writer, ring),
            Some(nested) => {
                // Into a scratch ring sized for the value, then into the
                // message's bytes.
                let hint = match &value {
                    ScalarValue::String(s) => s.len(),
                    ScalarValue::Bytes(b) => b.len(),
                    _ => 0,
                };
                let mut scratch_writer = Writer::new();
                let mut scratch = LoopBuf::with_capacity(hint + 64);
                encode_field(&fd, &value, &mut scratch_writer, &mut scratch)?;
                scratch_writer
                    .drain_to(&mut scratch, &mut nested.bytes)
                    .map_err(|e| invalid(e.to_string()))?;
                Ok(())
            }
        }
    }

    /// Starts a nested message field: the message `type_name` (or, for a
    /// map, one entry), whose fields follow, until [`Self::end_field`].
    pub fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), std::io::Error> {
        let fd = match self.stack.last() {
            None => return Ok(()),
            Some(Frame::Skipped) => {
                self.stack.push(Frame::Skipped);
                return Ok(());
            }
            Some(Frame::Message { desc, .. }) => match desc.fields.iter().find(|fd| fd.name == name) {
                Some(fd) => fd.clone(),
                None => {
                    self.stack.push(Frame::Skipped);
                    return Ok(());
                }
            },
        };
        let desc = match fd.field_type {
            FieldType::Map => entry_descriptor(&self.proto_file, &fd)?,
            FieldType::Message => {
                // A map entry's value is described by the map; elsewhere the
                // caller names the type.
                match fd.message_type_name.as_deref().filter(|_| self.in_map_entry()) {
                    Some(own) => self.resolve(own)?,
                    None => self.resolve(type_name)?,
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("field {name} is not a message: write it with field"),
                ))
            }
        };
        self.stack.push(Frame::Message {
            desc,
            nested: Some(Nested { number: fd.number as u32, bytes: Vec::new() }),
        });
        Ok(())
    }

    fn in_map_entry(&self) -> bool {
        matches!(self.stack.last(), Some(Frame::Message { desc, .. }) if desc.name.ends_with(".MapEntry"))
    }

    /// Ends a nested message field (or map entry): writes it, with its tag
    /// and length, into the message it is in. If the write does not fit the
    /// ring the field stays open, so that the call can be repeated.
    pub fn end_field(&mut self, writer: &mut Writer, ring: &mut LoopBuf) -> Result<(), WriteError> {
        let top = match self.stack.last_mut() {
            Some(Frame::Message { nested: Some(nested), .. }) => std::mem::take(nested),
            Some(Frame::Skipped) => {
                self.stack.pop();
                return Ok(());
            }
            _ => return Err(invalid("end_field without a start_field")),
        };
        let parent = self.stack.len().checked_sub(2).map(|i| &mut self.stack[i]);
        let result = match parent {
            Some(Frame::Message { nested: Some(parent), .. }) => {
                append_field(&mut parent.bytes, top.number, &top.bytes);
                Ok(())
            }
            Some(Frame::Message { nested: None, .. }) => writer.write_bytes_field(ring, top.number, &top.bytes),
            _ => Ok(()),
        };
        match result {
            Ok(()) => {
                self.stack.pop();
                Ok(())
            }
            Err(e) => {
                // Put the field back as it was.
                if let Some(Frame::Message { nested, .. }) = self.stack.last_mut() {
                    *nested = Some(top);
                }
                Err(e)
            }
        }
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
        let fd = match self.stack.last() {
            Some(Frame::Message { desc, .. }) => match desc.fields.iter().find(|fd| fd.name == name) {
                Some(fd) => fd.clone(),
                None => return Ok(()),
            },
            _ => return Ok(()),
        };
        let nested = match self.resolve(type_name) {
            Ok(n) => n,
            Err(_) => return Ok(()),
        };

        self.stack.push(Frame::Message { desc: nested, nested: None });
        let result = writer.write_message_field(ring, fd.number as u32, |w, ring| content(self, w, ring));
        self.stack.pop();
        result
    }
}

/// The message an entry of map field `fd` is: `key = 1`, `value = 2`.
fn entry_descriptor(proto: &ProtoFile, fd: &FieldDescriptor) -> Result<MessageDescriptor, std::io::Error> {
    let bad = |what: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, what);
    let key_type = fd
        .key_type_name
        .as_deref()
        .and_then(FieldType::from_scalar_name)
        .filter(|t| !matches!(t, FieldType::Double | FieldType::Float | FieldType::Bytes))
        .ok_or_else(|| bad(format!("map {} has a key type that is not an integer, bool or string", fd.name)))?;
    let value_name = fd.value_type_name.clone().unwrap_or_default();
    let value = FieldDescriptor::builder().number(2).name("value");
    let value = if let Some(t) = FieldType::from_scalar_name(&value_name) {
        value.field_type(t)
    } else if proto.enum_type(&value_name).is_some() {
        value.field_type(FieldType::Enum).enum_type_name(value_name)
    } else {
        value.field_type(FieldType::Message).message_type_name(value_name)
    };
    let entry = format!("{}.MapEntry", fd.name);
    Ok(MessageDescriptor::builder()
        .name(entry.clone())
        .full_name(entry)
        .add_field(FieldDescriptor::builder().number(1).name("key").field_type(key_type).build())
        .add_field(value.build())
        .build())
}

/// `bytes` as a length-delimited field `number`, appended to `out`.
fn append_field(out: &mut Vec<u8>, number: u32, bytes: &[u8]) {
    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    varint(out, u64::from(number) << 3 | 2);
    varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// One scalar field in its wire form.
fn encode_field(fd: &FieldDescriptor, value: &ScalarValue, writer: &mut Writer, ring: &mut LoopBuf) -> Result<(), WriteError> {
    let num = fd.number as u32;
    match fd.field_type {
        FieldType::Double => {
            writer.write_double_field(ring, num, as_f64(value))?;
        }
        FieldType::Float => {
            writer.write_float_field(ring, num, as_f32(value))?;
        }
        FieldType::Int32 | FieldType::Uint32 | FieldType::Enum | FieldType::Int64 | FieldType::Uint64 => {
            writer.write_varint_field(ring, num, as_u64(value))?;
        }
        FieldType::Fixed32 => {
            writer.write_fixed32_field(ring, num, as_u64(value) as u32)?;
        }
        FieldType::Fixed64 => {
            writer.write_fixed64_field(ring, num, as_u64(value))?;
        }
        FieldType::Sint32 | FieldType::Sint64 => {
            writer.write_svarint_field(ring, num, as_i64(value))?;
        }
        FieldType::Sfixed32 => {
            writer.write_fixed32_field(ring, num, as_i64(value) as u32)?;
        }
        FieldType::Sfixed64 => {
            writer.write_fixed64_field(ring, num, as_u64(value))?;
        }
        FieldType::Bool => {
            let b = matches!(value, ScalarValue::Bool(true))
                || matches!(value, ScalarValue::U64(v) if *v != 0)
                || matches!(value, ScalarValue::I32(v) if *v != 0)
                || matches!(value, ScalarValue::I64(v) if *v != 0);
            writer.write_bool_field(ring, num, b)?;
        }
        FieldType::String => match value {
            ScalarValue::String(s) => writer.write_string_field(ring, num, s)?,
            _ => return Ok(()),
        },
        FieldType::Bytes => match value {
            ScalarValue::Bytes(b) => writer.write_bytes_field(ring, num, b)?,
            ScalarValue::String(s) => writer.write_bytes_field(ring, num, s.as_bytes())?,
            _ => {}
        },
        FieldType::Message | FieldType::Map => {}
    }
    Ok(())
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

    // -- nested messages, repeated fields and maps (issue #513) -------------------

    const NESTED: &str = r#"
        syntax = "proto3";
        package demo;
        enum Color { RED = 0; GREEN = 1; BLUE = 2; }
        message Inner { int32 v = 1; repeated string tags = 2; }
        message R {
            repeated int32 nums = 1; repeated string names = 3; repeated Inner inners = 8;
            map<string, int32> counts = 9; map<int32, string> by_id = 10;
            map<string, Inner> inner_by_name = 13; map<string, Color> shades = 14;
            string s = 17; Inner one = 18;
        }
    "#;

    /// A serializer over `demo.R`, and the root message's bytes when finished.
    struct Pb {
        ser: ProtoModelSerializer,
        w: Writer,
        ring: LoopBuf,
    }

    impl Pb {
        fn new() -> Self {
            let mut ser = ProtoModelSerializer::new(ProtoFileParser::parse(NESTED).unwrap());
            ser.start_message("demo.R").unwrap();
            Self { ser, w: Writer::new(), ring: LoopBuf::with_capacity(4096) }
        }

        fn field(&mut self, name: &str, value: ScalarValue) {
            self.ser.field(&mut self.w, &mut self.ring, name, value).unwrap();
        }

        fn start(&mut self, name: &str, type_name: &str) {
            self.ser.start_field(name, type_name).unwrap();
        }

        fn end(&mut self) {
            self.ser.end_field(&mut self.w, &mut self.ring).unwrap();
        }

        fn finish(mut self) -> Vec<u8> {
            self.ser.end_message();
            let mut out = Vec::new();
            self.w.drain_to(&mut self.ring, &mut out).unwrap();
            out
        }
    }

    fn len_field(field: u32, body: &[u8]) -> Vec<u8> {
        tagged(field, 2, &[varint(body.len() as u64), body.to_vec()].concat())
    }

    fn int_field(field: u32, v: u64) -> Vec<u8> {
        tagged(field, 0, &varint(v))
    }

    #[test]
    fn a_nested_message_is_a_length_delimited_field() {
        let mut p = Pb::new();
        p.field("s", ScalarValue::String("x".into()));
        p.start("one", "demo.Inner");
        p.field("v", ScalarValue::I32(2));
        p.end();
        assert_eq!(
            p.finish(),
            [len_field(17, b"x"), len_field(18, &int_field(1, 2))].concat()
        );
    }

    #[test]
    fn repeated_scalars_are_one_field_per_element() {
        let mut p = Pb::new();
        for v in [1, 300] {
            p.field("nums", ScalarValue::I32(v));
        }
        p.field("names", ScalarValue::String("a".into()));
        p.field("names", ScalarValue::String("b".into()));
        assert_eq!(
            p.finish(),
            [int_field(1, 1), int_field(1, 300), len_field(3, b"a"), len_field(3, b"b")].concat()
        );
    }

    #[test]
    fn repeated_messages_each_have_their_own_field_even_when_empty() {
        let mut p = Pb::new();
        p.start("inners", "demo.Inner");
        p.field("v", ScalarValue::I32(1));
        p.end();
        p.start("inners", "demo.Inner");
        p.end();
        assert_eq!(p.finish(), [len_field(8, &int_field(1, 1)), len_field(8, &[])].concat());
    }

    #[test]
    fn messages_nest_to_any_depth() {
        let mut p = Pb::new();
        p.start("inners", "demo.Inner");
        p.field("tags", ScalarValue::String("t".into()));
        p.end();
        p.start("one", "demo.Inner");
        p.field("v", ScalarValue::I32(4));
        p.field("tags", ScalarValue::String("u".into()));
        p.end();
        assert_eq!(
            p.finish(),
            [len_field(8, &len_field(2, b"t")), len_field(18, &[int_field(1, 4), len_field(2, b"u")].concat())].concat()
        );
    }

    #[test]
    fn a_map_entry_is_a_message_with_the_key_as_field_1_and_the_value_as_field_2() {
        let mut p = Pb::new();
        p.start("counts", "counts.MapEntry");
        p.field("key", ScalarValue::String("a".into()));
        p.field("value", ScalarValue::I32(1));
        p.end();
        p.start("by_id", "by_id.MapEntry");
        p.field("key", ScalarValue::I32(-4));
        p.field("value", ScalarValue::String("minus four".into()));
        p.end();
        p.start("shades", "shades.MapEntry");
        p.field("key", ScalarValue::String("k".into()));
        p.field("value", ScalarValue::U64(2));
        p.end();
        assert_eq!(
            p.finish(),
            [
                len_field(9, &[len_field(1, b"a"), int_field(2, 1)].concat()),
                len_field(10, &[int_field(1, (-4i64) as u64), len_field(2, b"minus four")].concat()),
                len_field(14, &[len_field(1, b"k"), int_field(2, 2)].concat()),
            ]
            .concat()
        );
    }

    #[test]
    fn a_map_value_that_is_a_message() {
        let mut p = Pb::new();
        p.start("inner_by_name", "inner_by_name.MapEntry");
        p.field("key", ScalarValue::String("x".into()));
        p.start("value", "demo.Inner");
        p.field("v", ScalarValue::I32(7));
        p.end();
        p.end();
        assert_eq!(
            p.finish(),
            len_field(13, &[len_field(1, b"x"), len_field(2, &int_field(1, 7))].concat())
        );
    }

    #[test]
    fn an_entry_with_nothing_in_it_is_still_an_entry() {
        let mut p = Pb::new();
        p.start("counts", "counts.MapEntry");
        p.end();
        assert_eq!(p.finish(), len_field(9, &[]));
    }

    #[test]
    fn fields_the_message_does_not_have_are_skipped_with_everything_inside_them() {
        let mut p = Pb::new();
        p.start("nope", "demo.Inner");
        p.field("v", ScalarValue::I32(2));
        p.start("deeper", "demo.Inner");
        p.end();
        p.end();
        p.field("s", ScalarValue::String("x".into()));
        assert_eq!(p.finish(), len_field(17, b"x"));
    }

    #[test]
    fn a_field_given_the_wrong_kind_of_event_is_an_error() {
        let mut p = Pb::new();
        assert!(p.ser.field(&mut p.w, &mut p.ring, "one", ScalarValue::I32(1)).is_err(), "a message needs start_field");
        assert!(p.ser.field(&mut p.w, &mut p.ring, "counts", ScalarValue::I32(1)).is_err());
        assert!(p.ser.start_field("s", "demo.Inner").is_err(), "a string is not a message");
        assert!(p.ser.end_field(&mut p.w, &mut p.ring).is_err(), "nothing to end");
    }

    #[test]
    fn a_field_that_does_not_fit_the_ring_stays_open_to_be_ended_again() {
        // The caller grows the ring and repeats the call (the response does).
        let mut p = Pb::new();
        p.start("one", "demo.Inner");
        p.field("tags", ScalarValue::String("a fairly long tag".into()));
        let mut tiny = LoopBuf::with_capacity(4);
        let err = p.ser.end_field(&mut p.w, &mut tiny).unwrap_err();
        assert!(err.is_would_block() || err.to_string().contains("capacity"), "{err}");
        p.end();
        assert_eq!(p.finish(), len_field(18, &len_field(2, b"a fairly long tag")));
    }
}
