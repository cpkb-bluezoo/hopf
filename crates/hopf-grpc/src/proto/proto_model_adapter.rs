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
        let field_type = fd.field_type;
        let val = match field_type {
            FieldType::Bool => ScalarValue::Bool(value != 0),
            FieldType::Int32 | FieldType::Uint32 | FieldType::Fixed32 | FieldType::Sfixed32 => {
                ScalarValue::I32(value as i32)
            }
            FieldType::Sint32 => {
                let n = value as u32;
                ScalarValue::I32(((n >> 1) as i32) ^ (-((n & 1) as i32)))
            }
            FieldType::Sint64 => {
                ScalarValue::I64(((value >> 1) as i64) ^ (-((value & 1) as i64)))
            }
            // Enum, Int64, Uint64, Fixed64, Sfixed64 (and any other varint
            // field type) all pass the raw wire value through as-is.
            _ => ScalarValue::U64(value),
        };
        self.emit_field(&name, val)
    }

    fn handle_fixed64(&mut self, field_number: u32, value: u64) -> ParseResult<()> {
        let fd = match self.current_field(field_number) {
            Some(fd) => fd,
            None => return Ok(()),
        };
        let name = fd.name.clone();
        let val = if fd.field_type == FieldType::Double {
            ScalarValue::F64(f64::from_bits(value))
        } else {
            ScalarValue::U64(value)
        };
        self.emit_field(&name, val)
    }

    fn handle_fixed32(&mut self, field_number: u32, value: u32) -> ParseResult<()> {
        let fd = match self.current_field(field_number) {
            Some(fd) => fd,
            None => return Ok(()),
        };
        let name = fd.name.clone();
        let val = if fd.field_type == FieldType::Float {
            ScalarValue::F32(f32::from_bits(value))
        } else {
            ScalarValue::I32(value as i32)
        };
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
        let is_string = self
            .message_stack
            .front()
            .and_then(|ctx| ctx.message.fields.iter().find(|fd| fd.name == name))
            .is_some_and(|fd| fd.field_type == FieldType::String);
        let val = if is_string {
            ScalarValue::String(String::from_utf8_lossy(&data).into_owned())
        } else {
            ScalarValue::Bytes(data)
        };
        self.emit_field(&name, val)
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
}
