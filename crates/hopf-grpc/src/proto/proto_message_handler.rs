// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level semantic handler for protobuf message parsing events.

use super::ProtoParseError;

/// Provides location information during proto parsing.
pub trait ProtoLocator {
    /// Byte offset in the current parse stream.
    fn offset(&self) -> u64;
    /// Line number (1-based).
    fn line_number(&self) -> u64;
    /// Column number (1-based).
    fn column_number(&self) -> u64;
}

/// Scalar / bytes value delivered to [`ProtoMessageHandler::field`].
#[derive(Debug, Clone, PartialEq)]
pub enum ScalarValue {
    Bool(bool),
    I32(i32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    String(String),
    Bytes(Vec<u8>),
}

/// High-level semantic handler for protobuf message parsing events.
///
/// Analogous to JSON/MIME content handlers. Receives semantic events
/// (message start/end, field name and value) rather than low-level wire format.
pub trait ProtoMessageHandler: Send {
    /// Receives the locator for parse position information.
    fn set_locator(&mut self, _locator: &dyn ProtoLocator) {}

    /// Start of a message (root or nested).
    fn start_message(&mut self, type_name: &str) -> Result<(), ProtoParseError>;

    /// End of the current message.
    fn end_message(&mut self) -> Result<(), ProtoParseError>;

    /// Scalar field. Value is bool, number, string, or bytes.
    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError>;

    /// Start of a nested message field.
    fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), ProtoParseError>;

    /// End of a nested message field.
    fn end_field(&mut self) -> Result<(), ProtoParseError>;
}

impl ProtoMessageHandler for Box<dyn ProtoMessageHandler> {
    fn set_locator(&mut self, locator: &dyn ProtoLocator) {
        (**self).set_locator(locator);
    }
    fn start_message(&mut self, type_name: &str) -> Result<(), ProtoParseError> {
        (**self).start_message(type_name)
    }
    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        (**self).end_message()
    }
    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        (**self).field(name, value)
    }
    fn start_field(&mut self, name: &str, type_name: &str) -> Result<(), ProtoParseError> {
        (**self).start_field(name, type_name)
    }
    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        (**self).end_field()
    }
}

/// Default implementation of [`ProtoMessageHandler`] that does nothing.
/// Subclass (embed) to implement only the methods you need.
#[derive(Debug, Default)]
pub struct ProtoDefaultHandler;

impl ProtoMessageHandler for ProtoDefaultHandler {
    fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
        Ok(())
    }

    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        Ok(())
    }

    fn field(&mut self, _name: &str, _value: ScalarValue) -> Result<(), ProtoParseError> {
        Ok(())
    }

    fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
        Ok(())
    }

    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        Ok(())
    }
}
