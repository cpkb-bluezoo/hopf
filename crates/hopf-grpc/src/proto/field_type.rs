// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Protobuf field wire kinds from a `.proto` model.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldType {
    Double,
    Float,
    Int32,
    Int64,
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Bool,
    String,
    Bytes,
    Message,
    Enum,
    Map,
}

impl FieldType {
    /// The scalar type a `.proto` type name spells (`"int32"`, `"string"`, ...);
    /// `None` for a message or enum name.
    pub fn from_scalar_name(name: &str) -> Option<Self> {
        Some(match name {
            "double" => Self::Double,
            "float" => Self::Float,
            "int32" => Self::Int32,
            "int64" => Self::Int64,
            "uint32" => Self::Uint32,
            "uint64" => Self::Uint64,
            "sint32" => Self::Sint32,
            "sint64" => Self::Sint64,
            "fixed32" => Self::Fixed32,
            "fixed64" => Self::Fixed64,
            "sfixed32" => Self::Sfixed32,
            "sfixed64" => Self::Sfixed64,
            "bool" => Self::Bool,
            "string" => Self::String,
            "bytes" => Self::Bytes,
            _ => return None,
        })
    }

    pub fn is_scalar(self) -> bool {
        !matches!(self, Self::Message | Self::Enum | Self::Map)
    }

    pub fn is_varint(self) -> bool {
        matches!(
            self,
            Self::Int32
                | Self::Int64
                | Self::Uint32
                | Self::Uint64
                | Self::Sint32
                | Self::Sint64
                | Self::Bool
                | Self::Enum
        )
    }

    pub fn is_fixed64(self) -> bool {
        matches!(self, Self::Fixed64 | Self::Sfixed64 | Self::Double)
    }

    pub fn is_fixed32(self) -> bool {
        matches!(self, Self::Fixed32 | Self::Sfixed32 | Self::Float)
    }

    pub fn is_length_delimited(self) -> bool {
        matches!(self, Self::String | Self::Bytes | Self::Message | Self::Map)
    }
}
