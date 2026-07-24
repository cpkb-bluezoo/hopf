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
