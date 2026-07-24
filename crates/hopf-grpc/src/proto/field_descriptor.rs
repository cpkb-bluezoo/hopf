// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use super::FieldType;

/// Descriptor for a protobuf field.
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    pub number: i32,
    pub name: String,
    pub field_type: FieldType,
    pub repeated: bool,
    pub optional: bool,
    pub message_type_name: Option<String>,
    pub enum_type_name: Option<String>,
    pub key_type_name: Option<String>,
    pub value_type_name: Option<String>,
}

impl FieldDescriptor {
    pub fn builder() -> FieldDescriptorBuilder {
        FieldDescriptorBuilder::default()
    }
}

#[derive(Default)]
pub struct FieldDescriptorBuilder {
    number: i32,
    name: String,
    field_type: Option<FieldType>,
    repeated: bool,
    optional: bool,
    message_type_name: Option<String>,
    enum_type_name: Option<String>,
    key_type_name: Option<String>,
    value_type_name: Option<String>,
}

impl FieldDescriptorBuilder {
    pub fn number(mut self, number: i32) -> Self {
        self.number = number;
        self
    }
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
    pub fn field_type(mut self, field_type: FieldType) -> Self {
        self.field_type = Some(field_type);
        self
    }
    pub fn repeated(mut self, repeated: bool) -> Self {
        self.repeated = repeated;
        self
    }
    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }
    pub fn message_type_name(mut self, name: impl Into<String>) -> Self {
        self.message_type_name = Some(name.into());
        self
    }
    pub fn enum_type_name(mut self, name: impl Into<String>) -> Self {
        self.enum_type_name = Some(name.into());
        self
    }
    pub fn key_type_name(mut self, name: impl Into<String>) -> Self {
        self.key_type_name = Some(name.into());
        self
    }
    pub fn value_type_name(mut self, name: impl Into<String>) -> Self {
        self.value_type_name = Some(name.into());
        self
    }
    pub fn build(self) -> FieldDescriptor {
        FieldDescriptor {
            number: self.number,
            name: self.name,
            field_type: self.field_type.expect("field_type"),
            repeated: self.repeated,
            optional: self.optional,
            message_type_name: self.message_type_name,
            enum_type_name: self.enum_type_name,
            key_type_name: self.key_type_name,
            value_type_name: self.value_type_name,
        }
    }
}
