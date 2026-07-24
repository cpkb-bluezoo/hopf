// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::collections::HashMap;

use super::{EnumDescriptor, FieldDescriptor};

/// Descriptor for a protobuf message type.
#[derive(Debug, Clone)]
pub struct MessageDescriptor {
    pub name: String,
    pub full_name: String,
    pub fields: Vec<FieldDescriptor>,
    fields_by_number: HashMap<i32, usize>,
    pub nested_messages: HashMap<String, MessageDescriptor>,
    pub nested_enums: HashMap<String, EnumDescriptor>,
}

impl MessageDescriptor {
    pub fn field_by_number(&self, number: i32) -> Option<&FieldDescriptor> {
        self.fields_by_number
            .get(&number)
            .map(|&i| &self.fields[i])
    }

    pub fn builder() -> MessageDescriptorBuilder {
        MessageDescriptorBuilder::default()
    }
}

#[derive(Default)]
pub struct MessageDescriptorBuilder {
    name: String,
    full_name: String,
    fields: Vec<FieldDescriptor>,
    nested_messages: HashMap<String, MessageDescriptor>,
    nested_enums: HashMap<String, EnumDescriptor>,
}

impl MessageDescriptorBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
    pub fn full_name(mut self, full_name: impl Into<String>) -> Self {
        self.full_name = full_name.into();
        self
    }
    pub fn add_field(mut self, field: FieldDescriptor) -> Self {
        self.fields.push(field);
        self
    }
    pub fn add_nested_message(mut self, msg: MessageDescriptor) -> Self {
        self.nested_messages.insert(msg.name.clone(), msg);
        self
    }
    pub fn add_nested_enum(mut self, enm: EnumDescriptor) -> Self {
        self.nested_enums.insert(enm.name.clone(), enm);
        self
    }
    pub fn build(self) -> MessageDescriptor {
        let mut fields_by_number = HashMap::new();
        for (i, f) in self.fields.iter().enumerate() {
            fields_by_number.insert(f.number, i);
        }
        MessageDescriptor {
            name: self.name,
            full_name: self.full_name,
            fields: self.fields,
            fields_by_number,
            nested_messages: self.nested_messages,
            nested_enums: self.nested_enums,
        }
    }
}
