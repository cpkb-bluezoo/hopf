// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Descriptor for a protobuf enum type.

use std::collections::HashMap;

/// Descriptor for a protobuf enum type.
#[derive(Debug, Clone)]
pub struct EnumDescriptor {
    pub name: String,
    pub full_name: String,
    pub values_by_number: HashMap<i32, String>,
    values_by_name: HashMap<String, i32>,
}

impl EnumDescriptor {
    pub fn value_name(&self, number: i32) -> Option<&str> {
        self.values_by_number.get(&number).map(|s| s.as_str())
    }

    pub fn value_number(&self, name: &str) -> Option<i32> {
        self.values_by_name.get(name).copied()
    }

    pub fn builder() -> EnumDescriptorBuilder {
        EnumDescriptorBuilder::default()
    }
}

#[derive(Default)]
pub struct EnumDescriptorBuilder {
    name: String,
    full_name: String,
    values: Vec<(i32, String)>,
}

impl EnumDescriptorBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn full_name(mut self, full_name: impl Into<String>) -> Self {
        self.full_name = full_name.into();
        self
    }

    pub fn add_value(mut self, number: i32, name: impl Into<String>) -> Self {
        self.values.push((number, name.into()));
        self
    }

    /// Builds the descriptor. When several names share a number (an alias),
    /// the first declared is the one the number maps back to.
    pub fn build(self) -> EnumDescriptor {
        let mut values_by_number = HashMap::new();
        let mut values_by_name = HashMap::new();
        for (number, name) in self.values {
            values_by_name.insert(name.clone(), number);
            values_by_number.entry(number).or_insert(name);
        }
        EnumDescriptor {
            name: self.name,
            full_name: self.full_name,
            values_by_number,
            values_by_name,
        }
    }
}
