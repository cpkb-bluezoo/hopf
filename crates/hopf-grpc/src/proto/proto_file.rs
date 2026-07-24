// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Descriptor for a parsed `.proto` file (Proto model).

use std::collections::HashMap;

use super::{EnumDescriptor, MessageDescriptor, RpcDescriptor, ServiceDescriptor};

/// Descriptor for a parsed `.proto` file (Proto model).
#[derive(Debug, Clone)]
pub struct ProtoFile {
    pub package_name: String,
    pub syntax: String,
    pub messages: Vec<MessageDescriptor>,
    pub enums: Vec<EnumDescriptor>,
    pub services: Vec<ServiceDescriptor>,
    messages_by_full_name: HashMap<String, usize>,
    enums_by_full_name: HashMap<String, usize>,
    services_by_full_name: HashMap<String, usize>,
}

impl ProtoFile {
    pub fn message(&self, full_name: &str) -> Option<&MessageDescriptor> {
        self.messages_by_full_name
            .get(full_name)
            .map(|&i| &self.messages[i])
    }

    pub fn enum_type(&self, full_name: &str) -> Option<&EnumDescriptor> {
        self.enums_by_full_name
            .get(full_name)
            .map(|&i| &self.enums[i])
    }

    pub fn service(&self, full_name: &str) -> Option<&ServiceDescriptor> {
        self.services_by_full_name
            .get(full_name)
            .map(|&i| &self.services[i])
    }

    /// Resolves an RPC descriptor from a gRPC path (`/package.Service/Method`).
    pub fn get_rpc_by_path(&self, path: &str) -> Option<&RpcDescriptor> {
        if !path.starts_with('/') {
            return None;
        }
        let rest = &path[1..];
        let slash = rest.find('/')?;
        let method_name = &rest[slash + 1..];
        if method_name.is_empty() {
            return None;
        }
        let service = self.service(&rest[..slash])?;
        service.rpc(method_name)
    }

    pub fn builder() -> ProtoFileBuilder {
        ProtoFileBuilder::default()
    }
}

pub struct ProtoFileBuilder {
    package_name: String,
    syntax: String,
    messages: Vec<MessageDescriptor>,
    enums: Vec<EnumDescriptor>,
    services: Vec<ServiceDescriptor>,
}

impl Default for ProtoFileBuilder {
    fn default() -> Self {
        Self {
            package_name: String::new(),
            syntax: "proto3".to_string(),
            messages: Vec::new(),
            enums: Vec::new(),
            services: Vec::new(),
        }
    }
}

impl ProtoFileBuilder {
    pub fn package_name(mut self, package_name: impl Into<String>) -> Self {
        self.package_name = package_name.into();
        self
    }

    pub fn syntax(mut self, syntax: impl Into<String>) -> Self {
        let s = syntax.into();
        self.syntax = if s.is_empty() {
            "proto3".to_string()
        } else {
            s
        };
        self
    }

    pub fn add_message(mut self, msg: MessageDescriptor) -> Self {
        self.messages.push(msg);
        self
    }

    pub fn add_enum(mut self, enm: EnumDescriptor) -> Self {
        self.enums.push(enm);
        self
    }

    pub fn add_service(mut self, svc: ServiceDescriptor) -> Self {
        self.services.push(svc);
        self
    }

    pub fn build(self) -> ProtoFile {
        let mut messages_by_full_name = HashMap::new();
        for (i, m) in self.messages.iter().enumerate() {
            messages_by_full_name.insert(m.full_name.clone(), i);
        }
        let mut enums_by_full_name = HashMap::new();
        for (i, e) in self.enums.iter().enumerate() {
            enums_by_full_name.insert(e.full_name.clone(), i);
        }
        let mut services_by_full_name = HashMap::new();
        for (i, s) in self.services.iter().enumerate() {
            services_by_full_name.insert(s.full_name.clone(), i);
        }
        ProtoFile {
            package_name: self.package_name,
            syntax: self.syntax,
            messages: self.messages,
            enums: self.enums,
            services: self.services,
            messages_by_full_name,
            enums_by_full_name,
            services_by_full_name,
        }
    }
}
