// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Descriptor for a gRPC service.

use std::collections::HashMap;

use super::RpcDescriptor;

/// Descriptor for a gRPC service.
#[derive(Debug, Clone)]
pub struct ServiceDescriptor {
    pub name: String,
    pub full_name: String,
    pub rpcs: Vec<RpcDescriptor>,
    rpcs_by_name: HashMap<String, usize>,
}

impl ServiceDescriptor {
    pub fn rpc(&self, name: &str) -> Option<&RpcDescriptor> {
        self.rpcs_by_name.get(name).map(|&i| &self.rpcs[i])
    }

    /// Returns the gRPC path for this RPC: `/package.Service/Method`.
    pub fn rpc_path(&self, method_name: &str) -> String {
        format!("/{}/{}", self.full_name, method_name)
    }

    pub fn builder() -> ServiceDescriptorBuilder {
        ServiceDescriptorBuilder::default()
    }
}

#[derive(Default)]
pub struct ServiceDescriptorBuilder {
    name: String,
    full_name: String,
    rpcs: Vec<RpcDescriptor>,
}

impl ServiceDescriptorBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn full_name(mut self, full_name: impl Into<String>) -> Self {
        self.full_name = full_name.into();
        self
    }

    pub fn add_rpc(mut self, rpc: RpcDescriptor) -> Self {
        self.rpcs.push(rpc);
        self
    }

    pub fn build(self) -> ServiceDescriptor {
        let mut rpcs_by_name = HashMap::new();
        for (i, r) in self.rpcs.iter().enumerate() {
            rpcs_by_name.insert(r.name.clone(), i);
        }
        ServiceDescriptor {
            name: self.name,
            full_name: self.full_name,
            rpcs: self.rpcs,
            rpcs_by_name,
        }
    }
}
