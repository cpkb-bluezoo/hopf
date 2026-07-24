// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Descriptor for a gRPC RPC method.

/// Descriptor for a gRPC RPC method.
#[derive(Debug, Clone)]
pub struct RpcDescriptor {
    pub name: String,
    pub input_type_name: String,
    pub output_type_name: String,
    pub client_streaming: bool,
    pub server_streaming: bool,
}

impl RpcDescriptor {
    pub fn builder() -> RpcDescriptorBuilder {
        RpcDescriptorBuilder::default()
    }
}

#[derive(Default)]
pub struct RpcDescriptorBuilder {
    name: String,
    input_type_name: String,
    output_type_name: String,
    client_streaming: bool,
    server_streaming: bool,
}

impl RpcDescriptorBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn input_type_name(mut self, name: impl Into<String>) -> Self {
        self.input_type_name = name.into();
        self
    }

    pub fn output_type_name(mut self, name: impl Into<String>) -> Self {
        self.output_type_name = name.into();
        self
    }

    pub fn client_streaming(mut self, client_streaming: bool) -> Self {
        self.client_streaming = client_streaming;
        self
    }

    pub fn server_streaming(mut self, server_streaming: bool) -> Self {
        self.server_streaming = server_streaming;
        self
    }

    pub fn build(self) -> RpcDescriptor {
        RpcDescriptor {
            name: self.name,
            input_type_name: self.input_type_name,
            output_type_name: self.output_type_name,
            client_streaming: self.client_streaming,
            server_streaming: self.server_streaming,
        }
    }
}
