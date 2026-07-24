// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! ProtoFile IDL model, `.proto` parser, and rprotobuf bridges.

mod enum_descriptor;
mod field_descriptor;
mod field_type;
mod message_descriptor;
mod proto_file;
mod proto_file_parser;
mod proto_message_handler;
mod proto_model_adapter;
mod proto_model_serializer;
mod proto_parse_error;
mod rpc_descriptor;
mod service_descriptor;

pub use enum_descriptor::{EnumDescriptor, EnumDescriptorBuilder};
pub use field_descriptor::{FieldDescriptor, FieldDescriptorBuilder};
pub use field_type::FieldType;
pub use message_descriptor::{MessageDescriptor, MessageDescriptorBuilder};
pub use proto_file::{ProtoFile, ProtoFileBuilder};
pub use proto_file_parser::ProtoFileParser;
pub use proto_message_handler::{
    ProtoDefaultHandler, ProtoLocator, ProtoMessageHandler, ScalarValue,
};
pub use proto_model_adapter::ProtoModelAdapter;
pub use proto_model_serializer::ProtoModelSerializer;
pub use proto_parse_error::ProtoParseError;
pub use rpc_descriptor::{RpcDescriptor, RpcDescriptorBuilder};
pub use service_descriptor::{ServiceDescriptor, ServiceDescriptorBuilder};
