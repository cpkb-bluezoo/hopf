// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Unary gRPC echo server (HTTP/2 cleartext via CleartextHttpEndpoint).
//!
//! ```text
//! cargo run -p grpc-echo -- 127.0.0.1:8080
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_grpc::{
    GrpcHandlerFactory, GrpcResponseChannel, GrpcService, ProtoFileParser, ProtoMessageHandler,
    ProtoParseError, ScalarValue,
};
use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};

const PROTO: &str = r#"
syntax = "proto3";
package demo;
message EchoRequest { string text = 1; }
message EchoReply { string text = 1; }
service Echo {
  rpc Say (EchoRequest) returns (EchoReply);
}
"#;

struct EchoService;

impl GrpcService for EchoService {
    fn start_unary_call(
        &self,
        path: &str,
        response: GrpcResponseChannel,
    ) -> Option<Box<dyn ProtoMessageHandler>> {
        if path != "/demo.Echo/Say" {
            return None;
        }
        Some(Box::new(EchoHandler {
            response,
            text: String::new(),
        }))
    }
}

struct EchoHandler {
    response: GrpcResponseChannel,
    text: String,
}

impl ProtoMessageHandler for EchoHandler {
    fn start_message(&mut self, _type_name: &str) -> Result<(), ProtoParseError> {
        Ok(())
    }
    fn end_message(&mut self) -> Result<(), ProtoParseError> {
        let mut msg = self
            .response
            .open_message(None)
            .map_err(|e| ProtoParseError::new(e))?;
        msg.field("text", ScalarValue::String(self.text.clone()))
            .map_err(|e| ProtoParseError::new(e))?;
        msg.complete().map_err(|e| ProtoParseError::new(e))?;
        Ok(())
    }
    fn field(&mut self, name: &str, value: ScalarValue) -> Result<(), ProtoParseError> {
        if name == "text" {
            if let ScalarValue::String(s) = value {
                self.text = s;
            }
        }
        Ok(())
    }
    fn start_field(&mut self, _name: &str, _type_name: &str) -> Result<(), ProtoParseError> {
        Ok(())
    }
    fn end_field(&mut self) -> Result<(), ProtoParseError> {
        Ok(())
    }
}

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let proto = ProtoFileParser::parse(PROTO).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    })?;
    let factory = Arc::new(GrpcHandlerFactory::new(proto, Arc::new(EchoService)));

    let rt = Runtime::start(RuntimeConfig::default())?;
    let factory2 = Arc::clone(&factory);
    let (bound, _) = rt.add_tcp_listener(TcpListenerConfig::new(addr, move || {
        Box::new(CleartextHttpEndpoint::new(
            Arc::clone(&factory2) as Arc<dyn ServerHandlerFactory>,
            HttpLimits::default(),
        )) as Box<dyn ProtocolHandler>
    }))?;

    eprintln!("grpc echo on http://{bound}/demo.Echo/Say");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    rt.shutdown();
    Ok(())
}
