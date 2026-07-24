// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! WebSocket echo server (HTTP/1.1 Upgrade via CleartextHttpEndpoint).
//!
//! ```text
//! cargo run -p websocket-echo -- 127.0.0.1:8080
//! # then connect with any WebSocket client to ws://127.0.0.1:8080/
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};
use hopf_websocket::{EchoFactory, WebSocketConfig, WebSocketFactory};

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8080".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let factory = Arc::new(WebSocketFactory::new(
        EchoFactory,
        WebSocketConfig::default(),
    ));
    let rt = Runtime::start(RuntimeConfig::default())?;
    let factory2 = Arc::clone(&factory);
    let (bound, _) = rt.add_tcp_listener(TcpListenerConfig::new(addr, move || {
        Box::new(CleartextHttpEndpoint::new(
            Arc::clone(&factory2) as Arc<dyn ServerHandlerFactory>,
            HttpLimits::default(),
        )) as Box<dyn ProtocolHandler>
    }))?;

    eprintln!("websocket echo on ws://{bound}/");
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    rt.shutdown();
    Ok(())
}
