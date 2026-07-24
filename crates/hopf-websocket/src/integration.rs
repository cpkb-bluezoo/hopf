// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime TCP smokes (enable with `--features integration`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_http::{CleartextHttpEndpoint, HttpLimits, ServerHandlerFactory};
use crate::{
    calculate_accept, write_frame, EchoFactory, Opcode, WebSocketConfig, WebSocketFactory,
};

fn listen_ws() -> (Runtime, std::net::SocketAddr) {
    let factory = Arc::new(WebSocketFactory::new(
        EchoFactory,
        WebSocketConfig::default(),
    ));
    let rt = Runtime::start(RuntimeConfig::default()).unwrap();
    let factory2 = Arc::clone(&factory);
    let (addr, _) = rt
        .add_tcp_listener(TcpListenerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            move || {
                Box::new(CleartextHttpEndpoint::new(
                    Arc::clone(&factory2) as Arc<dyn ServerHandlerFactory>,
                    HttpLimits::default(),
                )) as Box<dyn ProtocolHandler>
            },
        ))
        .unwrap();
    (rt, addr)
}

#[test]
fn h1_websocket_echo() {
    let (rt, addr) = listen_ws();
    thread::sleep(Duration::from_millis(50));

    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    c.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let req = format!(
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    c.write_all(req.as_bytes()).unwrap();

    let mut buf = [0u8; 4096];
    let n = c.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("101"), "{resp}");
    assert!(resp.contains(&calculate_accept(key)), "{resp}");

    // Any bytes after the header block in the same read are leftover; ignore.
    let mut frame = Vec::new();
    write_frame(&mut frame, true, Opcode::Text, Some([1, 2, 3, 4]), b"hi");
    c.write_all(&frame).unwrap();

    let mut out = Vec::new();
    for _ in 0..20 {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.windows(4).any(|w| w == [0x81, 0x02, b'h', b'i']) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    assert!(
        out.windows(4).any(|w| w == [0x81, 0x02, b'h', b'i']),
        "echo frame missing in {out:?}"
    );

    rt.shutdown();
}
