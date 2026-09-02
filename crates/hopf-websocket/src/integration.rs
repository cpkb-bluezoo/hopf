// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Runtime TCP smokes (enable with `--features integration`).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hopf_core::{ConnHandle, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_http::{
    connect_http, CleartextHttpEndpoint, ClientHandler, ClientHandlerFactory, ClientWriter,
    Headers, HttpClientTimeouts, HttpLimits, ServerHandlerFactory,
};
use crate::{
    calculate_accept, write_frame, EchoFactory, Opcode, WebSocketConfig, WebSocketFactory,
    WebSocketOpening, WsEventHandler, WsSession, WsUpgradeHandler,
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

/// The other half of [`h1_websocket_echo`]: hopf's own HTTP client, driving
/// its real `ClientHandler`/`ClientWriter` machinery (via
/// [`hopf_http::connect_http`]), performs the WebSocket opening handshake
/// with [`WebSocketOpening`] and installs [`WsUpgradeHandler::client`] on a
/// successful `101` — exercising the shared client-side protocol-upgrade
/// path end to end against a real server, not a hand-rolled socket.
#[derive(Default)]
struct ClientOutcome {
    opened: bool,
    echoed_text: Option<String>,
    failed: Option<String>,
}

struct WsClientEvents {
    out: Arc<Mutex<ClientOutcome>>,
}

impl WsEventHandler for WsClientEvents {
    fn opened(&mut self, session: &mut WsSession<'_>, _conn: &ConnHandle) {
        self.out.lock().unwrap().opened = true;
        session.send_text("hi from the client");
    }

    fn text_message(&mut self, _session: &mut WsSession<'_>, text: &str) {
        self.out.lock().unwrap().echoed_text = Some(text.to_string());
    }
}

struct WsClientHandler {
    opening: WebSocketOpening,
    out: Arc<Mutex<ClientOutcome>>,
}

impl ClientHandler for WsClientHandler {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        self.opening.write_request(request, "/echo", "localhost");
    }

    fn switching_protocols(&mut self, request: &mut dyn ClientWriter, headers: &Headers) {
        if let Err(e) = self.opening.validate_response(headers) {
            self.out.lock().unwrap().failed = Some(e.to_string());
            return;
        }
        let events = Box::new(WsClientEvents {
            out: Arc::clone(&self.out),
        });
        // No real cross-thread re-entry is exercised by this test, so a
        // stub `ConnHandle` (matching the one this crate's own low-level
        // frame/session unit tests use) stands in for the connection's
        // real handle.
        let conn = ConnHandle::from_execute(Arc::new(|task| task()));
        if !request.upgrade(Box::new(WsUpgradeHandler::client(events, 1 << 20, conn))) {
            self.out.lock().unwrap().failed = Some("ClientWriter::upgrade refused".into());
        }
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        self.out.lock().unwrap().failed =
            Some(format!("expected 101, got {}", headers.status_code()));
    }

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &std::io::Error) {
        self.out.lock().unwrap().failed = Some(err.to_string());
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {}
}

struct WsClientFactory {
    out: Arc<Mutex<ClientOutcome>>,
}

impl ClientHandlerFactory for WsClientFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(WsClientHandler {
            opening: WebSocketOpening::new(None),
            out: Arc::clone(&self.out),
        })
    }
}

#[test]
fn h1_websocket_client_round_trip() {
    let (rt, addr) = listen_ws();
    let rt = Arc::new(rt);
    thread::sleep(Duration::from_millis(50));

    let out = Arc::new(Mutex::new(ClientOutcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(WsClientFactory {
        out: Arc::clone(&out),
    });

    connect_http(
        &rt,
        &addr.ip().to_string(),
        addr.port(),
        factory,
        HttpLimits::default(),
        false,
        HttpClientTimeouts::default(),
        None,
    )
    .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let g = out.lock().unwrap();
            if g.failed.is_some() || g.echoed_text.is_some() {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let g = out.lock().unwrap();
    assert!(g.failed.is_none(), "client-side upgrade failed: {:?}", g.failed);
    assert!(g.opened, "WsEventHandler::opened never fired");
    assert_eq!(g.echoed_text.as_deref(), Some("hi from the client"));
}
