// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.1, HTTP/2, or HTTP/3 client dial example — twin of `http-hello` / `http3-hello`.
//!
//! ```text
//! # H1 / H2 (cleartext)
//! cargo run -p http-hello -- 127.0.0.1:8080
//! cargo run -p http-get -- 127.0.0.1:8080 /
//! cargo run -p http-get -- --http2 127.0.0.1:8080 /
//!
//! # H3 (QUIC) — start http3-hello, then dial with its leaf PEM:
//! cargo run -p http3-hello -- 127.0.0.1:4433
//! cargo run -p http-get -- --http3 --ca "$TMPDIR/hopf-http3-hello/cert.pem" \
//!     127.0.0.1:4433 /
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpConnectorConfig};
use hopf_http::{
    connect_h3, H1Endpoint, H2Endpoint, Headers, HttpLimits, ClientHandler, ClientHandlerFactory,
    ClientWriter,
};
use hopf_quic::{client_config_from_pem, ALPN_H3};

struct GetOnce {
    host: String,
    path: String,
    out: Arc<Mutex<Outcome>>,
}

#[derive(Default)]
struct Outcome {
    status: u16,
    body: Vec<u8>,
    done: bool,
    error: Option<String>,
}

impl ClientHandler for GetOnce {
    fn start(&mut self, request: &mut dyn ClientWriter) {
        let mut h = Headers::new();
        h.set(":method", "GET");
        h.set(":path", &self.path);
        h.set("host", &self.host);
        h.set("connection", "close");
        request.headers(h);
        request.complete_request();
    }

    fn response_headers(&mut self, _request: &mut dyn ClientWriter, headers: &Headers) {
        self.out.lock().unwrap().status = headers.status_code();
    }

    fn response_body_content(&mut self, _request: &mut dyn ClientWriter, data: &[u8]) {
        self.out.lock().unwrap().body.extend_from_slice(data);
    }

    fn response_complete(&mut self, _request: &mut dyn ClientWriter) {
        self.out.lock().unwrap().done = true;
    }
}

struct GetFactory {
    host: String,
    path: String,
    out: Arc<Mutex<Outcome>>,
}

impl ClientHandlerFactory for GetFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(GetOnce {
            host: self.host.clone(),
            path: self.path.clone(),
            out: Arc::clone(&self.out),
        })
    }
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let mut http2 = false;
    let mut http3 = false;
    let mut ca: Option<PathBuf> = None;
    let mut server_name: Option<String> = None;
    let mut addr_s = None;
    let mut path_s = None;

    while let Some(a) = args.next() {
        if a == "--http2" || a == "--h2" {
            http2 = true;
        } else if a == "--http3" || a == "--h3" {
            http3 = true;
        } else if a == "--ca" {
            ca = args.next().map(PathBuf::from);
        } else if a == "--server-name" {
            server_name = args.next();
        } else if addr_s.is_none() {
            addr_s = Some(a);
        } else {
            path_s = Some(a);
        }
    }

    let addr_s = addr_s.unwrap_or_else(|| {
        if http3 {
            "127.0.0.1:4433".into()
        } else {
            "127.0.0.1:8080".into()
        }
    });
    let path = path_s.unwrap_or_else(|| "/".into());
    let addr: SocketAddr = addr_s
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let host = match addr {
        SocketAddr::V4(a) => a.ip().to_string(),
        SocketAddr::V6(a) => a.ip().to_string(),
    };
    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory {
        host: host.clone(),
        path: path.clone(),
        out: Arc::clone(&out),
    });
    let limits = HttpLimits::default();

    let rt = Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })?;

    let _quic_handle;
    if http3 {
        let ca = ca.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--http3 requires --ca <leaf-or-ca.pem> (see http3-hello cert path)",
            )
        })?;
        let client_cfg = client_config_from_pem(&ca, &[ALPN_H3])?;
        let name = server_name.unwrap_or_else(|| "localhost".into());
        _quic_handle = Some(connect_h3(
            addr,
            client_cfg,
            name,
            Arc::clone(&factory),
            limits,
        )?);
        eprintln!("hopf http-get dialing https://{addr}{path} (http3)");
    } else if http2 {
        let factory2 = Arc::clone(&factory);
        rt.connect(TcpConnectorConfig::new(addr, move || {
            Box::new(H2Endpoint::client(
                Arc::clone(&factory2),
                limits,
                false, // cleartext prior-knowledge
            )) as Box<dyn ProtocolHandler>
        }))?;
        eprintln!("hopf http-get dialing http2://{addr}{path} (prior-knowledge)");
    } else {
        let factory2 = Arc::clone(&factory);
        rt.connect(TcpConnectorConfig::new(addr, move || {
            Box::new(H1Endpoint::client(
                Arc::clone(&factory2),
                limits,
                false,
            )) as Box<dyn ProtocolHandler>
        }))?;
        eprintln!("hopf http-get dialing http://{addr}{path}");
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let g = out.lock().unwrap();
            if g.done || g.error.is_some() {
                break;
            }
        }
        if std::time::Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for HTTP response",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    let g = out.lock().unwrap();
    if let Some(err) = &g.error {
        return Err(io::Error::new(io::ErrorKind::Other, err.clone()));
    }
    print!("{}", String::from_utf8_lossy(&g.body));
    eprintln!("status {}", g.status);

    rt.shutdown();
    Ok(())
}
