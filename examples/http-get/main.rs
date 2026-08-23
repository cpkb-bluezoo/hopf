// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/1.1, HTTP/2, or HTTP/3 client dial example — accepts hostname or IP.
//!
//! ```text
//! # H1 / H2 (cleartext)
//! cargo run -p http-get -- example.com /
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

use hopf_core::{Runtime, RuntimeConfig};
use hopf_http::{
    client::{connect_http, HttpClientTimeouts},
    h3::connect_h3,
    Headers, HttpLimits, ClientHandler, ClientHandlerFactory, ClientWriter,
};
use hopf_quic::{client_config_from_pem, QuicDriverHandle, ALPN_H3};

struct GetOnce {
    host: String,
    path: String,
    http3: bool,
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
        if !self.http3 {
            h.set("connection", "close");
        }
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

    fn request_failed(&mut self, _request: &mut dyn ClientWriter, err: &io::Error) {
        let mut g = self.out.lock().unwrap();
        g.error = Some(err.to_string());
        g.done = true;
    }
}

struct GetFactory {
    host: String,
    path: String,
    http3: bool,
    out: Arc<Mutex<Outcome>>,
}

impl ClientHandlerFactory for GetFactory {
    fn create_handler(&self) -> Box<dyn ClientHandler> {
        Box::new(GetOnce {
            host: self.host.clone(),
            path: self.path.clone(),
            http3: self.http3,
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
    let mut host_s = None;
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
        } else if host_s.is_none() {
            host_s = Some(a);
        } else {
            path_s = Some(a);
        }
    }

    let host_s = host_s.unwrap_or_else(|| {
        if http3 {
            "127.0.0.1:4433".into()
        } else {
            "127.0.0.1:8080".into()
        }
    });
    let path = path_s.unwrap_or_else(|| "/".into());

    // Split "host:port" or "hostname" → (host, port)
    let default_port: u16 = if http3 { 4433 } else { 80 };
    let (host, port) = split_host_port(&host_s, default_port);

    let out = Arc::new(Mutex::new(Outcome::default()));
    let factory: Arc<dyn ClientHandlerFactory> = Arc::new(GetFactory {
        host: host.clone(),
        path: path.clone(),
        http3,
        out: Arc::clone(&out),
    });
    let limits = HttpLimits::default();

    let rt = Arc::new(Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })?);

    // Keep a handle alive so the QUIC driver isn't dropped early.
    let _h3_handle: Option<QuicDriverHandle>;

    if http3 {
        let ca = ca.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--http3 requires --ca <leaf-or-ca.pem>",
            )
        })?;
        let client_cfg = client_config_from_pem(&ca, &[ALPN_H3])?;
        let sni = server_name.unwrap_or_else(|| host.clone());
        // H3 needs a SocketAddr; try to parse, else do a quick system resolve.
        let addr = if let Ok(a) = host_s.parse::<SocketAddr>() {
            a
        } else {
            use std::net::ToSocketAddrs;
            (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e))?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))?
        };
        _h3_handle = Some(connect_h3(addr, client_cfg, sni, Arc::clone(&factory), limits)?);
        eprintln!("hopf http-get dialing https://{host}:{port}{path} (http3)");
    } else {
        _h3_handle = None;
        connect_http(
            &rt,
            &host,
            port,
            Arc::clone(&factory),
            limits,
            http2,
            HttpClientTimeouts::default(),
            None,
        )?;
        if http2 {
            eprintln!("hopf http-get dialing http2://{host}:{port}{path} (prior-knowledge)");
        } else {
            eprintln!("hopf http-get dialing http://{host}:{port}{path}");
        }
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
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
    drop(g);

    // Drop the QUIC handle before unwrapping the runtime.
    drop(_h3_handle);
    if let Ok(owned) = Arc::try_unwrap(rt) {
        owned.shutdown();
    }
    Ok(())
}

/// Split `"host:port"`, `"[::1]:port"`, or bare hostname into `(host, port)`.
fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.port());
    }
    if s.starts_with('[') {
        if let Some(bracket) = s.rfind(']') {
            let ip = &s[1..bracket];
            let rest = &s[bracket + 1..];
            let port = if rest.starts_with(':') {
                rest[1..].parse().unwrap_or(default_port)
            } else {
                default_port
            };
            return (ip.to_string(), port);
        }
    }
    if let Some(colon) = s.rfind(':') {
        if let Ok(p) = s[colon + 1..].parse::<u16>() {
            return (s[..colon].to_string(), p);
        }
    }
    (s.to_string(), default_port)
}
