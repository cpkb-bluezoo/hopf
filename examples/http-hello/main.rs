// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP hello server (H1 + H2 via ALPN/h2c) — twin of `http-get`.
//!
//! ```text
//! cargo run -p http-hello -- 127.0.0.1:8080
//! curl -v http://127.0.0.1:8080/
//! curl --http2-prior-knowledge http://127.0.0.1:8080/
//! curl --http2 http://127.0.0.1:8080/          # h2c Upgrade
//!
//! cargo run -p http-hello -- --tls 127.0.0.1:8443
//! curl -vk https://127.0.0.1:8443/
//! curl -vk --http2 https://127.0.0.1:8443/
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::generate_simple_self_signed;
use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};
use hopf_http::{
    AlpnHttpEndpoint, CleartextHttpEndpoint, Headers, HttpLimits, ServerHandler,
    ServerHandlerFactory, ServerWriter,
};
use hopf_tls::acceptor_from_pem;

struct Hello;

impl ServerHandler for Hello {
    fn headers(&mut self, response: &mut dyn ServerWriter, _headers: &Headers) {
        let body = b"Hello, world\n";
        let mut h = Headers::new();
        h.status(200);
        h.set("Content-Type", "text/plain; charset=utf-8");
        h.set("Content-Length", body.len().to_string());
        response.headers(h);
        response.start_response_body();
        response.response_body_content(body);
        response.end_response_body();
        response.complete();
    }

    fn request_complete(&mut self, _response: &mut dyn ServerWriter) {}
}

struct HelloFactory;

impl ServerHandlerFactory for HelloFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(Hello)
    }
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let mut tls = false;
    let mut addr_s = None;
    while let Some(a) = args.next() {
        if a == "--tls" {
            tls = true;
        } else {
            addr_s = Some(a);
        }
    }
    let addr: SocketAddr = addr_s
        .unwrap_or_else(|| {
            if tls {
                "127.0.0.1:8443".into()
            } else {
                "127.0.0.1:8080".into()
            }
        })
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let factory: Arc<dyn ServerHandlerFactory> = Arc::new(HelloFactory);
    let limits = HttpLimits::default();

    let rt = Runtime::start(RuntimeConfig::default())?;
    let bound = if tls {
        let dir = std::env::temp_dir().join("hopf-http-hello");
        std::fs::create_dir_all(&dir)?;
        let cert = generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem())?;
        std::fs::write(&key_path, cert.key_pair.serialize_pem())?;
        // Prefer h2; fall back to HTTP/1.1 — same ServerHandler either way.
        let acceptor = acceptor_from_pem(&cert_path, &key_path, &[b"h2", b"http/1.1"])?;
        let factory2 = Arc::clone(&factory);
        let (bound, _) = rt.add_tcp_listener(
            TcpListenerConfig::new(addr, move || {
                Box::new(AlpnHttpEndpoint::new(Arc::clone(&factory2), limits))
                    as Box<dyn ProtocolHandler>
            })
            .with_tls(acceptor),
        )?;
        eprintln!("cert {} key {}", cert_path.display(), key_path.display());
        bound
    } else {
        let factory2 = Arc::clone(&factory);
        let (bound, _) = rt.add_tcp_listener(TcpListenerConfig::new(addr, move || {
            Box::new(CleartextHttpEndpoint::new(Arc::clone(&factory2), limits))
                as Box<dyn ProtocolHandler>
        }))?;
        bound
    };

    eprintln!(
        "hopf http-hello listening on {}://{bound} ({} workers){}",
        if tls { "https" } else { "http" },
        rt.worker_count(),
        if tls { " ALPN h2,http/1.1" } else { " h2c prior-knowledge + Upgrade + HTTP/1.1" }
    );
    eprintln!("press Enter to stop");

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);

    eprintln!("shutting down");
    rt.shutdown();
    Ok(())
}
