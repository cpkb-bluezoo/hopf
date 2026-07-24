// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP/3 hello server — same [`ServerHandler`] as `http-hello`.
//!
//! ```text
//! cargo run -p http3-hello -- 127.0.0.1:4433
//! # Requires a curl build with HTTP/3 (nghttp3 / quiche):
//! curl -vk --http3-only https://127.0.0.1:4433/
//! ```
//!
//! In-tree smoke: `cargo test -p hopf-http --features h3 h3_get_hello`.
use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use hopf_http::{
    h3::listen_h3, Headers, HttpLimits, ServerHandler, ServerHandlerFactory, ServerWriter,
};
use hopf_quic::{server_config_from_pem, ALPN_H3};

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
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let dir = std::env::temp_dir().join("hopf-http3-hello");
    let _ = std::fs::create_dir_all(&dir);
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    write_self_signed(&cert_path, &key_path)?;

    let server = server_config_from_pem(&cert_path, &key_path, &[ALPN_H3])?;
    let factory: Arc<dyn ServerHandlerFactory> = Arc::new(HelloFactory);
    let handle = listen_h3(addr, server, factory, HttpLimits::default())?;

    eprintln!(
        "http3-hello listening on https://{}/ (ALPN h3)",
        handle.local_addr
    );
    eprintln!("try: curl -vk --http3-only https://{}/", handle.local_addr);

    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn write_self_signed(cert_path: &PathBuf, key_path: &PathBuf) -> io::Result<()> {
    let cert = generate_simple_self_signed(vec![
        "localhost".into(),
        "127.0.0.1".into(),
    ])
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(cert_path, cert.cert.pem())?;
    std::fs::write(key_path, cert.key_pair.serialize_pem())?;
    Ok(())
}
