// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TLS echo example (Tranche 3).
//!
//! Generates an ephemeral self-signed cert, listens with TLS-from-accept, echoes
//! plaintext after `security_established`.
//!
//! ```text
//! cargo run -p tls-echo -- 127.0.0.1:8443
//! # cert/key paths printed; use openssl s_client or a rustls client to connect
//! ```

use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

use rcgen::generate_simple_self_signed;
use hopf_core::{
    Endpoint, ProtocolHandler, Runtime, RuntimeConfig, SecurityInfo, TcpListenerConfig,
};
use hopf_tls::acceptor_from_pem;

struct TlsEcho;

impl ProtocolHandler for TlsEcho {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Ok(addr) = endpoint.remote_addr() {
            let _ = writeln!(io::stderr(), "tcp connected {addr} (awaiting TLS)");
        }
    }

    fn security_established(&mut self, endpoint: &mut dyn Endpoint, info: &SecurityInfo) {
        if let Ok(addr) = endpoint.remote_addr() {
            let alpn = info
                .alpn()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .unwrap_or_else(|| "-".into());
            let _ = writeln!(
                io::stderr(),
                "tls ready {addr} alpn={alpn} suite={:?}",
                info.cipher_suite()
            );
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
        if !endpoint.is_secure() {
            return;
        }
        endpoint.send(data);
        *data = &[];
    }

    fn disconnected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Ok(addr) = endpoint.remote_addr() {
            let _ = writeln!(io::stderr(), "disconnected {addr}");
        }
    }

    fn error(&mut self, endpoint: &mut dyn Endpoint, err: &io::Error) {
        if let Ok(addr) = endpoint.remote_addr() {
            let _ = writeln!(io::stderr(), "error on {addr}: {err}");
        }
    }
}

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8443".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let dir = std::env::temp_dir().join("hopf-tls-echo");
    std::fs::create_dir_all(&dir)?;
    let cert = generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let cert_path: PathBuf = dir.join("cert.pem");
    let key_path: PathBuf = dir.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.key_pair.serialize_pem())?;

    let acceptor = acceptor_from_pem(&cert_path, &key_path, &[b"http/1.1"])?;
    let rt = Runtime::start(RuntimeConfig::default())?;
    let (bound, _) = rt.add_tcp_listener(
        TcpListenerConfig::new(addr, || Box::new(TlsEcho) as Box<dyn ProtocolHandler>)
            .with_tls(acceptor),
    )?;

    eprintln!("hopf tls-echo on {bound}");
    eprintln!("cert {} key {}", cert_path.display(), key_path.display());
    eprintln!("press Enter to stop");
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    rt.shutdown();
    Ok(())
}
