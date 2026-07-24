// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! TCP echo example for Hopf Tranche 1.
//!
//! ```text
//! cargo run -p echo -- 127.0.0.1:8080
//! # other terminal:
//! nc 127.0.0.1 8080
//! ```

use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;

use hopf_core::{
    Endpoint, ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig,
};

struct Echo;

impl ProtocolHandler for Echo {
    fn connected(&mut self, endpoint: &mut dyn Endpoint) {
        if let Ok(addr) = endpoint.remote_addr() {
            let _ = writeln!(io::stderr(), "connected {addr}");
        }
    }

    fn receive(&mut self, endpoint: &mut dyn Endpoint, data: &mut &[u8]) {
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
        .unwrap_or_else(|| "127.0.0.1:8080".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let rt = Runtime::start(RuntimeConfig::default())?;
    let (bound, _) = rt.add_tcp_listener(TcpListenerConfig::new(addr, || {
        Box::new(Echo) as Box<dyn ProtocolHandler>
    }))?;
    eprintln!(
        "hopf echo listening on {bound} ({} workers)",
        rt.worker_count()
    );
    eprintln!("press Enter to stop");

    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);

    eprintln!("shutting down");
    rt.shutdown();
    Ok(())
}
