// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async FTP client example — downloads one file via PASV RETR.
//!
//! ```text
//! # Start the bundled FTP server:
//! cargo run -p ftp -- 127.0.0.1:2121 /tmp/ftp-root
//!
//! # Download a file:
//! cargo run -p ftp-get -- 127.0.0.1:2121 /hello.txt
//!
//! # Using a hostname:
//! FTP_USER=anon FTP_PASS=anon cargo run -p ftp-get -- ftp.example.com /pub/file.txt
//! ```

use std::env;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_core::{Runtime, RuntimeConfig};
use hopf_ftp::{FtpClient, FtpClientTimeouts, FtpGet, MessageReceiveCallback};

/// Writes each chunk straight to stdout as it arrives — the file is never
/// buffered whole in memory.
struct StdoutWriter {
    result: Arc<Mutex<Option<io::Result<()>>>>,
}

impl MessageReceiveCallback for StdoutWriter {
    fn message_content(&mut self, chunk: &[u8]) -> bool {
        io::stdout().write_all(chunk).is_ok()
    }

    fn end_message(&mut self, result: io::Result<()>) {
        *self.result.lock().unwrap() = Some(result);
    }
}

fn main() -> io::Result<()> {
    // Parse arguments: [host[:port]] [remote_path]
    let mut args = env::args().skip(1);
    let host_port = args.next().unwrap_or_else(|| "127.0.0.1:2121".into());
    let remote = args.next().unwrap_or_else(|| "/".into());

    let (host, port) = split_host_port(&host_port, 21);
    let user = env::var("FTP_USER").unwrap_or_else(|_| "ftp".into());
    let pass = env::var("FTP_PASS").unwrap_or_else(|_| "ftp".into());

    let result: Arc<Mutex<Option<io::Result<()>>>> = Arc::new(Mutex::new(None));
    let result2 = Arc::clone(&result);

    let pipeline = FtpGet::new(&remote, Box::new(StdoutWriter { result: result2 }));

    let rt = Arc::new(Runtime::start(RuntimeConfig {
        worker_threads: 1,
        ..Default::default()
    })?);

    eprintln!("hopf ftp-get dialing ftp://{host}:{port}{remote}");

    FtpClient::new(&host)
        .port(port)
        .credentials(&user, &pass)
        .timeouts(FtpClientTimeouts {
            dns: Duration::from_secs(5),
            connect: Duration::from_secs(10),
            stage: Duration::from_secs(30),
            data: Duration::from_secs(120),
        })
        .connect(&rt, Box::new(pipeline))?;

    // Block until the pipeline completes.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(r) = result.lock().unwrap().take() {
            r.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            break;
        }
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ftp-get: timed out waiting for file",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    if let Ok(owned) = Arc::try_unwrap(rt) {
        owned.shutdown();
    }
    Ok(())
}

/// Split `"host:port"`, `"[::1]:port"`, or bare `"hostname"` into `(host, port)`.
fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    // Full SocketAddr parse.
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.port());
    }
    // IPv6 literal `[::1]:port`
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
    // `"host:port"` or bare `"hostname"`.
    if let Some(colon) = s.rfind(':') {
        if let Ok(p) = s[colon + 1..].parse::<u16>() {
            return (s[..colon].to_string(), p);
        }
    }
    (s.to_string(), default_port)
}
