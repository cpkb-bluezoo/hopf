// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Async SMTP client example — twin of `smtp-server`.
//!
//! ```text
//! cargo run -p smtp-server -- 127.0.0.1:2525
//! cargo run -p smtp-send -- 127.0.0.1:2525 from@example.com to@example.com
//! # or by hostname (resolved via hopf-dns):
//! cargo run -p smtp-send -- mx.example.com:25 from@example.com to@example.com
//! ```

use std::env;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hopf_core::{Runtime, RuntimeConfig};
use hopf_smtp::{SmtpClient, SmtpClientTimeouts, SmtpSend};

fn main() -> io::Result<()> {
    let host_port = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2525".into());
    let (host, port) = split_host_port(&host_port, 25);
    let from = env::args()
        .nth(2)
        .unwrap_or_else(|| "sender@example.com".into());
    let to = env::args()
        .nth(3)
        .unwrap_or_else(|| "recipient@example.com".into());
    let subject = env::var("SMTP_SUBJECT").unwrap_or_else(|_| "Hopf test".into());
    let body = env::var("SMTP_BODY").unwrap_or_else(|_| "Hello from smtp-send.\r\n".into());
    let msg = format!("Subject: {subject}\r\n\r\n{body}");

    let rt = Arc::new(Runtime::start(RuntimeConfig::default())?);
    let done: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
    let done2 = Arc::clone(&done);

    let send = SmtpSend::new("smtp-send.local")
        .mail_from(from.clone())
        .rcpt_to(to.clone())
        .message(msg.into_bytes())
        .on_complete(Box::new(move |ok| *done2.lock().unwrap() = Some(ok)));

    SmtpClient::new(&host, port)
        .timeouts(SmtpClientTimeouts {
            connect: Duration::from_secs(10),
            stage: Duration::from_secs(10),
            message: Duration::from_secs(30),
            ..Default::default()
        })
        .connect(&rt, Arc::new(send))?;

    // Wait for completion.
    for _ in 0..600 {
        if done.lock().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let outcome = *done.lock().unwrap();
    match outcome {
        Some(true) => {
            eprintln!("sent to {to} via {host}:{port}");
            Ok(())
        }
        Some(false) => Err(io::Error::new(io::ErrorKind::Other, "SMTP delivery failed")),
        None => Err(io::Error::new(io::ErrorKind::TimedOut, "SMTP delivery timed out")),
    }
}

/// Split `"host:port"`, `"[::1]:port"`, or bare `"hostname"` into `(host, port)`.
fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return (addr.ip().to_string(), addr.port());
    }
    if s.starts_with('[') {
        if let Some(bracket) = s.rfind(']') {
            let ip = &s[1..bracket];
            let rest = &s[bracket + 1..];
            let port = if let Some(stripped) = rest.strip_prefix(':') {
                stripped.parse().unwrap_or(default_port)
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
