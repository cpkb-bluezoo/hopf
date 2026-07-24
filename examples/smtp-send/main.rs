// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Blocking SMTP client example — twin of `smtp-server`.
//!
//! ```text
//! cargo run -p smtp-server -- 127.0.0.1:2525
//! cargo run -p smtp-send -- 127.0.0.1:2525 from@example.com to@example.com
//! ```

use std::env;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hopf_smtp::SmtpClientBuilder;

fn main() -> io::Result<()> {
    let addr: SocketAddr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2525".into())
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let from = env::args()
        .nth(2)
        .unwrap_or_else(|| "sender@example.com".into());
    let to = env::args()
        .nth(3)
        .unwrap_or_else(|| "recipient@example.com".into());
    let subject = env::var("SMTP_SUBJECT").unwrap_or_else(|_| "Hopf test".into());
    let body = env::var("SMTP_BODY").unwrap_or_else(|_| "Hello from smtp-send.\n".into());

    let mut client = SmtpClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .connect(addr)
        .map_err(to_io)?;
    client.ehlo("smtp-send.local").map_err(to_io)?;
    client.mail(&from).map_err(to_io)?;
    client.rcpt(&to).map_err(to_io)?;
    let msg = format!("Subject: {subject}\r\n\r\n{body}");
    // Normalise body newlines to CRLF-ish for DATA.
    let msg = msg.replace('\n', "\r\n").replace("\r\r\n", "\r\n");
    client.data(msg.as_bytes()).map_err(to_io)?;
    let _ = client.quit();
    eprintln!("sent to {to} via {addr}");
    Ok(())
}

fn to_io(e: hopf_smtp::SmtpError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}
