// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Blocking SMTP / SMTPS client.

mod error;
mod reply;
mod stream;

pub use error::{SmtpError, SmtpResult};
pub use reply::SmtpReply;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::ClientConfig;

use crate::client::stream::SmtpStream;

use reply::read_reply;

/// Builder for [`SmtpClient`].
#[derive(Clone)]
pub struct SmtpClientBuilder {
    timeout: Duration,
    tls: Option<Arc<ClientConfig>>,
    server_name: Option<String>,
    implicit_tls: bool,
}

impl Default for SmtpClientBuilder {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            tls: None,
            server_name: None,
            implicit_tls: false,
        }
    }
}

impl SmtpClientBuilder {
    /// Create a builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// I/O timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Trust roots for STARTTLS / implicit TLS.
    pub fn tls(mut self, config: Arc<ClientConfig>, server_name: impl Into<String>) -> Self {
        self.tls = Some(config);
        self.server_name = Some(server_name.into());
        self
    }

    /// Dial with TLS from the first byte (SMTPS).
    pub fn implicit_tls(mut self, yes: bool) -> Self {
        self.implicit_tls = yes;
        self
    }

    /// Connect and read the welcome `220`.
    pub fn connect(self, addr: SocketAddr) -> SmtpResult<SmtpClient> {
        let mut stream = if self.implicit_tls {
            let tls = self.tls.as_ref().ok_or_else(|| {
                SmtpError::Config("implicit TLS requires SmtpClientBuilder::tls".into())
            })?;
            let name = self.server_name.as_deref().unwrap_or("localhost");
            SmtpStream::connect_tls(addr, Arc::clone(tls), name, self.timeout)?
        } else {
            SmtpStream::connect_plain(addr, self.timeout)?
        };
        let welcome = read_reply(&mut stream)?;
        if welcome.code != 220 {
            return Err(SmtpError::unexpected(Some(220), welcome));
        }
        Ok(SmtpClient {
            stream,
            peer: addr,
            timeout: self.timeout,
            tls: self.tls,
            server_name: self.server_name,
            welcome,
            capabilities: Vec::new(),
        })
    }
}

/// Blocking SMTP client session.
pub struct SmtpClient {
    stream: SmtpStream,
    peer: SocketAddr,
    #[allow(dead_code)]
    timeout: Duration,
    tls: Option<Arc<ClientConfig>>,
    server_name: Option<String>,
    welcome: SmtpReply,
    capabilities: Vec<String>,
}

impl SmtpClient {
    /// Connect cleartext with defaults.
    pub fn connect(addr: SocketAddr) -> SmtpResult<Self> {
        SmtpClientBuilder::new().connect(addr)
    }

    /// Welcome `220` reply.
    pub fn welcome(&self) -> &SmtpReply {
        &self.welcome
    }

    /// Peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// EHLO capability keywords (uppercased), after [`Self::ehlo`].
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Whether a capability is advertised (case-insensitive keyword match).
    pub fn has_capability(&self, keyword: &str) -> bool {
        let kw = keyword.to_ascii_uppercase();
        self.capabilities
            .iter()
            .any(|c| c.split_whitespace().next().unwrap_or("").eq_ignore_ascii_case(&kw))
    }

    /// Send a raw command and read one reply.
    pub fn command(&mut self, verb: &str, arg: Option<&str>) -> SmtpResult<SmtpReply> {
        let line = match arg {
            Some(a) if !a.is_empty() => format!("{verb} {a}\r\n"),
            _ => format!("{verb}\r\n"),
        };
        self.stream.write_all(line.as_bytes())?;
        self.stream.flush()?;
        read_reply(&mut self.stream)
    }

    /// Expect a specific reply code.
    pub fn expect(&mut self, verb: &str, arg: Option<&str>, code: u16) -> SmtpResult<SmtpReply> {
        let r = self.command(verb, arg)?;
        if r.code != code {
            return Err(SmtpError::unexpected(Some(code), r));
        }
        Ok(r)
    }

    /// `EHLO hostname` — stores capabilities.
    pub fn ehlo(&mut self, hostname: &str) -> SmtpResult<SmtpReply> {
        let r = self.expect("EHLO", Some(hostname), 250)?;
        self.capabilities = r
            .lines
            .iter()
            .skip(1)
            .map(|l| l.to_ascii_uppercase())
            .collect();
        Ok(r)
    }

    /// `HELO hostname`.
    pub fn helo(&mut self, hostname: &str) -> SmtpResult<SmtpReply> {
        self.capabilities.clear();
        self.expect("HELO", Some(hostname), 250)
    }

    /// `MAIL FROM:<addr>` (`addr` empty for null sender).
    pub fn mail(&mut self, reverse_path: &str) -> SmtpResult<SmtpReply> {
        let arg = if reverse_path.is_empty() {
            "FROM:<>".to_string()
        } else {
            format!("FROM:<{reverse_path}>")
        };
        self.expect("MAIL", Some(&arg), 250)
    }

    /// `RCPT TO:<addr>`.
    pub fn rcpt(&mut self, forward_path: &str) -> SmtpResult<SmtpReply> {
        let arg = format!("TO:<{forward_path}>");
        self.expect("RCPT", Some(&arg), 250)
    }

    /// `DATA` with dot-stuffed body; expects final `250`.
    pub fn data(&mut self, message: &[u8]) -> SmtpResult<SmtpReply> {
        let r = self.command("DATA", None)?;
        if r.code != 354 {
            return Err(SmtpError::unexpected(Some(354), r));
        }
        let stuffed = dot_stuff(message);
        self.stream.write_all(&stuffed)?;
        self.stream.write_all(b".\r\n")?;
        self.stream.flush()?;
        let r = read_reply(&mut self.stream)?;
        if r.code != 250 {
            return Err(SmtpError::unexpected(Some(250), r));
        }
        Ok(r)
    }

    /// Send via BDAT if CHUNKING is advertised; otherwise [`Self::data`].
    pub fn send_message(&mut self, message: &[u8]) -> SmtpResult<SmtpReply> {
        if self.has_capability("CHUNKING") {
            self.bdat(message)
        } else {
            self.data(message)
        }
    }

    /// `BDAT` LAST transfer of the whole message.
    pub fn bdat(&mut self, message: &[u8]) -> SmtpResult<SmtpReply> {
        let arg = format!("{} LAST", message.len());
        self.stream
            .write_all(format!("BDAT {arg}\r\n").as_bytes())?;
        self.stream.write_all(message)?;
        self.stream.flush()?;
        let r = read_reply(&mut self.stream)?;
        if r.code != 250 {
            return Err(SmtpError::unexpected(Some(250), r));
        }
        Ok(r)
    }

    /// Explicit TLS upgrade (`STARTTLS`).
    pub fn starttls(&mut self) -> SmtpResult<()> {
        let tls = self
            .tls
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| SmtpError::Config("STARTTLS requires SmtpClientBuilder::tls".into()))?;
        let name = self
            .server_name
            .clone()
            .unwrap_or_else(|| "localhost".into());
        let r = self.command("STARTTLS", None)?;
        if r.code != 220 {
            return Err(SmtpError::unexpected(Some(220), r));
        }
        self.stream.upgrade_tls(tls, &name)?;
        self.capabilities.clear();
        Ok(())
    }

    /// `AUTH PLAIN` with username/password.
    pub fn auth_plain(&mut self, user: &str, pass: &str) -> SmtpResult<SmtpReply> {
        let mut raw = Vec::new();
        raw.push(0);
        raw.extend_from_slice(user.as_bytes());
        raw.push(0);
        raw.extend_from_slice(pass.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
        self.expect("AUTH", Some(&format!("PLAIN {b64}")), 235)
    }

    /// `QUIT`.
    pub fn quit(&mut self) -> SmtpResult<SmtpReply> {
        let r = self.command("QUIT", None)?;
        self.stream.shutdown();
        Ok(r)
    }
}

/// Dot-stuff outbound: lines starting with `.` get an extra `.`.
pub fn dot_stuff(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 16);
    let mut line_start = true;
    for &b in message {
        if line_start && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        line_start = b == b'\n';
    }
    // Ensure message ends with CRLF before the terminating `.\r\n` from caller.
    if !message.ends_with(b"\r\n") {
        if message.ends_with(b"\n") {
            // already has LF
        } else if message.ends_with(b"\r") {
            out.push(b'\n');
        } else if !message.is_empty() {
            out.extend_from_slice(b"\r\n");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuff_leading_dot() {
        assert_eq!(dot_stuff(b".foo\r\n"), b"..foo\r\n");
    }
}
