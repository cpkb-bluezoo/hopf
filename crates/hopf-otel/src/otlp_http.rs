// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Blocking OTLP/HTTP client (runs on the export worker only).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Parsed `http://host:port/path` endpoint.
#[derive(Debug, Clone)]
pub struct HttpEndpoint {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Request path (e.g. `/v1/logs`).
    pub path: String,
}

impl HttpEndpoint {
    /// Parse a simple `http://host[:port]/path` URL (no TLS in this pass).
    pub fn parse(url: &str) -> Option<Self> {
        let rest = url.strip_prefix("http://")?;
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, "/".into()),
        };
        let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
            (h.to_string(), p.parse().ok()?)
        } else {
            (authority.to_string(), 80)
        };
        Some(Self { host, port, path })
    }
}

/// POST protobuf body to an OTLP/HTTP logs endpoint.
pub fn post_protobuf(endpoint: &HttpEndpoint, body: &[u8]) -> Result<u16, String> {
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&addr).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-protobuf\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         User-Agent: hopf-otel/{}\r\n\
         \r\n",
        endpoint.path,
        endpoint.host,
        body.len(),
        env!("CARGO_PKG_VERSION")
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(body).map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        Ok(status)
    } else {
        Err(format!("OTLP HTTP status {status}: {}", &text[..text.len().min(200)]))
    }
}
