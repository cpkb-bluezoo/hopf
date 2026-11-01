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
        let (host, port) = if authority.starts_with('[') {
            // An IPv6 literal: the colons inside the brackets are not a port.
            let close = authority.find(']')?;
            let host = authority[..=close].to_string();
            match authority[close + 1..].strip_prefix(':') {
                Some(p) => (host, p.parse().ok()?),
                None if authority.len() == close + 1 => (host, 80),
                None => return None,
            }
        } else if let Some((h, p)) = authority.rsplit_once(':') {
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

    // RFC 9110 section 7.2: the port is part of Host unless it is the default.
    let host_header = if endpoint.port == 80 {
        endpoint.host.clone()
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    };
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-protobuf\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         User-Agent: hopf-otel/{}\r\n\
         \r\n",
        endpoint.path,
        host_header,
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn a_url_gives_host_port_and_path() {
        let e = HttpEndpoint::parse("http://collector:4318/v1/logs").unwrap();
        assert_eq!((e.host.as_str(), e.port, e.path.as_str()), ("collector", 4318, "/v1/logs"));
    }

    #[test]
    fn the_port_defaults_to_80_and_the_path_to_a_slash() {
        let e = HttpEndpoint::parse("http://collector").unwrap();
        assert_eq!((e.host.as_str(), e.port, e.path.as_str()), ("collector", 80, "/"));
        let e = HttpEndpoint::parse("http://collector/").unwrap();
        assert_eq!((e.port, e.path.as_str()), (80, "/"));
    }

    #[test]
    fn a_path_keeps_its_query_string() {
        let e = HttpEndpoint::parse("http://c:1/v1/traces?x=1&y=2").unwrap();
        assert_eq!(e.path, "/v1/traces?x=1&y=2");
    }

    #[test]
    fn only_plain_http_urls_with_a_usable_port_are_accepted() {
        assert!(HttpEndpoint::parse("https://collector/").is_none());
        assert!(HttpEndpoint::parse("collector:4318").is_none());
        assert!(HttpEndpoint::parse("http://collector:notaport/").is_none());
        assert!(HttpEndpoint::parse("http://collector:99999/").is_none());
        assert!(HttpEndpoint::parse("http://collector:/").is_none());
    }

    #[test]
    fn an_ipv6_literal_is_accepted_with_or_without_a_port() {
        let e = HttpEndpoint::parse("http://[::1]:4318/v1/logs").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("[::1]", 4318));
        let e = HttpEndpoint::parse("http://[::1]/v1/logs").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("[::1]", 80));
    }

    /// Serves one connection: reads a whole request, answers with `reply`,
    /// and hands the request bytes back.
    pub(crate) fn serve_once(reply: &'static str) -> (u16, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if req.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            let _ = s.write_all(reply.as_bytes());
            let _ = tx.send(req);
        });
        (port, rx)
    }

    fn endpoint(port: u16) -> HttpEndpoint {
        HttpEndpoint { host: "127.0.0.1".into(), port, path: "/v1/logs".into() }
    }

    #[test]
    fn a_post_sends_the_protobuf_body_with_its_headers() {
        let (port, rx) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(post_protobuf(&endpoint(port), b"\x0a\x00body").unwrap(), 200);
        let req = rx.recv().unwrap();
        let text = String::from_utf8_lossy(&req).into_owned();
        assert!(text.starts_with("POST /v1/logs HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Content-Type: application/x-protobuf\r\n"));
        assert!(text.contains("Content-Length: 6\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains("User-Agent: hopf-otel/"));
        assert!(req.ends_with(b"\r\n\r\n\x0a\x00body"));
    }

    #[test]
    fn the_host_header_names_a_non_default_port() {
        let (port, rx) = serve_once("HTTP/1.1 200 OK\r\n\r\n");
        post_protobuf(&endpoint(port), b"x").unwrap();
        let text = String::from_utf8_lossy(&rx.recv().unwrap()).into_owned();
        assert!(text.contains(&format!("Host: 127.0.0.1:{port}\r\n")), "{text}");
    }

    #[test]
    fn any_2xx_is_success() {
        let (port, _rx) = serve_once("HTTP/1.1 202 Accepted\r\n\r\n");
        assert_eq!(post_protobuf(&endpoint(port), b"x").unwrap(), 202);
    }

    #[test]
    fn other_statuses_are_errors_that_quote_the_start_of_the_reply() {
        let (port, _rx) = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\nbusy");
        let err = post_protobuf(&endpoint(port), b"x").unwrap_err();
        assert!(err.contains("503") && err.contains("busy"), "{err}");
        let (port, _rx) = serve_once("HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\n");
        assert!(post_protobuf(&endpoint(port), b"x").unwrap_err().contains("301"));
    }

    #[test]
    fn a_reply_that_is_not_http_is_an_error() {
        let (port, _rx) = serve_once("garbage");
        assert!(post_protobuf(&endpoint(port), b"x").unwrap_err().contains("status 0"));
    }

    #[test]
    fn a_closed_port_is_an_error() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(post_protobuf(&endpoint(port), b"x").is_err());
    }
}
