// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Postfix XCLIENT attribute parsing (xtext + NAME/ADDR/…).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Decoded XCLIENT attribute overrides applied to a session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XclientOverrides {
    /// Client reverse hostname (`NAME`).
    pub name: Option<Option<String>>,
    /// Effective client address (`ADDR`); `None` inner clears.
    pub addr: Option<Option<IpAddr>>,
    /// Effective client port (`PORT`).
    pub port: Option<Option<u16>>,
    /// `SMTP` / `ESMTP` (`PROTO`).
    pub proto: Option<Option<String>>,
    /// HELO/EHLO name (`HELO`).
    pub helo: Option<Option<String>>,
    /// Informational proxied login (`LOGIN`) — not SASL AUTH.
    pub login: Option<Option<String>>,
    /// Effective local address (`DESTADDR`).
    pub dest_addr: Option<Option<IpAddr>>,
    /// Effective local port (`DESTPORT`).
    pub dest_port: Option<Option<u16>>,
}

/// Parse error for an XCLIENT command argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XclientParseError(pub String);

impl XclientParseError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Decode RFC 1891 xtext (`+HH` escapes). Tolerates unencoded values
/// (Postfix < 2.3 interop).
pub fn decode_xtext(value: &str) -> String {
    if !value.contains('+') {
        return value.to_string();
    }
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(char::from(((h1 << 4) | h2) as u8));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn unavailable(value: &str) -> bool {
    value.eq_ignore_ascii_case("[UNAVAILABLE]") || value.eq_ignore_ascii_case("[TEMPUNAVAIL]")
}

fn parse_ip(value: &str) -> Result<IpAddr, XclientParseError> {
    let s = value
        .strip_prefix("IPV6:")
        .or_else(|| value.strip_prefix("ipv6:"))
        .or_else(|| value.strip_prefix("Ipv6:"))
        .unwrap_or(value);
    s.parse()
        .map_err(|_| XclientParseError::new(format!("Invalid address value: {value}")))
}

/// Parse `attr=value` tokens from an XCLIENT argument string.
pub fn parse_xclient_args(args: &str) -> Result<XclientOverrides, XclientParseError> {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return Err(XclientParseError::new(
            "Syntax: XCLIENT attribute=value [...]",
        ));
    }
    let mut out = XclientOverrides::default();
    for pair in trimmed.split_whitespace() {
        let Some((attr, raw_value)) = pair.split_once('=') else {
            return Err(XclientParseError::new(format!(
                "Invalid XCLIENT attribute syntax: {pair}"
            )));
        };
        if attr.is_empty() {
            return Err(XclientParseError::new(format!(
                "Invalid XCLIENT attribute syntax: {pair}"
            )));
        }
        let attr_u = attr.to_ascii_uppercase();
        let decoded = decode_xtext(raw_value);
        let value = if unavailable(&decoded) {
            None
        } else {
            Some(decoded)
        };
        match attr_u.as_str() {
            "NAME" => out.name = Some(value),
            "ADDR" => {
                out.addr = Some(match value {
                    Some(v) => Some(parse_ip(&v)?),
                    None => None,
                });
            }
            "PORT" => {
                out.port = Some(match value {
                    Some(v) => {
                        let p: u16 = v.parse().map_err(|_| {
                            XclientParseError::new(format!("Invalid PORT value: {v}"))
                        })?;
                        Some(p)
                    }
                    None => None,
                });
            }
            "PROTO" => {
                if let Some(ref v) = value {
                    if !v.eq_ignore_ascii_case("SMTP") && !v.eq_ignore_ascii_case("ESMTP") {
                        return Err(XclientParseError::new(format!("Invalid PROTO value: {v}")));
                    }
                }
                out.proto = Some(value);
            }
            "HELO" => out.helo = Some(value),
            "LOGIN" => out.login = Some(value),
            "DESTADDR" => {
                out.dest_addr = Some(match value {
                    Some(v) => Some(parse_ip(&v)?),
                    None => None,
                });
            }
            "DESTPORT" => {
                out.dest_port = Some(match value {
                    Some(v) => {
                        let p: u16 = v.parse().map_err(|_| {
                            XclientParseError::new(format!("Invalid DESTPORT value: {v}"))
                        })?;
                        Some(p)
                    }
                    None => None,
                });
            }
            _ => {
                return Err(XclientParseError::new(format!(
                    "Unknown XCLIENT attribute: {attr}"
                )));
            }
        }
    }
    Ok(out)
}

/// Apply overrides onto effective peer/local addresses (Gumdrop-compatible).
pub fn apply_addr_overrides(
    peer: SocketAddr,
    local: SocketAddr,
    o: &XclientOverrides,
) -> (SocketAddr, SocketAddr) {
    let mut peer_ip = peer.ip();
    let mut peer_port = peer.port();
    let mut local_ip = local.ip();
    let mut local_port = local.port();

    if let Some(addr) = &o.addr {
        match addr {
            Some(ip) => peer_ip = *ip,
            None => peer_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
    if let Some(port) = &o.port {
        match port {
            Some(p) => peer_port = *p,
            None => peer_port = 0,
        }
        if o.addr.is_none() && matches!(peer_ip, IpAddr::V4(a) if a.is_unspecified()) {
            // PORT alone: Gumdrop seeds ADDR with loopback.
            peer_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        }
    }
    if let Some(addr) = &o.dest_addr {
        match addr {
            Some(ip) => local_ip = *ip,
            None => local_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }
    if let Some(port) = &o.dest_port {
        match port {
            Some(p) => local_port = *p,
            None => local_port = 25,
        }
        if o.dest_addr.is_none() && matches!(local_ip, IpAddr::V4(a) if a.is_unspecified()) {
            local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        }
    }

    (
        SocketAddr::new(peer_ip, peer_port),
        SocketAddr::new(local_ip, local_port),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn decode_xtext_plus_escapes() {
        assert_eq!(decode_xtext("a+40b"), "a@b");
        assert_eq!(decode_xtext("plain"), "plain");
    }

    #[test]
    fn parses_name_addr_helo() {
        let o = parse_xclient_args(
            "NAME=spike.example ADDR=168.100.189.2 HELO=spike.example PROTO=ESMTP",
        )
        .unwrap();
        assert_eq!(o.name, Some(Some("spike.example".into())));
        assert_eq!(
            o.addr,
            Some(Some(IpAddr::V4(Ipv4Addr::new(168, 100, 189, 2))))
        );
        assert_eq!(o.helo, Some(Some("spike.example".into())));
        assert_eq!(o.proto, Some(Some("ESMTP".into())));
    }

    #[test]
    fn parses_ipv6_addr_prefix() {
        let o = parse_xclient_args("ADDR=IPV6:2001:db8::1").unwrap();
        assert_eq!(
            o.addr,
            Some(Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))))
        );
    }

    #[test]
    fn unavailable_clears() {
        let o = parse_xclient_args("NAME=[UNAVAILABLE] LOGIN=[TEMPUNAVAIL]").unwrap();
        assert_eq!(o.name, Some(None));
        assert_eq!(o.login, Some(None));
    }

    #[test]
    fn rejects_unknown_attr() {
        assert!(parse_xclient_args("FOO=bar").is_err());
    }

    #[test]
    fn apply_overrides_peer() {
        let peer = "10.0.0.1:1234".parse().unwrap();
        let local = "10.0.0.2:25".parse().unwrap();
        let o = parse_xclient_args("ADDR=192.0.2.1 PORT=2525").unwrap();
        let (p, l) = apply_addr_overrides(peer, local, &o);
        assert_eq!(p, "192.0.2.1:2525".parse().unwrap());
        assert_eq!(l, local);
    }
}
