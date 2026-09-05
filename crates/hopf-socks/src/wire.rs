// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SOCKS4/4a (no formal RFC; see the historical protocol description) and
//! SOCKS5 (RFC 1928) wire types: version bytes, commands, address types,
//! reply codes, and incremental request/reply codecs.
//!
//! Every parser here follows the same shape: it borrows a byte slice that
//! may be a partial read (a client is never required to write a whole
//! handshake message in one segment) and returns a [`ParseResult`] telling
//! the caller whether to wait for more data, how many bytes were consumed,
//! or that the input is malformed.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// SOCKS4/4a version byte.
pub const VERSION_4: u8 = 0x04;
/// SOCKS5 (RFC 1928) version byte.
pub const VERSION_5: u8 = 0x05;

/// SOCKS5 sub-negotiation version byte (RFC 1929 §2) — distinct from, and
/// coincidentally equal to, the wire byte for other SOCKS5 sub-messages;
/// named separately here so call sites read as "the auth sub-negotiation
/// version," not "SOCKS version 1."
pub const AUTH_VERSION_1: u8 = 0x01;

/// RFC 1928 §4 command codes (also used, for CONNECT/BIND only, by
/// SOCKS4/4a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksCommand {
    /// Relay a TCP stream to a target.
    Connect,
    /// Listen for one inbound connection and relay it.
    Bind,
    /// SOCKS5 only: relay UDP datagrams to/from a target.
    UdpAssociate,
}

impl SocksCommand {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Connect),
            0x02 => Some(Self::Bind),
            0x03 => Some(Self::UdpAssociate),
            _ => None,
        }
    }

}

/// RFC 1928 §5 address type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

/// A SOCKS5 request/reply target address — an IP literal or a domain name
/// left for the caller to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksAddress {
    /// IPv4 or IPv6 literal.
    Ip(IpAddr),
    /// Hostname, to be resolved by whoever handles the request.
    Domain(String),
}

/// RFC 1928 §6 SOCKS5 reply codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Reply {
    /// Request granted.
    Succeeded = 0x00,
    /// General SOCKS server failure.
    GeneralFailure = 0x01,
    /// Connection not allowed by ruleset.
    NotAllowed = 0x02,
    /// Network unreachable.
    NetworkUnreachable = 0x03,
    /// Host unreachable.
    HostUnreachable = 0x04,
    /// Connection refused.
    ConnectionRefused = 0x05,
    /// TTL expired.
    TtlExpired = 0x06,
    /// Command not supported.
    CommandNotSupported = 0x07,
    /// Address type not supported.
    AddressTypeNotSupported = 0x08,
}

/// SOCKS4/4a's single-byte reply status (the historical protocol
/// description's §"Reply", `CD` field on the reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks4Reply {
    /// Request granted.
    Granted = 0x5a,
    /// Request rejected or failed.
    Rejected = 0x5b,
}

impl Socks4Reply {
    /// Coarsen a SOCKS5 reply code down to SOCKS4's single granted/rejected
    /// distinction, for a request that arrived over a SOCKS4/4a handshake.
    pub fn from_socks5(reply: Socks5Reply) -> Self {
        match reply {
            Socks5Reply::Succeeded => Self::Granted,
            _ => Self::Rejected,
        }
    }
}

/// Outcome of trying to parse one wire message from a possibly-partial
/// byte slice.
pub enum ParseResult<T> {
    /// Not enough bytes yet — wait for more and retry.
    Incomplete,
    /// The bytes present are not a valid message and never will be
    /// (malformed field, unsupported value) — close the connection.
    Invalid,
    /// Parsed `T`, having consumed `usize` bytes from the front of the
    /// input.
    Complete(T, usize),
}

/// A parsed SOCKS4/4a request (`VER,CD,DSTPORT(2),DSTIP(4),USERID,NUL`,
/// optionally followed by a hostname + NUL when the "magic IP"
/// `0.0.0.x` (x != 0) SOCKS4a convention is used).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks4Request {
    /// Requested command (CONNECT or BIND; UDP ASSOCIATE has no SOCKS4
    /// equivalent).
    pub command: SocksCommand,
    /// Target port.
    pub port: u16,
    /// Target address — an IPv4 literal, or a hostname when the SOCKS4a
    /// magic-IP convention was used.
    pub address: SocksAddress,
    /// USERID field, as sent (not validated here — see [`crate::auth`]).
    pub user_id: Vec<u8>,
}

/// Parse a SOCKS4/4a request. `data` starts at the version byte (`0x04`,
/// already peeked by the caller to select this parser).
pub fn parse_socks4_request(data: &[u8]) -> ParseResult<Socks4Request> {
    if data.len() < 9 {
        return ParseResult::Incomplete;
    }
    if data[0] != VERSION_4 {
        return ParseResult::Invalid;
    }
    let Some(command) = SocksCommand::from_u8(data[1]) else {
        return ParseResult::Invalid;
    };
    let port = u16::from_be_bytes([data[2], data[3]]);
    let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
    // SOCKS4a: DSTIP = 0.0.0.x, x != 0.
    let is_socks4a = ip.octets()[0] == 0 && ip.octets()[1] == 0 && ip.octets()[2] == 0 && ip.octets()[3] != 0;

    let Some(user_id_end) = data[8..].iter().position(|&b| b == 0) else {
        return ParseResult::Incomplete;
    };
    let user_id = data[8..8 + user_id_end].to_vec();
    let mut consumed = 8 + user_id_end + 1;

    let address = if is_socks4a {
        let rest = &data[consumed..];
        let Some(host_end) = rest.iter().position(|&b| b == 0) else {
            return ParseResult::Incomplete;
        };
        if host_end == 0 {
            return ParseResult::Invalid;
        }
        let Ok(host) = std::str::from_utf8(&rest[..host_end]) else {
            return ParseResult::Invalid;
        };
        let address = SocksAddress::Domain(host.to_string());
        consumed += host_end + 1;
        address
    } else {
        SocksAddress::Ip(IpAddr::V4(ip))
    };

    ParseResult::Complete(
        Socks4Request {
            command,
            port,
            address,
            user_id,
        },
        consumed,
    )
}

/// Encode a SOCKS4/4a reply (`VER=0,CD,DSTPORT(2),DSTIP(4)` — the historical
/// protocol description reserves the version byte position on the reply
/// for `0x00`). `bound` is conventionally zero for CONNECT (no real client
/// relies on it there) but is BIND's actual payload: Reply 1 carries the
/// listener's own bound address, Reply 2 the accepted peer's address.
/// SOCKS4 has no IPv6 concept — an IPv6 `bound` zero-fills DSTIP, which
/// only `bind` module callers can produce and only when a request's own
/// address family makes that impossible in practice (loopback bind chooses
/// its family to match).
pub fn encode_socks4_reply(reply: Socks4Reply, bound: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x00, reply as u8];
    out.extend_from_slice(&bound.port().to_be_bytes());
    match bound.ip() {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => out.extend_from_slice(&[0, 0, 0, 0]),
    }
    out
}

/// A parsed SOCKS5 method-selection greeting (`VER,NMETHODS,METHODS[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Greeting {
    /// Authentication methods the client offered, in the order sent.
    pub methods: Vec<u8>,
}

/// Parse a SOCKS5 greeting. `data` starts at the version byte (`0x05`).
pub fn parse_socks5_greeting(data: &[u8]) -> ParseResult<Socks5Greeting> {
    if data.is_empty() {
        return ParseResult::Incomplete;
    }
    if data[0] != VERSION_5 {
        return ParseResult::Invalid;
    }
    if data.len() < 2 {
        return ParseResult::Incomplete;
    }
    let nmethods = data[1] as usize;
    let total = 2 + nmethods;
    if data.len() < total {
        return ParseResult::Incomplete;
    }
    let methods = data[2..total].to_vec();
    ParseResult::Complete(Socks5Greeting { methods }, total)
}

/// Encode the server's method-selection reply (`VER,METHOD`).
pub fn encode_method_selection(method: u8) -> Vec<u8> {
    vec![VERSION_5, method]
}

/// A parsed RFC 1929 username/password sub-negotiation request
/// (`VER,ULEN,UNAME,PLEN,PASSWD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPasswordRequest {
    /// Username, decoded as UTF-8 (RFC 1929 doesn't mandate a charset;
    /// UTF-8 is the practical universal choice and rejecting invalid UTF-8
    /// outright is simpler than threading raw bytes through the
    /// [`crate::auth::SocksAuthenticator`] trait for no real-world benefit).
    pub username: String,
    /// Password, decoded the same way.
    pub password: String,
}

/// Parse an RFC 1929 §2 username/password request. `data` starts at the
/// sub-negotiation version byte (`0x01`).
pub fn parse_user_password_request(data: &[u8]) -> ParseResult<UserPasswordRequest> {
    if data.is_empty() {
        return ParseResult::Incomplete;
    }
    if data[0] != AUTH_VERSION_1 {
        return ParseResult::Invalid;
    }
    if data.len() < 2 {
        return ParseResult::Incomplete;
    }
    let ulen = data[1] as usize;
    if data.len() < 2 + ulen + 1 {
        return ParseResult::Incomplete;
    }
    let Ok(username) = std::str::from_utf8(&data[2..2 + ulen]) else {
        return ParseResult::Invalid;
    };
    let plen_offset = 2 + ulen;
    let plen = data[plen_offset] as usize;
    let total = plen_offset + 1 + plen;
    if data.len() < total {
        return ParseResult::Incomplete;
    }
    let Ok(password) = std::str::from_utf8(&data[plen_offset + 1..total]) else {
        return ParseResult::Invalid;
    };
    ParseResult::Complete(
        UserPasswordRequest {
            username: username.to_string(),
            password: password.to_string(),
        },
        total,
    )
}

/// Encode the RFC 1929 §2 username/password sub-negotiation reply
/// (`VER,STATUS` — `0x00` success, nonzero failure).
pub fn encode_user_password_reply(success: bool) -> Vec<u8> {
    vec![AUTH_VERSION_1, if success { 0x00 } else { 0x01 }]
}

/// A parsed SOCKS5 request (`VER,CMD,RSV,ATYP,DST.ADDR,DST.PORT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    /// Requested command.
    pub command: SocksCommand,
    /// Target address.
    pub address: SocksAddress,
    /// Target port.
    pub port: u16,
}

/// Parse a SOCKS5 request. `data` starts at the version byte (`0x05`).
/// Returns [`ParseResult::Invalid`] for an unrecognized `CMD` or `ATYP` —
/// the caller can't send a meaningful reply without knowing the request's
/// own framing length, so an unsupported command/address type is treated
/// the same as a malformed message rather than parsed-then-rejected.
pub fn parse_socks5_request(data: &[u8]) -> ParseResult<Socks5Request> {
    if data.len() < 4 {
        return ParseResult::Incomplete;
    }
    if data[0] != VERSION_5 {
        return ParseResult::Invalid;
    }
    let Some(command) = SocksCommand::from_u8(data[1]) else {
        return ParseResult::Invalid;
    };
    // data[2] is RSV, ignored.
    let atyp = data[3];
    let (address, addr_len) = match atyp {
        x if x == AddressType::Ipv4 as u8 => {
            if data.len() < 4 + 4 {
                return ParseResult::Incomplete;
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            (SocksAddress::Ip(IpAddr::V4(ip)), 4)
        }
        x if x == AddressType::Ipv6 as u8 => {
            if data.len() < 4 + 16 {
                return ParseResult::Incomplete;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            (SocksAddress::Ip(IpAddr::V6(Ipv6Addr::from(octets))), 16)
        }
        x if x == AddressType::DomainName as u8 => {
            if data.len() < 5 {
                return ParseResult::Incomplete;
            }
            let len = data[4] as usize;
            if data.len() < 5 + len {
                return ParseResult::Incomplete;
            }
            let Ok(host) = std::str::from_utf8(&data[5..5 + len]) else {
                return ParseResult::Invalid;
            };
            (SocksAddress::Domain(host.to_string()), 1 + len)
        }
        _ => return ParseResult::Invalid,
    };
    let port_offset = 4 + addr_len;
    if data.len() < port_offset + 2 {
        return ParseResult::Incomplete;
    }
    let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
    ParseResult::Complete(
        Socks5Request {
            command,
            address,
            port,
        },
        port_offset + 2,
    )
}

/// Encode a SOCKS5 reply (`VER,REP,RSV,ATYP,BND.ADDR,BND.PORT`).
pub fn encode_socks5_reply(reply: Socks5Reply, bound: std::net::SocketAddr) -> Vec<u8> {
    let mut out = vec![VERSION_5, reply as u8, 0x00];
    match bound.ip() {
        IpAddr::V4(v4) => {
            out.push(AddressType::Ipv4 as u8);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(AddressType::Ipv6 as u8);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn assert_complete<T: std::fmt::Debug + PartialEq>(
        result: ParseResult<T>,
        expected: T,
        expected_consumed: usize,
    ) {
        match result {
            ParseResult::Complete(v, n) => {
                assert_eq!(v, expected);
                assert_eq!(n, expected_consumed);
            }
            ParseResult::Incomplete => panic!("expected Complete, got Incomplete"),
            ParseResult::Invalid => panic!("expected Complete, got Invalid"),
        }
    }

    #[test]
    fn socks4_connect_round_trips() {
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&80u16.to_be_bytes());
        req.extend_from_slice(&[93, 184, 216, 34]);
        req.extend_from_slice(b"userid");
        req.push(0);
        assert_complete(
            parse_socks4_request(&req),
            Socks4Request {
                command: SocksCommand::Connect,
                port: 80,
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                user_id: b"userid".to_vec(),
            },
            req.len(),
        );
    }

    #[test]
    fn socks4a_magic_ip_carries_a_hostname() {
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.extend_from_slice(b"user");
        req.push(0);
        req.extend_from_slice(b"example.com");
        req.push(0);
        assert_complete(
            parse_socks4_request(&req),
            Socks4Request {
                command: SocksCommand::Connect,
                port: 443,
                address: SocksAddress::Domain("example.com".to_string()),
                user_id: b"user".to_vec(),
            },
            req.len(),
        );
    }

    #[test]
    fn socks4_magic_ip_with_zero_last_octet_is_not_socks4a() {
        // 0.0.0.0 does not trigger the SOCKS4a hostname extension (x must
        // be nonzero) — this is a real (if unusual) SOCKS4 IPv4 target.
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&1u16.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 0]);
        req.push(0);
        assert_complete(
            parse_socks4_request(&req),
            Socks4Request {
                command: SocksCommand::Connect,
                port: 1,
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                user_id: vec![],
            },
            req.len(),
        );
    }

    #[test]
    fn socks4_request_incomplete_without_userid_terminator() {
        let req = vec![0x04, 0x01, 0, 80, 93, 184, 216, 34, b'u', b's'];
        assert!(matches!(parse_socks4_request(&req), ParseResult::Incomplete));
    }

    #[test]
    fn socks4_request_too_short_is_incomplete_not_invalid() {
        assert!(matches!(
            parse_socks4_request(&[0x04, 0x01, 0, 80]),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn socks4_wrong_version_is_invalid() {
        let req = vec![0x05, 0x01, 0, 80, 1, 2, 3, 4, 0];
        assert!(matches!(parse_socks4_request(&req), ParseResult::Invalid));
    }

    #[test]
    fn socks4_unknown_command_is_invalid() {
        let req = vec![0x04, 0x09, 0, 80, 1, 2, 3, 4, 0];
        assert!(matches!(parse_socks4_request(&req), ParseResult::Invalid));
    }

    #[test]
    fn socks4_reply_encodes_granted_and_rejected_with_a_zero_bound_address() {
        let zero: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(
            encode_socks4_reply(Socks4Reply::Granted, zero),
            vec![0, 0x5a, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            encode_socks4_reply(Socks4Reply::Rejected, zero),
            vec![0, 0x5b, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn socks4_reply_encodes_a_real_bound_address_for_bind() {
        let addr: SocketAddr = "10.0.0.5:4000".parse().unwrap();
        assert_eq!(
            encode_socks4_reply(Socks4Reply::Granted, addr),
            vec![0, 0x5a, 0x0f, 0xa0, 10, 0, 0, 5]
        );
    }

    #[test]
    fn socks4_reply_zero_fills_dstip_for_an_ipv6_bound_address() {
        let addr: SocketAddr = "[::1]:80".parse().unwrap();
        assert_eq!(
            encode_socks4_reply(Socks4Reply::Granted, addr),
            vec![0, 0x5a, 0, 80, 0, 0, 0, 0]
        );
    }

    #[test]
    fn socks4_reply_from_socks5_coarsens_every_failure_to_rejected() {
        assert_eq!(Socks4Reply::from_socks5(Socks5Reply::Succeeded), Socks4Reply::Granted);
        for failure in [
            Socks5Reply::GeneralFailure,
            Socks5Reply::NotAllowed,
            Socks5Reply::NetworkUnreachable,
            Socks5Reply::HostUnreachable,
            Socks5Reply::ConnectionRefused,
            Socks5Reply::TtlExpired,
            Socks5Reply::CommandNotSupported,
            Socks5Reply::AddressTypeNotSupported,
        ] {
            assert_eq!(Socks4Reply::from_socks5(failure), Socks4Reply::Rejected);
        }
    }

    #[test]
    fn socks5_greeting_round_trips() {
        let mut g = vec![0x05, 2, 0x00, 0x02];
        assert_complete(
            parse_socks5_greeting(&g),
            Socks5Greeting {
                methods: vec![0x00, 0x02],
            },
            4,
        );
        g.push(0xff); // trailing byte from a pipelined next message
        assert_complete(
            parse_socks5_greeting(&g),
            Socks5Greeting {
                methods: vec![0x00, 0x02],
            },
            4,
        );
    }

    #[test]
    fn socks5_greeting_incomplete_waits_for_full_methods_list() {
        assert!(matches!(parse_socks5_greeting(&[0x05]), ParseResult::Incomplete));
        assert!(matches!(parse_socks5_greeting(&[0x05, 3, 0, 1]), ParseResult::Incomplete));
    }

    #[test]
    fn socks5_greeting_wrong_version_is_invalid() {
        assert!(matches!(
            parse_socks5_greeting(&[0x04, 1, 0]),
            ParseResult::Invalid
        ));
    }

    #[test]
    fn method_selection_encodes_two_bytes() {
        assert_eq!(encode_method_selection(0x02), vec![0x05, 0x02]);
    }

    #[test]
    fn user_password_request_round_trips() {
        let mut req = vec![0x01, 4];
        req.extend_from_slice(b"user");
        req.push(8);
        req.extend_from_slice(b"password");
        assert_complete(
            parse_user_password_request(&req),
            UserPasswordRequest {
                username: "user".to_string(),
                password: "password".to_string(),
            },
            req.len(),
        );
    }

    #[test]
    fn user_password_request_incomplete_mid_password() {
        let mut req = vec![0x01, 4];
        req.extend_from_slice(b"user");
        req.push(8);
        req.extend_from_slice(b"pass");
        assert!(matches!(
            parse_user_password_request(&req),
            ParseResult::Incomplete
        ));
    }

    #[test]
    fn user_password_reply_encodes_status_byte() {
        assert_eq!(encode_user_password_reply(true), vec![0x01, 0x00]);
        assert_eq!(encode_user_password_reply(false), vec![0x01, 0x01]);
    }

    #[test]
    fn socks5_request_ipv4_round_trips() {
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[93, 184, 216, 34]);
        req.extend_from_slice(&443u16.to_be_bytes());
        assert_complete(
            parse_socks5_request(&req),
            Socks5Request {
                command: SocksCommand::Connect,
                address: SocksAddress::Ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                port: 443,
            },
            req.len(),
        );
    }

    #[test]
    fn socks5_request_ipv6_round_trips() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&ip.octets());
        req.extend_from_slice(&80u16.to_be_bytes());
        assert_complete(
            parse_socks5_request(&req),
            Socks5Request {
                command: SocksCommand::Connect,
                address: SocksAddress::Ip(IpAddr::V6(ip)),
                port: 80,
            },
            req.len(),
        );
    }

    #[test]
    fn socks5_request_domain_name_round_trips() {
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        assert_complete(
            parse_socks5_request(&req),
            Socks5Request {
                command: SocksCommand::Connect,
                address: SocksAddress::Domain("example.com".to_string()),
                port: 443,
            },
            req.len(),
        );
    }

    #[test]
    fn socks5_request_bind_and_udp_associate_commands_parse() {
        let mut bind = vec![0x05, 0x02, 0x00, 0x01];
        bind.extend_from_slice(&[1, 2, 3, 4]);
        bind.extend_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            parse_socks5_request(&bind),
            ParseResult::Complete(
                Socks5Request {
                    command: SocksCommand::Bind,
                    ..
                },
                _
            )
        ));

        let mut udp = vec![0x05, 0x03, 0x00, 0x01];
        udp.extend_from_slice(&[0, 0, 0, 0]);
        udp.extend_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            parse_socks5_request(&udp),
            ParseResult::Complete(
                Socks5Request {
                    command: SocksCommand::UdpAssociate,
                    ..
                },
                _
            )
        ));
    }

    #[test]
    fn socks5_request_unknown_atyp_is_invalid() {
        let req = vec![0x05, 0x01, 0x00, 0x7f];
        assert!(matches!(parse_socks5_request(&req), ParseResult::Invalid));
    }

    #[test]
    fn socks5_request_domain_name_waits_for_full_length() {
        let req = vec![0x05, 0x01, 0x00, 0x03, 11, b'e', b'x'];
        assert!(matches!(parse_socks5_request(&req), ParseResult::Incomplete));
    }

    #[test]
    fn socks5_request_trailing_bytes_are_not_consumed() {
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&[93, 184, 216, 34]);
        req.extend_from_slice(&443u16.to_be_bytes());
        let expected_len = req.len();
        req.extend_from_slice(b"leftover");
        match parse_socks5_request(&req) {
            ParseResult::Complete(_, n) => assert_eq!(n, expected_len),
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn socks5_reply_encodes_ipv4_and_ipv6_bound_addresses() {
        let v4: SocketAddr = "93.184.216.34:1080".parse().unwrap();
        let encoded = encode_socks5_reply(Socks5Reply::Succeeded, v4);
        assert_eq!(
            encoded,
            vec![0x05, 0x00, 0x00, 0x01, 93, 184, 216, 34, 0x04, 0x38]
        );

        let v6: SocketAddr = "[2001:db8::1]:1080".parse().unwrap();
        let encoded = encode_socks5_reply(Socks5Reply::NotAllowed, v6);
        assert_eq!(encoded[0..3], [0x05, 0x02, 0x00]);
        assert_eq!(encoded[3], 0x04);
        assert_eq!(encoded.len(), 4 + 16 + 2);
    }
}
