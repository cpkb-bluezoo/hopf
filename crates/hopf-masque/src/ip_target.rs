// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! CONNECT-IP target parsing (RFC 9484 §3).
//!
//! Unlike CONNECT-UDP's always-concrete target, RFC 9484 §3's URI template
//! `/.well-known/masque/ip/{target}/{ipproto}/` makes **both** segments
//! optional-with-wildcard (a literal `*`): the common IP-proxying case is
//! an unscoped tunnel, not one pinned target. `target` may be a hostname,
//! an IPv4/IPv6 address, or an address+prefix (`%2F`-escaped slash before
//! the prefix length, RFC 9484 §3's own example) — this module only
//! extracts the segment text; which of those shapes it is, and whether to
//! allow it, is [`crate::ip_policy::ConnectIpPolicy`]'s job.

/// A CONNECT-IP request's decoded `target` segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpTarget {
    /// `*` — any allowable host (RFC 9484 §3).
    Wildcard,
    /// A concrete, percent-decoded hostname, IP address, or IP prefix
    /// (e.g. `target.example`, `2001:db8::1`, or `192.0.2.0/24`).
    Named(String),
}

/// A CONNECT-IP request's decoded `ipproto` segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProto {
    /// `*` — any IP protocol (RFC 9484 §3).
    Wildcard,
    /// A concrete IANA Internet Protocol Number (0-255).
    Number(u8),
}

/// A CONNECT-IP request's fully decoded target scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectIpTarget {
    /// The requested target scope.
    pub target: IpTarget,
    /// The requested IP protocol scope.
    pub ipproto: IpProto,
}

const PREFIX: &str = "/.well-known/masque/ip/";

/// Parse a `:path` against the RFC 9484 §3 URI template
/// `/.well-known/masque/ip/{target}/{ipproto}/`.
///
/// Both segments must be present (though either may be the literal
/// wildcard `*`) and validly percent-encoded — a partial or best-effort
/// decode would be worse than an outright rejection (`None`).
pub fn parse(path: &str) -> Option<ConnectIpTarget> {
    let rest = path.strip_prefix(PREFIX)?;
    let rest = rest.strip_suffix('/')?;
    let (target_enc, ipproto_enc) = rest.split_once('/')?;
    if target_enc.is_empty() || ipproto_enc.is_empty() {
        return None;
    }
    let target = if target_enc == "*" {
        IpTarget::Wildcard
    } else {
        let decoded = crate::percent::decode(target_enc)?;
        if decoded.is_empty() {
            return None;
        }
        IpTarget::Named(decoded)
    };
    let ipproto = if ipproto_enc == "*" {
        IpProto::Wildcard
    } else {
        let decoded = crate::percent::decode(ipproto_enc)?;
        IpProto::Number(decoded.parse().ok()?)
    };
    Some(ConnectIpTarget { target, ipproto })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_fully_wildcarded_request() {
        let t = parse("/.well-known/masque/ip/*/*/").unwrap();
        assert_eq!(t.target, IpTarget::Wildcard);
        assert_eq!(t.ipproto, IpProto::Wildcard);
    }

    #[test]
    fn parses_a_plain_hostname_with_a_concrete_protocol() {
        let t = parse("/.well-known/masque/ip/target.example/17/").unwrap();
        assert_eq!(t.target, IpTarget::Named("target.example".to_string()));
        assert_eq!(t.ipproto, IpProto::Number(17));
    }

    #[test]
    fn parses_an_ipv4_prefix() {
        let t = parse("/.well-known/masque/ip/192.0.2.0%2F24/*/").unwrap();
        assert_eq!(t.target, IpTarget::Named("192.0.2.0/24".to_string()));
    }

    #[test]
    fn parses_an_ipv6_prefix() {
        let t = parse("/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/*/").unwrap();
        assert_eq!(t.target, IpTarget::Named("2001:db8::/32".to_string()));
    }

    #[test]
    fn rejects_missing_trailing_slash() {
        assert!(parse("/.well-known/masque/ip/*/*").is_none());
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert!(parse("/.well-known/masque/udp/*/*/").is_none());
    }

    #[test]
    fn rejects_empty_target_segment() {
        assert!(parse("/.well-known/masque/ip//*/").is_none());
    }

    #[test]
    fn rejects_empty_ipproto_segment() {
        assert!(parse("/.well-known/masque/ip/*//").is_none());
    }

    #[test]
    fn rejects_non_numeric_ipproto() {
        assert!(parse("/.well-known/masque/ip/*/udp/").is_none());
    }

    #[test]
    fn rejects_ipproto_out_of_u8_range() {
        assert!(parse("/.well-known/masque/ip/*/256/").is_none());
    }

    #[test]
    fn rejects_truncated_percent_escape() {
        assert!(parse("/.well-known/masque/ip/target.example%2/*/").is_none());
    }
}
