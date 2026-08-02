// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAP URL parsing (RFC 4516) for referral chase.

use std::net::{SocketAddr, ToSocketAddrs};

use super::types::{
    LdapError, SearchRequest, SearchScope, DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT,
};

/// Parsed `ldap://` / `ldaps://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapUrl {
    /// Whether the URL scheme is `ldaps`.
    pub ldaps: bool,
    /// Host (required for chase; empty if omitted in the URL).
    pub host: String,
    /// Port (defaults: 389 / 636).
    pub port: u16,
    /// DN from the URL path (may be empty — then the referring operation's DN applies).
    pub dn: String,
    /// Optional attribute list (comma-separated in the URL).
    pub attributes: Vec<String>,
    /// Optional scope override.
    pub scope: Option<SearchScope>,
    /// Optional filter override (percent-decoded).
    pub filter: Option<String>,
}

impl LdapUrl {
    /// Parse an LDAP URL. Supports `ldap://` and `ldaps://`.
    pub fn parse(url: &str) -> Result<Self, LdapError> {
        let url = url.trim();
        let (ldaps, rest) = if let Some(r) = url.strip_prefix("ldaps://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("ldap://") {
            (false, r)
        } else {
            return Err(LdapError::Referral(format!(
                "unsupported referral URL scheme: {url}"
            )));
        };

        // host[:port][/dn[?attrs[?scope[?filter[?ext]]]]]
        let (authority, path_query) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };

        let (host, port) = parse_authority(authority, ldaps)?;
        if host.is_empty() {
            return Err(LdapError::Referral(
                "referral URL has no host".into(),
            ));
        }

        let mut parts = path_query.splitn(5, '?');
        let dn = percent_decode(parts.next().unwrap_or(""));
        let attributes = parts
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| percent_decode(s))
            .collect::<Vec<_>>();
        let scope = match parts.next().unwrap_or("").to_ascii_lowercase().as_str() {
            "" => None,
            "base" => Some(SearchScope::BaseObject),
            "one" => Some(SearchScope::SingleLevel),
            "sub" => Some(SearchScope::WholeSubtree),
            other => {
                return Err(LdapError::Referral(format!(
                    "unknown referral scope: {other}"
                )));
            }
        };
        let filter = {
            let f = parts.next().unwrap_or("");
            if f.is_empty() {
                None
            } else {
                Some(percent_decode(f))
            }
        };

        Ok(Self {
            ldaps,
            host,
            port,
            dn,
            attributes,
            scope,
            filter,
        })
    }

    /// Resolve to a socket address (blocking `ToSocketAddrs`).
    pub fn resolve_addr(&self) -> Result<SocketAddr, LdapError> {
        if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, self.port));
        }
        let query = format!("{}:{}", self.host, self.port);
        ToSocketAddrs::to_socket_addrs(&query)
            .map_err(LdapError::Io)?
            .next()
            .ok_or_else(|| {
                LdapError::Referral(format!(
                    "no addresses resolved for {}:{}",
                    self.host, self.port
                ))
            })
    }

    /// Build a [`SearchRequest`] for chasing, merging with `original`.
    ///
    /// Empty URL DN keeps `original.base_dn` (RFC 4511 §4.1.10).
    pub fn to_search_request(&self, original: &SearchRequest) -> SearchRequest {
        SearchRequest {
            base_dn: if self.dn.is_empty() {
                original.base_dn.clone()
            } else {
                self.dn.clone()
            },
            scope: self.scope.unwrap_or(original.scope),
            filter: self
                .filter
                .clone()
                .unwrap_or_else(|| original.filter.clone()),
            attributes: if self.attributes.is_empty() {
                original.attributes.clone()
            } else {
                self.attributes.clone()
            },
            size_limit: original.size_limit,
            time_limit: original.time_limit,
            types_only: original.types_only,
            deref_aliases: original.deref_aliases,
        }
    }
}

fn parse_authority(authority: &str, ldaps: bool) -> Result<(String, u16), LdapError> {
    if authority.is_empty() {
        return Ok((String::new(), if ldaps { DEFAULT_LDAPS_PORT } else { DEFAULT_LDAP_PORT }));
    }
    // IPv6 in brackets: [addr]:port
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| LdapError::Referral("malformed IPv6 in referral URL".into()))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse().map_err(|_| {
                LdapError::Referral(format!("bad port in referral URL: {p}"))
            })?
        } else if after.is_empty() {
            if ldaps {
                DEFAULT_LDAPS_PORT
            } else {
                DEFAULT_LDAP_PORT
            }
        } else {
            return Err(LdapError::Referral(
                "malformed host in referral URL".into(),
            ));
        };
        return Ok((host, port));
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        // Avoid treating bare IPv6 without brackets as host:port.
        if !h.contains(':') {
            let port = p.parse().map_err(|_| {
                LdapError::Referral(format!("bad port in referral URL: {p}"))
            })?;
            return Ok((h.to_string(), port));
        }
    }
    Ok((
        authority.to_string(),
        if ldaps {
            DEFAULT_LDAPS_PORT
        } else {
            DEFAULT_LDAP_PORT
        },
    ))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let u = LdapUrl::parse("ldap://ldap.example.com:1389/dc=example,dc=com").unwrap();
        assert!(!u.ldaps);
        assert_eq!(u.host, "ldap.example.com");
        assert_eq!(u.port, 1389);
        assert_eq!(u.dn, "dc=example,dc=com");
    }

    #[test]
    fn parse_with_filter_and_scope() {
        let u = LdapUrl::parse(
            "ldap://host/ou=People,dc=example,dc=com?uid?sub?(uid=alice)",
        )
        .unwrap();
        assert_eq!(u.scope, Some(SearchScope::WholeSubtree));
        assert_eq!(u.attributes, vec!["uid".to_string()]);
        assert_eq!(u.filter.as_deref(), Some("(uid=alice)"));
    }

    #[test]
    fn parse_ldaps_default_port() {
        let u = LdapUrl::parse("ldaps://secure.example.com/").unwrap();
        assert!(u.ldaps);
        assert_eq!(u.port, DEFAULT_LDAPS_PORT);
        assert!(u.dn.is_empty());
    }

    #[test]
    fn to_search_keeps_original_dn_when_url_dn_empty() {
        let u = LdapUrl::parse("ldap://other.example.com").unwrap();
        let orig = SearchRequest::new("dc=example,dc=com", "(uid=alice)");
        let req = u.to_search_request(&orig);
        assert_eq!(req.base_dn, "dc=example,dc=com");
        assert_eq!(req.filter, "(uid=alice)");
    }

    #[test]
    fn percent_decode_dn() {
        let u = LdapUrl::parse("ldap://h/cn=Alice%20Smith,dc=ex").unwrap();
        assert_eq!(u.dn, "cn=Alice Smith,dc=ex");
    }
}
