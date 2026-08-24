// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Shared request pseudo-header validation — RFC 9113 §8.3.1 (HTTP/2) and
//! RFC 9114 §4.3.1 (HTTP/3) require the same presence/ordering/uniqueness
//! rules, including RFC 8441 / RFC 9220 Extended CONNECT's `:protocol`.
//! Protocol-specific rules (H2's connection-specific-header/TE rejection)
//! stay with their own transport.

use std::collections::HashSet;

/// Pseudo-headers a server recognizes on inbound requests, including
/// `:protocol` for Extended CONNECT.
const KNOWN_REQUEST_PSEUDO_HEADERS: &[&str] =
    &[":method", ":scheme", ":authority", ":path", ":protocol"];

/// Validate a decoded request header list's pseudo-headers: presence,
/// ordering (must precede regular fields), uniqueness, and the CONNECT /
/// Extended CONNECT pseudo-header set. `Err(())` means the request is
/// malformed and must be rejected with a stream error.
pub(crate) fn validate_request_pseudo_headers(pairs: &[(String, String)]) -> Result<(), ()> {
    let mut seen_pseudo: HashSet<&str> = HashSet::new();
    let mut seen_regular = false;
    let mut method: Option<&str> = None;

    for (name, value) in pairs {
        if let Some(pseudo) = name.strip_prefix(':') {
            if seen_regular {
                return Err(()); // pseudo-header after a regular header
            }
            if !KNOWN_REQUEST_PSEUDO_HEADERS.contains(&name.as_str()) {
                return Err(()); // unknown pseudo-header
            }
            if !seen_pseudo.insert(name.as_str()) {
                return Err(()); // duplicated pseudo-header
            }
            if pseudo == "method" {
                method = Some(value.as_str());
            }
        } else {
            seen_regular = true;
        }
    }

    let is_connect = method.is_some_and(|m| m.eq_ignore_ascii_case("CONNECT"));
    let is_extended_connect = is_connect && seen_pseudo.contains(":protocol");

    if is_connect && !is_extended_connect {
        // Plain CONNECT: only :method and :authority, no :scheme/:path.
        if !seen_pseudo.contains(":method") || !seen_pseudo.contains(":authority") {
            return Err(());
        }
        if seen_pseudo.contains(":scheme") || seen_pseudo.contains(":path") {
            return Err(());
        }
    } else {
        // Regular requests and Extended CONNECT both require :method,
        // :scheme, :path.
        for required in [":method", ":scheme", ":path"] {
            if !seen_pseudo.contains(required) {
                return Err(());
            }
        }
    }

    // RFC 9114 §4.3.1: pseudo-header values and routing targets must be valid.
    for (name, value) in pairs {
        match name.as_str() {
            ":path" if !(is_connect && !is_extended_connect) => {
                if !crate::utils::is_valid_request_target(value) {
                    return Err(());
                }
            }
            ":authority" => {
                if !crate::utils::is_valid_host(value) {
                    return Err(());
                }
            }
            _ => {}
        }
    }

    if is_connect && !is_extended_connect {
        return Ok(());
    }

    // RFC 9114 §4.3.1: routing requires :authority or Host.
    let has_authority = pairs.iter().any(|(n, _)| n == ":authority");
    if !has_authority {
        let Some(host) = pairs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())
        else {
            return Err(());
        };
        if !crate::utils::is_valid_host(host) {
            return Err(());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    #[test]
    fn valid_request_accepted() {
        let p = pairs(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":authority", "x")]);
        assert!(validate_request_pseudo_headers(&p).is_ok());
    }

    #[test]
    fn missing_pseudo_header_rejected() {
        let p = pairs(&[(":method", "GET"), (":scheme", "https")]);
        assert!(validate_request_pseudo_headers(&p).is_err());
    }

    #[test]
    fn duplicate_pseudo_header_rejected() {
        let p = pairs(&[(":method", "GET"), (":method", "POST"), (":scheme", "https"), (":path", "/")]);
        assert!(validate_request_pseudo_headers(&p).is_err());
    }

    #[test]
    fn pseudo_header_after_regular_rejected() {
        let p = pairs(&[(":method", "GET"), ("x-a", "b"), (":scheme", "https"), (":path", "/")]);
        assert!(validate_request_pseudo_headers(&p).is_err());
    }

    #[test]
    fn unknown_pseudo_header_rejected() {
        let p = pairs(&[(":method", "GET"), (":scheme", "https"), (":path", "/"), (":bogus", "x")]);
        assert!(validate_request_pseudo_headers(&p).is_err());
    }

    #[test]
    fn extended_connect_accepted() {
        let p = pairs(&[
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", "https"),
            (":path", "/chat"),
            (":authority", "x"),
        ]);
        assert!(validate_request_pseudo_headers(&p).is_ok());
    }

    #[test]
    fn plain_connect_accepted_forbids_scheme_path() {
        let p = pairs(&[(":method", "CONNECT"), (":authority", "x:443")]);
        assert!(validate_request_pseudo_headers(&p).is_ok());

        let p2 = pairs(&[(":method", "CONNECT"), (":authority", "x:443"), (":scheme", "https")]);
        assert!(validate_request_pseudo_headers(&p2).is_err());
    }

    #[test]
    fn empty_path_rejected() {
        let p = pairs(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", ""),
            (":authority", "x"),
        ]);
        assert!(validate_request_pseudo_headers(&p).is_err());
    }

    #[test]
    fn missing_authority_and_host_rejected() {
        let p = pairs(&[(":method", "GET"), (":scheme", "https"), (":path", "/")]);
        assert!(validate_request_pseudo_headers(&p).is_err());
    }

    #[test]
    fn host_without_authority_accepted() {
        let p = pairs(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/"),
            ("host", "example.com"),
        ]);
        assert!(validate_request_pseudo_headers(&p).is_ok());
    }
}
