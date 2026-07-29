// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SPF macro expansion (RFC 7208 §7) — shared by the `a`/`mx`/`ptr`/`include`/
//! `exists`/`redirect`/`exp` domain-spec grammar.

use std::net::IpAddr;

/// Values substitutable for each macro letter. Not every context supplies
/// every value (e.g. `c`/`r`/`t` are meaningful only for `exp=` text).
#[derive(Debug, Clone, Default)]
pub struct MacroContext {
    /// `s` — sender (full `MAIL FROM` address, or `postmaster@<HELO>` if null).
    pub sender: String,
    /// `l` — sender local-part.
    pub local_part: String,
    /// `o` — sender domain part.
    pub sender_domain: String,
    /// `d` — the domain currently being evaluated (changes across recursion).
    pub domain: String,
    /// `i` — SMTP client IP.
    pub ip: Option<IpAddr>,
    /// `p` — validated client domain name (PTR + forward-confirmed), lazily
    /// resolved; `None` until computed, at which point `Some("unknown")` is
    /// substituted if validation failed.
    pub validated_domain: Option<String>,
    /// `h` — HELO/EHLO domain.
    pub helo_domain: String,
    /// `r` — the domain name of the host performing the SPF check (exp only).
    pub receiver: String,
    /// `t` — current UNIX timestamp (exp only).
    pub timestamp: u64,
}

/// Expand a domain-spec / explain-string. `Err` on malformed macro syntax
/// (RFC 7208 PermError).
pub fn expand(spec: &str, ctx: &MacroContext) -> Result<String, ()> {
    let chars: Vec<char> = spec.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= chars.len() {
            return Err(());
        }
        match chars[i] {
            '%' => {
                out.push('%');
                i += 1;
            }
            '_' => {
                out.push(' ');
                i += 1;
            }
            '-' => {
                out.push_str("%20");
                i += 1;
            }
            '{' => {
                i += 1;
                if i >= chars.len() {
                    return Err(());
                }
                let letter = chars[i];
                i += 1;
                let mut digits = String::new();
                while i < chars.len() && chars[i].is_ascii_digit() {
                    digits.push(chars[i]);
                    i += 1;
                }
                let mut reverse = false;
                if i < chars.len() && (chars[i] == 'r' || chars[i] == 'R') {
                    reverse = true;
                    i += 1;
                }
                let mut delims = String::new();
                while i < chars.len() && chars[i] != '}' {
                    let d = chars[i];
                    if !".-+,/_=".contains(d) {
                        return Err(());
                    }
                    delims.push(d);
                    i += 1;
                }
                if i >= chars.len() || chars[i] != '}' {
                    return Err(());
                }
                i += 1;
                let (value, url_escape) = macro_value(letter, ctx)?;
                let n: Option<usize> = if digits.is_empty() {
                    None
                } else {
                    Some(digits.parse().map_err(|_| ())?)
                };
                let transformed = transform(&value, &delims, reverse, n);
                if url_escape {
                    out.push_str(&url_encode(&transformed));
                } else {
                    out.push_str(&transformed);
                }
            }
            _ => return Err(()),
        }
    }
    Ok(out)
}

fn macro_value(letter: char, ctx: &MacroContext) -> Result<(String, bool), ()> {
    let url_escape = letter.is_ascii_uppercase();
    let value = match letter.to_ascii_lowercase() {
        's' => ctx.sender.clone(),
        'l' => ctx.local_part.clone(),
        'o' => ctx.sender_domain.clone(),
        'd' => ctx.domain.clone(),
        'i' => match ctx.ip {
            Some(IpAddr::V4(a)) => a.to_string(),
            Some(IpAddr::V6(a)) => ipv6_nibbles(&a),
            None => return Err(()),
        },
        'p' => ctx
            .validated_domain
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        'v' => match ctx.ip {
            Some(IpAddr::V4(_)) => "in-addr".to_string(),
            Some(IpAddr::V6(_)) => "ip6".to_string(),
            None => return Err(()),
        },
        'h' => ctx.helo_domain.clone(),
        'c' => match ctx.ip {
            Some(ip) => ip.to_string(),
            None => "unknown".to_string(),
        },
        'r' => ctx.receiver.clone(),
        't' => ctx.timestamp.to_string(),
        _ => return Err(()),
    };
    Ok((value, url_escape))
}

/// Dot-separated hex nibbles, most-significant first (RFC 7208 §7.3 `i` for IPv6).
fn ipv6_nibbles(addr: &std::net::Ipv6Addr) -> String {
    let mut parts = Vec::with_capacity(32);
    for byte in addr.octets() {
        parts.push(format!("{:x}", byte >> 4));
        parts.push(format!("{:x}", byte & 0xf));
    }
    parts.join(".")
}

fn transform(value: &str, delims: &str, reverse: bool, keep_last: Option<usize>) -> String {
    let delim_set: Vec<char> = if delims.is_empty() {
        vec!['.']
    } else {
        delims.chars().collect()
    };
    let mut parts: Vec<&str> = value.split(|c| delim_set.contains(&c)).collect();
    if reverse {
        parts.reverse();
    }
    if let Some(n) = keep_last {
        if n < parts.len() {
            parts = parts[parts.len() - n..].to_vec();
        }
    }
    parts.join(".")
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> MacroContext {
        MacroContext {
            sender: "strong-bad@email.example.com".into(),
            local_part: "strong-bad".into(),
            sender_domain: "email.example.com".into(),
            domain: "email.example.com".into(),
            ip: Some("192.0.2.3".parse().unwrap()),
            validated_domain: None,
            helo_domain: "email.example.com".into(),
            receiver: "receiver.example.net".into(),
            timestamp: 1_110_000_000,
        }
    }

    // RFC 7208 §7.4 worked examples.
    #[test]
    fn rfc_examples() {
        let c = ctx();
        assert_eq!(expand("%{s}", &c).unwrap(), "strong-bad@email.example.com");
        assert_eq!(expand("%{o}", &c).unwrap(), "email.example.com");
        assert_eq!(expand("%{d}", &c).unwrap(), "email.example.com");
        assert_eq!(expand("%{d4}", &c).unwrap(), "email.example.com");
        assert_eq!(expand("%{d3}", &c).unwrap(), "email.example.com");
        assert_eq!(expand("%{d2}", &c).unwrap(), "example.com");
        assert_eq!(expand("%{d1}", &c).unwrap(), "com");
        assert_eq!(expand("%{dr}", &c).unwrap(), "com.example.email");
        assert_eq!(expand("%{d2r}", &c).unwrap(), "example.email");
        assert_eq!(expand("%{l}", &c).unwrap(), "strong-bad");
        assert_eq!(expand("%{l-}", &c).unwrap(), "strong.bad");
        assert_eq!(expand("%{lr}", &c).unwrap(), "strong-bad");
        assert_eq!(expand("%{lr-}", &c).unwrap(), "bad.strong");
        assert_eq!(expand("%{l1r-}", &c).unwrap(), "strong");
    }

    #[test]
    fn exists_style_expansion() {
        let c = ctx();
        assert_eq!(
            expand("%{ir}.%{v}._spf.%{d2}", &c).unwrap(),
            "3.2.0.192.in-addr._spf.example.com"
        );
    }

    #[test]
    fn ipv6_nibble_expansion() {
        let mut c = ctx();
        c.ip = Some("2001:db8::cb01".parse().unwrap());
        let out = expand("%{i}", &c).unwrap();
        assert_eq!(
            out,
            "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"
        );
    }

    #[test]
    fn literal_percent_and_space() {
        let c = ctx();
        assert_eq!(expand("%%{d}", &c).unwrap(), "%{d}");
        assert_eq!(expand("%_%_", &c).unwrap(), "  ");
    }

    #[test]
    fn malformed_macro_is_error() {
        let c = ctx();
        assert!(expand("%{", &c).is_err());
        assert!(expand("%{q}", &c).is_err());
        assert!(expand("%", &c).is_err());
    }
}
