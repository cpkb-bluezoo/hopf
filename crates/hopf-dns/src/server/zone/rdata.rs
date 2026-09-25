// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Zone file presentation format (RFC 1035 §5, RFC 3597 §5) for RDATA:
//! text to wire when loading, wire to text when persisting.
//!
//! Types with a structured form here: A, AAAA, NS, CNAME, PTR, MX, TXT, SPF,
//! SOA, SRV and HINFO. Every other type is read and written in the RFC 3597
//! generic form `\# <length> <hex>`, so a zone holding (say) pre-signed DNSSEC
//! records still loads, serves and transfers intact.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::parser::Field;
use crate::wire::{decode_name, encode_name};

pub(crate) const TYPE_HINFO: u16 = 13;

const TYPES: &[(&str, u16)] = &[
    ("A", 1),
    ("NS", 2),
    ("CNAME", 5),
    ("SOA", 6),
    ("PTR", 12),
    ("HINFO", 13),
    ("MX", 15),
    ("TXT", 16),
    ("AAAA", 28),
    ("SRV", 33),
    ("DS", 43),
    ("RRSIG", 46),
    ("NSEC", 47),
    ("DNSKEY", 48),
    ("NSEC3", 50),
    ("NSEC3PARAM", 51),
    ("TLSA", 52),
    ("SVCB", 64),
    ("HTTPS", 65),
    ("SPF", 99),
    ("CAA", 257),
];

/// Mnemonic (or `TYPEnnn`) to type number.
pub(crate) fn type_from_mnemonic(s: &str) -> Option<u16> {
    let up = s.to_ascii_uppercase();
    if let Some((_, v)) = TYPES.iter().find(|(n, _)| *n == up) {
        return Some(*v);
    }
    up.strip_prefix("TYPE")?.parse().ok()
}

/// Type number to mnemonic (`TYPEnnn` when unnamed).
pub(crate) fn type_mnemonic(t: u16) -> String {
    match TYPES.iter().find(|(_, v)| *v == t) {
        Some((n, _)) => (*n).to_string(),
        None => format!("TYPE{t}"),
    }
}

/// BIND-style TTL: plain seconds, or units `s m h d w` (`1h30m`).
pub(crate) fn parse_ttl(s: &str) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse().ok();
    }
    let mut total: u64 = 0;
    let mut num: Option<u64> = None;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            num = Some(num.unwrap_or(0).checked_mul(10)?.checked_add(d as u64)?);
        } else {
            let unit = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                _ => return None,
            };
            total = total.checked_add(num.take()?.checked_mul(unit)?)?;
        }
    }
    if let Some(n) = num {
        total = total.checked_add(n)?;
    }
    u32::try_from(total).ok()
}

/// Expand a name token against `origin` (no trailing dot; empty for the
/// root). The result has no trailing dot and keeps its case.
pub(crate) fn expand_name(token: &str, origin: &str) -> Result<String, String> {
    if token.contains('\\') {
        return Err(format!("escapes in domain name {token:?} are not supported"));
    }
    let name = if token == "@" {
        origin.to_string()
    } else if token == "." {
        String::new()
    } else if let Some(abs) = token.strip_suffix('.') {
        abs.to_string()
    } else if origin.is_empty() {
        token.to_string()
    } else {
        format!("{token}.{origin}")
    };
    if name.split('.').any(|l| l.is_empty()) && !name.is_empty() {
        return Err(format!("empty label in {token:?}"));
    }
    Ok(name)
}

fn name_wire(token: &str, origin: &str) -> Result<Vec<u8>, String> {
    encode_name(&expand_name(token, origin)?).map_err(|e| e.to_string())
}

fn num<T: std::str::FromStr>(f: &Field, what: &str) -> Result<T, String> {
    f.text
        .parse()
        .map_err(|_| format!("bad {what}: {:?}", f.text))
}

/// Character-string with `\DDD` and `\X` escapes decoded (RFC 1035 §5.1).
fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        match b.get(i) {
            None => return Err("trailing backslash".into()),
            Some(d) if d.is_ascii_digit() => {
                let digits = b.get(i..i + 3).filter(|d| d.iter().all(u8::is_ascii_digit));
                let v: u32 = std::str::from_utf8(digits.ok_or("bad \\DDD escape")?)
                    .unwrap()
                    .parse()
                    .unwrap();
                out.push(u8::try_from(v).map_err(|_| "\\DDD escape above 255")?);
                i += 3;
            }
            Some(&c) => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn char_string(out: &mut Vec<u8>, f: &Field) -> Result<(), String> {
    let bytes = unescape(&f.text)?;
    if bytes.len() > 255 {
        return Err("character-string longer than 255 octets".into());
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(&bytes);
    Ok(())
}

fn expect(fields: &[Field], n: usize, what: &str) -> Result<(), String> {
    if fields.len() == n {
        Ok(())
    } else {
        Err(format!("{what} takes {n} field(s), found {}", fields.len()))
    }
}

/// Presentation-format RDATA fields to wire RDATA.
pub(crate) fn parse_rdata(rtype: u16, fields: &[Field], origin: &str) -> Result<Vec<u8>, String> {
    // RFC 3597 §5: `\# <length> <hex...>` is valid for every type.
    if fields.first().is_some_and(|f| !f.quoted && f.text == "\\#") {
        let len: usize = fields
            .get(1)
            .ok_or("missing length after \\#")?
            .text
            .parse()
            .map_err(|_| "bad \\# length")?;
        let hex: String = fields[2..].iter().map(|f| f.text.as_str()).collect();
        if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("bad \\# hex data".into());
        }
        let out: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        if out.len() != len {
            return Err(format!("\\# length {len} does not match {} data octets", out.len()));
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    match rtype {
        1 => {
            expect(fields, 1, "A")?;
            let a: Ipv4Addr = num(&fields[0], "IPv4 address")?;
            out.extend_from_slice(&a.octets());
        }
        28 => {
            expect(fields, 1, "AAAA")?;
            let a: Ipv6Addr = num(&fields[0], "IPv6 address")?;
            out.extend_from_slice(&a.octets());
        }
        2 | 5 | 12 => {
            expect(fields, 1, &type_mnemonic(rtype))?;
            out = name_wire(&fields[0].text, origin)?;
        }
        15 => {
            expect(fields, 2, "MX")?;
            out.extend_from_slice(&num::<u16>(&fields[0], "MX preference")?.to_be_bytes());
            out.extend_from_slice(&name_wire(&fields[1].text, origin)?);
        }
        16 | 99 => {
            if fields.is_empty() {
                return Err("TXT needs at least one string".into());
            }
            for f in fields {
                char_string(&mut out, f)?;
            }
        }
        6 => {
            expect(fields, 7, "SOA")?;
            out.extend_from_slice(&name_wire(&fields[0].text, origin)?);
            out.extend_from_slice(&name_wire(&fields[1].text, origin)?);
            out.extend_from_slice(&num::<u32>(&fields[2], "SOA serial")?.to_be_bytes());
            for f in &fields[3..] {
                let v = parse_ttl(&f.text).ok_or_else(|| format!("bad SOA timer {:?}", f.text))?;
                out.extend_from_slice(&v.to_be_bytes());
            }
        }
        33 => {
            expect(fields, 4, "SRV")?;
            for f in &fields[..3] {
                out.extend_from_slice(&num::<u16>(f, "SRV number")?.to_be_bytes());
            }
            out.extend_from_slice(&name_wire(&fields[3].text, origin)?);
        }
        TYPE_HINFO => {
            expect(fields, 2, "HINFO")?;
            char_string(&mut out, &fields[0])?;
            char_string(&mut out, &fields[1])?;
        }
        other => {
            return Err(format!(
                "type {} needs the generic \\# rdata form",
                type_mnemonic(other)
            ))
        }
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn generic(rdata: &[u8]) -> String {
    if rdata.is_empty() {
        "\\# 0".to_string()
    } else {
        format!("\\# {} {}", rdata.len(), hex(rdata))
    }
}

fn abs_name(rdata: &[u8], cursor: &mut usize) -> Option<String> {
    let n = decode_name(rdata, cursor).ok()?;
    Some(format!("{n}."))
}

fn quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in s {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03}")),
        }
    }
    out.push('"');
    out
}

fn char_strings(rdata: &[u8], mut i: usize, max: Option<usize>) -> Option<(Vec<String>, usize)> {
    let mut out = Vec::new();
    while i < rdata.len() && max.is_none_or(|m| out.len() < m) {
        let len = *rdata.get(i)? as usize;
        let s = rdata.get(i + 1..i + 1 + len)?;
        out.push(quote(s));
        i += 1 + len;
    }
    Some((out, i))
}

/// Wire RDATA to presentation format; falls back to the RFC 3597 generic
/// form when the type is not structured here or the RDATA is malformed.
pub(crate) fn format_rdata(rtype: u16, rdata: &[u8]) -> String {
    format_structured(rtype, rdata).unwrap_or_else(|| generic(rdata))
}

fn format_structured(rtype: u16, rdata: &[u8]) -> Option<String> {
    Some(match rtype {
        1 => Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?).to_string(),
        28 => Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?).to_string(),
        2 | 5 | 12 => {
            let mut c = 0;
            let n = abs_name(rdata, &mut c)?;
            (c == rdata.len()).then_some(n)?
        }
        15 => {
            let pref = u16::from_be_bytes(rdata.get(..2)?.try_into().ok()?);
            let mut c = 2;
            let n = abs_name(rdata, &mut c)?;
            (c == rdata.len()).then(|| format!("{pref} {n}"))?
        }
        16 | 99 => {
            let (v, end) = char_strings(rdata, 0, None)?;
            (!v.is_empty() && end == rdata.len()).then(|| v.join(" "))?
        }
        6 => {
            let mut c = 0;
            let m = abs_name(rdata, &mut c)?;
            let r = abs_name(rdata, &mut c)?;
            let t = rdata.get(c..)?;
            if t.len() != 20 {
                return None;
            }
            let f = |i: usize| u32::from_be_bytes(t[i * 4..i * 4 + 4].try_into().unwrap());
            format!("{m} {r} {} {} {} {} {}", f(0), f(1), f(2), f(3), f(4))
        }
        33 => {
            let g = |i: usize| Some(u16::from_be_bytes(rdata.get(i..i + 2)?.try_into().ok()?));
            let mut c = 6;
            let n = abs_name(rdata, &mut c)?;
            (c == rdata.len()).then(|| format!("{} {} {} {n}", g(0).unwrap(), g(2).unwrap(), g(4).unwrap()))?
        }
        TYPE_HINFO => {
            let (v, end) = char_strings(rdata, 0, Some(2))?;
            (v.len() == 2 && end == rdata.len()).then(|| v.join(" "))?
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(t: &str) -> Field {
        Field {
            text: t.into(),
            quoted: false,
        }
    }
    fn q(t: &str) -> Field {
        Field {
            text: t.into(),
            quoted: true,
        }
    }

    /// Text -> wire -> text -> wire is stable for every structured type.
    #[test]
    fn structured_types_round_trip_through_presentation_format() {
        let cases: Vec<(u16, Vec<Field>)> = vec![
            (1, vec![f("192.0.2.1")]),
            (28, vec![f("2001:db8::1")]),
            (2, vec![f("ns1")]),
            (5, vec![f("www.other.org.")]),
            (12, vec![f("@")]),
            (15, vec![f("10"), f("mail")]),
            (16, vec![q("v=spf1 -all"), q("second \"quoted\" \\ one")]),
            (
                6,
                vec![f("ns1"), f("host.master"), f("2024010101"), f("1h"), f("15m"), f("2w"), f("1d")],
            ),
            (33, vec![f("1"), f("2"), f("5060"), f("sip")]),
            (13, vec![q("amd64"), q("linux")]),
        ];
        for (ty, fields) in cases {
            let wire = parse_rdata(ty, &fields, "example.com").unwrap();
            let text = format_rdata(ty, &wire);
            let refields: Vec<Field> = split_presentation(&text);
            let again = parse_rdata(ty, &refields, "example.com").unwrap();
            assert_eq!(wire, again, "type {ty}: {text}");
        }
    }

    /// Minimal presentation splitter for the test (quotes, no escapes of space).
    fn split_presentation(s: &str) -> Vec<Field> {
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b' ' => i += 1,
                b'"' => {
                    let mut j = i + 1;
                    while b[j] != b'"' {
                        j += if b[j] == b'\\' { 2 } else { 1 };
                    }
                    out.push(q(&s[i + 1..j]));
                    i = j + 1;
                }
                _ => {
                    let j = s[i..].find(' ').map_or(s.len(), |n| i + n);
                    out.push(f(&s[i..j]));
                    i = j;
                }
            }
        }
        out
    }

    #[test]
    fn relative_names_are_completed_against_the_origin() {
        let w = parse_rdata(2, &[f("ns1")], "example.com").unwrap();
        assert_eq!(w, encode_name("ns1.example.com").unwrap());
        let w = parse_rdata(2, &[f("@")], "example.com").unwrap();
        assert_eq!(w, encode_name("example.com").unwrap());
        let w = parse_rdata(2, &[f("ns.other.net.")], "example.com").unwrap();
        assert_eq!(w, encode_name("ns.other.net").unwrap());
    }

    #[test]
    fn generic_form_carries_any_type_and_checks_the_length() {
        let w = parse_rdata(46, &[f("\\#"), f("4"), f("de"), f("adbeef")], "x").unwrap();
        assert_eq!(w, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(format_rdata(46, &w), "\\# 4 deadbeef");
        assert!(parse_rdata(46, &[f("\\#"), f("3"), f("deadbeef")], "x").is_err());
        assert!(parse_rdata(46, &[f("abc")], "x").is_err(), "no structured form for RRSIG");
        // A structured type may also use the generic form.
        assert_eq!(parse_rdata(1, &[f("\\#"), f("4"), f("c0000201")], "x").unwrap(), [192, 0, 2, 1]);
    }

    #[test]
    fn ttl_units_and_mnemonics() {
        assert_eq!(parse_ttl("3600"), Some(3600));
        assert_eq!(parse_ttl("1h30m"), Some(5400));
        assert_eq!(parse_ttl("2W"), Some(1_209_600));
        assert_eq!(parse_ttl("1x"), None);
        assert_eq!(parse_ttl("99999999999"), None);
        assert_eq!(type_from_mnemonic("mx"), Some(15));
        assert_eq!(type_from_mnemonic("TYPE65280"), Some(65280));
        assert_eq!(type_mnemonic(9999), "TYPE9999");
    }

    #[test]
    fn bad_rdata_is_rejected() {
        assert!(parse_rdata(1, &[f("1.2.3")], "x").is_err());
        assert!(parse_rdata(15, &[f("ten"), f("m")], "x").is_err());
        assert!(parse_rdata(16, &[q(&"a".repeat(256))], "x").is_err());
        assert!(parse_rdata(2, &[f("a..b")], "x").is_err());
    }
}
