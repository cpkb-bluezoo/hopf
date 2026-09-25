// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Zone file loading: turns [`ZoneParser`] events into a [`Zone`].
//!
//! Supports `$ORIGIN`, `$TTL`, `$INCLUDE` (relative to the including file),
//! `$GENERATE`, `@`, blank owners, TTL and class in either order, BIND TTL
//! units, and the record types listed in [`rdata`](super::rdata).
//!
//! Files are read on the calling thread in fixed-size chunks pushed through
//! the parser, so loading never holds a whole file in memory; call it from a
//! storage worker, not a reactor thread.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::error::ZoneError;
use super::model::{in_record, Zone};
use super::parser::{Field, ZoneEvents, ZoneParser};
use super::rdata::{expand_name, parse_rdata, parse_ttl, type_from_mnemonic};
use crate::wire::{normalize_name, DnsResourceRecord};

const CHUNK: usize = 16 * 1024;
const MAX_INCLUDE_DEPTH: usize = 8;
const MAX_GENERATE: u64 = 65_536;

impl Zone {
    /// Load a BIND-style zone file. `origin` seeds `$ORIGIN` (needed when
    /// the file uses relative names before any `$ORIGIN`); if given it must
    /// match the zone's SOA owner.
    pub fn from_zone_file(path: &Path, origin: Option<&str>) -> Result<Self, ZoneError> {
        let mut b = Builder::new(origin);
        b.base_dir = path.parent().map(Path::to_path_buf);
        b.parse_file(path)?;
        b.finish(origin)
    }

    /// Parse zone file text.
    pub fn from_zone_text(text: &str, origin: Option<&str>) -> Result<Self, ZoneError> {
        let mut b = Builder::new(origin);
        let mut p = ZoneParser::new(&mut b);
        p.push(text.as_bytes())?;
        p.finish()?;
        b.finish(origin)
    }
}

/// Test convenience: parse `text` as the zone `origin`.
#[cfg(test)]
pub(crate) fn parse_zone(origin: &str, text: &str) -> Result<Zone, ZoneError> {
    Zone::from_zone_text(text, Some(origin))
}

struct Builder {
    /// Current `$ORIGIN`: no trailing dot, empty for the root.
    origin: Option<String>,
    default_ttl: Option<u32>,
    last_ttl: Option<u32>,
    last_owner: Option<String>,
    records: Vec<DnsResourceRecord>,
    /// Indexes of `records` that had no TTL of their own or a default.
    needs_ttl: Vec<usize>,
    base_dir: Option<PathBuf>,
    depth: usize,
}

impl Builder {
    fn new(origin: Option<&str>) -> Self {
        Self {
            origin: origin.map(normalize_name),
            default_ttl: None,
            last_ttl: None,
            last_owner: None,
            records: Vec::new(),
            needs_ttl: Vec::new(),
            base_dir: None,
            depth: 0,
        }
    }

    fn parse_file(&mut self, path: &Path) -> Result<(), ZoneError> {
        let mut file = File::open(path)
            .map_err(|e| ZoneError::new(format!("{}: {e}", path.display())))?;
        let mut parser = ZoneParser::new(&mut *self);
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            parser.push(&buf[..n])?;
        }
        parser.finish()
    }

    fn origin_for(&self, line: usize) -> Result<&str, ZoneError> {
        self.origin
            .as_deref()
            .ok_or_else(|| ZoneError::at(line, "relative name before any $ORIGIN"))
    }

    fn owner(&self, line: usize, token: &str) -> Result<String, ZoneError> {
        let name = expand_name(token, self.origin_for(line)?).map_err(|e| ZoneError::at(line, e))?;
        Ok(normalize_name(&name))
    }

    fn finish(mut self, expected_origin: Option<&str>) -> Result<Zone, ZoneError> {
        let soa = self
            .records
            .iter()
            .find(|r| r.raw_type == 6)
            .ok_or_else(|| ZoneError::new("zone file has no SOA record"))?;
        let origin = soa.name.clone();
        if let Some(expected) = expected_origin {
            if normalize_name(expected) != origin {
                return Err(ZoneError::new(format!(
                    "SOA owner {origin:?} does not match zone {expected:?}"
                )));
            }
        }
        let minimum = soa.as_soa().map(|s| s.minimum);
        for &i in &self.needs_ttl {
            self.records[i].ttl = minimum.ok_or_else(|| ZoneError::new("malformed SOA"))?;
        }
        Zone::from_records(&origin, self.default_ttl.or(minimum).unwrap_or(0), self.records)
    }
}

fn is_class(s: &str) -> bool {
    matches!(s.to_ascii_uppercase().as_str(), "IN" | "CH" | "HS" | "CS")
}

impl ZoneEvents for Builder {
    fn origin(&mut self, line: usize, name: &str) -> Result<(), ZoneError> {
        let current = self.origin.as_deref().unwrap_or("");
        if self.origin.is_none() && !name.ends_with('.') && name != "@" {
            return Err(ZoneError::at(line, "$ORIGIN must be an absolute name"));
        }
        let name = expand_name(name, current).map_err(|e| ZoneError::at(line, e))?;
        self.origin = Some(normalize_name(&name));
        Ok(())
    }

    fn default_ttl(&mut self, line: usize, value: &str) -> Result<(), ZoneError> {
        self.default_ttl = Some(
            parse_ttl(value).ok_or_else(|| ZoneError::at(line, format!("bad $TTL {value:?}")))?,
        );
        Ok(())
    }

    fn include(&mut self, line: usize, file: &str, origin: Option<&str>) -> Result<(), ZoneError> {
        if self.depth >= MAX_INCLUDE_DEPTH {
            return Err(ZoneError::at(line, "$INCLUDE nested too deeply"));
        }
        let path = match &self.base_dir {
            Some(dir) if Path::new(file).is_relative() => dir.join(file),
            _ => PathBuf::from(file),
        };
        let saved = (self.origin.clone(), self.last_owner.clone(), self.base_dir.clone());
        if let Some(o) = origin {
            let name = expand_name(o, self.origin_for(line)?).map_err(|e| ZoneError::at(line, e))?;
            self.origin = Some(normalize_name(&name));
        }
        self.base_dir = path.parent().map(Path::to_path_buf);
        self.depth += 1;
        let result = self.parse_file(&path);
        self.depth -= 1;
        (self.origin, self.last_owner, self.base_dir) = saved;
        result.map_err(|mut e| {
            if e.line.is_none() {
                e.line = Some(line);
                e.message = format!("in $INCLUDE {file}: {}", e.message);
            } else {
                e.message = format!("{} (included from line {line})", e.message);
            }
            e
        })
    }

    fn generate(&mut self, line: usize, fields: &[Field]) -> Result<(), ZoneError> {
        let (start, stop, step) = parse_range(&fields[0].text)
            .ok_or_else(|| ZoneError::at(line, format!("bad $GENERATE range {:?}", fields[0].text)))?;
        if (stop.saturating_sub(start)) / step + 1 > MAX_GENERATE {
            return Err(ZoneError::at(line, "$GENERATE range too large"));
        }
        let mut i = start;
        while i <= stop {
            let expanded: Result<Vec<Field>, String> = fields[1..]
                .iter()
                .map(|f| {
                    Ok(Field {
                        text: substitute(&f.text, i)?,
                        quoted: f.quoted,
                    })
                })
                .collect();
            let expanded = expanded.map_err(|e| ZoneError::at(line, e))?;
            self.record(line, false, &expanded)?;
            i += step;
        }
        Ok(())
    }

    fn record(&mut self, line: usize, blank_owner: bool, fields: &[Field]) -> Result<(), ZoneError> {
        let mut i = 0;
        let owner = if blank_owner {
            self.last_owner
                .clone()
                .ok_or_else(|| ZoneError::at(line, "record has no owner and no previous record"))?
        } else {
            i = 1;
            self.owner(line, &fields[0].text)?
        };
        let mut ttl: Option<u32> = None;
        let mut saw_class = false;
        while let Some(f) = fields.get(i).filter(|f| !f.quoted) {
            if !saw_class && is_class(&f.text) {
                if !f.text.eq_ignore_ascii_case("IN") {
                    return Err(ZoneError::at(line, format!("unsupported class {}", f.text)));
                }
                saw_class = true;
            } else if ttl.is_none() && f.text.starts_with(|c: char| c.is_ascii_digit()) {
                ttl = Some(
                    parse_ttl(&f.text)
                        .ok_or_else(|| ZoneError::at(line, format!("bad TTL {:?}", f.text)))?,
                );
            } else {
                break;
            }
            i += 1;
        }
        let type_field = fields
            .get(i)
            .ok_or_else(|| ZoneError::at(line, "record has no type"))?;
        let rtype = type_from_mnemonic(&type_field.text)
            .ok_or_else(|| ZoneError::at(line, format!("unknown record type {:?}", type_field.text)))?;
        let rdata = parse_rdata(rtype, &fields[i + 1..], self.origin_for(line)?)
            .map_err(|e| ZoneError::at(line, e))?;

        let (effective, defaulted) = match ttl.or(self.default_ttl).or(self.last_ttl) {
            Some(t) => (t, false),
            None => (0, true),
        };
        if ttl.is_some() {
            self.last_ttl = ttl;
        }
        if defaulted {
            self.needs_ttl.push(self.records.len());
        }
        self.records.push(in_record(&owner, rtype, effective, rdata));
        self.last_owner = Some(owner);
        Ok(())
    }
}

/// `start-stop` or `start-stop/step`.
fn parse_range(s: &str) -> Option<(u64, u64, u64)> {
    let (range, step) = match s.split_once('/') {
        Some((r, st)) => (r, st.parse().ok().filter(|&n| n > 0)?),
        None => (s, 1),
    };
    let (a, b) = range.split_once('-')?;
    let (a, b): (u64, u64) = (a.parse().ok()?, b.parse().ok()?);
    (a <= b).then_some((a, b, step))
}

/// `$GENERATE` substitution: `$` is the counter, `${offset,width,radix}`
/// formats it, `$$` and `\$` are a literal `$`.
fn substitute(s: &str, i: u64) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'$') => {
                chars.next();
                out.push('$');
            }
            '$' if chars.peek() == Some(&'$') => {
                chars.next();
                out.push('$');
            }
            '$' if chars.peek() == Some(&'{') => {
                chars.next();
                let spec: String = chars.by_ref().take_while(|&c| c != '}').collect();
                let mut parts = spec.split(',');
                let offset: i64 = parts
                    .next()
                    .filter(|p| !p.is_empty())
                    .map_or(Ok(0), str::parse)
                    .map_err(|_| format!("bad $GENERATE offset in ${{{spec}}}"))?;
                let width: usize = parts
                    .next()
                    .map_or(Ok(0), str::parse)
                    .map_err(|_| format!("bad $GENERATE width in ${{{spec}}}"))?;
                let radix = parts.next().unwrap_or("d");
                let v = u64::try_from(i as i64 + offset).map_err(|_| "negative $GENERATE value".to_string())?;
                let digits = match radix {
                    "d" => format!("{v}"),
                    "o" => format!("{v:o}"),
                    "x" => format!("{v:x}"),
                    "X" => format!("{v:X}"),
                    other => return Err(format!("bad $GENERATE radix {other:?}")),
                };
                out.push_str(&format!("{digits:0>width$}"));
            }
            '$' => out.push_str(&i.to_string()),
            c => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const ZONE: &str = "\
$ORIGIN example.com.
$TTL 1h
@   IN SOA ns1 hostmaster (
        2024010101 ; serial
        3h 15m 2w 1h )
    NS  ns1
ns1 A   192.0.2.1
www 300 IN A 192.0.2.2
    AAAA 2001:db8::2 ; blank owner reuses www
mail IN 600 MX 10 mx
txt TXT \"hello world\" \"two\"
";

    #[test]
    fn a_typical_zone_loads_with_defaults_and_blank_owners() {
        let z = parse_zone("example.com", ZONE).unwrap();
        assert_eq!(z.serial(), 2024010101);
        assert_eq!(z.soa().refresh, 3 * 3600);
        assert_eq!(z.soa().expire, 14 * 86400);
        let ns = &z.rrset("example.com", 2)[0];
        assert_eq!(ns.ttl, 3600, "$TTL default");
        assert_eq!(z.rrset("www.example.com", 1)[0].ttl, 300);
        assert_eq!(
            z.rrset("www.example.com", 28).len(),
            1,
            "blank owner attaches AAAA to www"
        );
        assert_eq!(z.rrset("mail.example.com", 15)[0].ttl, 600, "class and TTL in either order");
        assert_eq!(z.rrset("txt.example.com", 16)[0].as_txt().as_deref(), Some("hello worldtwo"));
    }

    #[test]
    fn origin_can_be_taken_from_the_soa_and_relative_names_need_one() {
        let z = Zone::from_zone_text("$ORIGIN Example.ORG.\n@ SOA n h 1 2 3 4 5\n", None).unwrap();
        assert_eq!(z.origin(), "example.org");
        assert!(Zone::from_zone_text("www A 1.2.3.4\n", None).is_err());
        assert!(Zone::from_zone_text("$ORIGIN example.org.\n@ SOA n h 1 2 3 4 5\n", Some("other.org")).is_err());
    }

    #[test]
    fn records_without_any_ttl_take_the_soa_minimum() {
        let z = parse_zone("e.org", "@ SOA n h 1 2 3 4 77\nwww A 1.2.3.4\n").unwrap();
        assert_eq!(z.rrset("www.e.org", 1)[0].ttl, 77);
    }

    #[test]
    fn generate_expands_ranges_steps_and_formats() {
        let z = parse_zone(
            "e.org",
            "$TTL 60\n@ SOA n h 1 2 3 4 5\n$GENERATE 1-3 h$ A 10.0.0.$\n$GENERATE 0-4/2 x${1,3,x} TXT \"v$$\"\n",
        )
        .unwrap();
        assert_eq!(z.rrset("h2.e.org", 1)[0].as_a(), Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(z.rrset("h3.e.org", 1).len(), 1);
        assert_eq!(z.rrset("x001.e.org", 16)[0].as_txt().as_deref(), Some("v$"));
        assert_eq!(z.rrset("x003.e.org", 16).len(), 1);
        assert_eq!(z.rrset("x005.e.org", 16).len(), 1);
        assert!(parse_zone("e.org", "@ SOA n h 1 2 3 4 5\n$GENERATE 1-999999 h$ A 1.1.1.1\n").is_err());
    }

    #[test]
    fn errors_carry_line_numbers() {
        let e = parse_zone("e.org", "@ SOA n h 1 2 3 4 5\n\nwww A not-an-ip\n").unwrap_err();
        assert_eq!(e.line, Some(3));
        assert!(parse_zone("e.org", "@ SOA n h 1 2 3 4 5\nwww FOO x\n").is_err());
        assert!(parse_zone("e.org", "@ SOA n h 1 2 3 4 5\nwww CH A 1.1.1.1\n").is_err());
        assert!(parse_zone("e.org", "www A 1.1.1.1\n").is_err(), "no SOA");
    }

    #[test]
    fn include_reads_relative_files_and_restores_origin() {
        let dir = std::env::temp_dir().join(format!("hopf-zone-inc-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("main.zone"),
            "$ORIGIN example.org.\n$TTL 60\n@ SOA n h 1 2 3 4 5\n$INCLUDE sub/hosts.zone hosts\nafter A 1.1.1.1\n",
        )
        .unwrap();
        std::fs::write(dir.join("sub/hosts.zone"), "a A 2.2.2.2\n$INCLUDE deeper.zone\n").unwrap();
        std::fs::write(dir.join("sub/deeper.zone"), "b A 3.3.3.3\n").unwrap();
        let z = Zone::from_zone_file(&dir.join("main.zone"), Some("example.org")).unwrap();
        assert_eq!(z.rrset("a.hosts.example.org", 1).len(), 1, "include origin applies");
        assert_eq!(z.rrset("b.hosts.example.org", 1).len(), 1, "nested include, path relative to includer");
        assert_eq!(z.rrset("after.example.org", 1).len(), 1, "origin restored afterwards");

        std::fs::write(dir.join("loop.zone"), "$ORIGIN example.org.\n@ SOA n h 1 2 3 4 5\n$INCLUDE loop.zone\n").unwrap();
        let e = Zone::from_zone_file(&dir.join("loop.zone"), None).unwrap_err();
        assert!(e.to_string().contains("deeply"), "{e}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn chunk_boundaries_do_not_change_the_zone() {
        let whole = parse_zone("example.com", ZONE).unwrap().records();
        let mut b = Builder::new(Some("example.com"));
        {
            let mut p = ZoneParser::new(&mut b);
            for c in ZONE.as_bytes().chunks(3) {
                p.push(c).unwrap();
            }
            p.finish().unwrap();
        }
        assert_eq!(b.finish(Some("example.com")).unwrap().records(), whole);
    }
}
