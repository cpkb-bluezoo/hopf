// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

use std::collections::HashMap;

use super::error::DnsFormatError;

const COMPRESSION_MASK: u8 = 0xC0;
const COMPRESSION_POINTER: u8 = 0xC0;
const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;
const MAX_JUMPS: usize = 10;

/// Lowercase, strip trailing dot (RFC 1035 §2.3.3 case-insensitive compare).
pub fn normalize_name(name: &str) -> String {
    let mut n = name.to_ascii_lowercase();
    if n.ends_with('.') {
        n.pop();
    }
    n
}

/// Encode a domain name without compression (for RDATA domain names).
pub fn encode_name(name: &str) -> Result<Vec<u8>, DnsFormatError> {
    if name.is_empty() || name == "." {
        return Ok(vec![0]);
    }
    let mut name = name;
    if let Some(stripped) = name.strip_suffix('.') {
        name = stripped;
    }
    let mut out = Vec::new();
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.len() > MAX_LABEL_LENGTH {
            return Err(DnsFormatError::new(format!("label too long: {label}")));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    if out.len() > MAX_NAME_LENGTH {
        return Err(DnsFormatError::new(format!("name too long: {name}")));
    }
    Ok(out)
}

/// Decode a domain name; advances `cursor` in `data`.
pub fn decode_name(data: &[u8], cursor: &mut usize) -> Result<String, DnsFormatError> {
    decode_name_inner(data, cursor, 0)
}

fn decode_name_inner(data: &[u8], cursor: &mut usize, depth: usize) -> Result<String, DnsFormatError> {
    if depth > MAX_JUMPS {
        return Err(DnsFormatError::new("too many compression pointers"));
    }
    let mut labels = Vec::new();
    let mut total_len = 0usize;
    loop {
        if *cursor >= data.len() {
            return Err(DnsFormatError::new("truncated name"));
        }
        let len = data[*cursor];
        *cursor += 1;
        if len == 0 {
            break;
        }
        if (len & COMPRESSION_MASK) == COMPRESSION_POINTER {
            if *cursor >= data.len() {
                return Err(DnsFormatError::new("truncated compression pointer"));
            }
            let offset = (((len & 0x3F) as usize) << 8) | (data[*cursor] as usize);
            *cursor += 1;
            let mut ptr = offset;
            let rest = decode_name_inner(data, &mut ptr, depth + 1)?;
            if !labels.is_empty() {
                labels.push(b'.');
            }
            labels.extend_from_slice(rest.as_bytes());
            break;
        }
        let llen = len as usize;
        if *cursor + llen > data.len() {
            return Err(DnsFormatError::new("truncated label"));
        }
        total_len += 1 + llen;
        if total_len > MAX_NAME_LENGTH {
            return Err(DnsFormatError::new("name too long decode"));
        }
        if !labels.is_empty() {
            labels.push(b'.');
        }
        labels.extend_from_slice(&data[*cursor..*cursor + llen]);
        *cursor += llen;
    }
    Ok(String::from_utf8_lossy(&labels).into_owned())
}

/// Write a name with optional RFC 1035 compression table.
pub fn write_name_compressed(
    out: &mut Vec<u8>,
    name: &str,
    table: &mut HashMap<String, u16>,
) -> Result<(), DnsFormatError> {
    if name.is_empty() || name == "." {
        out.push(0);
        return Ok(());
    }
    let mut name = name.to_string();
    if name.ends_with('.') {
        name.pop();
    }
    let lower = name.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    for i in 0..labels.len() {
        let suffix = labels[i..].join(".");
        if let Some(&off) = table.get(&suffix) {
            let ptr = 0xC000u16 | off;
            out.push(((ptr >> 8) & 0xFF) as u8);
            out.push((ptr & 0xFF) as u8);
            return Ok(());
        }
        if out.len() < 0x3FFF {
            table.insert(suffix, out.len() as u16);
        }
        let label = labels[i].as_bytes();
        if label.len() > MAX_LABEL_LENGTH {
            return Err(DnsFormatError::new("label too long"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple() {
        let enc = encode_name("www.example.com").unwrap();
        let mut c = 0;
        let dec = decode_name(&enc, &mut c).unwrap();
        assert_eq!(dec, "www.example.com");
        assert_eq!(c, enc.len());
    }

    #[test]
    fn compression_pointer() {
        // "example.com" then pointer back to "example.com"
        let mut buf = encode_name("example.com").unwrap();
        let off = 0u16; // start of message name
        buf.push(0xC0);
        buf.push(off as u8);
        let mut c = 0;
        assert_eq!(decode_name(&buf, &mut c).unwrap(), "example.com");
        assert_eq!(decode_name(&buf, &mut c).unwrap(), "example.com");
    }
}
