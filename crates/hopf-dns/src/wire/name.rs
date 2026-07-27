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

/// RFC 4034 §6.1 canonical DNS name ordering: labels compared from the
/// rightmost (most significant, e.g. the TLD) down to the leftmost, as
/// raw lowercased octets. A name that is a proper suffix-match prefix of
/// another (fewer labels, otherwise identical from the right) sorts
/// first — which is exactly how `Vec<Vec<u8>>`'s own lexicographic `Ord`
/// already behaves once each name is split into labels and reversed.
pub fn canonical_compare(a: &str, b: &str) -> std::cmp::Ordering {
    canonical_labels(a).cmp(&canonical_labels(b))
}

fn canonical_labels(name: &str) -> Vec<Vec<u8>> {
    let n = normalize_name(name);
    if n.is_empty() {
        return Vec::new();
    }
    let mut labels: Vec<Vec<u8>> = n.split('.').map(|l| l.as_bytes().to_vec()).collect();
    labels.reverse();
    labels
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
    let mut total_len = 0usize;
    decode_name_inner(data, cursor, 0, &mut total_len)
}

/// `total_len` accumulates across the *entire* chain of compression-pointer
/// jumps (RFC 1035 §2.3.4's 255-octet limit applies to the whole decoded
/// name, not to whatever happens to sit in one pointer's target segment) —
/// it must be threaded through every recursive call, not reset per call.
fn decode_name_inner(
    data: &[u8],
    cursor: &mut usize,
    depth: usize,
    total_len: &mut usize,
) -> Result<String, DnsFormatError> {
    if depth > MAX_JUMPS {
        return Err(DnsFormatError::new("too many compression pointers"));
    }
    let mut labels = Vec::new();
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
            let rest = decode_name_inner(data, &mut ptr, depth + 1, total_len)?;
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
        *total_len += 1 + llen;
        if *total_len > MAX_NAME_LENGTH {
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
    use std::cmp::Ordering;

    #[test]
    fn canonical_ordering_sorts_by_rightmost_label_first() {
        // RFC 4034 §6.1: compare from the TLD-most label inward; a proper
        // suffix-prefix (fewer labels, otherwise identical) sorts first.
        let names = [
            "example",
            "a.example",
            "yljkjljk.a.example",
            "z.a.example",
            "z.example",
            "*.z.example",
        ];
        for w in names.windows(2) {
            assert_eq!(
                canonical_compare(w[0], w[1]),
                Ordering::Less,
                "{:?} should sort before {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn canonical_ordering_is_case_insensitive_and_reflexive() {
        assert_eq!(canonical_compare("WWW.Example.com", "www.example.com"), Ordering::Equal);
    }

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

    /// Builds a chain of `segments` pointer-linked labels, each
    /// `label_len` bytes, innermost first (offset 0). Returns the buffer
    /// and the offset of the outermost (last-written) segment, which is
    /// where a decoder would actually start.
    fn chained_labels(segments: usize, label_len: u8) -> (Vec<u8>, usize) {
        let mut buf = Vec::new();
        let mut prev_offset: Option<u16> = None;
        let mut outer_offset = 0usize;
        for i in 0..segments {
            outer_offset = buf.len();
            buf.push(label_len);
            buf.extend(std::iter::repeat(b'a' + (i as u8 % 26)).take(label_len as usize));
            match prev_offset {
                Some(off) => {
                    buf.push(0xC0 | ((off >> 8) as u8));
                    buf.push((off & 0xFF) as u8);
                }
                None => buf.push(0),
            }
            prev_offset = Some(outer_offset as u16);
        }
        (buf, outer_offset)
    }

    /// RFC 1035 §2.3.4: the 255-octet name limit applies to the whole
    /// decoded name, not to whichever single pointer-target segment
    /// happens to be checked — each segment here is only ~64 octets
    /// (comfortably under 255 on its own), but 4 of them chained together
    /// total 256, over the limit, well within the MAX_JUMPS=10 budget that
    /// used to be the only thing bounding this decode.
    #[test]
    fn cumulative_length_across_pointer_jumps_is_enforced() {
        let (buf, start) = chained_labels(4, 63); // 4 * (1 + 63) = 256 octets
        let mut c = start;
        let err = decode_name(&buf, &mut c).unwrap_err();
        assert!(format!("{err}").contains("too long"), "unexpected error: {err}");
    }

    /// The same chained-pointer shape, but under the 255-octet limit,
    /// must still decode successfully — the fix must not be overly strict.
    #[test]
    fn cumulative_length_under_the_limit_still_decodes() {
        let (buf, start) = chained_labels(3, 63); // 3 * (1 + 63) = 192 octets
        let mut c = start;
        let name = decode_name(&buf, &mut c).unwrap();
        assert_eq!(name.split('.').count(), 3);
    }
}
