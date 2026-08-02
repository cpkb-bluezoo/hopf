// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 4515 search filter string → BER encoding (Gumdrop `encodeFilter` port).

use crate::asn1::BerEncoder;

/// Encode an RFC 4515 filter string into `encoder` (context-tagged Filter CHOICE).
pub fn encode_filter(encoder: &mut BerEncoder, filter: &str) {
    let mut filter = filter.trim();
    if filter.starts_with('(') && filter.ends_with(')') && filter.len() >= 2 {
        filter = &filter[1..filter.len() - 1];
    }

    if filter.starts_with('&') {
        encoder.begin_context(0, true);
        encode_filter_list(encoder, &filter[1..]);
        encoder.end_context();
    } else if filter.starts_with('|') {
        encoder.begin_context(1, true);
        encode_filter_list(encoder, &filter[1..]);
        encoder.end_context();
    } else if filter.starts_with('!') {
        encoder.begin_context(2, true);
        encode_filter(encoder, filter[1..].trim());
        encoder.end_context();
    } else if filter.contains("=*") && filter.ends_with("=*") && !filter.contains("*=") {
        // Presence: (attr=*)
        let attr = &filter[..filter.len() - 2];
        encoder.write_context(7, attr.as_bytes());
    } else if let Some(idx) = filter.find("~=") {
        encoder.begin_context(8, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string_str(&filter[idx + 2..]);
        encoder.end_context();
    } else if filter.contains(":=") {
        encode_extensible_match(encoder, filter);
    } else if let Some(idx) = filter.find(">=") {
        encoder.begin_context(5, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string_str(&filter[idx + 2..]);
        encoder.end_context();
    } else if let Some(idx) = filter.find("<=") {
        encoder.begin_context(6, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string_str(&filter[idx + 2..]);
        encoder.end_context();
    } else if filter.contains('=') && filter.contains('*') {
        if let Some(idx) = filter.find('=') {
            encode_substring(encoder, &filter[..idx], &filter[idx + 1..]);
        }
    } else if let Some(idx) = filter.find('=') {
        encoder.begin_context(3, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string_str(&filter[idx + 1..]);
        encoder.end_context();
    } else {
        encoder.write_context(7, b"objectClass");
    }
}

fn encode_filter_list(encoder: &mut BerEncoder, filter_list: &str) {
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, c) in filter_list.char_indices() {
        match c {
            '(' => {
                if depth == 0 {
                    start = i;
                }
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    encode_filter(encoder, &filter_list[start..=i]);
                }
            }
            _ => {}
        }
    }
}

fn encode_substring(encoder: &mut BerEncoder, attr: &str, value: &str) {
    encoder.begin_context(4, true);
    encoder.write_octet_string_str(attr);
    encoder.begin_sequence();

    let part_count = value.bytes().filter(|&b| b == b'*').count() + 1;
    let mut start = 0usize;
    let mut part_index = 0usize;
    let length = value.len();

    while start <= length {
        let end = value[start..]
            .find('*')
            .map(|rel| start + rel)
            .unwrap_or(length);
        let part = &value[start..end];
        if !part.is_empty() {
            if part_index == 0 {
                encoder.write_context(0, part.as_bytes());
            } else if part_index == part_count - 1 {
                encoder.write_context(2, part.as_bytes());
            } else {
                encoder.write_context(1, part.as_bytes());
            }
        }
        part_index += 1;
        if end == length {
            break;
        }
        start = end + 1;
    }

    encoder.end_sequence();
    encoder.end_context();
}

fn encode_extensible_match(encoder: &mut BerEncoder, filter: &str) {
    let ext_idx = filter.find(":=").expect("caller checked :=");
    let lhs = &filter[..ext_idx];
    let match_value = &filter[ext_idx + 2..];

    let mut attr: Option<&str> = None;
    let mut matching_rule: Option<&str> = None;
    let mut dn_attributes = false;

    for (i, part) in lhs.split(':').enumerate() {
        let part = part.trim();
        if i == 0 && !part.is_empty() {
            attr = Some(part);
        } else if part.eq_ignore_ascii_case("dn") {
            dn_attributes = true;
        } else if !part.is_empty() {
            matching_rule = Some(part);
        }
    }

    encoder.begin_context(9, true);
    if let Some(rule) = matching_rule {
        encoder.write_context(1, rule.as_bytes());
    }
    if let Some(a) = attr {
        encoder.write_context(2, a.as_bytes());
    }
    encoder.write_context(3, match_value.as_bytes());
    if dn_attributes {
        encoder.write_context(4, &[0xFF]);
    }
    encoder.end_context();
}

#[cfg(test)]
mod tests {
    use super::encode_filter;
    use crate::asn1::{Asn1Type, BerDecoder, BerEncoder};

    #[test]
    fn encode_equality_uid_alice() {
        let mut enc = BerEncoder::new();
        encode_filter(&mut enc, "(uid=alice)");
        let bytes = enc.to_bytes();

        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let el = dec.next().expect("filter element");
        assert_eq!(el.tag(), Asn1Type::context_tag(3, true));
        assert_eq!(el.child_count(), 2);
        assert_eq!(el.child(0).as_string().as_deref(), Some("uid"));
        assert_eq!(el.child(1).as_string().as_deref(), Some("alice"));
    }

    #[test]
    fn encode_and_objectclass_uid() {
        let mut enc = BerEncoder::new();
        encode_filter(&mut enc, "(&(objectClass=person)(uid=alice))");
        let bytes = enc.to_bytes();

        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let el = dec.next().expect("AND filter");
        assert_eq!(el.tag(), Asn1Type::context_tag(0, true));
        assert_eq!(el.child_count(), 2);

        let eq1 = el.child(0);
        assert_eq!(eq1.tag(), Asn1Type::context_tag(3, true));
        assert_eq!(eq1.child(0).as_string().as_deref(), Some("objectClass"));
        assert_eq!(eq1.child(1).as_string().as_deref(), Some("person"));

        let eq2 = el.child(1);
        assert_eq!(eq2.tag(), Asn1Type::context_tag(3, true));
        assert_eq!(eq2.child(0).as_string().as_deref(), Some("uid"));
        assert_eq!(eq2.child(1).as_string().as_deref(), Some("alice"));
    }
}
