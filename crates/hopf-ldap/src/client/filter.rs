// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 4515 search filter string → BER encoding (Gumdrop `encodeFilter` port).

use crate::BerEncoder;

/// Encode an RFC 4515 filter string into `encoder` (context-tagged Filter CHOICE).
pub fn encode_filter(encoder: &mut BerEncoder, filter: &str) {
    let mut filter = filter.trim();
    if filter.starts_with('(') && filter.ends_with(')') && filter.len() >= 2 {
        filter = &filter[1..filter.len() - 1];
    }

    if let Some(rest) = filter.strip_prefix('&') {
        encoder.begin_context(0, true);
        encode_filter_list(encoder, rest);
        encoder.end_context();
    } else if let Some(rest) = filter.strip_prefix('|') {
        encoder.begin_context(1, true);
        encode_filter_list(encoder, rest);
        encoder.end_context();
    } else if let Some(rest) = filter.strip_prefix('!') {
        encoder.begin_context(2, true);
        encode_filter(encoder, rest.trim());
        encoder.end_context();
    } else if filter.contains("=*") && filter.ends_with("=*") && !filter.contains("*=") {
        // Presence: (attr=*)
        let attr = &filter[..filter.len() - 2];
        encoder.write_context(7, attr.as_bytes());
    } else if let Some(idx) = filter.find("~=") {
        encoder.begin_context(8, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string(&unescape(&filter[idx + 2..]));
        encoder.end_context();
    } else if filter.contains(":=") {
        encode_extensible_match(encoder, filter);
    } else if let Some(idx) = filter.find(">=") {
        encoder.begin_context(5, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string(&unescape(&filter[idx + 2..]));
        encoder.end_context();
    } else if let Some(idx) = filter.find("<=") {
        encoder.begin_context(6, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string(&unescape(&filter[idx + 2..]));
        encoder.end_context();
    } else if filter.contains('=') && filter.contains('*') {
        if let Some(idx) = filter.find('=') {
            encode_substring(encoder, &filter[..idx], &filter[idx + 1..]);
        }
    } else if let Some(idx) = filter.find('=') {
        encoder.begin_context(3, true);
        encoder.write_octet_string_str(&filter[..idx]);
        encoder.write_octet_string(&unescape(&filter[idx + 1..]));
        encoder.end_context();
    } else {
        encoder.write_context(7, b"objectClass");
    }
}

/// Decode the RFC 4515 section 3 `\XX` escapes of an assertion value. A
/// backslash not followed by two hex digits is kept as it is.
fn unescape(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
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
                encoder.write_context(0, &unescape(part));
            } else if part_index == part_count - 1 {
                encoder.write_context(2, &unescape(part));
            } else {
                encoder.write_context(1, &unescape(part));
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
    encoder.write_context(3, &unescape(match_value));
    if dn_attributes {
        encoder.write_context(4, &[0xFF]);
    }
    encoder.end_context();
}

#[cfg(test)]
mod tests {
    use super::encode_filter;
    use crate::{Asn1Type, BerDecoder, BerEncoder};

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

    fn decode(filter: &str) -> crate::Asn1Element {
        let mut enc = BerEncoder::new();
        encode_filter(&mut enc, filter);
        let mut dec = BerDecoder::new();
        dec.receive(&enc.to_bytes()).unwrap();
        dec.next().expect("filter element")
    }

    fn ctx(n: u8, constructed: bool) -> u8 {
        Asn1Type::context_tag(n, constructed)
    }

    fn bytes(e: &crate::Asn1Element) -> Vec<u8> {
        e.as_octet_string().expect("a string").to_vec()
    }

    #[test]
    fn presence_is_a_bare_attribute_name() {
        let el = decode("(mail=*)");
        assert_eq!(el.tag(), ctx(7, false));
        assert_eq!(bytes(&el), b"mail");
    }

    #[test]
    fn ordering_and_approximate_matches_pair_attribute_and_value() {
        for (filter, tag) in [("(age>=18)", 5), ("(age<=65)", 6), ("(cn~=jon)", 8)] {
            let el = decode(filter);
            assert_eq!(el.tag(), ctx(tag, true), "{filter}");
            assert_eq!(el.child_count(), 2);
        }
        let el = decode("(age>=18)");
        assert_eq!(el.child(0).as_string().as_deref(), Some("age"));
        assert_eq!(el.child(1).as_string().as_deref(), Some("18"));
    }

    #[test]
    fn substrings_are_initial_any_and_final() {
        let el = decode("(cn=ab*cd*ef*gh)");
        assert_eq!(el.tag(), ctx(4, true));
        assert_eq!(el.child(0).as_string().as_deref(), Some("cn"));
        let parts = el.child(1);
        let got: Vec<(u8, Vec<u8>)> = (0..parts.child_count())
            .map(|i| (Asn1Type::tag_number(parts.child(i).tag()), bytes(parts.child(i))))
            .collect();
        assert_eq!(
            got,
            [(0, b"ab".to_vec()), (1, b"cd".to_vec()), (1, b"ef".to_vec()), (2, b"gh".to_vec())]
        );
    }

    #[test]
    fn substrings_may_lack_an_initial_or_a_final_part() {
        let tags = |filter: &str| -> Vec<u8> {
            let el = decode(filter);
            let parts = el.child(1);
            (0..parts.child_count()).map(|i| Asn1Type::tag_number(parts.child(i).tag())).collect()
        };
        assert_eq!(tags("(cn=*mid*)"), [1]);
        assert_eq!(tags("(cn=*end)"), [2]);
        assert_eq!(tags("(cn=start*)"), [0]);
    }

    #[test]
    fn not_and_or_nest() {
        let el = decode("(!(|(a=1)(&(b=2)(c=3))))");
        assert_eq!(el.tag(), ctx(2, true));
        let or = el.child(0);
        assert_eq!(or.tag(), ctx(1, true));
        assert_eq!(or.child_count(), 2);
        let and = or.child(1);
        assert_eq!(and.tag(), ctx(0, true));
        assert_eq!(and.child_count(), 2);
    }

    #[test]
    fn an_empty_and_is_absolute_true() {
        let el = decode("(&)");
        assert_eq!(el.tag(), ctx(0, true));
        assert_eq!(el.child_count(), 0);
    }

    #[test]
    fn an_extensible_match_has_rule_attribute_value_and_dn_flag() {
        let el = decode("(cn:dn:2.4.6.8.10:=Dino)");
        assert_eq!(el.tag(), ctx(9, true));
        let parts: Vec<(u8, Vec<u8>)> = (0..el.child_count())
            .map(|i| (Asn1Type::tag_number(el.child(i).tag()), bytes(el.child(i))))
            .collect();
        assert_eq!(
            parts,
            [(1, b"2.4.6.8.10".to_vec()), (2, b"cn".to_vec()), (3, b"Dino".to_vec()), (4, vec![0xFF])]
        );
    }

    #[test]
    fn an_extensible_match_may_name_only_a_rule() {
        let el = decode("(:caseExactMatch:=Fred)");
        let tags: Vec<u8> = (0..el.child_count()).map(|i| Asn1Type::tag_number(el.child(i).tag())).collect();
        assert_eq!(tags, [1, 3]);
    }

    #[test]
    fn the_outer_parentheses_and_spaces_are_optional() {
        for filter in ["uid=alice", "  (uid=alice)  "] {
            let el = decode(filter);
            assert_eq!(el.tag(), ctx(3, true), "{filter:?}");
            assert_eq!(el.child(1).as_string().as_deref(), Some("alice"));
        }
    }

    #[test]
    fn a_filter_with_no_operator_matches_any_object() {
        let el = decode("(garbage)");
        assert_eq!(el.tag(), ctx(7, false));
        assert_eq!(bytes(&el), b"objectClass");
    }

    #[test]
    fn escaped_bytes_in_an_equality_value_are_decoded() {
        // RFC 4515 section 3: \28 \29 \2a \5c, and any other byte as \XX.
        let el = decode(r"(cn=\28x\29 \5c \2a \c3\a9)");
        assert_eq!(bytes(&el.child(1)), b"(x) \\ * \xc3\xa9");
    }

    #[test]
    fn an_escaped_star_in_a_substring_is_a_literal_not_a_wildcard() {
        let el = decode(r"(cn=a\2a*b)");
        assert_eq!(el.tag(), ctx(4, true));
        let parts = el.child(1);
        assert_eq!(parts.child_count(), 2);
        assert_eq!(bytes(&parts.child(0)), b"a*");
        assert_eq!(bytes(&parts.child(1)), b"b");
    }

    #[test]
    fn an_escaped_star_alone_is_an_equality_not_a_presence_test() {
        let el = decode(r"(cn=\2a)");
        assert_eq!(el.tag(), ctx(3, true));
        assert_eq!(bytes(&el.child(1)), b"*");
    }

    #[test]
    fn escapes_are_decoded_in_ordering_and_extensible_values() {
        assert_eq!(bytes(&decode(r"(n>=\28)").child(1)), b"(");
        assert_eq!(bytes(&decode(r"(cn:=a\29b)").child(1)), b"a)b");
    }

    #[test]
    fn a_backslash_not_followed_by_two_hex_digits_is_kept() {
        assert_eq!(bytes(&decode(r"(cn=a\zzb)").child(1)), b"a\\zzb");
        assert_eq!(bytes(&decode(r"(cn=a\2)").child(1)), b"a\\2");
    }
}
