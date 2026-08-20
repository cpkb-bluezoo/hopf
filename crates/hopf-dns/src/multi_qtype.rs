// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! RFC 10029 DNS Multiple QTYPEs.
//!
//! Lets a client request extra RRTYPEs (e.g. AAAA and HTTPS alongside a
//! primary A question) via an `MQTYPE-Query` EDNS0 option attached to the
//! primary question, instead of paying for a separate wire round trip per
//! type. A supporting server merges whatever extra answers it can into the
//! single response and echoes back which types it actually covered via an
//! `MQTYPE-Response` option; anything not echoed — including everything, if
//! the server doesn't support the mechanism at all — still needs a
//! standalone query. This module only builds/parses the two option
//! payloads; [`crate::client::DnsResolver::query_batch`] drives the
//! opportunistic-attach / per-server-capability-cache / standalone-fallback
//! behavior on top of it.

use crate::wire::DnsType;

/// EDNS option code for MQTYPE-Query: additional RRTYPEs a client wants
/// alongside the primary question.
pub const EDNS_OPTION_MQTYPE_QUERY: u16 = 20;
/// EDNS option code for MQTYPE-Response: the RRTYPEs a supporting server
/// actually merged into this response's answer section.
pub const EDNS_OPTION_MQTYPE_RESPONSE: u16 = 21;

/// Encode `additional_types` as an MQTYPE-Query option (code + length +
/// packed `u16` type values), ready to append into an OPT record's options
/// alongside whatever else belongs there (e.g. a COOKIE option).
pub fn encode_mqtype_query_option(additional_types: &[DnsType]) -> Vec<u8> {
    encode_mqtype_option(EDNS_OPTION_MQTYPE_QUERY, additional_types)
}

/// Encode `included_types` as an MQTYPE-Response option. Only needed by a
/// server (or, in tests, a stub server standing in for one) — the resolver
/// itself only ever parses this side.
pub fn encode_mqtype_response_option(included_types: &[DnsType]) -> Vec<u8> {
    encode_mqtype_option(EDNS_OPTION_MQTYPE_RESPONSE, included_types)
}

fn encode_mqtype_option(code: u16, types: &[DnsType]) -> Vec<u8> {
    let mut data = Vec::with_capacity(types.len() * 2);
    for t in types {
        data.extend_from_slice(&t.value().to_be_bytes());
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&data);
    out
}

/// Find and decode a `code`-tagged option (one of
/// [`EDNS_OPTION_MQTYPE_QUERY`]/[`EDNS_OPTION_MQTYPE_RESPONSE`]) out of an
/// OPT record's RDATA options blob, returning the RRTYPEs it lists.
///
/// `None` means the option isn't present at all — including when the
/// options blob itself is truncated/malformed, treated the same as
/// "absent" since either way the peer hasn't usably signaled support for
/// this RFC. This is the caller's cue to fall back to standalone queries
/// (and, for a response, to remember the server as not supporting the
/// mechanism — see [`crate::multi_qtype_cache::MultiQTypeCache`]).
/// Unrecognized type values inside an otherwise well-formed option are
/// silently skipped rather than failing the whole parse.
pub fn find_mqtype_option(opt_rdata: &[u8], code: u16) -> Option<Vec<DnsType>> {
    let mut i = 0;
    while i + 4 <= opt_rdata.len() {
        let opt_code = u16::from_be_bytes([opt_rdata[i], opt_rdata[i + 1]]);
        let len = u16::from_be_bytes([opt_rdata[i + 2], opt_rdata[i + 3]]) as usize;
        i += 4;
        if i + len > opt_rdata.len() {
            return None;
        }
        if opt_code == code {
            let mut types = Vec::new();
            let mut j = 0;
            while j + 2 <= len {
                let v = u16::from_be_bytes([opt_rdata[i + j], opt_rdata[i + j + 1]]);
                if let Some(t) = DnsType::from_value(v) {
                    types.push(t);
                }
                j += 2;
            }
            return Some(types);
        }
        i += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mqtype_query_option_round_trips() {
        let opt = encode_mqtype_query_option(&[DnsType::Aaaa, DnsType::Https]);
        let types = find_mqtype_option(&opt, EDNS_OPTION_MQTYPE_QUERY).unwrap();
        assert_eq!(types, vec![DnsType::Aaaa, DnsType::Https]);
        // A response-coded option lookup must not match a query-coded one.
        assert_eq!(find_mqtype_option(&opt, EDNS_OPTION_MQTYPE_RESPONSE), None);
    }

    #[test]
    fn mqtype_response_option_round_trips_alongside_other_options() {
        let mut combined = vec![0u8, 10, 0, 4, 1, 2, 3, 4]; // unrelated 4-byte option
        combined.extend_from_slice(&encode_mqtype_response_option(&[DnsType::A, DnsType::Aaaa]));
        let types = find_mqtype_option(&combined, EDNS_OPTION_MQTYPE_RESPONSE).unwrap();
        assert_eq!(types, vec![DnsType::A, DnsType::Aaaa]);
    }

    #[test]
    fn absent_or_truncated_option_is_none() {
        assert_eq!(find_mqtype_option(&[], EDNS_OPTION_MQTYPE_QUERY), None);
        let truncated = vec![0u8, 20, 0, 100, 1, 2]; // claims 100 bytes, has 2
        assert_eq!(find_mqtype_option(&truncated, EDNS_OPTION_MQTYPE_QUERY), None);
    }

    #[test]
    fn unknown_type_values_are_skipped_not_fatal() {
        // 65535 has no DnsType mapping; AAAA (28) does.
        let mut data = 65535u16.to_be_bytes().to_vec();
        data.extend_from_slice(&DnsType::Aaaa.value().to_be_bytes());
        let mut opt = EDNS_OPTION_MQTYPE_RESPONSE.to_be_bytes().to_vec();
        opt.extend_from_slice(&(data.len() as u16).to_be_bytes());
        opt.extend_from_slice(&data);
        let types = find_mqtype_option(&opt, EDNS_OPTION_MQTYPE_RESPONSE).unwrap();
        assert_eq!(types, vec![DnsType::Aaaa]);
    }
}
