// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPMessage encode helpers (bind / search / unbind).

use crate::BerEncoder;

use super::control::{encode_controls, Control};
use super::filter::encode_filter;
use super::types::{
    SearchRequest, APP_ABANDON_REQUEST, APP_BIND_REQUEST, APP_SEARCH_REQUEST, APP_UNBIND_REQUEST,
    LDAP_VERSION_3,
};

/// Encode a simple BindRequest LDAPMessage.
pub fn encode_bind_request(message_id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(message_id);
    enc.begin_application(APP_BIND_REQUEST, true);
    enc.write_integer_i32(LDAP_VERSION_3);
    enc.write_octet_string_str(dn);
    enc.write_context(0, password.as_bytes()); // simple auth [0]
    enc.end_application();
    enc.end_sequence();
    enc.into_bytes()
}

/// Encode a SearchRequest LDAPMessage.
pub fn encode_search_request(message_id: i32, request: &SearchRequest) -> Vec<u8> {
    encode_search_request_with_controls(message_id, request, &[])
}

/// Encode a SearchRequest LDAPMessage carrying `controls` (RFC 4511
/// section 4.1.11), e.g. an RFC 4533 Sync Request Control.
pub fn encode_search_request_with_controls(message_id: i32, request: &SearchRequest, controls: &[Control]) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(message_id);
    enc.begin_application(APP_SEARCH_REQUEST, true);
    enc.write_octet_string_str(&request.base_dn);
    enc.write_enumerated(request.scope.value());
    enc.write_enumerated(request.deref_aliases.value());
    enc.write_integer_i32(request.size_limit);
    enc.write_integer_i32(request.time_limit);
    enc.write_boolean(request.types_only);
    encode_filter(&mut enc, &request.filter);
    enc.begin_sequence();
    for attr in &request.attributes {
        enc.write_octet_string_str(attr);
    }
    enc.end_sequence();
    enc.end_application();
    encode_controls(&mut enc, controls);
    enc.end_sequence();
    enc.into_bytes()
}

/// Encode an AbandonRequest LDAPMessage (RFC 4511 section 4.11):
/// `[APPLICATION 16] MessageID`, an INTEGER with an implicit application tag.
/// Abandon has no response; it is how a client ends an operation such as a
/// persistent content synchronisation (RFC 4533 section 3.7).
pub fn encode_abandon_request(message_id: i32, abandon_id: i32) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(message_id);
    enc.write_application(APP_ABANDON_REQUEST, &minimal_integer(abandon_id));
    enc.end_sequence();
    enc.into_bytes()
}

/// Two's-complement big-endian content octets of an INTEGER, minimal length.
fn minimal_integer(value: i32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 3 && ((bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0) || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0)) {
        start += 1;
    }
    bytes[start..].to_vec()
}

/// Encode an UnbindRequest LDAPMessage.
///
/// RFC 4511 §4.3: `UnbindRequest ::= [APPLICATION 2] NULL` — application
/// class, primitive. Gumdrop's comment says application but the code used
/// `writeContext`; we emit the RFC-correct application tag.
pub fn encode_unbind_request(message_id: i32) -> Vec<u8> {
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(message_id);
    enc.write_application(APP_UNBIND_REQUEST, &[]);
    enc.end_sequence();
    enc.into_bytes()
}

/// Encode a STARTTLS ExtendedRequest (RFC 4511 §4.14).
pub fn encode_starttls_request(message_id: i32) -> Vec<u8> {
    encode_extended_request(message_id, super::types::OID_STARTTLS, None)
}

/// Encode an ExtendedRequest LDAPMessage (RFC 4511 §4.12).
pub fn encode_extended_request(
    message_id: i32,
    request_name: &str,
    request_value: Option<&[u8]>,
) -> Vec<u8> {
    use super::types::APP_EXTENDED_REQUEST;
    let mut enc = BerEncoder::new();
    enc.begin_sequence();
    enc.write_integer_i32(message_id);
    enc.begin_application(APP_EXTENDED_REQUEST, true);
    enc.write_context(0, request_name.as_bytes());
    if let Some(value) = request_value {
        enc.write_context(1, value);
    }
    enc.end_application();
    enc.end_sequence();
    enc.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Asn1Type, BerDecoder};
    use crate::client::types::{SearchScope, APP_ABANDON_REQUEST, APP_BIND_RESPONSE};

    #[test]
    fn bind_request_round_trip_decode() {
        let bytes = encode_bind_request(1, "cn=admin,dc=example,dc=com", "secret");
        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let msg = dec.next().expect("LDAPMessage");
        assert_eq!(msg.tag(), Asn1Type::SEQUENCE);
        assert_eq!(msg.child(0).as_i32().unwrap(), 1);
        let op = msg.child(1);
        assert_eq!(op.tag(), Asn1Type::application_tag(APP_BIND_REQUEST, true));
        assert_eq!(op.child(0).as_i32().unwrap(), 3);
        assert_eq!(
            op.child(1).as_string().as_deref(),
            Some("cn=admin,dc=example,dc=com")
        );
        assert_eq!(op.child(2).tag(), Asn1Type::context_tag(0, false));
        assert_eq!(op.child(2).as_octet_string(), Some(b"secret".as_slice()));
    }

    #[test]
    fn search_request_round_trip_decode() {
        let req = SearchRequest {
            base_dn: "dc=example,dc=com".into(),
            scope: SearchScope::WholeSubtree,
            filter: "(uid=alice)".into(),
            attributes: vec!["cn".into()],
            size_limit: 1,
            time_limit: 30,
            types_only: false,
            ..SearchRequest::default()
        };
        let bytes = encode_search_request(7, &req);
        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let msg = dec.next().expect("LDAPMessage");
        assert_eq!(msg.child(0).as_i32().unwrap(), 7);
        let op = msg.child(1);
        assert_eq!(op.tag(), Asn1Type::application_tag(APP_SEARCH_REQUEST, true));
        assert_eq!(op.child(0).as_string().as_deref(), Some("dc=example,dc=com"));
        assert_eq!(op.child(1).as_i32().unwrap(), 2); // scope
        assert_eq!(op.child(3).as_i32().unwrap(), 1); // sizeLimit
        let filter = op.child(6);
        assert_eq!(filter.tag(), Asn1Type::context_tag(3, true));
        assert_eq!(filter.child(0).as_string().as_deref(), Some("uid"));
        assert_eq!(filter.child(1).as_string().as_deref(), Some("alice"));
        let attrs = op.child(7);
        assert_eq!(attrs.child(0).as_string().as_deref(), Some("cn"));
    }

    #[test]
    fn unbind_uses_application_2_primitive() {
        let bytes = encode_unbind_request(3);
        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let msg = dec.next().unwrap();
        let op = msg.child(1);
        assert_eq!(
            op.tag(),
            Asn1Type::application_tag(APP_UNBIND_REQUEST, false)
        );
        assert!(!op.is_constructed());
        assert_eq!(op.as_octet_string(), Some([].as_slice()));
        // Ensure we did not emit context tag 2 (0x82).
        assert_ne!(op.tag(), Asn1Type::context_tag(2, false));
        let _ = APP_BIND_RESPONSE;
    }

    #[test]
    fn starttls_request_encodes_extended_oid() {
        use crate::client::types::{APP_EXTENDED_REQUEST, OID_STARTTLS};

        let bytes = encode_starttls_request(9);
        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let msg = dec.next().unwrap();
        assert_eq!(msg.child(0).as_i32().unwrap(), 9);
        let op = msg.child(1);
        assert_eq!(
            op.tag(),
            Asn1Type::application_tag(APP_EXTENDED_REQUEST, true)
        );
        assert_eq!(op.child(0).tag(), Asn1Type::context_tag(0, false));
        assert_eq!(
            op.child(0).as_string().as_deref(),
            Some(OID_STARTTLS)
        );
    }

    #[test]
    fn search_request_carries_controls_after_the_operation() {
        use crate::client::control::Control;
        let req = SearchRequest::new("dc=example,dc=com", "(objectClass=*)");
        let control = Control { oid: "1.2.3".into(), critical: true, value: Some(vec![0x30, 0x00]) };
        let bytes = encode_search_request_with_controls(4, &req, std::slice::from_ref(&control));
        let mut dec = BerDecoder::new();
        dec.receive(&bytes).unwrap();
        let msg = dec.next().unwrap();
        assert_eq!(msg.child_count(), 3, "id, operation, controls");
        assert_eq!(msg.child(2).tag(), Asn1Type::context_tag(0, true));
        assert_eq!(crate::client::control::decode_controls(&msg).unwrap(), vec![control]);
        // Without controls the message is unchanged.
        let plain = encode_search_request(4, &req);
        let mut dec = BerDecoder::new();
        dec.receive(&plain).unwrap();
        assert_eq!(dec.next().unwrap().child_count(), 2);
    }

    /// RFC 4511 section 4.11: `AbandonRequest ::= [APPLICATION 16] MessageID`.
    #[test]
    fn abandon_request_is_an_application_16_integer() {
        for (target, content) in [(1, vec![0x01]), (127, vec![0x7f]), (128, vec![0x00, 0x80]), (256, vec![0x01, 0x00]), (65_536, vec![0x01, 0x00, 0x00])] {
            let bytes = encode_abandon_request(9, target);
            let mut dec = BerDecoder::new();
            dec.receive(&bytes).unwrap();
            let msg = dec.next().unwrap();
            assert_eq!(msg.child(0).as_i32().unwrap(), 9);
            let op = msg.child(1);
            assert_eq!(op.tag(), Asn1Type::application_tag(APP_ABANDON_REQUEST, false));
            assert_eq!(op.as_octet_string(), Some(content.as_slice()), "target {target}");
            assert_eq!(op.as_i32().unwrap(), target);
        }
    }
}
