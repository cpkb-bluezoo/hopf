// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAPMessage encode helpers (bind / search / unbind).

use crate::asn1::BerEncoder;

use super::filter::encode_filter;
use super::types::{
    SearchRequest, APP_BIND_REQUEST, APP_SEARCH_REQUEST, APP_UNBIND_REQUEST, LDAP_VERSION_3,
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
    enc.end_sequence();
    enc.into_bytes()
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
    use crate::asn1::{Asn1Type, BerDecoder};
    use crate::client::types::{SearchScope, APP_BIND_RESPONSE};

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
}
