// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! LDAP controls (RFC 4511 section 4.1.11): the optional `[0] Controls`
//! trailer of an LDAPMessage, in both directions.

use crate::{Asn1Element, Asn1Error, Asn1Type, BerEncoder};

/// One control: an OID, a criticality, and an optional BER value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// `controlType`, a dotted-decimal OID.
    pub oid: String,
    /// `criticality`: the server must fail the operation rather than ignore a
    /// critical control it does not support.
    pub critical: bool,
    /// `controlValue`, itself BER, when the control has one.
    pub value: Option<Vec<u8>>,
}

impl Control {
    /// A control with the given OID and no value, non-critical.
    pub fn new(oid: impl Into<String>) -> Self {
        Self { oid: oid.into(), critical: false, value: None }
    }
}

/// Context tag number of the `Controls` field of an LDAPMessage.
const CTX_CONTROLS: u8 = 0;

/// Append `controls` to an LDAPMessage being built: `[0] SEQUENCE OF Control`.
/// Writes nothing for an empty list, as the field is OPTIONAL.
pub(crate) fn encode_controls(enc: &mut BerEncoder, controls: &[Control]) {
    if controls.is_empty() {
        return;
    }
    enc.begin_context(CTX_CONTROLS, true);
    for c in controls {
        enc.begin_sequence();
        enc.write_octet_string_str(&c.oid);
        if c.critical {
            enc.write_boolean(true); // DEFAULT FALSE: only encoded when TRUE
        }
        if let Some(v) = &c.value {
            enc.write_octet_string(v);
        }
        enc.end_sequence();
    }
    enc.end_context();
}

/// Read the controls of a decoded LDAPMessage, if it has any: the element
/// after the protocolOp, when tagged `[0]`.
pub(crate) fn decode_controls(message: &Asn1Element) -> Result<Vec<Control>, Asn1Error> {
    let mut out = Vec::new();
    for i in 2..message.child_count() {
        let field = message.child(i);
        if field.tag() != Asn1Type::context_tag(CTX_CONTROLS, true) {
            continue;
        }
        for j in 0..field.child_count() {
            let c = field.child(j);
            let oid = c
                .child(0)
                .as_string()
                .ok_or_else(|| Asn1Error::new("control without controlType"))?;
            let mut critical = false;
            let mut value = None;
            for k in 1..c.child_count() {
                let part = c.child(k);
                if part.tag() == Asn1Type::BOOLEAN {
                    critical = part.as_bool()?;
                } else if part.tag() == Asn1Type::OCTET_STRING {
                    value = part.as_octet_string().map(<[u8]>::to_vec);
                }
            }
            out.push(Control { oid, critical, value });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BerDecoder;

    fn message_with(controls: &[Control]) -> Asn1Element {
        let mut enc = BerEncoder::new();
        enc.begin_sequence();
        enc.write_integer_i32(1);
        enc.write_null(); // stand-in protocolOp
        encode_controls(&mut enc, controls);
        enc.end_sequence();
        let mut dec = BerDecoder::new();
        dec.receive(&enc.into_bytes()).unwrap();
        dec.next().expect("a message")
    }

    #[test]
    fn controls_round_trip_with_and_without_value_and_criticality() {
        let controls = vec![
            Control { oid: "1.2.3".into(), critical: true, value: Some(vec![0x30, 0x00]) },
            Control { oid: "4.5.6".into(), critical: false, value: None },
            Control { oid: "7.8.9".into(), critical: false, value: Some(vec![1, 2, 3]) },
        ];
        assert_eq!(decode_controls(&message_with(&controls)).unwrap(), controls);
    }

    /// Criticality DEFAULT FALSE is left off the wire, and no controls means no
    /// `[0]` field at all.
    #[test]
    fn empty_and_default_encodings_are_minimal() {
        assert!(decode_controls(&message_with(&[])).unwrap().is_empty());
        let mut enc = BerEncoder::new();
        encode_controls(&mut enc, &[]);
        assert!(enc.into_bytes().is_empty());
        let mut enc = BerEncoder::new();
        encode_controls(&mut enc, &[Control::new("1.2.3")]);
        // [0] { SEQUENCE { OCTET STRING "1.2.3" } }: no BOOLEAN, no value.
        assert_eq!(enc.into_bytes(), [0xa0, 0x09, 0x30, 0x07, 0x04, 0x05, b'1', b'.', b'2', b'.', b'3']);
    }
}
