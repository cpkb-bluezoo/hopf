// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL frame bodies (SASL spec section 5.3) carried on frame-type `0x01`
//! frames, exchanged before the AMQP-layer protocol header (see
//! [`super::frame`]).

use super::types::{decode, Encoder, Value};
use super::Amqp1Error;

const SASL_MECHANISMS: u64 = 0x40;
const SASL_INIT: u64 = 0x41;
const SASL_CHALLENGE: u64 = 0x42;
const SASL_RESPONSE: u64 = 0x43;
const SASL_OUTCOME: u64 = 0x44;

/// SASL outcome codes (SASL spec 5.3.3.2).
pub mod outcome_code {
    /// Authentication succeeded.
    pub const OK: u8 = 0;
    /// Authentication failed due to bad credentials.
    pub const AUTH: u8 = 1;
    /// Authentication failed due to a system error.
    pub const SYS: u8 = 2;
    /// System error that is unlikely to be corrected by retrying.
    pub const SYS_PERM: u8 = 3;
    /// System error that may be corrected by retrying later.
    pub const SYS_TEMP: u8 = 4;
}

/// A decoded SASL frame body.
#[derive(Debug, Clone, PartialEq)]
pub enum SaslBody {
    /// `sasl-mechanisms` — server-advertised mechanism names.
    Mechanisms(Vec<String>),
    /// `sasl-init` — client's chosen mechanism, optional initial response.
    Init {
        /// Chosen mechanism name.
        mechanism: String,
        /// Initial response bytes, if the mechanism has one.
        initial_response: Option<Vec<u8>>,
        /// Target hostname, for virtual hosting.
        hostname: Option<String>,
    },
    /// `sasl-challenge` — server challenge bytes.
    Challenge(Vec<u8>),
    /// `sasl-response` — client response bytes.
    Response(Vec<u8>),
    /// `sasl-outcome` — final result.
    Outcome {
        /// One of [`outcome_code`].
        code: u8,
        /// Additional data (e.g. a SCRAM-style final server message).
        additional_data: Option<Vec<u8>>,
    },
}

impl SaslBody {
    /// Encode to bytes (a SASL-type frame's body).
    pub fn encode(&self) -> Vec<u8> {
        let value = match self {
            SaslBody::Mechanisms(mechs) => {
                let mut items = Vec::new();
                match mechs.len() {
                    0 => items.push(None),
                    1 => items.push(Some(Value::Symbol(mechs[0].clone()))),
                    _ => {
                        let mut enc = Encoder::new();
                        enc.symbol_array(mechs);
                        let (v, _) = decode(&enc.into_bytes()).expect("just-encoded symbol array");
                        items.push(Some(v));
                    }
                }
                described_list(SASL_MECHANISMS, items)
            }
            SaslBody::Init { mechanism, initial_response, hostname } => described_list(
                SASL_INIT,
                vec![
                    Some(Value::Symbol(mechanism.clone())),
                    initial_response.clone().map(Value::Binary),
                    hostname.clone().map(Value::String),
                ],
            ),
            SaslBody::Challenge(c) => described_list(SASL_CHALLENGE, vec![Some(Value::Binary(c.clone()))]),
            SaslBody::Response(r) => described_list(SASL_RESPONSE, vec![Some(Value::Binary(r.clone()))]),
            SaslBody::Outcome { code, additional_data } => described_list(
                SASL_OUTCOME,
                vec![Some(Value::Ubyte(*code)), additional_data.clone().map(Value::Binary)],
            ),
        };
        let mut enc = Encoder::new();
        enc.value(&value);
        enc.into_bytes()
    }

    /// Decode a SASL frame body.
    pub fn decode(body: &[u8]) -> Result<Self, Amqp1Error> {
        let (value, _) = decode(body)?;
        let Value::Described(descriptor, value) = &value else {
            return Err(Amqp1Error::Malformed("SASL frame body is not a described type"));
        };
        let code = descriptor.as_u64().ok_or(Amqp1Error::Malformed("non-numeric SASL descriptor"))?;
        let list = value.as_list().ok_or(Amqp1Error::Malformed("SASL body is not a list"))?;
        Ok(match code {
            SASL_MECHANISMS => {
                let mechs = list
                    .first()
                    .and_then(Value::as_symbol_multiple)
                    .ok_or(Amqp1Error::RequiredFieldMissing("sasl-server-mechanisms"))?;
                SaslBody::Mechanisms(mechs)
            }
            SASL_INIT => SaslBody::Init {
                mechanism: list
                    .first()
                    .and_then(Value::as_str)
                    .ok_or(Amqp1Error::RequiredFieldMissing("mechanism"))?
                    .to_string(),
                initial_response: list.get(1).and_then(Value::as_binary).map(<[u8]>::to_vec),
                hostname: list.get(2).and_then(Value::as_str).map(str::to_string),
            },
            SASL_CHALLENGE => SaslBody::Challenge(
                list.first()
                    .and_then(Value::as_binary)
                    .ok_or(Amqp1Error::RequiredFieldMissing("challenge"))?
                    .to_vec(),
            ),
            SASL_RESPONSE => SaslBody::Response(
                list.first()
                    .and_then(Value::as_binary)
                    .ok_or(Amqp1Error::RequiredFieldMissing("response"))?
                    .to_vec(),
            ),
            SASL_OUTCOME => SaslBody::Outcome {
                code: list
                    .first()
                    .and_then(Value::as_u64)
                    .ok_or(Amqp1Error::RequiredFieldMissing("code"))? as u8,
                additional_data: list.get(1).and_then(Value::as_binary).map(<[u8]>::to_vec),
            },
            other => return Err(Amqp1Error::UnknownDescriptor(other)),
        })
    }
}

fn described_list(descriptor_code: u64, items: Vec<Option<Value>>) -> Value {
    let mut items = items;
    while matches!(items.last(), Some(None)) {
        items.pop();
    }
    let list: Vec<Value> = items.into_iter().map(|o| o.unwrap_or(Value::Null)).collect();
    Value::Described(Box::new(Value::Ulong(descriptor_code)), Box::new(Value::List(list)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanisms_roundtrips() {
        let body = SaslBody::Mechanisms(vec!["PLAIN".into(), "ANONYMOUS".into()]);
        let bytes = body.encode();
        assert_eq!(SaslBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn single_mechanism_roundtrips() {
        let body = SaslBody::Mechanisms(vec!["ANONYMOUS".into()]);
        let bytes = body.encode();
        assert_eq!(SaslBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn init_with_response_and_hostname_roundtrips() {
        let body = SaslBody::Init {
            mechanism: "PLAIN".into(),
            initial_response: Some(vec![0, b'u', b's', b'e', b'r', 0, b'p', b'w']),
            hostname: Some("broker.example.test".into()),
        };
        let bytes = body.encode();
        assert_eq!(SaslBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn init_without_response_roundtrips() {
        let body = SaslBody::Init { mechanism: "ANONYMOUS".into(), initial_response: None, hostname: None };
        let bytes = body.encode();
        assert_eq!(SaslBody::decode(&bytes).unwrap(), body);
    }

    #[test]
    fn challenge_response_outcome_roundtrip() {
        let c = SaslBody::Challenge(vec![1, 2, 3]);
        assert_eq!(SaslBody::decode(&c.encode()).unwrap(), c);
        let r = SaslBody::Response(vec![4, 5]);
        assert_eq!(SaslBody::decode(&r.encode()).unwrap(), r);
        let o = SaslBody::Outcome { code: outcome_code::OK, additional_data: None };
        assert_eq!(SaslBody::decode(&o.encode()).unwrap(), o);
        let o2 = SaslBody::Outcome { code: outcome_code::AUTH, additional_data: Some(vec![9]) };
        assert_eq!(SaslBody::decode(&o2.encode()).unwrap(), o2);
    }
}
