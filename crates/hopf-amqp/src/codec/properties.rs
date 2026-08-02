// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Basic content properties (AMQP 0-9-1 content header property flags).

use super::table::{decode_shortstr, decode_table, encode_shortstr, encode_table, FieldTable};
use super::AmqpError;

/// Basic class content properties. Body is opaque bytes elsewhere.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BasicProperties {
    /// MIME content type (opaque shortstr).
    pub content_type: Option<String>,
    /// MIME content encoding (opaque shortstr).
    pub content_encoding: Option<String>,
    /// Application headers.
    pub headers: Option<FieldTable>,
    /// 1 = non-persistent, 2 = persistent.
    pub delivery_mode: Option<u8>,
    /// Message priority 0–9.
    pub priority: Option<u8>,
    /// Application correlation id.
    pub correlation_id: Option<String>,
    /// Address to reply to.
    pub reply_to: Option<String>,
    /// Message expiration (as string, typically milliseconds).
    pub expiration: Option<String>,
    /// Application message id.
    pub message_id: Option<String>,
    /// Timestamp.
    pub timestamp: Option<u64>,
    /// Message type name.
    pub message_type: Option<String>,
    /// Creating user id.
    pub user_id: Option<String>,
    /// Creating application id.
    pub app_id: Option<String>,
    /// Intra-cluster routing id (deprecated, rarely used).
    pub cluster_id: Option<String>,
}

impl BasicProperties {
    /// Empty properties.
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode property flags + property values (content-header payload after
    /// class/weight/body-size).
    pub fn encode(&self) -> Result<Vec<u8>, AmqpError> {
        let mut flags: u16 = 0;
        let mut body = Vec::new();

        if let Some(ref s) = self.content_type {
            flags |= 1 << 15;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.content_encoding {
            flags |= 1 << 14;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref t) = self.headers {
            flags |= 1 << 13;
            encode_table(&mut body, t)?;
        }
        if let Some(m) = self.delivery_mode {
            flags |= 1 << 12;
            body.push(m);
        }
        if let Some(p) = self.priority {
            flags |= 1 << 11;
            body.push(p);
        }
        if let Some(ref s) = self.correlation_id {
            flags |= 1 << 10;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.reply_to {
            flags |= 1 << 9;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.expiration {
            flags |= 1 << 8;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.message_id {
            flags |= 1 << 7;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(t) = self.timestamp {
            flags |= 1 << 6;
            body.extend_from_slice(&t.to_be_bytes());
        }
        if let Some(ref s) = self.message_type {
            flags |= 1 << 5;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.user_id {
            flags |= 1 << 4;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.app_id {
            flags |= 1 << 3;
            encode_shortstr(&mut body, s)?;
        }
        if let Some(ref s) = self.cluster_id {
            flags |= 1 << 2;
            encode_shortstr(&mut body, s)?;
        }

        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decode from property flags + values.
    pub fn decode(data: &mut &[u8]) -> Result<Self, AmqpError> {
        if data.len() < 2 {
            return Err(AmqpError::Malformed("truncated property flags"));
        }
        let flags = u16::from_be_bytes([data[0], data[1]]);
        *data = &data[2..];
        let mut props = Self::default();

        if flags & (1 << 15) != 0 {
            props.content_type = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 14) != 0 {
            props.content_encoding = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 13) != 0 {
            props.headers = Some(decode_table(data)?);
        }
        if flags & (1 << 12) != 0 {
            if data.is_empty() {
                return Err(AmqpError::Malformed("truncated delivery-mode"));
            }
            props.delivery_mode = Some(data[0]);
            *data = &data[1..];
        }
        if flags & (1 << 11) != 0 {
            if data.is_empty() {
                return Err(AmqpError::Malformed("truncated priority"));
            }
            props.priority = Some(data[0]);
            *data = &data[1..];
        }
        if flags & (1 << 10) != 0 {
            props.correlation_id = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 9) != 0 {
            props.reply_to = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 8) != 0 {
            props.expiration = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 7) != 0 {
            props.message_id = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 6) != 0 {
            if data.len() < 8 {
                return Err(AmqpError::Malformed("truncated timestamp"));
            }
            props.timestamp = Some(u64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]));
            *data = &data[8..];
        }
        if flags & (1 << 5) != 0 {
            props.message_type = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 4) != 0 {
            props.user_id = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 3) != 0 {
            props.app_id = Some(decode_shortstr(data)?.to_owned());
        }
        if flags & (1 << 2) != 0 {
            props.cluster_id = Some(decode_shortstr(data)?.to_owned());
        }
        // Bit 1 / 0 reserved — ignore presence.
        Ok(props)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn properties_round_trip() {
        let mut props = BasicProperties::new();
        props.content_type = Some("application/json".into());
        props.content_encoding = Some("gzip".into());
        props.delivery_mode = Some(2);
        props.priority = Some(5);
        props.correlation_id = Some("c-1".into());
        props.message_id = Some("m-1".into());
        props.timestamp = Some(1_700_000_000);
        props.app_id = Some("hopf".into());

        let encoded = props.encode().unwrap();
        let mut rest: &[u8] = &encoded;
        let decoded = BasicProperties::decode(&mut rest).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, props);
    }
}
