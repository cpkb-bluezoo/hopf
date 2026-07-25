// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT control packet types, protocol versions, QoS, and packet structs.

use super::properties::Properties;

/// MQTT control packet types (MQTT 3.1.1 §2.2.1, MQTT 5.0 §2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Client request to connect to a server.
    Connect,
    /// Connect acknowledgment.
    Connack,
    /// Publish message.
    Publish,
    /// Publish acknowledgment (QoS 1).
    Puback,
    /// Publish received (QoS 2 delivery part 1).
    Pubrec,
    /// Publish release (QoS 2 delivery part 2).
    Pubrel,
    /// Publish complete (QoS 2 delivery part 3).
    Pubcomp,
    /// Client subscribe request.
    Subscribe,
    /// Subscribe acknowledgment.
    Suback,
    /// Unsubscribe request.
    Unsubscribe,
    /// Unsubscribe acknowledgment.
    Unsuback,
    /// Ping request.
    Pingreq,
    /// Ping response.
    Pingresp,
    /// Client is disconnecting.
    Disconnect,
    /// Authentication exchange (MQTT 5.0 only).
    Auth,
}

impl PacketType {
    /// Numeric packet type value (fixed header bits 7-4).
    pub fn value(self) -> u8 {
        match self {
            Self::Connect => 1,
            Self::Connack => 2,
            Self::Publish => 3,
            Self::Puback => 4,
            Self::Pubrec => 5,
            Self::Pubrel => 6,
            Self::Pubcomp => 7,
            Self::Subscribe => 8,
            Self::Suback => 9,
            Self::Unsubscribe => 10,
            Self::Unsuback => 11,
            Self::Pingreq => 12,
            Self::Pingresp => 13,
            Self::Disconnect => 14,
            Self::Auth => 15,
        }
    }

    /// Packet type from the fixed header's high nibble (1-15).
    pub fn from_value(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Connect,
            2 => Self::Connack,
            3 => Self::Publish,
            4 => Self::Puback,
            5 => Self::Pubrec,
            6 => Self::Pubrel,
            7 => Self::Pubcomp,
            8 => Self::Subscribe,
            9 => Self::Suback,
            10 => Self::Unsubscribe,
            11 => Self::Unsuback,
            12 => Self::Pingreq,
            13 => Self::Pingresp,
            14 => Self::Disconnect,
            15 => Self::Auth,
            _ => return None,
        })
    }
}

/// MQTT protocol version (protocol level in the CONNECT variable header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    /// MQTT 3.1.1 (protocol level 4).
    V311,
    /// MQTT 5.0 (protocol level 5).
    V5,
}

impl ProtocolVersion {
    /// Protocol name field on the wire (`"MQTT"` for both versions).
    pub fn protocol_name(self) -> &'static str {
        "MQTT"
    }

    /// Protocol level byte.
    pub fn level(self) -> u8 {
        match self {
            Self::V311 => 4,
            Self::V5 => 5,
        }
    }

    /// Version from the protocol level byte.
    pub fn from_level(level: u8) -> Option<Self> {
        match level {
            4 => Some(Self::V311),
            5 => Some(Self::V5),
            _ => None,
        }
    }

    /// Whether this version carries MQTT 5.0 properties on the wire.
    pub fn is_v5(self) -> bool {
        matches!(self, Self::V5)
    }
}

/// MQTT Quality of Service level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoS {
    /// At most once delivery. No acknowledgment.
    AtMostOnce,
    /// At least once delivery. PUBACK acknowledgment.
    AtLeastOnce,
    /// Exactly once delivery. Four-step handshake.
    ExactlyOnce,
}

impl QoS {
    /// Numeric QoS value (0, 1, or 2).
    pub fn value(self) -> u8 {
        match self {
            Self::AtMostOnce => 0,
            Self::AtLeastOnce => 1,
            Self::ExactlyOnce => 2,
        }
    }

    /// QoS from its numeric value.
    pub fn from_value(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::AtMostOnce),
            1 => Some(Self::AtLeastOnce),
            2 => Some(Self::ExactlyOnce),
            _ => None,
        }
    }
}

/// MQTT 5.0 reason codes (unified table; §2.4 and per-packet sections list
/// which codes are valid for which packet type).
///
/// MQTT 3.1.1 CONNACK uses a narrower return-code table (0-5); those values
/// coincide with the low end of this one and are exposed as `CONNACK_*`
/// constants for clarity at call sites.
pub mod reason {
    /// Success / Normal disconnection / Granted QoS 0.
    pub const SUCCESS: u8 = 0x00;
    /// Granted QoS 1.
    pub const GRANTED_QOS_1: u8 = 0x01;
    /// Granted QoS 2.
    pub const GRANTED_QOS_2: u8 = 0x02;
    /// Disconnect with Will Message.
    pub const DISCONNECT_WITH_WILL_MESSAGE: u8 = 0x04;
    /// No matching subscribers.
    pub const NO_MATCHING_SUBSCRIBERS: u8 = 0x10;
    /// No subscription existed.
    pub const NO_SUBSCRIPTION_EXISTED: u8 = 0x11;
    /// Continue authentication.
    pub const CONTINUE_AUTHENTICATION: u8 = 0x18;
    /// Re-authenticate.
    pub const REAUTHENTICATE: u8 = 0x19;
    /// Unspecified error.
    pub const UNSPECIFIED_ERROR: u8 = 0x80;
    /// Malformed packet.
    pub const MALFORMED_PACKET: u8 = 0x81;
    /// Protocol error.
    pub const PROTOCOL_ERROR: u8 = 0x82;
    /// Implementation specific error.
    pub const IMPLEMENTATION_SPECIFIC_ERROR: u8 = 0x83;
    /// Unsupported protocol version.
    pub const UNSUPPORTED_PROTOCOL_VERSION: u8 = 0x84;
    /// Client identifier not valid.
    pub const CLIENT_IDENTIFIER_NOT_VALID: u8 = 0x85;
    /// Bad user name or password.
    pub const BAD_USER_NAME_OR_PASSWORD: u8 = 0x86;
    /// Not authorized.
    pub const NOT_AUTHORIZED: u8 = 0x87;
    /// Server unavailable.
    pub const SERVER_UNAVAILABLE: u8 = 0x88;
    /// Server busy.
    pub const SERVER_BUSY: u8 = 0x89;
    /// Banned.
    pub const BANNED: u8 = 0x8A;
    /// Server shutting down.
    pub const SERVER_SHUTTING_DOWN: u8 = 0x8B;
    /// Bad authentication method.
    pub const BAD_AUTHENTICATION_METHOD: u8 = 0x8C;
    /// Keep alive timeout.
    pub const KEEP_ALIVE_TIMEOUT: u8 = 0x8D;
    /// Session taken over.
    pub const SESSION_TAKEN_OVER: u8 = 0x8E;
    /// Topic filter invalid.
    pub const TOPIC_FILTER_INVALID: u8 = 0x8F;
    /// Topic name invalid.
    pub const TOPIC_NAME_INVALID: u8 = 0x90;
    /// Packet identifier in use.
    pub const PACKET_IDENTIFIER_IN_USE: u8 = 0x91;
    /// Packet identifier not found.
    pub const PACKET_IDENTIFIER_NOT_FOUND: u8 = 0x92;
    /// Receive Maximum exceeded.
    pub const RECEIVE_MAXIMUM_EXCEEDED: u8 = 0x93;
    /// Topic alias invalid.
    pub const TOPIC_ALIAS_INVALID: u8 = 0x94;
    /// Packet too large.
    pub const PACKET_TOO_LARGE: u8 = 0x95;
    /// Message rate too high.
    pub const MESSAGE_RATE_TOO_HIGH: u8 = 0x96;
    /// Quota exceeded.
    pub const QUOTA_EXCEEDED: u8 = 0x97;
    /// Administrative action.
    pub const ADMINISTRATIVE_ACTION: u8 = 0x98;
    /// Payload format invalid.
    pub const PAYLOAD_FORMAT_INVALID: u8 = 0x99;
    /// Retain not supported.
    pub const RETAIN_NOT_SUPPORTED: u8 = 0x9A;
    /// QoS not supported.
    pub const QOS_NOT_SUPPORTED: u8 = 0x9B;
    /// Use another server.
    pub const USE_ANOTHER_SERVER: u8 = 0x9C;
    /// Server moved.
    pub const SERVER_MOVED: u8 = 0x9D;
    /// Shared subscriptions not supported.
    pub const SHARED_SUBSCRIPTIONS_NOT_SUPPORTED: u8 = 0x9E;
    /// Connection rate exceeded.
    pub const CONNECTION_RATE_EXCEEDED: u8 = 0x9F;
    /// Maximum connect time.
    pub const MAXIMUM_CONNECT_TIME: u8 = 0xA0;
    /// Subscription Identifiers not supported.
    pub const SUBSCRIPTION_IDENTIFIERS_NOT_SUPPORTED: u8 = 0xA1;
    /// Wildcard Subscriptions not supported.
    pub const WILDCARD_SUBSCRIPTIONS_NOT_SUPPORTED: u8 = 0xA2;

    /// MQTT 3.1.1 CONNACK return codes (§3.2.2.3 Table 3.1); a narrower
    /// table than the v5 reason codes above, kept as distinct constants so
    /// callers building a v3.1.1 CONNACK don't reach for a v5-only code.
    pub mod connack_v311 {
        /// Connection accepted.
        pub const ACCEPTED: u8 = 0x00;
        /// Unacceptable protocol version.
        pub const UNACCEPTABLE_PROTOCOL_VERSION: u8 = 0x01;
        /// Identifier rejected.
        pub const IDENTIFIER_REJECTED: u8 = 0x02;
        /// Server unavailable.
        pub const SERVER_UNAVAILABLE: u8 = 0x03;
        /// Bad user name or password.
        pub const BAD_USER_NAME_OR_PASSWORD: u8 = 0x04;
        /// Not authorized.
        pub const NOT_AUTHORIZED: u8 = 0x05;
    }
}

/// Decoded CONNECT packet (type 1).
///
/// Retains a struct (unlike the flat-parameter shape used for every other
/// packet type) because it has a dozen-plus fields.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectPacket {
    /// Protocol version from the Protocol Level field.
    pub version: ProtocolVersion,
    /// Clean Session (3.1.1) / Clean Start (5.0) flag.
    pub clean_session: bool,
    /// Keep Alive interval in seconds (0 disables keepalive).
    pub keep_alive: u16,
    /// MQTT 5.0 CONNECT properties.
    pub properties: Properties,
    /// Client Identifier.
    pub client_id: String,
    /// Will Topic / Payload / QoS / Retain / Properties, if the Will Flag was set.
    pub will: Option<Will>,
    /// User Name, if the User Name Flag was set.
    pub username: Option<String>,
    /// Password, if the Password Flag was set.
    pub password: Option<Vec<u8>>,
}

/// Will Message fields from a CONNECT packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Will {
    /// QoS to publish the Will Message with.
    pub qos: QoS,
    /// Whether the Will Message should be retained.
    pub retain: bool,
    /// Will Topic.
    pub topic: String,
    /// Will Message payload.
    pub payload: Vec<u8>,
    /// MQTT 5.0 Will Properties (Will Delay Interval, etc.).
    pub properties: Properties,
}

/// Decoded PUBLISH variable header (topic, packet id, properties) — the
/// part [`crate::codec::parser::MqttFrameParser`] parses before it starts
/// streaming payload bytes via [`crate::codec::parser::MqttFrameHandler::publish_data`].
#[derive(Debug, Clone, PartialEq)]
pub struct PublishHeader {
    /// Redelivery flag.
    pub dup: bool,
    /// QoS level.
    pub qos: QoS,
    /// Retain flag.
    pub retain: bool,
    /// Topic name.
    pub topic: String,
    /// Packet identifier (present, non-zero, only when `qos != AtMostOnce`).
    pub packet_id: u16,
    /// MQTT 5.0 PUBLISH properties.
    pub properties: Properties,
    /// Payload length in bytes (the parser streams exactly this many bytes
    /// via `publish_data` before calling `end_publish`).
    pub payload_len: u32,
}

/// One topic filter + subscription options from a SUBSCRIBE packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscribeFilter {
    /// Topic filter (may contain `+` / `#` wildcards).
    pub topic_filter: String,
    /// Maximum QoS the server may use to forward matching messages.
    pub max_qos: QoS,
    /// No Local (MQTT 5.0): don't forward the subscriber's own publishes back to it.
    pub no_local: bool,
    /// Retain As Published (MQTT 5.0): keep the RETAIN flag as published rather than always set.
    pub retain_as_published: bool,
    /// Retain Handling (MQTT 5.0, 0-2): when to send retained messages at subscribe time.
    pub retain_handling: u8,
}

impl SubscribeFilter {
    /// Decode subscription options (MQTT 5.0 §3.8.3.1) from one options byte.
    pub fn options_from_byte(topic_filter: String, byte: u8) -> Option<Self> {
        Some(Self {
            topic_filter,
            max_qos: QoS::from_value(byte & 0x03)?,
            no_local: byte & 0x04 != 0,
            retain_as_published: byte & 0x08 != 0,
            retain_handling: (byte >> 4) & 0x03,
        })
    }

    /// Encode subscription options (MQTT 3.1.1 ignores everything but `max_qos`).
    pub fn options_byte(&self) -> u8 {
        let mut b = self.max_qos.value() & 0x03;
        if self.no_local {
            b |= 0x04;
        }
        if self.retain_as_published {
            b |= 0x08;
        }
        b |= (self.retain_handling & 0x03) << 4;
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_type_round_trips_through_value() {
        for t in [
            PacketType::Connect,
            PacketType::Connack,
            PacketType::Publish,
            PacketType::Puback,
            PacketType::Pubrec,
            PacketType::Pubrel,
            PacketType::Pubcomp,
            PacketType::Subscribe,
            PacketType::Suback,
            PacketType::Unsubscribe,
            PacketType::Unsuback,
            PacketType::Pingreq,
            PacketType::Pingresp,
            PacketType::Disconnect,
            PacketType::Auth,
        ] {
            assert_eq!(PacketType::from_value(t.value()), Some(t));
        }
        assert_eq!(PacketType::from_value(0), None);
        assert_eq!(PacketType::from_value(16), None);
    }

    #[test]
    fn protocol_version_from_level() {
        assert_eq!(ProtocolVersion::from_level(4), Some(ProtocolVersion::V311));
        assert_eq!(ProtocolVersion::from_level(5), Some(ProtocolVersion::V5));
        assert_eq!(ProtocolVersion::from_level(3), None);
    }

    #[test]
    fn subscribe_options_round_trip() {
        let f = SubscribeFilter {
            topic_filter: "a/b".into(),
            max_qos: QoS::ExactlyOnce,
            no_local: true,
            retain_as_published: true,
            retain_handling: 2,
        };
        let byte = f.options_byte();
        let parsed = SubscribeFilter::options_from_byte("a/b".into(), byte).unwrap();
        assert_eq!(parsed, f);
    }
}
