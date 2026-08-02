// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Staged CONNECT / PUBLISH / SUBSCRIBE handler SPI (Gumdrop shape, matching
//! `hopf-pop3` / `hopf-imap`'s `HandlerFactory` pattern).
//!
//! Default implementations accept all traffic (subject to CONNECT
//! username/password when a [`CredentialStore`] is configured). Custom
//! factories override [`MqttHandlerFactory`] to install policy per stage.

use std::net::SocketAddr;
use std::sync::Arc;

use hopf_auth::CredentialStore;

use crate::codec::packet::{reason, ConnectPacket, QoS};
use crate::codec::SubscribeFilter;

/// Per-connection metadata visible to handlers.
#[derive(Debug, Clone)]
pub struct MqttConnectionMetadata {
    /// Client address.
    pub peer: SocketAddr,
    /// Local listen address.
    pub local: SocketAddr,
    /// Transport has TLS.
    pub tls: bool,
    /// Assigned / accepted client id after CONNECT (filled after auth).
    pub client_id: Option<String>,
    /// W3C `traceparent` for the active span when OTel traces are enabled.
    ///
    /// Pass to outbound HTTP clients (for example
    /// `hopf_otel::with_traceparent`) so microservice calls continue the
    /// distributed trace. Timing/duration stay in telemetry — this field is
    /// propagation identity only.
    pub traceparent: Option<String>,
}

/// A CONNECT authorization decision.
pub enum ConnectDecision {
    /// Let the client in.
    Accept,
    /// Refuse with a version-appropriate CONNACK reason/return code (see
    /// [`crate::codec::packet::reason`] and
    /// [`crate::codec::packet::reason::connack_v311`]).
    Reject(u8),
}

/// A PUBLISH authorization decision.
pub enum PublishDecision {
    /// Allow the publish to proceed.
    Accept,
    /// Reject with a PUBACK/PUBREC reason code (MQTT 5) or disconnect (v3).
    Reject(u8),
}

/// A single SUBSCRIBE filter authorization decision.
pub enum SubscribeDecision {
    /// Grant the subscription at the requested (or reduced) QoS.
    Accept(QoS),
    /// Reject this filter with a SUBACK reason code.
    Reject(u8),
}

/// Authorizes each CONNECT. One instance per connection (built by
/// [`MqttHandlerFactory::create`]), so implementations can hold
/// per-connection state if needed (most won't).
pub trait ConnectHandler: Send {
    /// Decide whether to accept `packet`.
    fn authorize(
        &mut self,
        packet: &ConnectPacket,
        meta: &MqttConnectionMetadata,
    ) -> ConnectDecision;
}

/// Authorizes each PUBLISH (Gumdrop `PublishHandler` parity).
pub trait PublishHandler: Send {
    /// Decide whether to accept a publish to `topic`.
    fn authorize(
        &mut self,
        client_id: &str,
        topic: &str,
        qos: QoS,
        retain: bool,
        meta: &MqttConnectionMetadata,
    ) -> PublishDecision;
}

/// Authorizes each SUBSCRIBE filter (Gumdrop `SubscribeHandler` parity).
pub trait SubscribeHandler: Send {
    /// Decide whether to accept `filter` for `client_id`.
    fn authorize(
        &mut self,
        client_id: &str,
        filter: &SubscribeFilter,
        meta: &MqttConnectionMetadata,
    ) -> SubscribeDecision;
}

/// Factory for per-connection staged handlers.
pub trait MqttHandlerFactory: Send + Sync {
    /// Create the CONNECT handler for a new connection.
    fn create(&self) -> Box<dyn ConnectHandler>;

    /// Create the PUBLISH handler for a new connection.
    fn create_publish(&self) -> Box<dyn PublishHandler> {
        Box::new(AcceptAllPublishHandler)
    }

    /// Create the SUBSCRIBE handler for a new connection.
    fn create_subscribe(&self) -> Box<dyn SubscribeHandler> {
        Box::new(AcceptAllSubscribeHandler)
    }
}

/// Default: require CONNECT credentials when a store is configured; reject
/// anonymous CONNECT unless [`MqttConfig::allow_anonymous`] was set.
pub struct DefaultConnectHandler {
    credentials: Option<Arc<dyn CredentialStore>>,
    allow_anonymous: bool,
}

impl ConnectHandler for DefaultConnectHandler {
    fn authorize(
        &mut self,
        packet: &ConnectPacket,
        _meta: &MqttConnectionMetadata,
    ) -> ConnectDecision {
        let reject = || {
            if packet.version.is_v5() {
                ConnectDecision::Reject(reason::NOT_AUTHORIZED)
            } else {
                ConnectDecision::Reject(reason::connack_v311::NOT_AUTHORIZED)
            }
        };
        let reject_bad_pass = || {
            if packet.version.is_v5() {
                ConnectDecision::Reject(reason::BAD_USER_NAME_OR_PASSWORD)
            } else {
                ConnectDecision::Reject(reason::connack_v311::BAD_USER_NAME_OR_PASSWORD)
            }
        };

        match &self.credentials {
            Some(store) => {
                let authorized = match (&packet.username, &packet.password) {
                    (Some(user), Some(pass)) => {
                        store.password_match(user, &String::from_utf8_lossy(pass))
                    }
                    _ => false,
                };
                if authorized {
                    ConnectDecision::Accept
                } else {
                    reject_bad_pass()
                }
            }
            None if self.allow_anonymous => ConnectDecision::Accept,
            None => reject(),
        }
    }
}

/// Default PUBLISH policy: accept everything.
pub struct AcceptAllPublishHandler;

impl PublishHandler for AcceptAllPublishHandler {
    fn authorize(
        &mut self,
        _client_id: &str,
        _topic: &str,
        _qos: QoS,
        _retain: bool,
        _meta: &MqttConnectionMetadata,
    ) -> PublishDecision {
        PublishDecision::Accept
    }
}

/// Default SUBSCRIBE policy: accept everything at the requested QoS.
pub struct AcceptAllSubscribeHandler;

impl SubscribeHandler for AcceptAllSubscribeHandler {
    fn authorize(
        &mut self,
        _client_id: &str,
        filter: &SubscribeFilter,
        _meta: &MqttConnectionMetadata,
    ) -> SubscribeDecision {
        SubscribeDecision::Accept(filter.max_qos)
    }
}

/// Factory for [`DefaultConnectHandler`] (+ accept-all publish/subscribe).
pub struct DefaultMqttHandlerFactory {
    credentials: Option<Arc<dyn CredentialStore>>,
    allow_anonymous: bool,
}

impl DefaultMqttHandlerFactory {
    /// Build from config fields (`credentials` + `allow_anonymous`).
    pub fn new(credentials: Option<Arc<dyn CredentialStore>>, allow_anonymous: bool) -> Self {
        Self {
            credentials,
            allow_anonymous,
        }
    }
}

impl MqttHandlerFactory for DefaultMqttHandlerFactory {
    fn create(&self) -> Box<dyn ConnectHandler> {
        Box::new(DefaultConnectHandler {
            credentials: self.credentials.clone(),
            allow_anonymous: self.allow_anonymous,
        })
    }
}

#[cfg(test)]
mod default_connect_tests {
    use super::*;
    use crate::codec::packet::{ConnectPacket, ProtocolVersion};
    use crate::codec::properties::Properties;
    use std::net::{IpAddr, Ipv4Addr};

    fn meta() -> MqttConnectionMetadata {
        MqttConnectionMetadata {
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1883),
            tls: false,
            client_id: None,
            traceparent: None,
        }
    }

    fn pkt() -> ConnectPacket {
        ConnectPacket {
            version: ProtocolVersion::V5,
            clean_session: true,
            keep_alive: 60,
            properties: Properties::new(),
            client_id: "c".into(),
            will: None,
            username: None,
            password: None,
        }
    }

    #[test]
    fn rejects_when_neither_credentials_nor_anonymous() {
        let mut h = DefaultConnectHandler {
            credentials: None,
            allow_anonymous: false,
        };
        assert!(matches!(
            h.authorize(&pkt(), &meta()),
            ConnectDecision::Reject(_)
        ));
    }

    #[test]
    fn accepts_anonymous_when_opted_in() {
        let mut h = DefaultConnectHandler {
            credentials: None,
            allow_anonymous: true,
        };
        assert!(matches!(
            h.authorize(&pkt(), &meta()),
            ConnectDecision::Accept
        ));
    }
}
