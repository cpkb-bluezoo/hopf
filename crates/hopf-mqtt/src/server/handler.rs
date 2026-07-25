// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Staged CONNECT handler SPI (Gumdrop shape, matching `hopf-pop3` /
//! `hopf-imap`'s `HandlerFactory` pattern).
//!
//! Only CONNECT is staged for now — PUBLISH and SUBSCRIBE authorization
//! stay inline in `MqttControlHandler` (accept once connected, reject a
//! malformed filter/topic). Staging those too, with the same `proceed` /
//! `reject` shape POP3/IMAP use for their per-command SPI, is future work.

use std::sync::Arc;

use hopf_auth::CredentialStore;

use crate::codec::packet::{reason, ConnectPacket};

/// A CONNECT authorization decision.
pub enum ConnectDecision {
    /// Let the client in.
    Accept,
    /// Refuse with a version-appropriate CONNACK reason/return code (see
    /// [`crate::codec::packet::reason`] and
    /// [`crate::codec::packet::reason::connack_v311`]).
    Reject(u8),
}

/// Authorizes each CONNECT. One instance per connection (built by
/// [`MqttHandlerFactory::create`]), so implementations can hold
/// per-connection state if needed (most won't).
pub trait ConnectHandler: Send {
    /// Decide whether to accept `packet`.
    fn authorize(&mut self, packet: &ConnectPacket) -> ConnectDecision;
}

/// Factory for [`ConnectHandler`] — one call per accepted TCP connection.
pub trait MqttHandlerFactory: Send + Sync {
    /// Create the handler for a new connection.
    fn create(&self) -> Box<dyn ConnectHandler>;
}

/// Default: accept unconditionally, or require CONNECT username/password to
/// match a [`CredentialStore`] when one is configured.
pub struct DefaultConnectHandler {
    credentials: Option<Arc<dyn CredentialStore>>,
}

impl ConnectHandler for DefaultConnectHandler {
    fn authorize(&mut self, packet: &ConnectPacket) -> ConnectDecision {
        let Some(store) = &self.credentials else {
            return ConnectDecision::Accept;
        };
        let authorized = match (&packet.username, &packet.password) {
            (Some(user), Some(pass)) => store.password_match(user, &String::from_utf8_lossy(pass)),
            _ => false,
        };
        if authorized {
            ConnectDecision::Accept
        } else if packet.version.is_v5() {
            ConnectDecision::Reject(reason::BAD_USER_NAME_OR_PASSWORD)
        } else {
            ConnectDecision::Reject(reason::connack_v311::BAD_USER_NAME_OR_PASSWORD)
        }
    }
}

/// Factory for [`DefaultConnectHandler`].
pub struct DefaultMqttHandlerFactory {
    credentials: Option<Arc<dyn CredentialStore>>,
}

impl DefaultMqttHandlerFactory {
    /// Build from an optional credential store (`None` accepts every CONNECT).
    pub fn new(credentials: Option<Arc<dyn CredentialStore>>) -> Self {
        Self { credentials }
    }
}

impl MqttHandlerFactory for DefaultMqttHandlerFactory {
    fn create(&self) -> Box<dyn ConnectHandler> {
        Box::new(DefaultConnectHandler {
            credentials: self.credentials.clone(),
        })
    }
}
