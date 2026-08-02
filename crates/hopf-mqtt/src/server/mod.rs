// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT server: config, listener factory, `ProtocolHandler`.
//!
//! CONNECT / PUBLISH / SUBSCRIBE authorization is staged (see [`handler`]),
//! matching Gumdrop and `hopf-pop3` / `hopf-imap`'s handler-factory shape —
//! the default requires [`MqttConfig::with_credentials`] or
//! [`MqttConfig::allow_anonymous`]; PUBLISH/SUBSCRIBE still default to
//! accept-all. `MqttService::with_handler_factory` swaps in custom policy.

pub mod auth;
pub mod broker;
mod config;
mod control;
mod expiry;
mod handler;
mod metrics;
mod publish_spool;
mod service;
pub mod store;

#[cfg(feature = "websocket")]
pub mod ws;

pub use config::{MqttConfig, DEFAULT_CONNECT_TIMEOUT};
pub use control::MqttControlHandler;
pub use handler::{
    AcceptAllPublishHandler, AcceptAllSubscribeHandler, ConnectDecision, ConnectHandler,
    DefaultConnectHandler, DefaultMqttHandlerFactory, MqttConnectionMetadata, MqttHandlerFactory,
    PublishDecision, PublishHandler, SubscribeDecision, SubscribeHandler,
};
pub use metrics::MqttServerMetrics;
pub use service::MqttService;
pub use store::{
    queued_message, FileBackedMessageStore, InMemoryMessageStore, MqttMessageStore, QueuedMessage,
};
