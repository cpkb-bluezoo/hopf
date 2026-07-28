// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT server: config, listener factory, `ProtocolHandler`.
//!
//! CONNECT authorization is staged (see [`handler`]), matching
//! `hopf-pop3` / `hopf-imap`'s handler-factory shape — the default checks
//! `MqttConfig::credentials`, and `MqttService::with_handler_factory` swaps
//! in custom policy. PUBLISH and SUBSCRIBE decisions stay inline in
//! `MqttControlHandler` for now (accept once connected, reject a malformed
//! filter/topic); staging those too is future work.

pub mod broker;
mod config;
mod control;
mod handler;
mod service;
mod store;

#[cfg(feature = "websocket")]
pub mod ws;

pub use config::{MqttConfig, DEFAULT_CONNECT_TIMEOUT};
pub use control::MqttControlHandler;
pub use handler::{ConnectDecision, ConnectHandler, DefaultConnectHandler, DefaultMqttHandlerFactory, MqttHandlerFactory};
pub use service::MqttService;
