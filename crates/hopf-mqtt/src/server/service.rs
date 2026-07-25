// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT service registration on a [`Runtime`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ProtocolHandler, Runtime, TcpListenerConfig};

use super::config::MqttConfig;
use super::control::MqttControlHandler;
use super::handler::{DefaultMqttHandlerFactory, MqttHandlerFactory};

/// Registers the MQTT TCP listener for a [`MqttConfig`].
pub struct MqttService {
    config: Arc<MqttConfig>,
    handler_factory: Arc<dyn MqttHandlerFactory>,
}

impl MqttService {
    /// Wrap `config`, authorizing CONNECT via `config.credentials` (or
    /// unconditionally, if `None`).
    pub fn new(config: MqttConfig) -> Self {
        let handler_factory = Arc::new(DefaultMqttHandlerFactory::new(config.credentials.clone()));
        Self {
            config: Arc::new(config),
            handler_factory,
        }
    }

    /// Wrap `config`, authorizing CONNECT via a custom [`MqttHandlerFactory`]
    /// instead of the default `config.credentials` check.
    pub fn with_handler_factory(config: MqttConfig, handler_factory: Arc<dyn MqttHandlerFactory>) -> Self {
        Self {
            config: Arc::new(config),
            handler_factory,
        }
    }

    /// Build a [`TcpListenerConfig`] for the MQTT port (for composing with
    /// other listeners via `hopf_core::Composition`, mirroring
    /// `SmtpService::control_listener` / `Pop3Service::control_listener`).
    pub fn control_listener(&self) -> TcpListenerConfig {
        let config = Arc::clone(&self.config);
        let handler_factory = Arc::clone(&self.handler_factory);
        TcpListenerConfig::new(self.config.listen, move || {
            Box::new(MqttControlHandler::new(Arc::clone(&config), handler_factory.create())) as Box<dyn ProtocolHandler>
        })
    }

    /// Register the listener directly on `runtime`; returns the bound address.
    pub fn start(&self, runtime: &Runtime) -> io::Result<SocketAddr> {
        let (addr, _) = runtime.add_tcp_listener(self.control_listener())?;
        Ok(addr)
    }
}
