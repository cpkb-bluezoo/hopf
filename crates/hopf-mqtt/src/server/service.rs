// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! MQTT service registration on a [`Runtime`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::{ProtocolHandler, Runtime, TcpListenerConfig};

use super::config::MqttConfig;
use super::control::MqttControlHandler;
use super::handler::{DefaultMqttHandlerFactory, MqttHandlerFactory};
use super::metrics::MqttServerMetrics;

/// Registers the MQTT TCP listener for a [`MqttConfig`].
pub struct MqttService {
    config: Arc<MqttConfig>,
    handler_factory: Arc<dyn MqttHandlerFactory>,
    metrics: Arc<MqttServerMetrics>,
    otel_metrics: Option<Arc<hopf_otel::MqttServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
}

impl MqttService {
    /// Wrap `config`, authorizing CONNECT via `config.credentials` (or
    /// unconditionally, if `None`).
    pub fn new(config: MqttConfig) -> Self {
        let handler_factory = Arc::new(DefaultMqttHandlerFactory::new(config.credentials.clone()));
        Self {
            config: Arc::new(config),
            handler_factory,
            metrics: MqttServerMetrics::shared(),
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Wrap `config`, authorizing CONNECT via a custom [`MqttHandlerFactory`]
    /// instead of the default `config.credentials` check.
    pub fn with_handler_factory(config: MqttConfig, handler_factory: Arc<dyn MqttHandlerFactory>) -> Self {
        Self {
            config: Arc::new(config),
            handler_factory,
            metrics: MqttServerMetrics::shared(),
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Wire OTLP/JSONL MQTT metrics and connection/publish traces from a pipeline.
    ///
    /// When traces are enabled, handlers see a W3C `traceparent` on
    /// [`MqttConnectionMetadata`](crate::server::MqttConnectionMetadata) for
    /// outbound HTTP via `hopf_otel::with_traceparent`.
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.mqtt_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            self.export = Some(pipeline.export_handle());
        }
        self
    }

    /// Shared process-local metrics.
    pub fn metrics(&self) -> &Arc<MqttServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the MQTT port (for composing with
    /// other listeners via `hopf_core::Composition`, mirroring
    /// `SmtpService::control_listener` / `Pop3Service::control_listener`).
    pub fn control_listener(&self) -> TcpListenerConfig {
        let config = Arc::clone(&self.config);
        let handler_factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        TcpListenerConfig::new(self.config.listen, move || {
            Box::new(
                MqttControlHandler::new(Arc::clone(&config), handler_factory.create(), Arc::clone(&metrics))
                    .with_telemetry(otel_metrics.clone(), export.clone(), traces_enabled),
            ) as Box<dyn ProtocolHandler>
        })
    }

    /// Register the listener directly on `runtime`; returns the bound address.
    pub fn start(&self, runtime: &Runtime) -> io::Result<SocketAddr> {
        let (addr, _) = runtime.add_tcp_listener(self.control_listener())?;
        Ok(addr)
    }
}
