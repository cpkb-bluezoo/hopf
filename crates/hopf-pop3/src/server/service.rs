// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! POP3 service configuration and listener factory.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_mailbox::MailboxFactory;

use crate::server::control::Pop3ControlHandler;
use crate::server::handler::{DefaultPop3HandlerFactory, Pop3HandlerFactory};
use crate::server::metrics::Pop3ServerMetrics;

/// Default transaction idle timeout (10 minutes).
pub const DEFAULT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(600);

/// POP3 server configuration.
#[derive(Clone)]
pub struct Pop3Config {
    /// Listen address (default typically `0.0.0.0:110`).
    pub listen: SocketAddr,
    /// Hostname for greetings and APOP timestamps.
    pub hostname: String,
    /// Credential store (USER/PASS, APOP, SASL).
    pub store: Arc<dyn CredentialStore>,
    /// Mailbox factory (opens INBOX after auth).
    pub mailbox_factory: Arc<dyn MailboxFactory>,
    /// Optional TLS acceptor (STLS / implicit).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Implicit TLS from accept (POP3S).
    pub implicit_tls: bool,
    /// Greeting text (without `+OK` prefix). Empty → built-in.
    pub greeting: String,
    /// Advertise and accept APOP.
    pub enable_apop: bool,
    /// Advertise and accept UTF8.
    pub enable_utf8: bool,
    /// Advertise PIPELINING in CAPA (pipelining always works).
    pub enable_pipelining: bool,
    /// Delay after a failed auth before the next attempt is accepted.
    pub login_delay: Duration,
    /// CAPA EXPIRE days (`None` = omit EXPIRE line).
    pub expire_days: Option<u32>,
    /// Idle timeout in TRANSACTION state.
    pub transaction_timeout: Duration,
}

impl Pop3Config {
    /// Plain POP3 with credential store and mailbox factory.
    pub fn new(
        listen: SocketAddr,
        hostname: impl Into<String>,
        store: Arc<dyn CredentialStore>,
        mailbox_factory: Arc<dyn MailboxFactory>,
    ) -> Self {
        Self {
            listen,
            hostname: hostname.into(),
            store,
            mailbox_factory,
            tls_acceptor: None,
            implicit_tls: false,
            greeting: String::new(),
            enable_apop: true,
            enable_utf8: true,
            enable_pipelining: false,
            login_delay: Duration::ZERO,
            expire_days: None,
            transaction_timeout: DEFAULT_TRANSACTION_TIMEOUT,
        }
    }

    /// Attach TLS acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Implicit TLS listener (POP3S).
    pub fn implicit_tls(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Custom greeting banner text.
    pub fn with_greeting(mut self, greeting: impl Into<String>) -> Self {
        self.greeting = greeting.into();
        self
    }
}

/// Registers the POP3 listener on a [`Runtime`].
pub struct Pop3Service {
    config: Pop3Config,
    metrics: Arc<Pop3ServerMetrics>,
    handler_factory: Arc<dyn Pop3HandlerFactory>,
    runtime: Arc<Runtime>,
    otel_metrics: Option<Arc<hopf_otel::Pop3ServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
}

impl Pop3Service {
    /// Stock default handler factory.
    pub fn new(config: Pop3Config, runtime: Arc<Runtime>) -> Self {
        let greeting = if config.greeting.is_empty() {
            format!("{} POP3 server ready", config.hostname)
        } else {
            config.greeting.clone()
        };
        let factory = Arc::new(DefaultPop3HandlerFactory::new(greeting));
        Self {
            config,
            metrics: Pop3ServerMetrics::shared(),
            handler_factory: factory,
            runtime,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Custom application handler factory.
    pub fn with_handler_factory(
        config: Pop3Config,
        runtime: Arc<Runtime>,
        factory: Arc<dyn Pop3HandlerFactory>,
    ) -> Self {
        Self {
            config,
            metrics: Pop3ServerMetrics::shared(),
            handler_factory: factory,
            runtime,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Wire OTLP/JSONL POP3 metrics and connection/retrieve traces from a pipeline.
    ///
    /// When traces are enabled, handlers see a W3C `traceparent` on
    /// [`Pop3ConnectionMetadata`](crate::Pop3ConnectionMetadata) for outbound
    /// HTTP via `hopf_otel::with_traceparent`.
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.pop3_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            self.export = Some(pipeline.export_handle());
        }
        self
    }

    /// Shared metrics.
    pub fn metrics(&self) -> &Arc<Pop3ServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the POP3 port.
    pub fn control_listener(&self) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let runtime = Arc::clone(&self.runtime);
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            Box::new(
                Pop3ControlHandler::new(
                    factory.create(),
                    Arc::clone(&metrics),
                    config.clone(),
                    Arc::clone(&runtime),
                )
                .with_telemetry(otel_metrics.clone(), export.clone(), traces_enabled),
            ) as Box<dyn ProtocolHandler>
        });
        if let Some(tls) = &self.config.tls_acceptor {
            if self.config.implicit_tls {
                cfg = cfg.with_tls(Arc::clone(tls));
            } else {
                cfg = cfg.with_starttls_acceptor(Arc::clone(tls));
            }
        }
        cfg
    }

    /// Register the listener; returns bound address.
    pub fn start(&self) -> std::io::Result<SocketAddr> {
        let cfg = self.control_listener();
        let (addr, _) = self.runtime.add_tcp_listener(cfg)?;
        Ok(addr)
    }
}
