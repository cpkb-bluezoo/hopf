// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP service configuration and listener factory.

use std::net::SocketAddr;
use std::sync::Arc;

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{IpNet, ProtocolHandler, Runtime, TcpListenerConfig};

use crate::server::control::SmtpControlHandler;
use crate::server::handler::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, SmtpHandlerFactory,
};
use crate::server::metrics::SmtpServerMetrics;

/// Default max message size (35 MiB).
pub const DEFAULT_MAX_MESSAGE_SIZE: u64 = 35 * 1024 * 1024;
/// Default max recipients per transaction.
pub const DEFAULT_MAX_RECIPIENTS: usize = 100;
/// Default max MAIL FROM transactions per SMTP session (RFC 9422 MAILMAX).
pub const DEFAULT_MAX_MAIL_TRANSACTIONS: u32 = 100;

/// SMTP server configuration.
#[derive(Clone)]
pub struct SmtpConfig {
    /// Listen address (default typically `0.0.0.0:25`).
    pub listen: SocketAddr,
    /// Hostname used in greetings and EHLO ads.
    pub hostname: String,
    /// Max message size in bytes.
    pub max_message_size: u64,
    /// Max RCPT TO per transaction (also advertised as LIMITS RCPTMAX).
    pub max_recipients: usize,
    /// Max MAIL FROM commands per session (LIMITS MAILMAX). Counted
    /// regardless of success or failure (RFC 9422 §4.1).
    pub max_mail_transactions: u32,
    /// Require AUTH before MAIL FROM.
    pub auth_required: bool,
    /// Optional TLS acceptor (STARTTLS / implicit).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Implicit TLS from accept (SMTPS).
    pub implicit_tls: bool,
    /// Credential store for AUTH (optional). When set, the full SASL
    /// mechanism set the store supports is advertised and driven via
    /// `hopf_auth::create_server` (same pattern as hopf-pop3/hopf-imap).
    pub store: Option<Arc<dyn CredentialStore>>,
    /// TCP peers allowed to issue XCLIENT (real socket IP, never the
    /// overridden ADDR). Empty = XCLIENT disabled (default; matches
    /// Gumdrop's deny-by-default `isXclientAuthorized`).
    pub xclient_allow: Vec<IpNet>,
}

impl SmtpConfig {
    /// Plain SMTP with hostname.
    pub fn new(listen: SocketAddr, hostname: impl Into<String>) -> Self {
        Self {
            listen,
            hostname: hostname.into(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_recipients: DEFAULT_MAX_RECIPIENTS,
            max_mail_transactions: DEFAULT_MAX_MAIL_TRANSACTIONS,
            auth_required: false,
            tls_acceptor: None,
            implicit_tls: false,
            store: None,
            xclient_allow: Vec::new(),
        }
    }

    /// Attach TLS acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Implicit TLS listener.
    pub fn implicit_tls(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Require authentication before MAIL.
    pub fn auth_required(mut self, yes: bool) -> Self {
        self.auth_required = yes;
        self
    }

    /// Credential store for AUTH.
    pub fn with_store(mut self, store: Arc<dyn CredentialStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Override LIMITS MAILMAX (and the matching session counter).
    pub fn with_max_mail_transactions(mut self, n: u32) -> Self {
        self.max_mail_transactions = n.max(1);
        self
    }

    /// Authorize XCLIENT from these CIDRs (real TCP peer only). Empty
    /// clears the allowlist and disables XCLIENT again.
    pub fn with_xclient_allow(mut self, nets: Vec<IpNet>) -> Self {
        self.xclient_allow = nets;
        self
    }

    /// Whether the real TCP peer may issue XCLIENT.
    pub fn xclient_authorized(&self, peer: SocketAddr) -> bool {
        if self.xclient_allow.is_empty() {
            return false;
        }
        let ip = peer.ip();
        self.xclient_allow.iter().any(|n| n.contains(ip))
    }
}

/// Registers the SMTP listener on a [`Runtime`].
pub struct SmtpService {
    config: SmtpConfig,
    metrics: Arc<SmtpServerMetrics>,
    handler_factory: Arc<dyn SmtpHandlerFactory>,
    otel_metrics: Option<Arc<hopf_otel::SmtpServerMetrics>>,
    export: Option<hopf_otel::ExportHandle>,
    traces_enabled: bool,
}

impl SmtpService {
    /// Stock accept-all handler factory.
    pub fn new(config: SmtpConfig) -> Self {
        let factory = Arc::new(AcceptAllSmtpHandlerFactory::new(
            AcceptAllSmtpHandler::new(config.hostname.clone()),
        ));
        Self {
            config,
            metrics: SmtpServerMetrics::shared(),
            handler_factory: factory,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Custom application handler factory.
    pub fn with_handler_factory(
        config: SmtpConfig,
        factory: Arc<dyn SmtpHandlerFactory>,
    ) -> Self {
        Self {
            config,
            metrics: SmtpServerMetrics::shared(),
            handler_factory: factory,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
        }
    }

    /// Wire OTLP/JSONL SMTP metrics and connection/transaction traces from a pipeline.
    ///
    /// When `traces_enabled` is true (from the pipeline config), handlers see a
    /// W3C `traceparent` on [`SmtpConnectionMetadata`](crate::SmtpConnectionMetadata)
    /// for outbound HTTP propagation via `hopf_otel::with_traceparent`.
    pub fn with_telemetry(mut self, pipeline: &hopf_otel::TelemetryPipeline) -> Self {
        let cfg = pipeline.config();
        if cfg.metrics_enabled {
            self.otel_metrics = Some(pipeline.smtp_metrics());
        }
        if cfg.traces_enabled {
            self.export = Some(pipeline.export_handle());
            self.traces_enabled = true;
        } else if cfg.metrics_enabled {
            // Metrics alone still need the shared export handle (already inside metrics).
            self.export = Some(pipeline.export_handle());
        }
        self
    }

    /// Shared process-local metrics.
    pub fn metrics(&self) -> &Arc<SmtpServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the SMTP port.
    pub fn control_listener(&self, _runtime: Arc<Runtime>) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let otel_metrics = self.otel_metrics.clone();
        let export = self.export.clone();
        let traces_enabled = self.traces_enabled;
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            let peer = SocketAddr::from(([0, 0, 0, 0], 0));
            let local = config.listen;
            Box::new(
                SmtpControlHandler::new(
                    factory.create(),
                    Arc::clone(&metrics),
                    config.clone(),
                    peer,
                    local,
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
    pub fn start(&self, runtime: Arc<Runtime>) -> std::io::Result<SocketAddr> {
        let cfg = self.control_listener(Arc::clone(&runtime));
        let (addr, _) = runtime.add_tcp_listener(cfg)?;
        Ok(addr)
    }
}
