// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SMTP service configuration and listener factory.

use std::net::SocketAddr;
use std::sync::Arc;

use hopf_auth::TrustPolicy;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{ProtocolHandler, Runtime, TcpListenerConfig};

use crate::server::control::SmtpControlHandler;
use crate::server::handler::{
    AcceptAllSmtpHandler, AcceptAllSmtpHandlerFactory, SmtpHandlerFactory,
};
use crate::server::metrics::SmtpServerMetrics;

/// Default max message size (35 MiB).
pub const DEFAULT_MAX_MESSAGE_SIZE: u64 = 35 * 1024 * 1024;
/// Default max recipients per transaction.
pub const DEFAULT_MAX_RECIPIENTS: usize = 100;

/// SMTP server configuration.
#[derive(Clone)]
pub struct SmtpConfig {
    /// Listen address (default typically `0.0.0.0:25`).
    pub listen: SocketAddr,
    /// Hostname used in greetings and EHLO ads.
    pub hostname: String,
    /// Max message size in bytes.
    pub max_message_size: u64,
    /// Max RCPT TO per transaction.
    pub max_recipients: usize,
    /// Require AUTH before MAIL FROM.
    pub auth_required: bool,
    /// Optional TLS acceptor (STARTTLS / implicit).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Implicit TLS from accept (SMTPS).
    pub implicit_tls: bool,
    /// Trust policy for AUTH PLAIN (optional).
    pub policy: Option<Arc<dyn TrustPolicy>>,
}

impl SmtpConfig {
    /// Plain SMTP with hostname.
    pub fn new(listen: SocketAddr, hostname: impl Into<String>) -> Self {
        Self {
            listen,
            hostname: hostname.into(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_recipients: DEFAULT_MAX_RECIPIENTS,
            auth_required: false,
            tls_acceptor: None,
            implicit_tls: false,
            policy: None,
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

    /// Trust policy for AUTH PLAIN.
    pub fn with_policy(mut self, policy: Arc<dyn TrustPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// Registers the SMTP listener on a [`Runtime`].
pub struct SmtpService {
    config: SmtpConfig,
    metrics: Arc<SmtpServerMetrics>,
    handler_factory: Arc<dyn SmtpHandlerFactory>,
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
        }
    }

    /// Shared metrics.
    pub fn metrics(&self) -> &Arc<SmtpServerMetrics> {
        &self.metrics
    }

    /// Build a [`TcpListenerConfig`] for the SMTP port.
    pub fn control_listener(&self, _runtime: Arc<Runtime>) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let metrics = Arc::clone(&self.metrics);
        let config = self.config.clone();
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            let peer = SocketAddr::from(([0, 0, 0, 0], 0));
            let local = config.listen;
            Box::new(SmtpControlHandler::new(
                factory.create(),
                Arc::clone(&metrics),
                config.clone(),
                peer,
                local,
            )) as Box<dyn ProtocolHandler>
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
