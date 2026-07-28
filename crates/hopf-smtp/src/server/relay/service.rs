// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`SimpleRelayService`] — SMTP service with shared [`DnsResolver`] for MX relay.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hopf_core::Runtime;
use hopf_dns::DnsResolver;

use crate::server::service::{SmtpConfig, SmtpService};

use super::handler::SimpleRelayHandlerFactory;

/// MX-based open-relay SMTP service (Gumdrop `SimpleRelayService`).
///
/// Creates [`super::SimpleRelayHandler`] instances that accept mail for any
/// domain, look up MX records via [`DnsResolver`], and forward with
/// [`crate::SmtpClient`].
pub struct SimpleRelayService {
    smtp: SmtpService,
    dns: Arc<DnsResolver>,
    hostname: String,
}

impl SimpleRelayService {
    /// Build from SMTP config + runtime (opens a system DNS resolver on a worker).
    pub fn new(config: SmtpConfig, runtime: Arc<Runtime>) -> std::io::Result<Self> {
        Self::with_dns_timeout(config, runtime, Duration::from_secs(5))
    }

    /// As [`Self::new`] with an explicit DNS query timeout.
    pub fn with_dns_timeout(
        config: SmtpConfig,
        runtime: Arc<Runtime>,
        dns_timeout: Duration,
    ) -> std::io::Result<Self> {
        let hostname = config.hostname.clone();
        let dns = Arc::new(DnsResolver::for_runtime(&runtime)?);
        dns.set_timeout(dns_timeout);
        let factory = Arc::new(
            SimpleRelayHandlerFactory::new(Arc::clone(&dns), Arc::clone(&runtime), hostname.clone())
                .with_outbound_port(25),
        );
        let smtp = SmtpService::with_handler_factory(config, factory);
        Ok(Self {
            smtp,
            dns,
            hostname,
        })
    }

    /// Use an already-configured resolver (e.g. custom upstreams / test stub).
    pub fn with_resolver(
        config: SmtpConfig,
        runtime: Arc<Runtime>,
        dns: Arc<DnsResolver>,
        outbound_port: u16,
    ) -> Self {
        let hostname = config.hostname.clone();
        let factory = Arc::new(
            SimpleRelayHandlerFactory::new(Arc::clone(&dns), Arc::clone(&runtime), hostname.clone())
                .with_outbound_port(outbound_port),
        );
        let smtp = SmtpService::with_handler_factory(config, factory);
        Self {
            smtp,
            dns,
            hostname,
        }
    }

    /// Shared DNS resolver.
    pub fn dns(&self) -> &Arc<DnsResolver> {
        &self.dns
    }

    /// Local EHLO / greeting hostname.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// Underlying SMTP service.
    pub fn smtp(&self) -> &SmtpService {
        &self.smtp
    }

    /// Register the SMTP listener; returns bound address.
    pub fn start(&self, runtime: Arc<Runtime>) -> std::io::Result<SocketAddr> {
        self.smtp.start(runtime)
    }
}
