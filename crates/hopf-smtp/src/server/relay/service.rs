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
///
/// **Security:** this is an open relay by design. Prefer a non-empty
/// [`SmtpConfig::acl`] allow list and keep [`SmtpConfig::auth_required`]
/// enabled unless you intentionally turn it off. [`Self::start`] warns via
/// telemetry when no CIDR allow list is configured, but does not refuse to
/// start.
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
    ///
    /// When [`SmtpConfig::acl`] has an empty allow list (open to every peer),
    /// emits a telemetry warning — open relays without a CIDR allowlist are
    /// a common abuse vector. Startup is not blocked.
    pub fn start(&self, runtime: Arc<Runtime>) -> std::io::Result<SocketAddr> {
        if self.smtp.config().acl.allow.is_empty() {
            let msg = "SimpleRelayService started with no PeerAcl allow CIDRs \
                       (open to all peers); configure SmtpConfig::with_acl if \
                       this is not intentional";
            if let Some(t) = runtime.telemetry() {
                t.on_warn(msg);
            } else {
                // No telemetry hook — still surface on stderr so operators notice.
                eprintln!("hopf-smtp: WARN: {msg}");
            }
        }
        self.smtp.start(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::{IpNet, PeerAcl, RuntimeConfig, TelemetryHook};
    use std::sync::Mutex;

    struct WarnCapture {
        msgs: Mutex<Vec<String>>,
    }

    impl TelemetryHook for WarnCapture {
        fn on_warn(&self, msg: &str) {
            self.msgs.lock().unwrap().push(msg.to_string());
        }
    }

    #[test]
    fn start_without_allow_cidrs_emits_telemetry_warning() {
        let capture = Arc::new(WarnCapture {
            msgs: Mutex::new(Vec::new()),
        });
        let hook: Arc<dyn TelemetryHook> = capture.clone();
        let rt = Arc::new(Runtime::start_with_telemetry(RuntimeConfig::default(), Some(hook)).unwrap());
        let config = SmtpConfig::new("127.0.0.1:0".parse().unwrap(), "relay.test").auth_required(false);
        let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());
        let relay = SimpleRelayService::with_resolver(config, Arc::clone(&rt), dns, 25);
        let _addr = relay.start(Arc::clone(&rt)).unwrap();
        let msgs = capture.msgs.lock().unwrap();
        assert!(
            msgs.iter().any(|m| m.contains("no PeerAcl allow CIDRs")),
            "expected open-relay CIDR warning, got {msgs:?}"
        );
        drop(relay);
        drop(msgs);
        // Allow the Arc to drop uniquely so Runtime::shutdown can run.
        drop(rt);
    }

    #[test]
    fn start_with_allow_cidrs_is_silent() {
        let capture = Arc::new(WarnCapture {
            msgs: Mutex::new(Vec::new()),
        });
        let hook: Arc<dyn TelemetryHook> = capture.clone();
        let rt = Arc::new(Runtime::start_with_telemetry(RuntimeConfig::default(), Some(hook)).unwrap());
        let acl = PeerAcl {
            allow: vec![IpNet::parse("127.0.0.0/8").unwrap()],
            deny: Vec::new(),
        };
        let config = SmtpConfig::new("127.0.0.1:0".parse().unwrap(), "relay.test")
            .auth_required(false)
            .with_acl(acl);
        let dns = Arc::new(DnsResolver::for_runtime(&rt).unwrap());
        let relay = SimpleRelayService::with_resolver(config, Arc::clone(&rt), dns, 25);
        let _addr = relay.start(Arc::clone(&rt)).unwrap();
        assert!(
            capture.msgs.lock().unwrap().is_empty(),
            "must not warn when allow CIDRs are configured"
        );
        drop(relay);
        drop(rt);
    }
}
