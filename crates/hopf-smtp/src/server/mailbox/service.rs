// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`LocalDeliveryService`] — SMTP service that delivers to local mailboxes.

use std::net::SocketAddr;
use std::sync::Arc;

use hopf_core::Runtime;
use hopf_mailbox::MailboxFactory;

use crate::server::service::{SmtpConfig, SmtpService};

use super::handler::LocalDeliveryHandlerFactory;

/// Local-delivery SMTP service (Gumdrop `LocalDeliveryService`).
///
/// Accepts mail only for `local_domain`. The local-part of each RCPT TO is the
/// mailbox username. Messages are APPENDed to `INBOX` on the Runtime storage
/// pool.
///
/// # Properties
///
/// | Property | Source | Required | Notes |
/// |----------|--------|:--------:|-------|
/// | `local_domain` | constructor | yes | Case-insensitive domain match at RCPT TO |
/// | `hostname` | [`SmtpConfig::hostname`] | yes | Greeting / EHLO banner |
/// | `mailbox_factory` | constructor | yes | mbox or Maildir++ factory |
/// | `max_message_size` | [`SmtpConfig`] | no | Default ~35 MiB |
/// | `max_recipients` | [`SmtpConfig`] | no | Default 100 |
/// | `auth_required` | [`SmtpConfig`] | no | Submission-style AUTH gate |
/// | `policy` | [`SmtpConfig`] | no | TrustPolicy for AUTH PLAIN |
/// | TLS | [`SmtpConfig`] | no | STARTTLS / implicit SMTPS |
pub struct LocalDeliveryService {
    smtp: SmtpService,
    local_domain: String,
    hostname: String,
}

impl LocalDeliveryService {
    /// Build from SMTP config, Runtime (for the storage pool), mailbox factory,
    /// and the single local domain this MX accepts.
    ///
    /// # Panics
    ///
    /// Panics if `local_domain` is empty (mirrors Gumdrop's start-time check).
    pub fn new(
        config: SmtpConfig,
        runtime: Arc<Runtime>,
        mailbox_factory: Arc<dyn MailboxFactory>,
        local_domain: impl Into<String>,
    ) -> Self {
        let local_domain = local_domain.into();
        assert!(
            !local_domain.is_empty(),
            "local_domain must be configured for LocalDeliveryService"
        );
        let hostname = config.hostname.clone();
        let factory = Arc::new(LocalDeliveryHandlerFactory::new(
            mailbox_factory,
            Arc::clone(&runtime),
            local_domain.clone(),
            hostname.clone(),
        ));
        let smtp = SmtpService::with_handler_factory(config, factory);
        Self {
            smtp,
            local_domain,
            hostname,
        }
    }

    /// Domain this service accepts (case-insensitive comparison at RCPT TO).
    pub fn local_domain(&self) -> &str {
        &self.local_domain
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
