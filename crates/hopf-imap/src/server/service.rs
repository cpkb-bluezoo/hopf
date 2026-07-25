// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP server configuration and listener factory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_mailbox::MailboxFactory;

use crate::handler::{DefaultImapHandlerFactory, ImapHandlerFactory};
use crate::quota::{QuotaManager, UnlimitedQuotaManager};
use crate::server::control::ImapControlHandler;

/// Default max command line (octets).
pub const DEFAULT_MAX_LINE: usize = crate::server::codec::MAX_COMMAND_LINE;

/// IMAP server configuration.
#[derive(Clone)]
pub struct ImapConfig {
    /// Listen address (default typically `0.0.0.0:143`).
    pub listen: SocketAddr,
    /// Hostname for greetings and capabilities.
    pub hostname: String,
    /// Credential store (LOGIN / AUTHENTICATE PLAIN).
    pub store: Arc<dyn CredentialStore>,
    /// Mailbox factory (opens store after auth).
    pub mailbox_factory: Arc<dyn MailboxFactory>,
    /// Optional TLS acceptor (STARTTLS / implicit).
    pub tls_acceptor: Option<SharedTlsAcceptor>,
    /// Implicit TLS from accept (IMAPS).
    pub implicit_tls: bool,
    /// Greeting text (without untagged OK / capability prefix). Empty → built-in.
    pub greeting: String,
    /// Max command-line length.
    pub max_line: usize,
    /// Advertise and accept IDLE (RFC 2177).
    pub enable_idle: bool,
    /// Advertise and accept NAMESPACE (RFC 2342).
    pub enable_namespace: bool,
    /// Advertise and accept QUOTA (RFC 9208).
    pub enable_quota: bool,
    /// Advertise and accept MOVE (RFC 6851).
    pub enable_move: bool,
    /// Advertise CONDSTORE (RFC 7162); ENABLE required for session use.
    pub enable_condstore: bool,
    /// Advertise QRESYNC (RFC 7162); ENABLE required for session use.
    pub enable_qresync: bool,
    /// Advertise ENABLE (RFC 5161).
    pub enable_enable: bool,
    /// Quota backend (default: unlimited).
    pub quota_manager: Arc<dyn QuotaManager>,
    /// Server ID fields for the ID command (RFC 2971). Empty → built-in defaults.
    pub server_id: BTreeMap<String, String>,
}

impl ImapConfig {
    /// Plain IMAP with credential store and mailbox factory.
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
            max_line: DEFAULT_MAX_LINE,
            enable_idle: true,
            enable_namespace: true,
            enable_quota: true,
            enable_move: true,
            enable_condstore: true,
            enable_qresync: true,
            enable_enable: true,
            quota_manager: Arc::new(UnlimitedQuotaManager),
            server_id: BTreeMap::new(),
        }
    }

    /// Attach TLS acceptor.
    pub fn with_tls(mut self, acceptor: SharedTlsAcceptor) -> Self {
        self.tls_acceptor = Some(acceptor);
        self
    }

    /// Implicit TLS listener (IMAPS).
    pub fn implicit_tls(mut self) -> Self {
        self.implicit_tls = true;
        self
    }

    /// Custom greeting banner text.
    pub fn with_greeting(mut self, greeting: impl Into<String>) -> Self {
        self.greeting = greeting.into();
        self
    }

    /// Replace the quota manager.
    pub fn with_quota_manager(mut self, mgr: Arc<dyn QuotaManager>) -> Self {
        self.quota_manager = mgr;
        self
    }

    /// Set ID command fields.
    pub fn with_server_id(mut self, fields: BTreeMap<String, String>) -> Self {
        self.server_id = fields;
        self
    }
}

/// Registers the IMAP listener on a [`Runtime`].
pub struct ImapService {
    config: ImapConfig,
    handler_factory: Arc<dyn ImapHandlerFactory>,
    runtime: Arc<Runtime>,
}

impl ImapService {
    /// Stock default handler factory.
    pub fn new(config: ImapConfig, runtime: Arc<Runtime>) -> Self {
        let greeting = if config.greeting.is_empty() {
            format!("{} IMAP4rev2 server ready", config.hostname)
        } else {
            config.greeting.clone()
        };
        let factory = Arc::new(DefaultImapHandlerFactory::new(greeting));
        Self {
            config,
            handler_factory: factory,
            runtime,
        }
    }

    /// Custom application handler factory.
    pub fn with_handler_factory(
        config: ImapConfig,
        runtime: Arc<Runtime>,
        factory: Arc<dyn ImapHandlerFactory>,
    ) -> Self {
        Self {
            config,
            handler_factory: factory,
            runtime,
        }
    }

    /// Build a [`TcpListenerConfig`] for the IMAP port.
    pub fn control_listener(&self) -> TcpListenerConfig {
        let factory = Arc::clone(&self.handler_factory);
        let config = self.config.clone();
        let runtime = Arc::clone(&self.runtime);
        let mut cfg = TcpListenerConfig::new(self.config.listen, move || {
            Box::new(ImapControlHandler::new(
                factory.create(),
                config.clone(),
                Arc::clone(&runtime),
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
    pub fn start(&self) -> std::io::Result<SocketAddr> {
        let cfg = self.control_listener();
        let (addr, _) = self.runtime.add_tcp_listener(cfg)?;
        Ok(addr)
    }
}
