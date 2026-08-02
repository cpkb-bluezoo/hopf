// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! IMAP server configuration and listener factory.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hopf_auth::CredentialStore;
use hopf_core::tls::SharedTlsAcceptor;
use hopf_core::{ProtocolHandler, Runtime, TcpListenerConfig};
use hopf_mailbox::MailboxFactory;

use crate::server::handler::{DefaultImapHandlerFactory, ImapHandlerFactory};
use crate::server::quota::{QuotaManager, UnlimitedQuotaManager};
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
    /// When set, send a `PREAUTH` greeting and open this user's store
    /// (external authentication — RFC 9051 §7.1). Empty / `None` → normal `OK`.
    pub preauth_username: Option<String>,
    /// Max command-line length.
    pub max_line: usize,
    /// Advertise and accept IDLE (RFC 2177).
    pub enable_idle: bool,
    /// Maximum IDLE duration before the server ends the command with a tagged OK.
    /// Default: 29 minutes (RFC 2177 client guidance).
    pub idle_max_duration: std::time::Duration,
    /// Advertise and accept NAMESPACE (RFC 2342).
    pub enable_namespace: bool,
    /// Other-users namespace descriptors for NAMESPACE (empty → `NIL`).
    pub other_users_namespaces: Vec<NamespaceDesc>,
    /// Shared namespace descriptors for NAMESPACE (empty → `NIL`).
    pub shared_namespaces: Vec<NamespaceDesc>,
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

/// One NAMESPACE triple: prefix + hierarchy delimiter (RFC 2342).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceDesc {
    /// Namespace prefix (e.g. `"#shared/"`).
    pub prefix: String,
    /// Hierarchy delimiter character.
    pub delimiter: char,
}

impl NamespaceDesc {
    /// Construct a namespace descriptor.
    pub fn new(prefix: impl Into<String>, delimiter: char) -> Self {
        Self {
            prefix: prefix.into(),
            delimiter,
        }
    }
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
            preauth_username: None,
            max_line: DEFAULT_MAX_LINE,
            enable_idle: true,
            idle_max_duration: crate::server::idle::IDLE_MAX_DURATION,
            enable_namespace: true,
            other_users_namespaces: Vec::new(),
            shared_namespaces: Vec::new(),
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

    /// Emit a PREAUTH greeting and open `username`'s store (external auth).
    pub fn with_preauth(mut self, username: impl Into<String>) -> Self {
        self.preauth_username = Some(username.into());
        self
    }

    /// Other-users NAMESPACE entries (RFC 2342).
    pub fn with_other_users_namespaces(mut self, ns: Vec<NamespaceDesc>) -> Self {
        self.other_users_namespaces = ns;
        self
    }

    /// Shared NAMESPACE entries (RFC 2342).
    pub fn with_shared_namespaces(mut self, ns: Vec<NamespaceDesc>) -> Self {
        self.shared_namespaces = ns;
        self
    }

    /// Maximum IDLE duration before auto-completing the command.
    pub fn with_idle_max_duration(mut self, d: std::time::Duration) -> Self {
        self.idle_max_duration = d;
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
        let factory = Arc::new(DefaultImapHandlerFactory::new(greeting).with_preauth(
            config.preauth_username.clone(),
        ));
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
