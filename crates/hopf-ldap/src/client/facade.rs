// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! High-level LDAP client facade ([`LdapClient`]).

use std::sync::{Arc, Mutex};

use hopf_core::{Runtime, TcpConnectorConfig, UnixConnectorConfig};

use super::endpoint::LdapEndpoint;
use super::session::{LdapSession, LdapShared, ReadyCallback};
use super::types::{LdapClientConfig, LdapError};

/// LDAPv3 client facade (RFC 4511).
///
/// Dial via [`Runtime::connect`](hopf_core::Runtime::connect). On ready, the
/// callback receives an [`LdapSession`] for bind / search / unbind / STARTTLS.
pub struct LdapClient;

impl LdapClient {
    /// Dial `config` on `runtime` and invoke `on_ready` when the session can
    /// send LDAP messages (after TCP connect, or after TLS handshake for LDAPS).
    ///
    /// For STARTTLS dials ([`LdapClientConfig::with_starttls`]), the ready
    /// callback fires on plaintext connect; call [`LdapSession::start_tls`]
    /// before bind.
    ///
    /// Returns immediately after scheduling the dial. Hostname resolution (when
    /// not using [`LdapClientConfig::from_addr`]) uses blocking `ToSocketAddrs`.
    pub fn connect<F>(
        runtime: &Runtime,
        config: LdapClientConfig,
        on_ready: F,
    ) -> Result<(), LdapError>
    where
        F: FnOnce(Result<LdapSession, LdapError>) + Send + 'static,
    {
        let implicit_tls = config.is_ldaps();
        let tls = config.tls();
        let starttls = config.starttls();
        let connect_timeout = config.connect_timeout_opt();

        let shared = Arc::new(LdapShared::new(starttls));
        let on_ready: Arc<Mutex<Option<ReadyCallback>>> =
            Arc::new(Mutex::new(Some(Box::new(on_ready))));

        let shared_f = Arc::clone(&shared);
        let on_ready_f = Arc::clone(&on_ready);

        if let Some(path) = config.unix_path() {
            let shared_f2 = Arc::clone(&shared_f);
            let on_ready_f2 = Arc::clone(&on_ready_f);
            let mut cfg = UnixConnectorConfig::new(path, move || {
                Box::new(LdapEndpoint::new(
                    Arc::clone(&shared_f2),
                    Arc::clone(&on_ready_f2),
                    implicit_tls,
                ))
            })
            .connect_timeout(connect_timeout);
            if let Some((connector, server_name)) = tls {
                cfg = cfg.with_tls(connector, server_name);
            }
            return runtime.connect_unix(cfg).map_err(LdapError::Io);
        }

        let addr = config.resolve_addr()?;
        let mut cfg = TcpConnectorConfig::new(addr, move || {
            Box::new(LdapEndpoint::new(
                Arc::clone(&shared_f),
                Arc::clone(&on_ready_f),
                implicit_tls,
            ))
        })
        .connect_timeout(connect_timeout);

        if let Some((connector, server_name)) = tls {
            cfg = cfg.with_tls(connector, server_name);
        }

        runtime.connect(cfg).map_err(LdapError::Io)
    }
}
