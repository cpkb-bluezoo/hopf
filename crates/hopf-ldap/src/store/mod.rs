// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`LdapCredentialStore`] — Gumdrop `LDAPRealm` search-then-bind port.
//!
//! # Reactor safety
//!
//! [`CredentialStore::password_match`](hopf_auth::CredentialStore::password_match)
//! **must not** run on a Hopf reactor thread. It blocks on a `Condvar` with a
//! timeout while LDAP callbacks complete on the reactor. Call it from a
//! storage/worker pool (or equivalent off-reactor context).

use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use hopf_auth::{
    CertificateIdentity, CredentialStore, SaslMechanism, ScramCredentials, TokenValidation,
};
use hopf_core::{Runtime, SharedTlsConnector};

use crate::client::{
    LdapClient, LdapClientConfig, LdapError, LdapResultCode, LdapSession, LdapUrl, SearchDone,
    SearchEntry, SearchRequest, SearchScope, DEFAULT_LDAP_PORT, DEFAULT_MAX_REFERRAL_HOPS,
};

/// Escape RFC 4515 filter value specials (`\ * ( )` NUL), matching Gumdrop
/// `LDAPRealm.escapeLDAPFilter`.
pub fn escape_ldap_filter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

/// Configuration for [`LdapCredentialStore`].
#[derive(Clone)]
pub struct LdapStoreConfig {
    /// LDAP server hostname or IP literal.
    pub host: String,
    /// Port (default [`DEFAULT_LDAP_PORT`]).
    pub port: u16,
    /// When set, dial with implicit TLS (LDAPS).
    pub ldaps: Option<(SharedTlsConnector, String)>,
    /// When set, dial plaintext then STARTTLS before bind (mutually exclusive
    /// with [`ldaps`](Self::ldaps) — `with_starttls` clears LDAPS).
    pub starttls: Option<(SharedTlsConnector, String)>,
    /// Search base DN.
    pub base_dn: String,
    /// Optional service-account bind DN.
    pub bind_dn: Option<String>,
    /// Optional service-account password.
    pub bind_password: Option<String>,
    /// User search filter; `{0}` is replaced with the escaped username.
    /// Default: `(uid={0})`.
    pub user_filter: String,
    /// Overall timeout for each connect/search/bind phase.
    pub timeout: Duration,
    /// Follow LDAP referrals / SearchResultReference URLs (default `false`).
    pub chase_referrals: bool,
    /// Maximum referral hops (default [`DEFAULT_MAX_REFERRAL_HOPS`]).
    pub max_referral_hops: u32,
    /// Runtime used to dial LDAP connections.
    pub runtime: Arc<Runtime>,
}

impl LdapStoreConfig {
    /// Build a config with defaults (`port` 389, filter `(uid={0})`, 30s timeout,
    /// referral chase **off**).
    pub fn new(host: impl Into<String>, base_dn: impl Into<String>, runtime: Arc<Runtime>) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_LDAP_PORT,
            ldaps: None,
            starttls: None,
            base_dn: base_dn.into(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(uid={0})".into(),
            timeout: Duration::from_secs(30),
            chase_referrals: false,
            max_referral_hops: DEFAULT_MAX_REFERRAL_HOPS,
            runtime,
        }
    }

    /// Enable LDAPS (clears STARTTLS).
    pub fn with_ldaps(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.ldaps = Some((connector, server_name.into()));
        self.starttls = None;
        self
    }

    /// Enable STARTTLS after plaintext dial (clears LDAPS).
    pub fn with_starttls(
        mut self,
        connector: SharedTlsConnector,
        server_name: impl Into<String>,
    ) -> Self {
        self.starttls = Some((connector, server_name.into()));
        self.ldaps = None;
        self
    }

    /// Service bind credentials.
    pub fn with_bind(mut self, dn: impl Into<String>, password: impl Into<String>) -> Self {
        self.bind_dn = Some(dn.into());
        self.bind_password = Some(password.into());
        self
    }

    /// Override user filter (must contain `{0}`).
    pub fn with_user_filter(mut self, filter: impl Into<String>) -> Self {
        self.user_filter = filter.into();
        self
    }

    /// Override operation timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Enable or disable referral chase (off by default — SSRF / credential
    /// reuse risk when following attacker-influenced URLs).
    pub fn with_chase_referrals(mut self, chase: bool) -> Self {
        self.chase_referrals = chase;
        self
    }

    /// Cap referral chase depth.
    pub fn with_max_referral_hops(mut self, hops: u32) -> Self {
        self.max_referral_hops = hops;
        self
    }
}

/// Production [`CredentialStore`] backed by LDAP search-then-bind.
pub struct LdapCredentialStore {
    config: LdapStoreConfig,
}

impl LdapCredentialStore {
    /// Create a store from configuration.
    pub fn new(config: LdapStoreConfig) -> Self {
        Self { config }
    }

    fn client_config_primary(&self) -> LdapClientConfig {
        let mut cfg = LdapClientConfig::new(&self.config.host, self.config.port)
            .connect_timeout(Some(self.config.timeout));
        if let Some((connector, sni)) = &self.config.ldaps {
            cfg = cfg.with_tls(connector.clone(), sni.clone());
        } else if let Some((connector, sni)) = &self.config.starttls {
            cfg = cfg.with_starttls(connector.clone(), sni.clone());
        }
        cfg
    }

    fn client_config_from_url(&self, url: &LdapUrl) -> Result<LdapClientConfig, LdapError> {
        let mut cfg = LdapClientConfig::new(&url.host, url.port)
            .connect_timeout(Some(self.config.timeout));
        if url.ldaps {
            let (connector, sni) = self
                .config
                .ldaps
                .as_ref()
                .or(self.config.starttls.as_ref())
                .ok_or_else(|| {
                    LdapError::Referral(
                        "ldaps:// referral requires TLS connector on the store".into(),
                    )
                })?;
            cfg = cfg.with_tls(connector.clone(), sni.clone());
        } else if let Some((connector, sni)) = &self.config.starttls {
            // Prefer STARTTLS on plaintext referral targets when configured.
            cfg = cfg.with_starttls(connector.clone(), sni.clone());
        }
        Ok(cfg)
    }

    /// Dial, optional STARTTLS, wait for session.
    fn connect_session(&self, cfg: LdapClientConfig) -> Result<LdapSession, LdapError> {
        let need_starttls = cfg.has_starttls();
        let session = wait_for(self.config.timeout, |tx| {
            LdapClient::connect(self.config.runtime.as_ref(), cfg, move |r| {
                let _ = tx.send(r);
            })
        })
        .and_then(std::convert::identity)?;

        if need_starttls {
            wait_for(self.config.timeout, |tx| {
                session.start_tls(move |r| {
                    let _ = tx.send(r);
                });
                Ok(())
            })
            .and_then(std::convert::identity)?;
        }
        Ok(session)
    }

    fn service_bind(&self, session: &LdapSession) -> Result<Vec<String>, LdapError> {
        let dn = self.config.bind_dn.clone().unwrap_or_default();
        let password = self.config.bind_password.clone().unwrap_or_default();
        let result = wait_for(self.config.timeout, |tx| {
            if dn.is_empty() {
                session.bind_anonymous(move |r| {
                    let _ = tx.send(r);
                });
            } else {
                session.bind(&dn, &password, move |r| {
                    let _ = tx.send(r);
                });
            }
            Ok(())
        })
        .and_then(std::convert::identity)?;
        if result.success {
            Ok(Vec::new())
        } else if result.result_code == LdapResultCode::Referral {
            Ok(result.referrals)
        } else {
            Err(LdapError::BindFailed(result.result_code))
        }
    }

    fn search_once(
        &self,
        cfg: LdapClientConfig,
        request: SearchRequest,
    ) -> Result<(Option<String>, Vec<String>), LdapError> {
        let session = self.connect_session(cfg)?;
        let bind_referrals = self.service_bind(&session)?;
        if !bind_referrals.is_empty() {
            session.unbind();
            // Propagate service-bind referrals as chase targets (no search).
            return Ok((None, bind_referrals));
        }

        let found = Arc::new(Mutex::new(None::<String>));
        let found2 = Arc::clone(&found);
        let done = wait_for(self.config.timeout, |tx| {
            session.search(
                request,
                move |entry: SearchEntry| {
                    let mut g = found2.lock().unwrap_or_else(|e| e.into_inner());
                    if g.is_none() {
                        *g = Some(entry.dn);
                    }
                },
                move |r| {
                    let _ = tx.send(r);
                },
            );
            Ok(())
        })?;
        session.unbind();

        let done = done?;
        accept_search_done(&done)?;
        let dn = found.lock().unwrap_or_else(|e| e.into_inner()).clone();
        Ok((dn, done.referrals))
    }

    fn find_user_dn(&self, username: &str) -> Result<Option<String>, LdapError> {
        let filter = self
            .config
            .user_filter
            .replace("{0}", &escape_ldap_filter(username));
        let original = SearchRequest {
            base_dn: self.config.base_dn.clone(),
            scope: SearchScope::WholeSubtree,
            filter,
            attributes: vec!["dn".into()],
            size_limit: 1,
            ..SearchRequest::default()
        };

        let mut queue: Vec<(LdapClientConfig, SearchRequest)> =
            vec![(self.client_config_primary(), original.clone())];
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(format!(
            "ldap://{}:{}/{}",
            self.config.host, self.config.port, self.config.base_dn
        ));
        let mut hops = 0u32;

        while let Some((cfg, request)) = queue.pop() {
            let (dn, referrals) = self.search_once(cfg, request.clone())?;
            if dn.is_some() {
                return Ok(dn);
            }
            if !self.config.chase_referrals || referrals.is_empty() {
                continue;
            }
            for url_str in referrals {
                if hops >= self.config.max_referral_hops {
                    return Err(LdapError::Referral(format!(
                        "exceeded max referral hops ({})",
                        self.config.max_referral_hops
                    )));
                }
                if !visited.insert(url_str.clone()) {
                    continue;
                }
                let url = match LdapUrl::parse(&url_str) {
                    Ok(u) => u,
                    Err(_) => continue,
                };
                let next_cfg = match self.client_config_from_url(&url) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let next_req = url.to_search_request(&request);
                hops += 1;
                queue.push((next_cfg, next_req));
            }
        }
        Ok(None)
    }

    fn attempt_bind(&self, dn: &str, password: &str) -> Result<bool, LdapError> {
        let mut queue: Vec<LdapClientConfig> = vec![self.client_config_primary()];
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(format!("ldap://{}:{}", self.config.host, self.config.port));
        let mut hops = 0u32;

        while let Some(cfg) = queue.pop() {
            let session = self.connect_session(cfg)?;
            let result = wait_for(self.config.timeout, |tx| {
                session.bind(dn, password, move |r| {
                    let _ = tx.send(r);
                });
                Ok(())
            })
            .and_then(std::convert::identity)?;
            session.unbind();

            if result.success {
                return Ok(true);
            }
            if result.result_code == LdapResultCode::InvalidCredentials {
                return Ok(false);
            }
            if !self.config.chase_referrals
                || result.result_code != LdapResultCode::Referral
                || result.referrals.is_empty()
            {
                return Ok(false);
            }
            for url_str in result.referrals {
                if hops >= self.config.max_referral_hops {
                    break;
                }
                if !visited.insert(url_str.clone()) {
                    continue;
                }
                let Ok(url) = LdapUrl::parse(&url_str) else {
                    continue;
                };
                let Ok(next_cfg) = self.client_config_from_url(&url) else {
                    continue;
                };
                hops += 1;
                queue.push(next_cfg);
            }
        }
        Ok(false)
    }
}

fn accept_search_done(done: &SearchDone) -> Result<(), LdapError> {
    if done.result_code.is_success()
        || matches!(
            done.result_code,
            LdapResultCode::NoSuchObject
                | LdapResultCode::SizeLimitExceeded
                | LdapResultCode::Referral
        )
    {
        Ok(())
    } else {
        Err(LdapError::SearchFailed(done.result_code))
    }
}

impl CredentialStore for LdapCredentialStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        vec![SaslMechanism::Plain, SaslMechanism::Login]
    }

    /// Search-then-bind (with optional referral chase). **Must not run on a
    /// reactor thread** (blocks).
    fn password_match(&self, username: &str, password: &str) -> bool {
        if username.is_empty() {
            return false;
        }
        match self.find_user_dn(username) {
            Ok(Some(dn)) => self.attempt_bind(&dn, password).unwrap_or(false),
            _ => false,
        }
    }

    fn plaintext_password(&self, _username: &str) -> Option<String> {
        None
    }

    fn digest_ha1(&self, _username: &str, _realm: &str) -> Option<String> {
        None
    }

    fn scram_credentials(&self, _username: &str) -> Option<ScramCredentials> {
        None
    }

    fn validate_bearer(&self, _token: &str) -> Option<TokenValidation> {
        None
    }

    fn authenticate_certificate(&self, _cert_key: &str) -> Option<CertificateIdentity> {
        None
    }
}

/// Oneshot channel + Condvar wait used off-reactor.
struct WaitSender<T> {
    inner: Arc<(Mutex<WaitState<T>>, Condvar)>,
}

struct WaitState<T> {
    value: Option<T>,
    done: bool,
}

impl<T> WaitSender<T> {
    fn send(self, value: T) {
        let (lock, cvar) = &*self.inner;
        let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
        g.value = Some(value);
        g.done = true;
        cvar.notify_one();
    }
}

fn wait_for<T, F>(timeout: Duration, start: F) -> Result<T, LdapError>
where
    T: Send + 'static,
    F: FnOnce(WaitSender<T>) -> Result<(), LdapError>,
{
    let inner = Arc::new((
        Mutex::new(WaitState {
            value: None,
            done: false,
        }),
        Condvar::new(),
    ));
    let tx = WaitSender {
        inner: Arc::clone(&inner),
    };
    start(tx)?;

    let (lock, cvar) = &*inner;
    let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
    let deadline = Instant::now() + timeout;
    while !g.done {
        let now = Instant::now();
        if now >= deadline {
            return Err(LdapError::Timeout);
        }
        let (guard, result) = cvar
            .wait_timeout(g, deadline - now)
            .unwrap_or_else(|e| e.into_inner());
        g = guard;
        if result.timed_out() && !g.done {
            return Err(LdapError::Timeout);
        }
    }
    g.value.take().ok_or(LdapError::Closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hopf_core::RuntimeConfig;

    #[test]
    fn escape_specials() {
        assert_eq!(escape_ldap_filter(r"a*b"), r"a\2ab");
        assert_eq!(escape_ldap_filter("a(b)c"), r"a\28b\29c");
        assert_eq!(escape_ldap_filter(r"a\b"), r"a\5cb");
        assert_eq!(escape_ldap_filter("a\0b"), r"a\00b");
        assert_eq!(escape_ldap_filter("alice"), "alice");
    }

    #[test]
    fn supported_mechanisms_plain_login_only() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let store = LdapCredentialStore::new(LdapStoreConfig::new(
            "127.0.0.1",
            "dc=example,dc=com",
            rt,
        ));
        let mechs = store.supported_mechanisms();
        assert_eq!(mechs, vec![SaslMechanism::Plain, SaslMechanism::Login]);
        assert!(store.digest_ha1("u", "r").is_none());
        assert!(store.scram_credentials("u").is_none());
        assert!(store.plaintext_password("u").is_none());
        assert!(store.validate_bearer("t").is_none());
    }
}
