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
    CertificateIdentity, Cb, CredentialStore, SaslMechanism, ScramCredentials, TokenValidation,
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
                tx.send(r);
            })
        })
        .and_then(std::convert::identity)?;

        if need_starttls {
            wait_for(self.config.timeout, |tx| {
                session.start_tls(move |r| {
                    tx.send(r);
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
                    tx.send(r);
                });
            } else {
                session.bind(&dn, &password, move |r| {
                    tx.send(r);
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
                    tx.send(r);
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
                    tx.send(r);
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

    fn validate_bearer(&self, _token: &str, cb: Cb<Option<TokenValidation>>) {
        cb(None);
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
        let (tx, rx) = std::sync::mpsc::channel();
        store.validate_bearer("t", Box::new(move |r| { let _ = tx.send(r); }));
        assert!(rx.recv().unwrap().is_none());
    }

    // -----------------------------------------------------------------
    // Search-then-bind against a scripted LDAP server
    // -----------------------------------------------------------------

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use crate::client::session_tests::{bind_response, done, entry};
    use crate::{Asn1Element, Asn1Type, BerDecoder};

    /// Answers each request with the messages `handler` returns.
    type Handler = Arc<dyn Fn(&Asn1Element) -> Vec<Vec<u8>> + Send + Sync>;

    struct Directory {
        port: u16,
        requests: Arc<Mutex<Vec<Asn1Element>>>,
    }

    fn serve(handler: Handler) -> Directory {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let handler = Arc::clone(&handler);
                let log = Arc::clone(&log);
                thread::spawn(move || {
                    let mut dec = BerDecoder::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        if dec.receive(&buf[..n]).is_err() {
                            return;
                        }
                        while let Some(msg) = dec.next() {
                            let id = msg.child(0).as_i32().unwrap();
                            let tag = Asn1Type::tag_number(msg.child(1).tag());
                            log.lock().unwrap().push(msg.clone());
                            if tag == 2 {
                                return;
                            }
                            let _ = id;
                            for reply in handler(&msg) {
                                if stream.write_all(&reply).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        Directory { port, requests }
    }

    fn id(m: &Asn1Element) -> i32 {
        m.child(0).as_i32().unwrap()
    }

    fn op(m: &Asn1Element) -> u8 {
        Asn1Type::tag_number(m.child(1).tag())
    }

    /// A directory with one user, `alice`, whose password is `secret`.
    fn alice() -> Handler {
        Arc::new(|m| match op(m) {
            0 => {
                let dn = m.child(1).child(1).as_string().unwrap_or_default();
                let pw = m.child(1).child(2).as_string().unwrap_or_default();
                let ok = dn.is_empty() || (dn == "uid=alice,dc=example" && pw == "secret");
                vec![bind_response(id(m), if ok { 0 } else { 49 }, "", "", &[])]
            }
            3 => {
                let filter = m.child(1).child(6);
                let who = filter.child(1).as_octet_string().unwrap_or_default().to_vec();
                let mut out = Vec::new();
                if who == b"alice" {
                    out.push(entry(id(m), "uid=alice,dc=example", &[]));
                }
                out.push(done(id(m), 0, &[]));
                out
            }
            _ => vec![],
        })
    }

    fn store(port: u16) -> LdapCredentialStore {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", rt)
                .with_port(port)
                .with_timeout(Duration::from_secs(5)),
        )
    }

    #[test]
    fn the_right_password_matches() {
        let dir = serve(alice());
        let s = store(dir.port);
        assert!(s.password_match("alice", "secret"));
    }

    #[test]
    fn the_wrong_password_does_not() {
        let dir = serve(alice());
        assert!(!store(dir.port).password_match("alice", "nope"));
    }

    #[test]
    fn an_unknown_user_or_an_empty_name_does_not() {
        let dir = serve(alice());
        let s = store(dir.port);
        assert!(!s.password_match("bob", "secret"));
        assert!(!s.password_match("", "secret"));
    }

    #[test]
    fn the_search_asks_for_the_user_with_the_configured_filter() {
        let dir = serve(alice());
        store(dir.port).password_match("alice", "secret");
        let requests = dir.requests.lock().unwrap();
        let search = requests.iter().find(|m| op(m) == 3).expect("a search");
        let op = search.child(1);
        assert_eq!(op.child(0).as_string().as_deref(), Some("dc=example"));
        assert_eq!(op.child(1).as_i32().unwrap(), 2, "whole subtree");
        assert_eq!(op.child(3).as_i32().unwrap(), 1, "one entry is enough");
    }

    #[test]
    fn a_name_with_filter_characters_is_searched_for_literally() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        let dir = serve(Arc::new(move |m| {
            if op(m) == 3 {
                let value = m.child(1).child(6).child(1).as_octet_string().unwrap_or_default().to_vec();
                s2.lock().unwrap().push(value);
                return vec![done(id(m), 0, &[])];
            }
            vec![bind_response(id(m), 0, "", "", &[])]
        }));
        store(dir.port).password_match("a*(b)\\c", "x");
        assert_eq!(seen.lock().unwrap().as_slice(), [b"a*(b)\\c".to_vec()]);
    }

    #[test]
    fn a_service_account_is_bound_before_the_search() {
        let dir = serve(alice());
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let s = LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", rt)
                .with_port(dir.port)
                .with_bind("uid=alice,dc=example", "secret")
                .with_timeout(Duration::from_secs(5)),
        );
        assert!(s.password_match("alice", "secret"));
        let requests = dir.requests.lock().unwrap();
        let ops: Vec<u8> = requests.iter().map(|m| op(m)).collect();
        assert_eq!(&ops[..2], [0, 3], "bind then search: {ops:?}");
    }

    #[test]
    fn a_refused_service_account_matches_nobody() {
        let dir = serve(alice());
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let s = LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", rt)
                .with_port(dir.port)
                .with_bind("uid=svc,dc=example", "wrong")
                .with_timeout(Duration::from_secs(5)),
        );
        assert!(!s.password_match("alice", "secret"));
    }

    #[test]
    fn a_failed_search_matches_nobody() {
        let dir = serve(Arc::new(|m| match op(m) {
            3 => vec![done(id(m), 50, &[])],
            _ => vec![bind_response(id(m), 0, "", "", &[])],
        }));
        assert!(!store(dir.port).password_match("alice", "secret"));
    }

    #[test]
    fn a_server_that_never_answers_times_out_to_no_match() {
        let dir = serve(Arc::new(|_| vec![]));
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let s = LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", rt)
                .with_port(dir.port)
                .with_timeout(Duration::from_millis(300)),
        );
        assert!(!s.password_match("alice", "secret"));
    }

    #[test]
    fn nothing_listening_matches_nobody() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(!store(port).password_match("alice", "secret"));
    }

    #[test]
    fn a_referral_is_chased_to_the_directory_that_has_the_user() {
        let real = serve(alice());
        let real_port = real.port;
        let front = serve(Arc::new(move |m| match op(m) {
            3 => vec![done(id(m), 10, &[&format!("ldap://127.0.0.1:{real_port}/dc=example")])],
            _ => vec![bind_response(id(m), 0, "", "", &[])],
        }));
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let chasing = LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", Arc::clone(&rt))
                .with_port(front.port)
                .with_chase_referrals(true)
                .with_timeout(Duration::from_secs(5)),
        );
        assert!(chasing.password_match("alice", "secret"));
        let not_chasing = LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", rt)
                .with_port(front.port)
                .with_chase_referrals(false)
                .with_timeout(Duration::from_secs(5)),
        );
        assert!(!not_chasing.password_match("alice", "secret"));
    }

    #[test]
    fn referral_chasing_stops_at_the_hop_limit() {
        // A directory that always refers to a fresh URL on itself.
        let port_cell = Arc::new(Mutex::new(0u16));
        let pc = Arc::clone(&port_cell);
        let counter = Arc::new(Mutex::new(0u32));
        let dir = serve(Arc::new(move |m| match op(m) {
            3 => {
                let mut n = counter.lock().unwrap();
                *n += 1;
                let port = *pc.lock().unwrap();
                vec![done(id(m), 10, &[&format!("ldap://127.0.0.1:{port}/dc=hop{n}")])]
            }
            _ => vec![bind_response(id(m), 0, "", "", &[])],
        }));
        *port_cell.lock().unwrap() = dir.port;
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let s = LdapCredentialStore::new(
            LdapStoreConfig::new("127.0.0.1", "dc=example", rt)
                .with_port(dir.port)
                .with_chase_referrals(true)
                .with_max_referral_hops(2)
                .with_timeout(Duration::from_secs(5)),
        );
        assert!(!s.password_match("alice", "secret"));
        let searches = dir.requests.lock().unwrap().iter().filter(|m| op(m) == 3).count();
        assert_eq!(searches, 3, "the first search plus two hops");
    }

    #[test]
    fn the_unused_credential_kinds_are_not_offered() {
        let rt = Arc::new(Runtime::start(RuntimeConfig::default()).unwrap());
        let s = LdapCredentialStore::new(LdapStoreConfig::new("127.0.0.1", "dc=example", rt));
        assert!(s.authenticate_certificate("any").is_none());
    }
}
