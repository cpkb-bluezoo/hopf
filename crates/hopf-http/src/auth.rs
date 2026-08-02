// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Basic, Digest, and Bearer authentication.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hopf_auth::crypto::decode_base64;
use hopf_auth::digest_md5::parse_params;
use hopf_auth::http_digest::{challenge_header, new_nonce, verify_authorization};
use hopf_auth::{
    CredentialStore, IdentityMaterial, PeerContext, TrustDecision, TrustPolicy,
};

use crate::headers::Headers;
use crate::stream::{ServerHandler, ServerHandlerFactory, ServerWriter};

/// Realm string for `WWW-Authenticate: Basic realm="…"`.
#[derive(Debug, Clone)]
pub struct BasicAuthConfig {
    /// Realm presented to the client.
    pub realm: String,
}

impl BasicAuthConfig {
    /// Create with realm.
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
        }
    }
}

/// Factory that challenges with Basic and only forwards when [`TrustPolicy`] accepts.
pub struct BasicAuthFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    policy: Arc<dyn TrustPolicy>,
    config: BasicAuthConfig,
}

impl BasicAuthFactory {
    /// Wrap `inner` with Basic auth using `policy`.
    pub fn new(
        inner: Arc<dyn ServerHandlerFactory>,
        policy: Arc<dyn TrustPolicy>,
        config: BasicAuthConfig,
    ) -> Self {
        Self {
            inner,
            policy,
            config,
        }
    }
}

impl ServerHandlerFactory for BasicAuthFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(BasicAuthHandler {
            inner: self.inner.create_handler(),
            policy: Arc::clone(&self.policy),
            realm: self.config.realm.clone(),
            authorized: false,
            challenged: false,
        })
    }
}

struct BasicAuthHandler {
    inner: Box<dyn ServerHandler>,
    policy: Arc<dyn TrustPolicy>,
    realm: String,
    authorized: bool,
    challenged: bool,
}

impl BasicAuthHandler {
    fn check_auth(&mut self, headers: &Headers) -> bool {
        if let Some(id) = parse_basic_authorization(headers.get("authorization")) {
            return self.policy.evaluate(&id, &PeerContext::unknown()) == TrustDecision::Accept;
        }
        false
    }

    fn send_challenge(&mut self, response: &mut dyn ServerWriter) {
        let mut h = Headers::new();
        h.status(401);
        h.set(
            "www-authenticate",
            format!("Basic realm=\"{}\"", self.realm),
        );
        h.set("content-length", "0");
        response.headers(h);
        response.complete();
        self.challenged = true;
    }
}

impl ServerHandler for BasicAuthHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        if self.check_auth(headers) {
            self.authorized = true;
            self.inner.headers(response, headers);
        } else {
            self.send_challenge(response);
        }
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.start_request_body(response);
        }
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.authorized {
            self.inner.request_body_content(response, data);
        }
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.end_request_body(response);
        }
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.request_complete(response);
        } else if !self.challenged {
            self.send_challenge(response);
        }
    }
}

/// Parse `Authorization: Basic …` into username/password material.
pub fn parse_basic_authorization(value: Option<&str>) -> Option<IdentityMaterial> {
    let value = value?.trim();
    let rest = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = decode_base64(rest.trim())?;
    let s = String::from_utf8(decoded).ok()?;
    let (username, password) = s.split_once(':')?;
    Some(IdentityMaterial::UsernamePassword {
        username: username.to_string(),
        password: password.to_string(),
    })
}

/// How long an issued nonce remains acceptable if never used, by default.
/// RFC 7616 doesn't mandate a value; five minutes matches typical
/// real-world Digest implementations.
const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(300);

/// HTTP Digest configuration.
#[derive(Debug, Clone)]
pub struct DigestAuthConfig {
    /// Realm name.
    pub realm: String,
    /// How long an issued nonce remains acceptable if never used —
    /// see [`DEFAULT_NONCE_TTL`].
    pub nonce_ttl: Duration,
}

impl DigestAuthConfig {
    /// Create with realm (default nonce TTL).
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            nonce_ttl: DEFAULT_NONCE_TTL,
        }
    }

    /// Override the nonce TTL.
    pub fn with_nonce_ttl(mut self, ttl: Duration) -> Self {
        self.nonce_ttl = ttl;
        self
    }
}

/// Factory for HTTP Digest (RFC 7616) using a [`CredentialStore`] for HA1.
pub struct DigestAuthFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    store: Arc<dyn CredentialStore>,
    config: DigestAuthConfig,
    nonces: Arc<Mutex<HashMap<String, Instant>>>,
}

impl DigestAuthFactory {
    /// Wrap `inner` with Digest auth.
    pub fn new(
        inner: Arc<dyn ServerHandlerFactory>,
        store: Arc<dyn CredentialStore>,
        config: DigestAuthConfig,
    ) -> Self {
        Self {
            inner,
            store,
            config,
            nonces: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ServerHandlerFactory for DigestAuthFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(DigestAuthHandler {
            inner: self.inner.create_handler(),
            store: Arc::clone(&self.store),
            realm: self.config.realm.clone(),
            nonce_ttl: self.config.nonce_ttl,
            nonces: Arc::clone(&self.nonces),
            authorized: false,
            challenged: false,
        })
    }
}

struct DigestAuthHandler {
    inner: Box<dyn ServerHandler>,
    store: Arc<dyn CredentialStore>,
    realm: String,
    nonce_ttl: Duration,
    nonces: Arc<Mutex<HashMap<String, Instant>>>,
    authorized: bool,
    challenged: bool,
}

impl DigestAuthHandler {
    fn prune_expired_nonces(&self, nonces: &mut HashMap<String, Instant>) {
        let ttl = self.nonce_ttl;
        nonces.retain(|_, issued_at| issued_at.elapsed() <= ttl);
    }

    /// Consume a tracked nonce: `true` only if `nonce` was actually issued
    /// by [`Self::send_challenge`], hasn't already been used (nonces are
    /// single-use — removed here on success), and hasn't expired. This is
    /// the real replay check: an attacker replaying a captured
    /// `Authorization: Digest` header (even with a byte-identical,
    /// cryptographically valid `response` value) presents a nonce that's
    /// already gone from the map on the second attempt.
    fn consume_nonce(&self, nonce: &str) -> bool {
        let mut nonces = self.nonces.lock().unwrap();
        self.prune_expired_nonces(&mut nonces);
        nonces.remove(nonce).is_some()
    }

    fn check_auth(&mut self, headers: &Headers) -> bool {
        let Some(auth) = headers.get("authorization") else {
            return false;
        };
        let auth = auth.trim();
        let Some(creds) = auth
            .strip_prefix("Digest ")
            .or_else(|| auth.strip_prefix("digest "))
        else {
            return false;
        };
        let params = parse_params(creds);
        let Some(username) = params.get("username") else {
            return false;
        };
        let Some(nonce) = params.get("nonce") else {
            return false;
        };
        // Consult (and consume) the tracked nonce *before* verifying the
        // credential hash — an untracked/expired/already-used nonce is
        // rejected outright, regardless of whether `response` is
        // otherwise cryptographically correct.
        if !self.consume_nonce(nonce) {
            return false;
        }
        let Some(ha1) = self.store.digest_ha1(username, &self.realm) else {
            return false;
        };
        let method = headers.method().unwrap_or("GET");
        let uri = params
            .get("uri")
            .map(|s| s.as_str())
            .or_else(|| headers.path())
            .unwrap_or("/");
        verify_authorization(creds, &ha1, method, uri, Some(nonce))
    }

    fn send_challenge(&mut self, response: &mut dyn ServerWriter) {
        let nonce = new_nonce();
        {
            let mut nonces = self.nonces.lock().unwrap();
            self.prune_expired_nonces(&mut nonces);
            nonces.insert(nonce.clone(), Instant::now());
        }
        let mut h = Headers::new();
        h.status(401);
        h.set(
            "www-authenticate",
            format!("Digest {}", challenge_header(&self.realm, &nonce)),
        );
        h.set("content-length", "0");
        response.headers(h);
        response.complete();
        self.challenged = true;
    }
}

impl ServerHandler for DigestAuthHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        if self.check_auth(headers) {
            self.authorized = true;
            self.inner.headers(response, headers);
        } else {
            self.send_challenge(response);
        }
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.start_request_body(response);
        }
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.authorized {
            self.inner.request_body_content(response, data);
        }
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.end_request_body(response);
        }
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.request_complete(response);
        } else if !self.challenged {
            self.send_challenge(response);
        }
    }
}

/// Re-export client Digest credential builder.
pub use hopf_auth::http_digest::client_authorization as build_digest_authorization;

/// Bearer token auth via [`TrustPolicy`] / [`IdentityMaterial::Bearer`].
pub struct BearerAuthFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    policy: Arc<dyn TrustPolicy>,
    /// Optional realm for WWW-Authenticate Bearer.
    pub realm: Option<String>,
}

impl BearerAuthFactory {
    /// Wrap with Bearer auth.
    pub fn new(inner: Arc<dyn ServerHandlerFactory>, policy: Arc<dyn TrustPolicy>) -> Self {
        Self {
            inner,
            policy,
            realm: None,
        }
    }

    /// Set realm parameter on challenge.
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }
}

impl ServerHandlerFactory for BearerAuthFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(BearerAuthHandler {
            inner: self.inner.create_handler(),
            policy: Arc::clone(&self.policy),
            realm: self.realm.clone(),
            authorized: false,
            challenged: false,
        })
    }
}

struct BearerAuthHandler {
    inner: Box<dyn ServerHandler>,
    policy: Arc<dyn TrustPolicy>,
    realm: Option<String>,
    authorized: bool,
    challenged: bool,
}

impl BearerAuthHandler {
    fn check_auth(&mut self, headers: &Headers) -> bool {
        let Some(auth) = headers.get("authorization") else {
            return false;
        };
        let auth = auth.trim();
        let Some(token) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        else {
            return false;
        };
        self.policy.evaluate(
            &IdentityMaterial::Bearer(token.trim().to_string()),
            &PeerContext::unknown(),
        ) == TrustDecision::Accept
    }

    fn send_challenge(&mut self, response: &mut dyn ServerWriter) {
        let mut h = Headers::new();
        h.status(401);
        let wa = match &self.realm {
            Some(r) => format!("Bearer realm=\"{r}\""),
            None => "Bearer".into(),
        };
        h.set("www-authenticate", wa);
        h.set("content-length", "0");
        response.headers(h);
        response.complete();
        self.challenged = true;
    }
}

impl ServerHandler for BearerAuthHandler {
    fn headers(&mut self, response: &mut dyn ServerWriter, headers: &Headers) {
        if self.check_auth(headers) {
            self.authorized = true;
            self.inner.headers(response, headers);
        } else {
            self.send_challenge(response);
        }
    }

    fn start_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.start_request_body(response);
        }
    }

    fn request_body_content(&mut self, response: &mut dyn ServerWriter, data: &[u8]) {
        if self.authorized {
            self.inner.request_body_content(response, data);
        }
    }

    fn end_request_body(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.end_request_body(response);
        }
    }

    fn request_complete(&mut self, response: &mut dyn ServerWriter) {
        if self.authorized {
            self.inner.request_complete(response);
        } else if !self.challenged {
            self.send_challenge(response);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hopf_auth::{PasswordTrustPolicy, PeerContext, TrustDecision};

    #[test]
    fn parse_basic_alice() {
        let id = parse_basic_authorization(Some("Basic YWxpY2U6czNjcmV0")).unwrap();
        assert_eq!(
            id,
            IdentityMaterial::UsernamePassword {
                username: "alice".into(),
                password: "s3cret".into(),
            }
        );
    }

    #[test]
    fn policy_via_basic() {
        let policy = PasswordTrustPolicy::new()
            .with_user("alice", "s3cret")
            .shared();
        let id = parse_basic_authorization(Some("Basic YWxpY2U6czNjcmV0")).unwrap();
        assert_eq!(
            policy.evaluate(&id, &PeerContext::unknown()),
            TrustDecision::Accept
        );
    }


    #[cfg(feature = "integration")]
    mod integration {
        use super::super::*;
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::Arc;
        use std::time::Duration;

        use hopf_auth::{PasswordStore, PasswordTrustPolicy, TrustPolicy};
        use hopf_core::{ProtocolHandler, Runtime, RuntimeConfig, TcpListenerConfig};

        use crate::h1::H1Endpoint;
        use crate::{Headers, HttpLimits, ServerHandler, ServerHandlerFactory, ServerWriter};

    struct OkHandler;
    impl ServerHandler for OkHandler {
        fn headers(&mut self, response: &mut dyn ServerWriter, _headers: &Headers) {
            let mut h = Headers::new();
            h.status(200);
            h.set("content-length", "2");
            response.headers(h);
            response.start_response_body();
            response.response_body_content(b"ok");
            response.end_response_body();
            response.complete();
        }
        fn request_complete(&mut self, _: &mut dyn ServerWriter) {}
    }
    struct OkFactory;
    impl ServerHandlerFactory for OkFactory {
        fn create_handler(&self) -> Box<dyn ServerHandler> {
            Box::new(OkHandler)
        }
    }

    fn listen(factory: Arc<dyn ServerHandlerFactory>) -> (Runtime, std::net::SocketAddr) {
        let rt = Runtime::start(RuntimeConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let factory2 = Arc::clone(&factory);
        let (addr, _) = rt
            .add_tcp_listener(TcpListenerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                move || {
                    Box::new(H1Endpoint::server(
                        Arc::clone(&factory2),
                        HttpLimits::default(),
                        false,
                    )) as Box<dyn ProtocolHandler>
                },
            ))
            .unwrap();
        (rt, addr)
    }

    #[test]
    fn basic_auth_challenge_and_success() {
        let policy = PasswordTrustPolicy::new()
            .with_user("alice", "s3cret")
            .shared();
        let factory: Arc<dyn ServerHandlerFactory> = Arc::new(BasicAuthFactory::new(
            Arc::new(OkFactory),
            policy,
            BasicAuthConfig::new("test"),
        ));
        let (rt, addr) = listen(factory);

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("401"), "{resp}");

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWxpY2U6czNjcmV0\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("200"), "{resp}");
        rt.shutdown();
    }

    #[test]
    fn digest_auth_challenge_and_success() {
        let store: Arc<dyn CredentialStore> =
            Arc::new(
                PasswordStore::new()
                    .with_digest_realm("test")
                    .with_user("alice", "s3cret"),
            );
        let factory: Arc<dyn ServerHandlerFactory> = Arc::new(DigestAuthFactory::new(
            Arc::new(OkFactory),
            store,
            DigestAuthConfig::new("test"),
        ));
        let (rt, addr) = listen(factory);

        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("401"), "{resp}");
        let lower = resp.to_ascii_lowercase();
        assert!(lower.contains("digest"), "{resp}");
        let nonce = resp
            .split("nonce=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("nonce");
        let creds = build_digest_authorization("alice", "s3cret", "test", nonce, "GET", "/");
        let req = format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Digest {creds}\r\nConnection: close\r\n\r\n"
        );
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        let resp = String::from_utf8_lossy(&buf);
        assert!(resp.contains("200"), "{resp}");
        rt.shutdown();
    }

    /// Sends `req` over a fresh connection and returns the whole response
    /// as text.
    fn send_request(addr: std::net::SocketAddr, req: &str) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn digest_req(creds: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Digest {creds}\r\nConnection: close\r\n\r\n"
        )
    }

    fn challenge_nonce(resp: &str) -> String {
        resp.split("nonce=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("nonce")
            .to_string()
    }

    /// A captured, cryptographically-valid `Authorization: Digest` header
    /// replayed verbatim on a second request must be rejected — issue
    /// #122: the nonce is single-use, so its second presentation fails
    /// even though `response` is byte-identical to the first, successful
    /// attempt.
    #[test]
    fn digest_auth_replayed_credentials_are_rejected() {
        let store: Arc<dyn CredentialStore> = Arc::new(
            PasswordStore::new()
                .with_digest_realm("test")
                .with_user("alice", "s3cret"),
        );
        let factory: Arc<dyn ServerHandlerFactory> = Arc::new(DigestAuthFactory::new(
            Arc::new(OkFactory),
            store,
            DigestAuthConfig::new("test"),
        ));
        let (rt, addr) = listen(factory);

        let resp = send_request(
            addr,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        let nonce = challenge_nonce(&resp);
        let creds = build_digest_authorization("alice", "s3cret", "test", &nonce, "GET", "/");

        let first = send_request(addr, &digest_req(&creds));
        assert!(first.contains("200"), "first use should succeed: {first}");

        // Exact same Authorization header, second request — a replay.
        let second = send_request(addr, &digest_req(&creds));
        assert!(
            second.contains("401"),
            "replayed credentials must be rejected: {second}"
        );

        rt.shutdown();
    }

    /// Credentials built around a nonce the server never issued (forged,
    /// or from a different server instance) must be rejected outright,
    /// even with an otherwise-correct `response` hash.
    #[test]
    fn digest_auth_unissued_nonce_is_rejected() {
        let store: Arc<dyn CredentialStore> = Arc::new(
            PasswordStore::new()
                .with_digest_realm("test")
                .with_user("alice", "s3cret"),
        );
        let factory: Arc<dyn ServerHandlerFactory> = Arc::new(DigestAuthFactory::new(
            Arc::new(OkFactory),
            store,
            DigestAuthConfig::new("test"),
        ));
        let (rt, addr) = listen(factory);

        let forged_nonce = "0000deadbeef0000deadbeef00000000";
        let creds =
            build_digest_authorization("alice", "s3cret", "test", forged_nonce, "GET", "/");
        let resp = send_request(addr, &digest_req(&creds));
        assert!(resp.contains("401"), "{resp}");

        rt.shutdown();
    }

    /// A nonce older than the configured TTL is rejected even though it
    /// was genuinely issued and never used.
    #[test]
    fn digest_auth_nonce_expires_after_ttl() {
        let store: Arc<dyn CredentialStore> = Arc::new(
            PasswordStore::new()
                .with_digest_realm("test")
                .with_user("alice", "s3cret"),
        );
        let factory: Arc<dyn ServerHandlerFactory> = Arc::new(DigestAuthFactory::new(
            Arc::new(OkFactory),
            store,
            DigestAuthConfig::new("test").with_nonce_ttl(Duration::from_millis(50)),
        ));
        let (rt, addr) = listen(factory);

        let resp = send_request(
            addr,
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        );
        let nonce = challenge_nonce(&resp);
        let creds = build_digest_authorization("alice", "s3cret", "test", &nonce, "GET", "/");

        std::thread::sleep(Duration::from_millis(150));
        let resp = send_request(addr, &digest_req(&creds));
        assert!(resp.contains("401"), "expired nonce must be rejected: {resp}");

        rt.shutdown();
    }

    #[test]
    fn bearer_auth_success() {
        let store = PasswordStore::new().with_token("tok", "alice");
        let policy: Arc<dyn TrustPolicy> = Arc::new(store);
        let factory: Arc<dyn ServerHandlerFactory> =
            Arc::new(BearerAuthFactory::new(Arc::new(OkFactory), policy).with_realm("api"));
        let (rt, addr) = listen(factory);
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer tok\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut buf = Vec::new();
        let _ = c.read_to_end(&mut buf);
        assert!(String::from_utf8_lossy(&buf).contains("200"));
        rt.shutdown();
    }
    }
}
