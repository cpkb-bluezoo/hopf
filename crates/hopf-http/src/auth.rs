// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! HTTP Basic, Digest, and Bearer authentication.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

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

/// HTTP Digest configuration.
#[derive(Debug, Clone)]
pub struct DigestAuthConfig {
    /// Realm name.
    pub realm: String,
}

impl DigestAuthConfig {
    /// Create with realm.
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
        }
    }
}

/// Factory for HTTP Digest (RFC 7616) using a [`CredentialStore`] for HA1.
pub struct DigestAuthFactory {
    inner: Arc<dyn ServerHandlerFactory>,
    store: Arc<dyn CredentialStore>,
    config: DigestAuthConfig,
    nonces: Arc<Mutex<HashSet<String>>>,
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
            nonces: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl ServerHandlerFactory for DigestAuthFactory {
    fn create_handler(&self) -> Box<dyn ServerHandler> {
        Box::new(DigestAuthHandler {
            inner: self.inner.create_handler(),
            store: Arc::clone(&self.store),
            realm: self.config.realm.clone(),
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
    nonces: Arc<Mutex<HashSet<String>>>,
    authorized: bool,
    challenged: bool,
}

impl DigestAuthHandler {
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
        let Some(ha1) = self.store.digest_ha1(username, &self.realm) else {
            return false;
        };
        let method = headers.method().unwrap_or("GET");
        let uri = params
            .get("uri")
            .map(|s| s.as_str())
            .or_else(|| headers.path())
            .unwrap_or("/");
        verify_authorization(creds, &ha1, method, uri, None)
    }

    fn send_challenge(&mut self, response: &mut dyn ServerWriter) {
        let nonce = new_nonce();
        self.nonces.lock().unwrap().insert(nonce.clone());
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
            Arc::new(PasswordStore::new().with_user("alice", "s3cret"));
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
