// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Credential store (Gumdrop `Realm` surface used by SASL / HTTP Digest).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::crypto::{
    ct_eq, decode_base64, encode_base64, generate_nonce_hex, hmac_sha256, pbkdf2_sha256, sha256,
    from_hex,
};
use crate::http_digest::{compute_ha1, DigestAlgorithm};
use crate::mechanism::SaslMechanism;
use crate::role::RolePolicy;
use crate::{IdentityMaterial, PeerContext, TrustDecision, TrustPolicy};

/// SCRAM-SHA-256 stored credentials (RFC 5802).
#[derive(Debug, Clone)]
pub struct ScramCredentials {
    /// Base64-encoded salt.
    pub salt_b64: String,
    /// PBKDF2 iteration count.
    pub iterations: u32,
    /// `StoredKey = H(ClientKey)`.
    pub stored_key: Vec<u8>,
    /// `ServerKey = HMAC(SaltedPassword, "Server Key")`.
    pub server_key: Vec<u8>,
}

impl ScramCredentials {
    /// Derive from plaintext password (SCRAM-SHA-256). Enrollment only —
    /// do not persist the password afterward.
    pub fn derive(password: &str, salt: &[u8], iterations: u32) -> Self {
        let salted = pbkdf2_sha256(password.as_bytes(), salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key).to_vec();
        let server_key = hmac_sha256(&salted, b"Server Key");
        Self {
            salt_b64: encode_base64(salt),
            iterations,
            stored_key,
            server_key,
        }
    }

    /// Verify a candidate password against these stored credentials
    /// (constant-time `StoredKey` compare).
    pub fn verify_password(&self, password: &str) -> bool {
        let Some(salt) = decode_base64(&self.salt_b64) else {
            return false;
        };
        let derived = Self::derive(password, &salt, self.iterations);
        ct_eq(&derived.stored_key, &self.stored_key)
            && ct_eq(&derived.server_key, &self.server_key)
    }
}

/// Bearer / OAuth token validation result.
#[derive(Debug, Clone)]
pub struct TokenValidation {
    /// Authenticated username / subject.
    pub username: String,
    /// Optional scopes.
    pub scopes: Vec<String>,
}

/// Certificate → user mapping result (SASL EXTERNAL).
#[derive(Debug, Clone)]
pub struct CertificateIdentity {
    /// Mapped username.
    pub username: String,
}

/// One-shot completion callback — see [`CredentialStore::validate_bearer`].
pub type Cb<T> = Box<dyn FnOnce(T) + Send>;

/// Backend for SASL mechanisms and HTTP Digest (Gumdrop `Realm`).
pub trait CredentialStore: Send + Sync {
    /// Mechanisms this store can drive.
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        SaslMechanism::all().to_vec()
    }

    /// PLAIN / LOGIN / Basic — verify the password presented on the wire.
    ///
    /// Implementations should compare against a salted hash (or delegate to
    /// LDAP/PAM), never store recoverable passwords for this check alone.
    fn password_match(&self, username: &str, password: &str) -> bool;

    /// Precomputed `H(username:realm:password)` hex for HTTP Digest, with
    /// `H` the hash of `algorithm`. `None` when the user, the realm or the
    /// algorithm is not held.
    fn digest_ha1(&self, username: &str, realm: &str, algorithm: DigestAlgorithm) -> Option<String>;

    /// SCRAM-SHA-256 credentials.
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials>;

    /// OAUTHBEARER / HTTP Bearer. Callback-based (unlike every other method
    /// here) because a real implementation typically validates the token
    /// against a remote introspection endpoint (RFC 7662) — see
    /// [`crate::oauth_introspection::IntrospectionCredentialStore`] — and
    /// must not block the caller's thread while that network round trip is
    /// in flight. `cb` may be invoked either synchronously (before this
    /// call returns, as the default and [`PasswordStore`]'s override do)
    /// or later from another thread.
    fn validate_bearer(&self, token: &str, cb: Cb<Option<TokenValidation>>) {
        let _ = token;
        cb(None);
    }

    /// SASL EXTERNAL — `cert_key` is typically SHA-256 fingerprint hex or subject DN.
    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        let _ = cert_key;
        None
    }

    /// Authorization identity switch (`authzid`).
    fn authorize_as(&self, authcid: &str, authzid: &str) -> bool {
        authzid.is_empty() || authzid == authcid
    }
}

#[derive(Debug, Clone)]
struct StoredUser {
    scram: ScramCredentials,
    /// `H(user:digest_realm:password)` per algorithm, for the algorithms a
    /// digest realm was configured with at enrollment.
    ha1: HashMap<DigestAlgorithm, String>,
}

/// In-memory credential map for demos and tests (Gumdrop `BasicRealm` lite).
///
/// Enrollment accepts a password **once**, then keeps only SCRAM-SHA-256
/// material (and optional Digest HA1). Plaintext is not retained.
///
/// HTTP Digest works when [`Self::with_digest_realm`] matches the challenge
/// realm: with SHA-256, and also with MD5 if [`Self::with_md5_digest`] was
/// asked for.
#[derive(Debug, Default)]
pub struct PasswordStore {
    users: HashMap<String, StoredUser>,
    /// Bearer token → username.
    tokens: HashMap<String, String>,
    /// Cert fingerprint/DN → username.
    certs: HashMap<String, String>,
    /// Default SCRAM iterations.
    scram_iterations: u32,
    /// Realm used to precompute HA1 at [`Self::insert`] / [`Self::with_user`].
    digest_realm: String,
    /// Also precompute the MD5 HA1 (off by default).
    digest_md5: bool,
    /// Role names per enrolled username ([`RolePolicy`]).
    roles: HashMap<String, HashSet<String>>,
}

impl PasswordStore {
    /// Empty store (no Digest HA1 until [`Self::with_digest_realm`]).
    pub fn new() -> Self {
        Self {
            scram_iterations: 4096,
            ..Default::default()
        }
    }

    /// Realm for HTTP Digest HA1 precomputation (SHA-256).
    ///
    /// Call **before** enrolling users. HA1 is stored only for this realm;
    /// [`CredentialStore::digest_ha1`] returns `None` for any other realm.
    pub fn with_digest_realm(mut self, realm: impl Into<String>) -> Self {
        self.digest_realm = realm.into();
        self
    }

    /// Also precompute the MD5 HA1, for a server that still answers MD5
    /// Digest clients. Call before enrolling users, after
    /// [`Self::with_digest_realm`].
    pub fn with_md5_digest(mut self) -> Self {
        self.digest_md5 = true;
        self
    }

    /// PBKDF2 iteration count for SCRAM enrollment (default 4096).
    pub fn with_scram_iterations(mut self, iterations: u32) -> Self {
        self.scram_iterations = iterations.max(1);
        self
    }

    /// Enroll `username` from a password: derive SCRAM (+ HA1 if a digest
    /// realm is set), then discard the password.
    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        let u = username.into();
        let password = password.into();
        let salt = from_hex(&generate_nonce_hex(16)).unwrap_or_else(|| vec![0u8; 16]);
        let scram = ScramCredentials::derive(&password, &salt, self.scram_iterations);
        let mut ha1 = HashMap::new();
        if !self.digest_realm.is_empty() {
            ha1.insert(
                DigestAlgorithm::Sha256,
                compute_ha1(DigestAlgorithm::Sha256, &u, &self.digest_realm, &password),
            );
            if self.digest_md5 {
                ha1.insert(
                    DigestAlgorithm::Md5,
                    compute_ha1(DigestAlgorithm::Md5, &u, &self.digest_realm, &password),
                );
            }
        }
        self.users.insert(u, StoredUser { scram, ha1 });
    }

    /// Enroll from already-hashed SCRAM material (no password involved).
    ///
    /// `ha1` holds any precomputed Digest HA1 values for the store's
    /// configured realm.
    pub fn insert_scram(
        &mut self,
        username: impl Into<String>,
        scram: ScramCredentials,
        ha1: Vec<(DigestAlgorithm, String)>,
    ) {
        self.users.insert(
            username.into(),
            StoredUser { scram, ha1: ha1.into_iter().collect() },
        );
    }

    /// Builder insert (password enrollment).
    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.insert(username, password);
        self
    }

    /// Builder insert of precomputed SCRAM credentials.
    pub fn with_scram(
        mut self,
        username: impl Into<String>,
        scram: ScramCredentials,
        ha1: Vec<(DigestAlgorithm, String)>,
    ) -> Self {
        self.insert_scram(username, scram, ha1);
        self
    }

    /// Register a bearer token for `username`.
    pub fn with_token(mut self, token: impl Into<String>, username: impl Into<String>) -> Self {
        self.tokens.insert(token.into(), username.into());
        self
    }

    /// Map certificate fingerprint/DN to username.
    pub fn with_certificate(
        mut self,
        cert_key: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        self.certs.insert(cert_key.into(), username.into());
        self
    }

    /// Grant `role` to `username` ([`RolePolicy::is_user_in_role`]).
    pub fn with_role(mut self, username: impl Into<String>, role: impl Into<String>) -> Self {
        self.add_role(username, role);
        self
    }

    /// Grant `role` to `username`.
    pub fn add_role(&mut self, username: impl Into<String>, role: impl Into<String>) {
        self.roles
            .entry(username.into())
            .or_default()
            .insert(role.into());
    }

    /// Shared trait object.
    pub fn shared(self) -> Arc<dyn CredentialStore> {
        Arc::new(self)
    }
}

impl RolePolicy for PasswordStore {
    fn is_user_in_role(&self, username: &str, role: &str) -> bool {
        self.roles
            .get(username)
            .map(|r| r.contains(role))
            .unwrap_or(false)
    }
}

impl RolePolicy for Arc<PasswordStore> {
    fn is_user_in_role(&self, username: &str, role: &str) -> bool {
        (**self).is_user_in_role(username, role)
    }
}

impl CredentialStore for PasswordStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        vec![
            SaslMechanism::Plain,
            SaslMechanism::Login,
            SaslMechanism::ScramSha256,
            SaslMechanism::OauthBearer,
            SaslMechanism::XOauth2,
            SaslMechanism::External,
        ]
    }

    fn password_match(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .map(|u| u.scram.verify_password(password))
            .unwrap_or(false)
    }

    fn digest_ha1(&self, username: &str, realm: &str, algorithm: DigestAlgorithm) -> Option<String> {
        if realm != self.digest_realm || self.digest_realm.is_empty() {
            return None;
        }
        self.users.get(username)?.ha1.get(&algorithm).cloned()
    }

    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        self.users.get(username).map(|u| u.scram.clone())
    }

    fn validate_bearer(&self, token: &str, cb: Cb<Option<TokenValidation>>) {
        cb(self.tokens.get(token).map(|u| TokenValidation {
            username: u.clone(),
            scopes: Vec::new(),
        }));
    }

    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        self.certs.get(cert_key).map(|u| CertificateIdentity {
            username: u.clone(),
        })
    }
}

/// Bridges [`PasswordStore::validate_bearer`]'s callback back to a plain
/// return value for [`TrustPolicy::evaluate`], which — unlike the SASL
/// chain — has no offload machinery of its own to defer through. Safe
/// **only** because `PasswordStore::validate_bearer` is a pure in-memory
/// lookup that always invokes its callback before returning; this is not a
/// general async-to-sync bridge and must not be reused for a
/// `CredentialStore` whose `validate_bearer` can complete asynchronously
/// (e.g. [`crate::oauth_introspection::IntrospectionCredentialStore`]).
fn validate_bearer_sync(store: &PasswordStore, token: &str) -> Option<TokenValidation> {
    let (tx, rx) = std::sync::mpsc::channel();
    store.validate_bearer(token, Box::new(move |r| {
        let _ = tx.send(r);
    }));
    rx.try_recv().unwrap_or_else(|_| {
        panic!(
            "PasswordStore::validate_bearer completed asynchronously; \
             TrustPolicy::evaluate's sync bridge assumption was violated"
        )
    })
}

impl TrustPolicy for PasswordStore {
    fn evaluate(&self, identity: &IdentityMaterial, _peer: &PeerContext) -> TrustDecision {
        match identity {
            IdentityMaterial::UsernamePassword { username, password } => {
                if self.password_match(username, password) {
                    TrustDecision::Accept
                } else {
                    TrustDecision::Reject
                }
            }
            IdentityMaterial::Bearer(token) => {
                if validate_bearer_sync(self, token).is_some() {
                    TrustDecision::Accept
                } else {
                    TrustDecision::Reject
                }
            }
            IdentityMaterial::CertDn(dn) => {
                if self.authenticate_certificate(dn).is_some() {
                    TrustDecision::Accept
                } else {
                    TrustDecision::Reject
                }
            }
            IdentityMaterial::CertSan(sans) => {
                if sans
                    .iter()
                    .any(|s| self.authenticate_certificate(s).is_some())
                {
                    TrustDecision::Accept
                } else {
                    TrustDecision::Reject
                }
            }
            IdentityMaterial::Opaque(_) => TrustDecision::Reject,
        }
    }
}

#[cfg(test)]
mod role_tests {
    use super::*;

    #[test]
    fn password_store_role_membership() {
        let password = generate_nonce_hex(12);
        let store = PasswordStore::new()
            .with_user("alice", &password)
            .with_role("alice", "webdav:read");
        assert!(store.is_user_in_role("alice", "webdav:read"));
        assert!(!store.is_user_in_role("alice", "webdav:write"));
    }
}

impl CredentialStore for Arc<dyn CredentialStore> {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        (**self).supported_mechanisms()
    }
    fn password_match(&self, username: &str, password: &str) -> bool {
        (**self).password_match(username, password)
    }
    fn digest_ha1(&self, username: &str, realm: &str, algorithm: DigestAlgorithm) -> Option<String> {
        (**self).digest_ha1(username, realm, algorithm)
    }
    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        (**self).scram_credentials(username)
    }
    fn validate_bearer(&self, token: &str, cb: Cb<Option<TokenValidation>>) {
        (**self).validate_bearer(token, cb)
    }
    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        (**self).authenticate_certificate(cert_key)
    }
    fn authorize_as(&self, authcid: &str, authzid: &str) -> bool {
        (**self).authorize_as(authcid, authzid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_discards_plaintext() {
        let store = PasswordStore::new().with_user("alice", "s3cret");
        assert!(store.password_match("alice", "s3cret"));
        assert!(!store.password_match("alice", "wrong"));
        assert!(!store.password_match("bob", "s3cret"));
        assert!(store.scram_credentials("alice").is_some());
    }

    #[test]
    fn digest_ha1_requires_matching_realm() {
        let store = PasswordStore::new()
            .with_digest_realm("example")
            .with_user("alice", "s3cret");
        assert!(store.digest_ha1("alice", "example", DigestAlgorithm::Sha256).is_some());
        assert!(store.digest_ha1("alice", "other", DigestAlgorithm::Sha256).is_none());
        assert!(store.digest_ha1("bob", "example", DigestAlgorithm::Sha256).is_none());
    }

    #[test]
    fn md5_ha1_is_held_only_when_asked_for() {
        let sha_only = PasswordStore::new().with_digest_realm("r").with_user("alice", "p");
        assert!(sha_only.digest_ha1("alice", "r", DigestAlgorithm::Sha256).is_some());
        assert!(sha_only.digest_ha1("alice", "r", DigestAlgorithm::Md5).is_none());
        let both = PasswordStore::new().with_digest_realm("r").with_md5_digest().with_user("alice", "p");
        assert_eq!(
            both.digest_ha1("alice", "r", DigestAlgorithm::Md5),
            Some(compute_ha1(DigestAlgorithm::Md5, "alice", "r", "p"))
        );
        assert_eq!(
            both.digest_ha1("alice", "r", DigestAlgorithm::Sha256),
            Some(compute_ha1(DigestAlgorithm::Sha256, "alice", "r", "p"))
        );
    }

    #[test]
    fn no_digest_realm_means_no_ha1() {
        let store = PasswordStore::new().with_user("alice", "p");
        assert!(store.digest_ha1("alice", "", DigestAlgorithm::Sha256).is_none());
    }
}
