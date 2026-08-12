// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Credential store (Gumdrop `Realm` surface used by SASL / HTTP Digest).

use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::{
    ct_eq, decode_base64, encode_base64, generate_nonce_hex, hmac_sha256, md5_hex, pbkdf2_sha256,
    sha256, from_hex,
};
use crate::mechanism::SaslMechanism;
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

    /// Look up a recoverable plaintext password.
    ///
    /// **Only** for legacy mechanisms that require it (CRAM-MD5 default
    /// path, POP3 APOP). Production stores should leave this as `None` and
    /// override [`cram_md5_digest`] / supply a custom APOP verifier instead.
    fn plaintext_password(&self, username: &str) -> Option<String> {
        let _ = username;
        None
    }

    /// Precomputed `MD5(username:realm:password)` hex for DIGEST-MD5 / HTTP Digest.
    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String>;

    /// Expected CRAM-MD5 hex digest for `challenge` (RFC 2195).
    fn cram_md5_digest(&self, username: &str, challenge: &str) -> Option<String> {
        let password = self.plaintext_password(username)?;
        Some(crate::cram_md5::compute_response(&password, challenge))
    }

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
    /// `MD5(user:digest_realm:password)` when a digest realm was configured
    /// at enrollment.
    ha1: Option<String>,
}

/// In-memory credential map for demos and tests (Gumdrop `BasicRealm` lite).
///
/// Enrollment accepts a password **once**, then keeps only SCRAM-SHA-256
/// material (and optional Digest HA1). Plaintext is not retained.
///
/// Does **not** support CRAM-MD5 or POP3 APOP (those need a recoverable
/// secret or a custom [`CredentialStore`]). DIGEST-MD5 / HTTP Digest work
/// when [`Self::with_digest_realm`] matches the challenge realm.
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
}

impl PasswordStore {
    /// Empty store (no Digest HA1 until [`Self::with_digest_realm`]).
    pub fn new() -> Self {
        Self {
            scram_iterations: 4096,
            ..Default::default()
        }
    }

    /// Realm for DIGEST-MD5 / HTTP Digest HA1 precomputation.
    ///
    /// Call **before** enrolling users. HA1 is stored only for this realm;
    /// [`CredentialStore::digest_ha1`] returns `None` for any other realm.
    pub fn with_digest_realm(mut self, realm: impl Into<String>) -> Self {
        self.digest_realm = realm.into();
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
        let ha1 = if self.digest_realm.is_empty() {
            None
        } else {
            Some(md5_hex(
                format!("{u}:{}:{password}", self.digest_realm).as_bytes(),
            ))
        };
        self.users.insert(u, StoredUser { scram, ha1 });
    }

    /// Enroll from already-hashed SCRAM material (no password involved).
    ///
    /// `ha1` is optional Digests HA1 for the store's configured realm.
    pub fn insert_scram(
        &mut self,
        username: impl Into<String>,
        scram: ScramCredentials,
        ha1: Option<String>,
    ) {
        self.users.insert(
            username.into(),
            StoredUser { scram, ha1 },
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
        ha1: Option<String>,
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

    /// Shared trait object.
    pub fn shared(self) -> Arc<dyn CredentialStore> {
        Arc::new(self)
    }
}

impl CredentialStore for PasswordStore {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        let mut mechs = vec![
            SaslMechanism::Plain,
            SaslMechanism::Login,
            SaslMechanism::ScramSha256,
            SaslMechanism::OauthBearer,
            SaslMechanism::External,
        ];
        if !self.digest_realm.is_empty() {
            mechs.insert(3, SaslMechanism::DigestMd5);
        }
        mechs
    }

    fn password_match(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .map(|u| u.scram.verify_password(password))
            .unwrap_or(false)
    }

    fn plaintext_password(&self, _username: &str) -> Option<String> {
        None
    }

    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String> {
        if realm != self.digest_realm || self.digest_realm.is_empty() {
            return None;
        }
        self.users.get(username)?.ha1.clone()
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

impl CredentialStore for Arc<dyn CredentialStore> {
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        (**self).supported_mechanisms()
    }
    fn password_match(&self, username: &str, password: &str) -> bool {
        (**self).password_match(username, password)
    }
    fn plaintext_password(&self, username: &str) -> Option<String> {
        (**self).plaintext_password(username)
    }
    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String> {
        (**self).digest_ha1(username, realm)
    }
    fn cram_md5_digest(&self, username: &str, challenge: &str) -> Option<String> {
        (**self).cram_md5_digest(username, challenge)
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
        assert!(store.plaintext_password("alice").is_none());
        assert!(store.password_match("alice", "s3cret"));
        assert!(!store.password_match("alice", "wrong"));
        assert!(!store.password_match("bob", "s3cret"));
        assert!(store.scram_credentials("alice").is_some());
        assert!(!store.supported_mechanisms().contains(&SaslMechanism::CramMd5));
    }

    #[test]
    fn digest_ha1_requires_matching_realm() {
        let store = PasswordStore::new()
            .with_digest_realm("example")
            .with_user("alice", "s3cret");
        assert!(store.digest_ha1("alice", "example").is_some());
        assert!(store.digest_ha1("alice", "other").is_none());
        assert!(store
            .supported_mechanisms()
            .contains(&SaslMechanism::DigestMd5));
    }
}
