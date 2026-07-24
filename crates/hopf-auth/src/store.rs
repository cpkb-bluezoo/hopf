// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Credential store (Gumdrop `Realm` surface used by SASL / HTTP Digest).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::crypto::{
    encode_base64, generate_nonce_hex, hmac_sha256, md5_hex, pbkdf2_sha256, sha256, from_hex,
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
    /// Derive from plaintext password (SCRAM-SHA-256).
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

/// Backend for SASL mechanisms and HTTP Digest (Gumdrop `Realm`).
pub trait CredentialStore: Send + Sync {
    /// Mechanisms this store can drive.
    fn supported_mechanisms(&self) -> Vec<SaslMechanism> {
        SaslMechanism::all().to_vec()
    }

    /// PLAIN / LOGIN / Basic.
    fn password_match(&self, username: &str, password: &str) -> bool;

    /// Look up plaintext password when needed for CRAM-MD5 (demo stores only).
    /// Production stores should override [`cram_md5_digest`] instead.
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

    /// OAUTHBEARER / HTTP Bearer.
    fn validate_bearer(&self, token: &str) -> Option<TokenValidation> {
        let _ = token;
        None
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

/// In-memory password / token / cert map (Gumdrop `BasicRealm` lite).
#[derive(Debug, Default)]
pub struct PasswordStore {
    passwords: HashMap<String, String>,
    /// Bearer token → username.
    tokens: HashMap<String, String>,
    /// Cert fingerprint/DN → username.
    certs: HashMap<String, String>,
    /// Cached SCRAM creds.
    scram: Mutex<HashMap<String, ScramCredentials>>,
    /// Default SCRAM iterations.
    scram_iterations: u32,
}

impl PasswordStore {
    /// Empty store.
    pub fn new() -> Self {
        Self {
            scram_iterations: 4096,
            ..Default::default()
        }
    }

    /// Insert username/password.
    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        let u = username.into();
        self.passwords.insert(u.clone(), password.into());
        self.scram.lock().unwrap().remove(&u);
    }

    /// Builder insert.
    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.insert(username, password);
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
    fn password_match(&self, username: &str, password: &str) -> bool {
        self.passwords
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }

    fn plaintext_password(&self, username: &str) -> Option<String> {
        self.passwords.get(username).cloned()
    }

    fn digest_ha1(&self, username: &str, realm: &str) -> Option<String> {
        let password = self.passwords.get(username)?;
        let a1 = format!("{username}:{realm}:{password}");
        Some(md5_hex(a1.as_bytes()))
    }

    fn scram_credentials(&self, username: &str) -> Option<ScramCredentials> {
        let password = self.passwords.get(username)?;
        let mut cache = self.scram.lock().unwrap();
        if let Some(c) = cache.get(username) {
            return Some(c.clone());
        }
        let salt = from_hex(&generate_nonce_hex(16)).unwrap_or_else(|| vec![0u8; 16]);
        let creds = ScramCredentials::derive(password, &salt, self.scram_iterations);
        cache.insert(username.to_string(), creds.clone());
        Some(creds)
    }

    fn validate_bearer(&self, token: &str) -> Option<TokenValidation> {
        self.tokens.get(token).map(|u| TokenValidation {
            username: u.clone(),
            scopes: Vec::new(),
        })
    }

    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        self.certs.get(cert_key).map(|u| CertificateIdentity {
            username: u.clone(),
        })
    }
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
                if self.validate_bearer(token).is_some() {
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
    fn validate_bearer(&self, token: &str) -> Option<TokenValidation> {
        (**self).validate_bearer(token)
    }
    fn authenticate_certificate(&self, cert_key: &str) -> Option<CertificateIdentity> {
        (**self).authenticate_certificate(cert_key)
    }
    fn authorize_as(&self, authcid: &str, authzid: &str) -> bool {
        (**self).authorize_as(authcid, authzid)
    }
}
