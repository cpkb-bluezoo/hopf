// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Trust policy and identity material for Hopf protocols
//! ([#2](https://github.com/cpkb-bluezoo/hopf/issues/2)).
//!
//! SASL mechanisms (Gumdrop parity, excluding GSSAPI): PLAIN, LOGIN, CRAM-MD5,
//! DIGEST-MD5, SCRAM-SHA-256, OAUTHBEARER, EXTERNAL.

#![warn(missing_docs)]

pub mod cram_md5;
pub mod crypto;
pub mod digest_md5;
pub mod external;
pub mod http_digest;
pub mod login;
pub mod mechanism;
pub mod oauthbearer;
pub mod plain;
pub mod scram;
pub mod session;
pub mod store;

pub use mechanism::SaslMechanism;
pub use session::{
    create_client, create_server, SaslClient, SaslClientStep, SaslServer, SaslServerOptions,
    SaslServerStep,
};
pub use store::{
    CertificateIdentity, CredentialStore, PasswordStore, ScramCredentials, TokenValidation,
};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Peer / connection context passed with identity material.
#[derive(Debug, Clone, Copy)]
pub struct PeerContext {
    /// Remote socket address when known.
    pub peer: Option<SocketAddr>,
}

impl PeerContext {
    /// Unknown peer.
    pub fn unknown() -> Self {
        Self { peer: None }
    }

    /// Known peer address.
    pub fn from_addr(peer: SocketAddr) -> Self {
        Self { peer: Some(peer) }
    }
}

/// Presented credentials or other identity evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityMaterial {
    /// HTTP Basic / simple password login.
    UsernamePassword {
        /// Username.
        username: String,
        /// Password (plaintext as presented on the wire).
        password: String,
    },
    /// Bearer token (OAuth-style or opaque).
    Bearer(String),
    /// Certificate subject DN (UTF-8 string form).
    CertDn(String),
    /// Certificate SAN entries.
    CertSan(Vec<String>),
    /// Opaque bytes for protocol-specific schemes.
    Opaque(Vec<u8>),
}

/// Decision from a [`TrustPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustDecision {
    /// Accept the peer / request.
    Accept,
    /// Reject.
    Reject,
}

/// Decide accept/reject given identity material and peer context.
pub trait TrustPolicy: Send + Sync {
    /// Evaluate credentials.
    fn evaluate(&self, identity: &IdentityMaterial, peer: &PeerContext) -> TrustDecision;
}

/// In-memory username → password map (demos). Prefer [`PasswordStore`] when
/// also using SASL / Digest.
#[derive(Debug, Default, Clone)]
pub struct PasswordTrustPolicy {
    users: HashMap<String, String>,
}

impl PasswordTrustPolicy {
    /// Empty policy (rejects all username/password).
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a user.
    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.users.insert(username.into(), password.into());
    }

    /// Builder-style insert.
    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.insert(username, password);
        self
    }

    /// Convert into a full [`PasswordStore`].
    pub fn into_store(self) -> PasswordStore {
        let mut s = PasswordStore::new();
        for (u, p) in self.users {
            s.insert(u, p);
        }
        s
    }

    /// Wrap as shared policy.
    pub fn shared(self) -> Arc<dyn TrustPolicy> {
        Arc::new(self)
    }
}

impl TrustPolicy for PasswordTrustPolicy {
    fn evaluate(&self, identity: &IdentityMaterial, _peer: &PeerContext) -> TrustDecision {
        match identity {
            IdentityMaterial::UsernamePassword { username, password } => {
                if self.users.get(username).map(|p| p == password).unwrap_or(false) {
                    TrustDecision::Accept
                } else {
                    TrustDecision::Reject
                }
            }
            _ => TrustDecision::Reject,
        }
    }
}

impl TrustPolicy for Arc<dyn TrustPolicy> {
    fn evaluate(&self, identity: &IdentityMaterial, peer: &PeerContext) -> TrustDecision {
        (**self).evaluate(identity, peer)
    }
}

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{create_client, create_server, SaslClientStep, SaslServerStep};

    #[test]
    fn password_policy_accepts_known_user() {
        let p = PasswordTrustPolicy::new().with_user("alice", "s3cret");
        let id = IdentityMaterial::UsernamePassword {
            username: "alice".into(),
            password: "s3cret".into(),
        };
        assert_eq!(
            p.evaluate(&id, &PeerContext::unknown()),
            TrustDecision::Accept
        );
    }

    fn roundtrip(mech: SaslMechanism, store: Arc<dyn CredentialStore>) {
        let opts = SaslServerOptions {
            hostname: "mail.example".into(),
            realm: "example".into(),
            peer_certificate: if mech == SaslMechanism::External {
                Some("fp-alice".into())
            } else {
                None
            },
            ..Default::default()
        };
        let mut server = create_server(mech, Arc::clone(&store), opts);
        let (user, pass) = match mech {
            SaslMechanism::OauthBearer => ("alice", "tok-alice"),
            SaslMechanism::External => ("", ""),
            _ => ("alice", "s3cret"),
        };
        let mut client = create_client(mech, user, pass, "mail.example");

        let mut client_msg: Option<Vec<u8>> = if client.has_initial_response() {
            match client.evaluate(None) {
                SaslClientStep::Response(b) | SaslClientStep::Complete(b) => Some(b),
                SaslClientStep::Failure => panic!("client initial failed for {mech}"),
            }
        } else {
            None
        };

        for _ in 0..8 {
            if server.server_first() && client_msg.is_none() {
                // server sends first
            }
            let step = server.step(client_msg.as_deref());
            match step {
                SaslServerStep::Challenge(ch) => match client.evaluate(Some(&ch)) {
                    SaslClientStep::Response(b) | SaslClientStep::Complete(b) => {
                        client_msg = if b.is_empty() { None } else { Some(b) };
                    }
                    SaslClientStep::Failure => panic!("client failed on challenge for {mech}"),
                },
                SaslServerStep::Complete { username, final_message } => {
                    if let Some(fin) = final_message {
                        let _ = client.evaluate(Some(&fin));
                    }
                    assert!(
                        username == "alice" || mech == SaslMechanism::External && !username.is_empty(),
                        "mech={mech} user={username}"
                    );
                    return;
                }
                SaslServerStep::Failure => panic!("server failed for {mech}"),
            }
        }
        panic!("did not complete {mech}");
    }

    #[test]
    fn all_sasl_mechanisms_roundtrip() {
        let store: Arc<dyn CredentialStore> = Arc::new(
            PasswordStore::new()
                .with_user("alice", "s3cret")
                .with_token("tok-alice", "alice")
                .with_certificate("fp-alice", "alice"),
        );
        for mech in SaslMechanism::all() {
            roundtrip(*mech, Arc::clone(&store));
        }
    }
}
