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
pub mod oauth_introspection;
pub mod oauthbearer;
pub mod plain;
pub mod scram;
pub mod session;
pub mod store;

#[cfg(all(feature = "pam", unix))]
pub mod pam;

pub use mechanism::SaslMechanism;
pub use oauth_introspection::{
    IntrospectionCredentialStore, IntrospectionRequest, IntrospectionResponse,
    IntrospectionTransport,
};
pub use session::{
    create_client, create_server, SaslClient, SaslClientStep, SaslServer, SaslServerOptions,
    SaslServerStep,
};
pub use store::{
    CertificateIdentity, Cb, CredentialStore, PasswordStore, ScramCredentials, TokenValidation,
};

#[cfg(all(feature = "pam", unix))]
pub use pam::{PamCredentialStore, PamStoreConfig, DEFAULT_PAM_SERVICE};

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

/// In-memory username → SCRAM-hashed password map (demos). Prefer
/// [`PasswordStore`] when also using SASL / Digest.
#[derive(Debug, Default, Clone)]
pub struct PasswordTrustPolicy {
    users: HashMap<String, ScramCredentials>,
}

impl PasswordTrustPolicy {
    /// Empty policy (rejects all username/password).
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a user (password enrolled then discarded).
    pub fn insert(&mut self, username: impl Into<String>, password: impl Into<String>) {
        let salt = crate::crypto::from_hex(&crate::crypto::generate_nonce_hex(16))
            .unwrap_or_else(|| vec![0u8; 16]);
        let creds = ScramCredentials::derive(&password.into(), &salt, 4096);
        self.users.insert(username.into(), creds);
    }

    /// Builder-style insert.
    pub fn with_user(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.insert(username, password);
        self
    }

    /// Convert into a full [`PasswordStore`].
    pub fn into_store(self) -> PasswordStore {
        let mut s = PasswordStore::new();
        for (u, scram) in self.users {
            s.insert_scram(u, scram, None);
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
                if self
                    .users
                    .get(username)
                    .map(|c| c.verify_password(password))
                    .unwrap_or(false)
                {
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
        let mut client = create_client(mech, user, pass, "mail.example", "smtp", None);

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
            let (tx, rx) = std::sync::mpsc::channel();
            server.step(client_msg.as_deref(), Box::new(move |s| { let _ = tx.send(s); }));
            let step = rx.recv().expect("step completes synchronously in tests");
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
                .with_digest_realm("example")
                .with_user("alice", "s3cret")
                .with_token("tok-alice", "alice")
                .with_certificate("fp-alice", "alice"),
        );
        for mech in store.supported_mechanisms() {
            roundtrip(mech, Arc::clone(&store));
        }
    }

    /// `ScramSha256Plus` is deliberately excluded from
    /// [`SaslMechanism::all`] (see its doc comment — advertising it by
    /// default would be a lie for every protocol crate today), but it must
    /// still be fully constructible and functional through the same
    /// factory functions for a caller that explicitly wires channel
    /// binding through.
    #[test]
    fn scram_plus_not_in_all_but_still_usable_via_factories() {
        assert!(!SaslMechanism::all().contains(&SaslMechanism::ScramSha256Plus));

        let store: Arc<dyn CredentialStore> =
            Arc::new(PasswordStore::new().with_user("alice", "s3cret"));
        let channel_binding = vec![0x42u8; 32];
        let opts = SaslServerOptions {
            channel_binding: Some(channel_binding.clone()),
            ..Default::default()
        };
        let mut server = create_server(SaslMechanism::ScramSha256Plus, store, opts);
        let mut client = create_client(
            SaslMechanism::ScramSha256Plus,
            "alice",
            "s3cret",
            "mail.example",
            "smtp",
            Some(&channel_binding),
        );
        assert_eq!(server.mechanism(), SaslMechanism::ScramSha256Plus);
        assert_eq!(client.mechanism(), SaslMechanism::ScramSha256Plus);

        let mut client_msg = match client.evaluate(None) {
            SaslClientStep::Response(b) => Some(b),
            other => panic!("unexpected initial step: {other:?}"),
        };
        for _ in 0..8 {
            let (tx, rx) = std::sync::mpsc::channel();
            server.step(client_msg.as_deref(), Box::new(move |s| { let _ = tx.send(s); }));
            match rx.recv().expect("step completes synchronously in tests") {
                SaslServerStep::Challenge(ch) => match client.evaluate(Some(&ch)) {
                    SaslClientStep::Response(b) | SaslClientStep::Complete(b) => {
                        client_msg = if b.is_empty() { None } else { Some(b) };
                    }
                    SaslClientStep::Failure => panic!("client failed"),
                },
                SaslServerStep::Complete { username, .. } => {
                    assert_eq!(username, "alice");
                    return;
                }
                SaslServerStep::Failure => panic!("server failed"),
            }
        }
        panic!("did not complete");
    }
}
