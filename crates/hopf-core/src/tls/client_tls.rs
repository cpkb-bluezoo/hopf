// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`ClientTlsBuilder`]: how a client trusts the server it dials, and what it
//! presents in return, in one place.
//!
//! The fixed helpers ([`connector_from_pem`](super::connector_from_pem),
//! [`public_trust_connector`](super::public_trust_connector),
//! [`connector_from_pem_with_client_cert`](super::connector_from_pem_with_client_cert),
//! [`connector_with_verify_override`](super::connector_with_verify_override))
//! each fix one combination. The builder combines them: trust anchors (or the
//! public WebPKI), a client certificate for mutual TLS, a verifier of your own
//! in place of the trust check (a pinned public key, DANE), ALPN and the TCP
//! version policy.

use bytes::Bytes;

use super::engine::{ServerCredentials, VerifyFn, VerifyOverride};
use super::pem::{trusted_connector, SharedTlsConnector};
use super::TcpTlsVersionPolicy;
use crate::crypto::trust::{public_trust_store, TrustStore};

/// What the client trusts.
#[derive(Clone, Default)]
enum Trust {
    /// The public WebPKI (the OS roots, else a vendored copy).
    #[default]
    Public,
    /// These anchors.
    Store(TrustStore),
    /// Whatever the verifier says; no trust store.
    Verifier(VerifyFn),
}

/// Builds a [`SharedTlsConnector`]. See the module documentation.
///
/// ```no_run
/// use hopf_core::{ClientTlsBuilder, ServerCredentials};
/// # fn creds() -> ServerCredentials { unimplemented!() }
/// # fn main() -> std::io::Result<()> {
/// // Public WebPKI trust, and a client certificate for mutual TLS.
/// let connector = ClientTlsBuilder::new().client_credentials(creds()).alpn(&[b"dot"]).build();
/// # let _ = connector; Ok(()) }
/// ```
#[derive(Clone, Default)]
pub struct ClientTlsBuilder {
    trust: Trust,
    credentials: Option<ServerCredentials>,
    alpn: Vec<Bytes>,
    version_policy: TcpTlsVersionPolicy,
}

impl ClientTlsBuilder {
    /// Trust the public WebPKI, present no certificate, negotiate TLS 1.3 or
    /// 1.2 and offer no ALPN.
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust only these anchors (DER CA or leaf certificates).
    pub fn trust_store(mut self, store: TrustStore) -> Self {
        self.trust = Trust::Store(store);
        self
    }

    /// Trust only these DER certificates.
    pub fn trust_anchors(self, anchors: impl IntoIterator<Item = Bytes>) -> Self {
        let mut store = TrustStore::new();
        for anchor in anchors {
            store.add_anchor(anchor);
        }
        self.trust_store(store)
    }

    /// The public WebPKI roots (the default).
    pub fn public_trust(mut self) -> Self {
        self.trust = Trust::Public;
        self
    }

    /// Decide for yourself whether the server's chain (DER, leaf first) for
    /// the name being verified is trusted. The verdict replaces the trust
    /// store entirely, so a verifier that wants the usual chain check as well
    /// as, say, a pinned key runs
    /// [`TrustStore::verify_server_chain`](crate::crypto::trust::TrustStore::verify_server_chain)
    /// itself.
    pub fn verify(mut self, verify: VerifyFn) -> Self {
        self.trust = Trust::Verifier(verify);
        self
    }

    /// The certificate chain and key to present when the server asks for a
    /// client certificate (mutual TLS).
    pub fn client_credentials(mut self, credentials: ServerCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// ALPN protocol names to offer, most preferred first.
    pub fn alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| Bytes::copy_from_slice(p)).collect();
        self
    }

    /// Which TLS versions to use over TCP (the default negotiates 1.3 or 1.2).
    pub fn tcp_version_policy(mut self, policy: TcpTlsVersionPolicy) -> Self {
        self.version_policy = policy;
        self
    }

    /// Build the connector.
    pub fn build(self) -> SharedTlsConnector {
        let (store, verify) = match self.trust {
            Trust::Public => (Some(public_trust_store()), None),
            Trust::Store(store) => (Some(store), None),
            Trust::Verifier(verify) => (None, Some(VerifyOverride(verify))),
        };
        trusted_connector(store, verify, self.alpn, self.credentials, self.version_policy)
    }
}
