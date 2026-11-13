// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! [`ServerTlsBuilder`]: one place to say how a server presents itself and
//! how it treats client certificates, for a TCP listener
//! ([`ServerTlsBuilder::build`]) or a QUIC one (`hopf_quic::server_config_from_tls_builder`).
//!
//! The fixed helpers ([`acceptor_from_pem_with_client_auth`](super::acceptor_from_pem_with_client_auth),
//! [`acceptor_from_pem_with_sni`](super::acceptor_from_pem_with_sni), ...) each
//! fix one combination. This builder combines what they offer and adds what
//! a server that changes while it runs needs: a credentials resolver that is
//! consulted for every handshake (rotated certificates, one per SNI name), and
//! client trust that is consulted for every handshake too, either as a trust
//! store fetched anew ([`client_trust`](ServerTlsBuilder::client_trust)) or as
//! a verdict computed from the client's chain
//! ([`client_verify`](ServerTlsBuilder::client_verify)). Nothing is fixed at
//! build time that a restart would otherwise have to refresh.

use std::io;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;

use super::engine::{
    ClientAuthPolicy, ClientTrustSource, ClientVerifyOverride, HandshakeConfig, ServerCredentials,
    ServerCredentialsResolver,
};
use super::negotiating::ServerTlsMaterial;
use super::pem::{server_credentials_from_pem, SharedTlsAcceptor, TlsAcceptor};
use super::{TcpTlsVersionPolicy, TlsVariant};
use crate::crypto::trust::TrustStore;

/// How a server trusts the certificates its clients present.
#[derive(Clone, Default)]
enum ClientTrust {
    #[default]
    Unset,
    /// A fixed set of anchors.
    Store(TrustStore),
    /// Anchors fetched for each handshake.
    Source(ClientTrustSource),
    /// A verdict computed from the chain, instead of anchors.
    Verify(ClientVerifyOverride),
}

/// Builds a server's TLS configuration. See the module documentation.
///
/// ```no_run
/// use hopf_core::crypto::TrustStore;
/// use hopf_core::{ClientAuthPolicy, ServerTlsBuilder};
/// # fn current_clients() -> TrustStore { TrustStore::new() }
/// # fn main() -> std::io::Result<()> {
/// let acceptor = ServerTlsBuilder::new()
///     .credentials_from_pem("server.pem".as_ref(), "server.key".as_ref())?
///     .alpn(&[b"dot"])
///     .client_auth(ClientAuthPolicy::Require)
///     // Called for every handshake, so swapping the trust anchors needs no restart.
///     .client_trust(current_clients)
///     .build()?;
/// # let _ = acceptor; Ok(()) }
/// ```
#[derive(Clone, Default)]
pub struct ServerTlsBuilder {
    creds: Option<ServerCredentials>,
    resolver: Option<ServerCredentialsResolver>,
    alpn: Vec<Bytes>,
    client_auth: ClientAuthPolicy,
    trust: ClientTrust,
    version_policy: TcpTlsVersionPolicy,
}

impl ServerTlsBuilder {
    /// A builder with nothing set: it needs credentials or a resolver before
    /// it can build.
    pub fn new() -> Self {
        Self::default()
    }

    /// The certificate chain and key to present. With a
    /// [`server_resolver`](Self::server_resolver) as well, these are the
    /// fallback for a name the resolver does not know.
    pub fn credentials(mut self, creds: ServerCredentials) -> Self {
        self.creds = Some(creds);
        self
    }

    /// [`credentials`](Self::credentials) read from a PEM certificate chain and
    /// a PKCS#8 PEM key.
    pub fn credentials_from_pem(self, cert_path: &Path, key_path: &Path) -> io::Result<Self> {
        Ok(self.credentials(server_credentials_from_pem(cert_path, key_path)?))
    }

    /// Choose the credentials for each handshake from the client's SNI (`None`
    /// if it sent none). The resolver is called on every handshake, so it can
    /// serve several hostnames and hand out a rotated certificate as soon as
    /// it has one. Returning `None` falls back to
    /// [`credentials`](Self::credentials), if set.
    pub fn server_resolver(mut self, resolver: ServerCredentialsResolver) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// The ALPN protocol names to accept, most preferred first.
    pub fn alpn(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| Bytes::copy_from_slice(p)).collect();
        self
    }

    /// Whether to ask clients for a certificate. The default,
    /// [`ClientAuthPolicy::None`], never asks. Anything else needs one of
    /// [`client_trust_store`](Self::client_trust_store),
    /// [`client_trust`](Self::client_trust) or
    /// [`client_verify`](Self::client_verify).
    pub fn client_auth(mut self, policy: ClientAuthPolicy) -> Self {
        self.client_auth = policy;
        self
    }

    /// Verify client certificates against a fixed set of trust anchors.
    pub fn client_trust_store(mut self, store: TrustStore) -> Self {
        self.trust = ClientTrust::Store(store);
        self
    }

    /// Verify client certificates against the trust anchors `current` returns,
    /// called afresh for every handshake. Swap what it returns (a reloaded
    /// directory, a refreshed bundle) and the next handshake uses it, with no
    /// restart.
    pub fn client_trust(mut self, current: impl Fn() -> TrustStore + Send + Sync + 'static) -> Self {
        self.trust = ClientTrust::Source(ClientTrustSource::new(current));
        self
    }

    /// Decide for yourself whether a client's chain (DER, leaf first) is
    /// trusted, called for every handshake that presents one. The verdict
    /// replaces any trust store: use it for an allow-list of subjects, a
    /// revocation check or a directory lookup.
    pub fn client_verify(mut self, verify: ClientVerifyOverride) -> Self {
        self.trust = ClientTrust::Verify(verify);
        self
    }

    /// Which TLS versions to accept over TCP (the default negotiates 1.3 or
    /// 1.2). QUIC is always 1.3.
    pub fn tcp_version_policy(mut self, policy: TcpTlsVersionPolicy) -> Self {
        self.version_policy = policy;
        self
    }

    fn validate(&self) -> io::Result<()> {
        let invalid = |msg: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned()));
        if self.creds.is_none() && self.resolver.is_none() {
            return invalid("a server needs credentials or a credentials resolver");
        }
        match (self.client_auth, &self.trust) {
            (ClientAuthPolicy::None, ClientTrust::Unset) => Ok(()),
            (ClientAuthPolicy::None, _) => {
                invalid("client trust is set but client_auth is None, so no client certificate would be asked for")
            }
            (_, ClientTrust::Unset) => invalid(
                "client_auth asks for a client certificate, but no client_trust_store, client_trust or client_verify says whom to trust",
            ),
            _ => Ok(()),
        }
    }

    /// Set this configuration on `config`: the credentials, resolver, ALPN
    /// protocols (when any were given) and client-certificate policy. This is
    /// how a QUIC (or DTLS) server takes the same configuration as a TCP one.
    ///
    /// # Errors
    /// [`io::ErrorKind::InvalidInput`] if the configuration is inconsistent:
    /// no credentials and no resolver, client authentication with nothing to
    /// trust, or trust with no client authentication.
    pub fn apply_to(&self, config: &mut HandshakeConfig) -> io::Result<()> {
        self.validate()?;
        config.server = self.creds.clone();
        config.server_resolver = self.resolver.clone();
        if !self.alpn.is_empty() {
            config.alpn = self.alpn.clone();
        }
        config.client_auth = self.client_auth;
        config.client_trust_store = None;
        config.client_trust_source = None;
        config.client_verify_override = None;
        match &self.trust {
            ClientTrust::Unset => {}
            ClientTrust::Store(store) => config.client_trust_store = Some(store.clone()),
            ClientTrust::Source(source) => config.client_trust_source = Some(source.clone()),
            ClientTrust::Verify(verify) => config.client_verify_override = Some(verify.clone()),
        }
        Ok(())
    }

    /// Build the acceptor for a TCP listener.
    ///
    /// # Errors
    /// As [`apply_to`](Self::apply_to).
    pub fn build(self) -> io::Result<SharedTlsAcceptor> {
        self.validate()?;
        Ok(Arc::new(self))
    }
}

impl TlsAcceptor for ServerTlsBuilder {
    fn accept(&self) -> TlsVariant {
        let mut material = ServerTlsMaterial {
            creds: self.creds.clone(),
            alpn: self.alpn.clone(),
            client_auth: self.client_auth,
            client_trust_store: None,
            client_trust_source: None,
            client_verify_override: None,
            server_resolver: self.resolver.clone(),
            version_policy: self.version_policy,
        };
        match &self.trust {
            ClientTrust::Unset => {}
            ClientTrust::Store(store) => material.client_trust_store = Some(store.clone()),
            ClientTrust::Source(source) => material.client_trust_source = Some(source.clone()),
            ClientTrust::Verify(verify) => material.client_verify_override = Some(verify.clone()),
        }
        material.into_variant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::trust::TrustStore;

    fn creds() -> ServerCredentials {
        ServerCredentials {
            cert_chain: vec![Bytes::from_static(b"cert")],
            signing_key_pkcs8: Bytes::from_static(b"key"),
        }
    }

    fn resolver() -> ServerCredentialsResolver {
        ServerCredentialsResolver(Arc::new(|_| Some(creds())))
    }

    fn invalid(r: io::Result<impl Sized>) -> String {
        let e = r.err().expect("expected an error");
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        e.to_string()
    }

    #[test]
    fn a_server_needs_credentials_or_a_resolver() {
        assert!(invalid(ServerTlsBuilder::new().build()).contains("credentials"));
        assert!(ServerTlsBuilder::new().credentials(creds()).build().is_ok());
        assert!(ServerTlsBuilder::new().server_resolver(resolver()).build().is_ok());
    }

    #[test]
    fn asking_for_client_certificates_needs_something_to_trust() {
        let asks = ServerTlsBuilder::new().credentials(creds()).client_auth(ClientAuthPolicy::Require);
        assert!(invalid(asks.clone().build()).contains("whom to trust"));
        assert!(asks.clone().client_trust_store(TrustStore::new()).build().is_ok());
        assert!(asks.clone().client_trust(TrustStore::new).build().is_ok());
        assert!(asks.client_verify(ClientVerifyOverride::new(|_| true)).build().is_ok());
    }

    #[test]
    fn client_trust_without_client_auth_is_a_mistake_not_a_silent_no_op() {
        let b = ServerTlsBuilder::new().credentials(creds()).client_trust(TrustStore::new);
        assert!(invalid(b.build()).contains("client_auth is None"));
    }

    #[test]
    fn apply_to_sets_a_handshake_config_the_way_build_would() {
        let b = ServerTlsBuilder::new()
            .credentials(creds())
            .server_resolver(resolver())
            .alpn(&[b"doq"])
            .client_auth(ClientAuthPolicy::Request)
            .client_trust(TrustStore::new);
        let mut config = HandshakeConfig::default();
        b.apply_to(&mut config).unwrap();
        assert!(config.server.is_some() && config.server_resolver.is_some());
        assert_eq!(config.alpn, vec![Bytes::from_static(b"doq")]);
        assert_eq!(config.client_auth, ClientAuthPolicy::Request);
        assert!(config.client_trust_source.is_some());
        assert!(config.client_trust_store.is_none() && config.client_verify_override.is_none());

        // Re-applying a different trust source replaces the earlier one.
        let b = b.client_verify(ClientVerifyOverride::new(|_| true));
        b.apply_to(&mut config).unwrap();
        assert!(config.client_verify_override.is_some() && config.client_trust_source.is_none());
    }

    #[test]
    fn apply_to_keeps_the_configs_alpn_when_none_was_given() {
        let mut config = HandshakeConfig { alpn: vec![Bytes::from_static(b"h3")], ..Default::default() };
        ServerTlsBuilder::new().credentials(creds()).apply_to(&mut config).unwrap();
        assert_eq!(config.alpn, vec![Bytes::from_static(b"h3")]);
    }
}
