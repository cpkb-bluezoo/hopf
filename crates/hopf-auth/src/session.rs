// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL client/server session traits and factories.

use std::sync::Arc;

use crate::mechanism::SaslMechanism;
use crate::store::CredentialStore;

/// Server-side step result.
#[derive(Debug, Clone)]
pub enum SaslServerStep {
    /// Send another challenge to the client.
    Challenge(Vec<u8>),
    /// Authentication succeeded.
    Complete {
        /// Authenticated (or authorized) username.
        username: String,
        /// Optional final server message (e.g. SCRAM `v=…`, DIGEST `rspauth`).
        final_message: Option<Vec<u8>>,
    },
    /// Authentication failed.
    Failure,
}

/// Server SASL exchange (one authentication attempt).
pub trait SaslServer: Send {
    /// Mechanism name.
    fn mechanism(&self) -> SaslMechanism;
    /// Whether the server sends the first challenge before any client data.
    fn server_first(&self) -> bool {
        false
    }
    /// Process client response (`None` = empty / initial).
    fn step(&mut self, client_response: Option<&[u8]>) -> SaslServerStep;
}

/// Client-side step result.
#[derive(Debug, Clone)]
pub enum SaslClientStep {
    /// Send response to the server.
    Response(Vec<u8>),
    /// Finished successfully (may still need to consume a final server message).
    Complete(Vec<u8>),
    /// Failed.
    Failure,
}

/// Client SASL exchange.
pub trait SaslClient: Send {
    /// Mechanism name.
    fn mechanism(&self) -> SaslMechanism;
    /// Whether the client sends data with the AUTH command (initial response).
    fn has_initial_response(&self) -> bool;
    /// Process server challenge (`None` / empty for initial).
    fn evaluate(&mut self, challenge: Option<&[u8]>) -> SaslClientStep;
    /// True after a successful complete.
    fn is_complete(&self) -> bool;
}

/// Options for creating a server mechanism.
#[derive(Debug, Clone)]
pub struct SaslServerOptions {
    /// Hostname for CRAM challenges / DIGEST digest-uri service.
    pub hostname: String,
    /// Realm string for DIGEST-MD5.
    pub realm: String,
    /// Optional peer certificate fingerprint/DN for EXTERNAL.
    pub peer_certificate: Option<String>,
    /// This connection's `tls-server-end-point` channel-binding data
    /// (RFC 5929 §4), required for SCRAM-SHA-256-PLUS. `None` when
    /// creating plain SCRAM-SHA-256 (or any other mechanism, where it's
    /// unused).
    pub channel_binding: Option<Vec<u8>>,
}

impl Default for SaslServerOptions {
    fn default() -> Self {
        Self {
            hostname: "localhost".into(),
            realm: "hopf".into(),
            peer_certificate: None,
            channel_binding: None,
        }
    }
}

/// Create a server session for `mechanism`.
pub fn create_server(
    mechanism: SaslMechanism,
    store: Arc<dyn CredentialStore>,
    opts: SaslServerOptions,
) -> Box<dyn SaslServer> {
    match mechanism {
        SaslMechanism::Plain => Box::new(crate::plain::PlainServer::new(store)),
        SaslMechanism::Login => Box::new(crate::login::LoginServer::new(store)),
        SaslMechanism::CramMd5 => Box::new(crate::cram_md5::CramMd5Server::new(store, opts.hostname)),
        SaslMechanism::DigestMd5 => {
            Box::new(crate::digest_md5::DigestMd5Server::new(store, opts.realm))
        }
        SaslMechanism::ScramSha256 => Box::new(crate::scram::ScramSha256Server::new(store)),
        SaslMechanism::ScramSha256Plus => {
            let mut s = crate::scram::ScramSha256Server::new(store);
            if let Some(cb) = opts.channel_binding {
                s = s.with_channel_binding(cb);
            }
            Box::new(s)
        }
        SaslMechanism::OauthBearer => Box::new(crate::oauthbearer::OauthBearerServer::new(store)),
        SaslMechanism::External => {
            let mut s = crate::external::ExternalServer::new(store);
            if let Some(k) = opts.peer_certificate {
                s.set_peer_certificate(k);
            }
            Box::new(s)
        }
    }
}

/// Create a client session. `cert_authzid` is used for EXTERNAL (optional
/// authzid). `channel_binding` is required for
/// [`SaslMechanism::ScramSha256Plus`] — this connection's
/// `tls-server-end-point` data (RFC 5929 §4); ignored by every other
/// mechanism.
pub fn create_client(
    mechanism: SaslMechanism,
    username: &str,
    password: &str,
    host: &str,
    channel_binding: Option<&[u8]>,
) -> Box<dyn SaslClient> {
    match mechanism {
        SaslMechanism::Plain => Box::new(crate::plain::PlainClient::new(username, password)),
        SaslMechanism::Login => Box::new(crate::login::LoginClient::new(username, password)),
        SaslMechanism::CramMd5 => Box::new(crate::cram_md5::CramMd5Client::new(username, password)),
        SaslMechanism::DigestMd5 => {
            Box::new(crate::digest_md5::DigestMd5Client::new(username, password, host))
        }
        SaslMechanism::ScramSha256 => {
            Box::new(crate::scram::ScramSha256Client::new(username, password))
        }
        SaslMechanism::ScramSha256Plus => Box::new(crate::scram::ScramSha256Client::new_plus(
            username,
            password,
            channel_binding.unwrap_or(&[]).to_vec(),
        )),
        SaslMechanism::OauthBearer => {
            // password slot carries the bearer token
            Box::new(crate::oauthbearer::OauthBearerClient::new(username, password))
        }
        SaslMechanism::External => Box::new(crate::external::ExternalClient::new(username)),
    }
}
