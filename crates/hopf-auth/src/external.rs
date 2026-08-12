// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL EXTERNAL (RFC 4422 Appendix A) — certificate identity supplied by TLS layer.

use std::sync::Arc;

use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

/// Server EXTERNAL: client_response is authzid (may be empty);
/// `cert_key` must be set via [`ExternalServer::with_peer_certificate`] before stepping.
pub(crate) struct ExternalServer {
    store: Arc<dyn CredentialStore>,
    cert_key: Option<String>,
}

impl ExternalServer {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self {
            store,
            cert_key: None,
        }
    }

    /// Set peer certificate fingerprint or subject DN (from TLS SecurityInfo).
    pub fn with_peer_certificate(mut self, cert_key: impl Into<String>) -> Self {
        self.cert_key = Some(cert_key.into());
        self
    }

    /// Set peer certificate key after construction.
    pub fn set_peer_certificate(&mut self, cert_key: impl Into<String>) {
        self.cert_key = Some(cert_key.into());
    }
}

impl SaslServer for ExternalServer {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::External
    }

    fn step(&mut self, client_response: Option<&[u8]>, cb: crate::session::Cb<SaslServerStep>) {
        let Some(cert_key) = self.cert_key.clone() else {
            return cb(SaslServerStep::Failure);
        };
        let Some(id) = self.store.authenticate_certificate(&cert_key) else {
            return cb(SaslServerStep::Failure);
        };
        let authzid = client_response
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        if !self.store.authorize_as(&id.username, &authzid) {
            return cb(SaslServerStep::Failure);
        }
        let username = if authzid.is_empty() {
            id.username
        } else {
            authzid
        };
        cb(SaslServerStep::Complete {
            username,
            final_message: None,
        });
    }
}

/// Client EXTERNAL: sends optional authzid (username field).
pub(crate) struct ExternalClient {
    authzid: String,
    complete: bool,
}

impl ExternalClient {
    pub fn new(authzid: &str) -> Self {
        Self {
            authzid: authzid.into(),
            complete: false,
        }
    }
}

impl SaslClient for ExternalClient {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::External
    }

    fn has_initial_response(&self) -> bool {
        true
    }

    fn evaluate(&mut self, _challenge: Option<&[u8]>) -> SaslClientStep {
        self.complete = true;
        SaslClientStep::Complete(self.authzid.as_bytes().to_vec())
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Helper: create EXTERNAL server with cert key already set.
pub fn create_external_server(
    store: Arc<dyn CredentialStore>,
    cert_key: impl Into<String>,
) -> Box<dyn SaslServer> {
    Box::new(ExternalServer::new(store).with_peer_certificate(cert_key))
}
