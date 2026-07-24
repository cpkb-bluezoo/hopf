// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL PLAIN (RFC 4616).

use std::sync::Arc;

use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

/// Parse `authzid\\0authcid\\0password`.
pub fn parse_credentials(credentials: &[u8]) -> Option<(String, String, String)> {
    let mut nuls = Vec::new();
    for (i, b) in credentials.iter().enumerate() {
        if *b == 0 {
            nuls.push(i);
            if nuls.len() == 2 {
                break;
            }
        }
    }
    if nuls.len() != 2 {
        return None;
    }
    let authzid = String::from_utf8_lossy(&credentials[..nuls[0]]).into_owned();
    let authcid = String::from_utf8_lossy(&credentials[nuls[0] + 1..nuls[1]]).into_owned();
    let password = String::from_utf8_lossy(&credentials[nuls[1] + 1..]).into_owned();
    Some((authzid, authcid, password))
}

/// Encode PLAIN initial response (empty authzid).
pub fn encode_credentials(authzid: &str, authcid: &str, password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(authzid.len() + authcid.len() + password.len() + 2);
    out.extend_from_slice(authzid.as_bytes());
    out.push(0);
    out.extend_from_slice(authcid.as_bytes());
    out.push(0);
    out.extend_from_slice(password.as_bytes());
    out
}

pub(crate) struct PlainServer {
    store: Arc<dyn CredentialStore>,
}

impl PlainServer {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self { store }
    }
}

impl SaslServer for PlainServer {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Plain
    }

    fn step(&mut self, client_response: Option<&[u8]>) -> SaslServerStep {
        let Some(data) = client_response.filter(|d| !d.is_empty()) else {
            return SaslServerStep::Failure;
        };
        let Some((authzid, authcid, password)) = parse_credentials(data) else {
            return SaslServerStep::Failure;
        };
        if !self.store.password_match(&authcid, &password) {
            return SaslServerStep::Failure;
        }
        if !self.store.authorize_as(&authcid, &authzid) {
            return SaslServerStep::Failure;
        }
        let username = if authzid.is_empty() {
            authcid
        } else {
            authzid
        };
        SaslServerStep::Complete {
            username,
            final_message: None,
        }
    }
}

pub(crate) struct PlainClient {
    username: String,
    password: String,
    complete: bool,
}

impl PlainClient {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            complete: false,
        }
    }
}

impl SaslClient for PlainClient {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Plain
    }

    fn has_initial_response(&self) -> bool {
        true
    }

    fn evaluate(&mut self, _challenge: Option<&[u8]>) -> SaslClientStep {
        self.complete = true;
        SaslClientStep::Complete(encode_credentials("", &self.username, &self.password))
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_encode_parse_roundtrip() {
        let raw = encode_credentials("z", "alice", "secret");
        let (z, u, p) = parse_credentials(&raw).unwrap();
        assert_eq!((z.as_str(), u.as_str(), p.as_str()), ("z", "alice", "secret"));
        assert!(parse_credentials(b"nuls").is_none());
        assert!(parse_credentials(b"one\0only").is_none());
    }
}

