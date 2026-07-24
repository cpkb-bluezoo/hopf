// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL OAUTHBEARER (RFC 7628).

use std::collections::HashMap;
use std::sync::Arc;

use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

/// Parse GS2 + `auth=Bearer` message (decoded).
pub fn parse_credentials(credentials: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    let Some(first) = credentials.find('\u{0001}') else {
        return result;
    };
    let gs2 = &credentials[..first];
    for field in gs2.split(',') {
        if let Some(user) = field.strip_prefix("a=") {
            result.insert("user".into(), user.to_string());
        }
    }
    let mut part_start = first + 1;
    let bytes = credentials.as_bytes();
    while part_start < credentials.len() {
        let rest = &credentials[part_start..];
        let part_end = rest
            .find('\u{0001}')
            .map(|i| part_start + i)
            .unwrap_or(credentials.len());
        let part = &credentials[part_start..part_end];
        if let Some(token) = part.strip_prefix("auth=Bearer ") {
            result.insert("token".into(), token.to_string());
        }
        part_start = if part_end < credentials.len() {
            part_end + 1
        } else {
            break;
        };
        let _ = bytes;
    }
    result
}

/// Build client message.
pub fn encode_credentials(authzid: &str, token: &str) -> Vec<u8> {
    let gs2 = if authzid.is_empty() {
        "n,".to_string()
    } else {
        format!("n,a={authzid},")
    };
    format!("{gs2}\u{0001}auth=Bearer {token}\u{0001}\u{0001}").into_bytes()
}

pub(crate) struct OauthBearerServer {
    store: Arc<dyn CredentialStore>,
}

impl OauthBearerServer {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self { store }
    }
}

impl SaslServer for OauthBearerServer {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::OauthBearer
    }

    fn step(&mut self, client_response: Option<&[u8]>) -> SaslServerStep {
        let Some(raw) = client_response.filter(|d| !d.is_empty()) else {
            return SaslServerStep::Failure;
        };
        let text = String::from_utf8_lossy(raw);
        let parsed = parse_credentials(&text);
        let Some(token) = parsed.get("token") else {
            return SaslServerStep::Failure;
        };
        let Some(v) = self.store.validate_bearer(token) else {
            return SaslServerStep::Failure;
        };
        let username = parsed
            .get("user")
            .cloned()
            .filter(|u| !u.is_empty())
            .unwrap_or(v.username);
        SaslServerStep::Complete {
            username,
            final_message: None,
        }
    }
}

pub(crate) struct OauthBearerClient {
    username: String,
    token: String,
    complete: bool,
}

impl OauthBearerClient {
    pub fn new(username: &str, token: &str) -> Self {
        Self {
            username: username.into(),
            token: token.into(),
            complete: false,
        }
    }
}

impl SaslClient for OauthBearerClient {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::OauthBearer
    }

    fn has_initial_response(&self) -> bool {
        true
    }

    fn evaluate(&mut self, _challenge: Option<&[u8]>) -> SaslClientStep {
        self.complete = true;
        SaslClientStep::Complete(encode_credentials(&self.username, &self.token))
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauthbearer_parse_encode() {
        let raw = encode_credentials("bob", "tok-1");
        let text = String::from_utf8(raw).unwrap();
        let m = parse_credentials(&text);
        assert_eq!(m.get("user").map(String::as_str), Some("bob"));
        assert_eq!(m.get("token").map(String::as_str), Some("tok-1"));
        assert!(parse_credentials("no-separators").is_empty());
    }
}
