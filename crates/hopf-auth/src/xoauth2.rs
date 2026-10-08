// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL XOAUTH2 — Google's pre-standard bearer-token mechanism, which Gmail
//! and Microsoft 365 still advertise for IMAP, POP3 and SMTP submission
//! alongside (or instead of) RFC 7628 OAUTHBEARER.
//!
//! One message from the client, no GS2 header:
//!
//! ```text
//! user=<address>^Aauth=Bearer <token>^A^A
//! ```
//!
//! Success is the protocol's own OK. On failure the server may first send
//! a challenge carrying a base64 JSON error (`{"status":"401",…}`), to
//! which the client must answer with an empty response before the server
//! returns its final NO; [`XOauth2Client`] does that.
//!
//! Reference: <https://developers.google.com/gmail/imap/xoauth2-protocol>.

use std::collections::HashMap;
use std::sync::Arc;

use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

/// Parse the (decoded) client message into `user` and `token`.
pub fn parse_credentials(credentials: &str) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for part in credentials.split('\u{0001}') {
        if let Some(user) = part.strip_prefix("user=") {
            result.insert("user".into(), user.to_string());
        } else if let Some(token) = part.strip_prefix("auth=Bearer ") {
            result.insert("token".into(), token.to_string());
        }
    }
    result
}

/// Build the client message (before base64).
pub fn encode_credentials(user: &str, token: &str) -> Vec<u8> {
    format!("user={user}\u{0001}auth=Bearer {token}\u{0001}\u{0001}").into_bytes()
}

pub(crate) struct XOauth2Server {
    store: Arc<dyn CredentialStore>,
}

impl XOauth2Server {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self { store }
    }
}

impl SaslServer for XOauth2Server {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::XOauth2
    }

    fn step(&mut self, client_response: Option<&[u8]>, cb: crate::session::Cb<SaslServerStep>) {
        let Some(raw) = client_response.filter(|d| !d.is_empty()) else {
            return cb(SaslServerStep::Failure);
        };
        let text = String::from_utf8_lossy(raw);
        let parsed = parse_credentials(&text);
        let Some(token) = parsed.get("token").cloned() else {
            return cb(SaslServerStep::Failure);
        };
        let requested_user = parsed.get("user").cloned().filter(|u| !u.is_empty());
        self.store.validate_bearer(
            &token,
            Box::new(move |result| {
                let Some(v) = result else {
                    return cb(SaslServerStep::Failure);
                };
                // The token decides who the client is; a `user=` that names
                // someone else is not honoured.
                if requested_user.as_deref().is_some_and(|u| u != v.username) {
                    return cb(SaslServerStep::Failure);
                }
                cb(SaslServerStep::Complete { username: v.username, final_message: None })
            }),
        );
    }
}

/// Client side: sends the credentials once (as the initial response when
/// the protocol allows one, otherwise in reply to the server's empty
/// challenge), and answers an error challenge with the empty response the
/// mechanism requires.
pub(crate) struct XOauth2Client {
    username: String,
    token: String,
    sent: bool,
    failed: bool,
}

impl XOauth2Client {
    pub fn new(username: &str, token: &str) -> Self {
        Self { username: username.into(), token: token.into(), sent: false, failed: false }
    }
}

impl SaslClient for XOauth2Client {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::XOauth2
    }

    fn has_initial_response(&self) -> bool {
        true
    }

    fn evaluate(&mut self, challenge: Option<&[u8]>) -> SaslClientStep {
        if self.failed {
            return SaslClientStep::Failure;
        }
        if !self.sent {
            // Either the initial response (challenge `None`) or the reply
            // to the server's empty `+` when no initial response was sent.
            self.sent = true;
            return SaslClientStep::Response(encode_credentials(&self.username, &self.token));
        }
        // Credentials already went out: any challenge now is the error
        // report. Acknowledge it with an empty response; the server's
        // final reply (NO) follows.
        let _ = challenge;
        self.failed = true;
        SaslClientStep::Response(Vec::new())
    }

    fn is_complete(&self) -> bool {
        self.sent && !self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_parse_round_trip() {
        let raw = encode_credentials("user@example.com", "ya29.token123");
        assert_eq!(raw, b"user=user@example.com\x01auth=Bearer ya29.token123\x01\x01".to_vec());
        let m = parse_credentials(std::str::from_utf8(&raw).unwrap());
        assert_eq!(m.get("user").map(String::as_str), Some("user@example.com"));
        assert_eq!(m.get("token").map(String::as_str), Some("ya29.token123"));
        assert!(parse_credentials("nothing here").is_empty());
    }

    #[test]
    fn client_with_initial_response_then_success() {
        let mut c = XOauth2Client::new("u@x", "tok");
        assert!(c.has_initial_response());
        assert!(!c.is_complete());
        match c.evaluate(None) {
            SaslClientStep::Response(r) => assert_eq!(r, encode_credentials("u@x", "tok")),
            other => panic!("{other:?}"),
        }
        // The server's OK ends it; nothing more is exchanged.
        assert!(c.is_complete());
    }

    #[test]
    fn client_without_initial_response_answers_the_empty_challenge() {
        let mut c = XOauth2Client::new("u@x", "tok");
        match c.evaluate(Some(b"")) {
            SaslClientStep::Response(r) => assert_eq!(r, encode_credentials("u@x", "tok")),
            other => panic!("{other:?}"),
        }
        assert!(c.is_complete());
    }

    #[test]
    fn client_acknowledges_an_error_challenge_with_an_empty_response() {
        let mut c = XOauth2Client::new("u@x", "bad");
        let _ = c.evaluate(None);
        // Gmail: `+ eyJzdGF0dXMiOiI0MDEiLCJzY2hlbWVzIjoiYmVhcmVyIiwic2NvcGUiOiJodHRwczovL21haWwuZ29vZ2xlLmNvbS8ifQ==`
        let err = br#"{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}"#;
        match c.evaluate(Some(err)) {
            SaslClientStep::Response(r) => assert!(r.is_empty(), "must be the empty response"),
            other => panic!("{other:?}"),
        }
        assert!(!c.is_complete());
        assert!(matches!(c.evaluate(Some(b"")), SaslClientStep::Failure));
    }

    #[test]
    fn mechanism_registry_knows_it() {
        assert_eq!(SaslMechanism::from_name("xoauth2"), Some(SaslMechanism::XOauth2));
        assert_eq!(SaslMechanism::XOauth2.name(), "XOAUTH2");
        assert!(SaslMechanism::XOauth2.requires_tls());
        assert!(!SaslMechanism::XOauth2.is_challenge_response());
        assert!(SaslMechanism::all().contains(&SaslMechanism::XOauth2));
    }
}
