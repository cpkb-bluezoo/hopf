// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL CRAM-MD5 (RFC 2195).

use std::sync::Arc;

use crate::crypto::{ct_eq_hex, hmac_md5, to_hex};
use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

/// HMAC-MD5(password, challenge) as lowercase hex.
pub fn compute_response(password: &str, challenge: &str) -> String {
    to_hex(&hmac_md5(password.as_bytes(), challenge.as_bytes()))
}

/// Generate `<timestamp.pid@hostname>` challenge.
pub fn generate_challenge(hostname: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("<{ts}.{pid}@{hostname}>")
}

pub(crate) struct CramMd5Server {
    store: Arc<dyn CredentialStore>,
    challenge: String,
    sent: bool,
}

impl CramMd5Server {
    pub fn new(store: Arc<dyn CredentialStore>, hostname: String) -> Self {
        Self {
            store,
            challenge: generate_challenge(&hostname),
            sent: false,
        }
    }
}

impl SaslServer for CramMd5Server {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::CramMd5
    }

    fn server_first(&self) -> bool {
        true
    }

    fn step(&mut self, client_response: Option<&[u8]>) -> SaslServerStep {
        if !self.sent {
            self.sent = true;
            return SaslServerStep::Challenge(self.challenge.as_bytes().to_vec());
        }
        let Some(raw) = client_response else {
            return SaslServerStep::Failure;
        };
        let text = String::from_utf8_lossy(raw);
        let Some((user, digest)) = text.rsplit_once(' ') else {
            return SaslServerStep::Failure;
        };
        let Some(expected) = self.store.cram_md5_digest(user, &self.challenge) else {
            return SaslServerStep::Failure;
        };
        if ct_eq_hex(digest, &expected) {
            SaslServerStep::Complete {
                username: user.to_string(),
                final_message: None,
            }
        } else {
            SaslServerStep::Failure
        }
    }
}

pub(crate) struct CramMd5Client {
    username: String,
    password: String,
    complete: bool,
}

impl CramMd5Client {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            complete: false,
        }
    }
}

impl SaslClient for CramMd5Client {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::CramMd5
    }

    fn has_initial_response(&self) -> bool {
        false
    }

    fn evaluate(&mut self, challenge: Option<&[u8]>) -> SaslClientStep {
        let Some(ch) = challenge else {
            return SaslClientStep::Failure;
        };
        self.complete = true;
        let challenge_str = String::from_utf8_lossy(ch);
        let digest = compute_response(&self.password, &challenge_str);
        SaslClientStep::Complete(format!("{} {digest}", self.username).into_bytes())
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}
