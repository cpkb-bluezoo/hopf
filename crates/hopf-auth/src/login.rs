// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL LOGIN (legacy two-step Base64 username then password).

use std::sync::Arc;

use crate::crypto::{decode_base64, encode_base64};
use crate::mechanism::SaslMechanism;
use crate::session::{SaslClient, SaslClientStep, SaslServer, SaslServerStep};
use crate::store::CredentialStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// About to send (or just sent) Username prompt.
    ExpectUsername,
    /// Waiting for password after Username received.
    ExpectPassword,
    Done,
}

pub(crate) struct LoginServer {
    store: Arc<dyn CredentialStore>,
    phase: Phase,
    username: String,
    prompted: bool,
}

impl LoginServer {
    pub fn new(store: Arc<dyn CredentialStore>) -> Self {
        Self {
            store,
            phase: Phase::ExpectUsername,
            username: String::new(),
            prompted: false,
        }
    }
}

impl SaslServer for LoginServer {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Login
    }

    fn server_first(&self) -> bool {
        true
    }

    fn step(&mut self, client_response: Option<&[u8]>) -> SaslServerStep {
        if self.phase == Phase::Done {
            return SaslServerStep::Failure;
        }
        if !self.prompted {
            self.prompted = true;
            return SaslServerStep::Challenge(b"Username:".to_vec());
        }
        let Some(raw) = client_response else {
            return SaslServerStep::Failure;
        };
        match self.phase {
            Phase::ExpectUsername => {
                self.username = decode_utf8_or_b64(raw);
                self.phase = Phase::ExpectPassword;
                SaslServerStep::Challenge(b"Password:".to_vec())
            }
            Phase::ExpectPassword => {
                let pass = decode_utf8_or_b64(raw);
                self.phase = Phase::Done;
                if self.store.password_match(&self.username, &pass) {
                    SaslServerStep::Complete {
                        username: self.username.clone(),
                        final_message: None,
                    }
                } else {
                    SaslServerStep::Failure
                }
            }
            Phase::Done => SaslServerStep::Failure,
        }
    }
}

fn decode_utf8_or_b64(raw: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(raw) {
        if let Some(decoded) = decode_base64(s) {
            if let Ok(u) = String::from_utf8(decoded) {
                return u;
            }
        }
        return s.to_string();
    }
    String::from_utf8_lossy(raw).into_owned()
}

pub(crate) struct LoginClient {
    username: String,
    password: String,
    step: u8,
    complete: bool,
}

impl LoginClient {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            step: 0,
            complete: false,
        }
    }
}

impl SaslClient for LoginClient {
    fn mechanism(&self) -> SaslMechanism {
        SaslMechanism::Login
    }

    fn has_initial_response(&self) -> bool {
        false
    }

    fn evaluate(&mut self, _challenge: Option<&[u8]>) -> SaslClientStep {
        match self.step {
            0 => {
                self.step = 1;
                SaslClientStep::Response(encode_base64(self.username.as_bytes()).into_bytes())
            }
            1 => {
                self.step = 2;
                self.complete = true;
                SaslClientStep::Complete(encode_base64(self.password.as_bytes()).into_bytes())
            }
            _ => SaslClientStep::Failure,
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}
