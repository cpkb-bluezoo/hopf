// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! SASL LOGIN (legacy two-step Base64 username then password).

use std::sync::Arc;

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

    fn step(&mut self, client_response: Option<&[u8]>, cb: crate::session::Cb<SaslServerStep>) {
        if self.phase == Phase::Done {
            return cb(SaslServerStep::Failure);
        }
        if !self.prompted {
            self.prompted = true;
            return cb(SaslServerStep::Challenge(b"Username:".to_vec()));
        }
        let Some(raw) = client_response else {
            return cb(SaslServerStep::Failure);
        };
        cb(match self.phase {
            Phase::ExpectUsername => {
                self.username = String::from_utf8_lossy(raw).into_owned();
                self.phase = Phase::ExpectPassword;
                SaslServerStep::Challenge(b"Password:".to_vec())
            }
            Phase::ExpectPassword => {
                let pass = String::from_utf8_lossy(raw).into_owned();
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
        });
    }
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
                SaslClientStep::Response(self.username.as_bytes().to_vec())
            }
            1 => {
                self.step = 2;
                self.complete = true;
                SaslClientStep::Complete(self.password.as_bytes().to_vec())
            }
            _ => SaslClientStep::Failure,
        }
    }

    fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PasswordStore;

    fn step(server: &mut LoginServer, response: Option<&[u8]>) -> SaslServerStep {
        let (tx, rx) = std::sync::mpsc::channel();
        server.step(response, Box::new(move |s| {
            let _ = tx.send(s);
        }));
        rx.recv().unwrap()
    }

    #[test]
    fn client_answers_with_the_raw_credentials() {
        // The transport does the base64; the mechanism must not.
        let mut client = LoginClient::new("alice", "s3cret");
        match client.evaluate(Some(b"Username:")) {
            SaslClientStep::Response(r) => assert_eq!(r, b"alice"),
            other => panic!("{other:?}"),
        }
        match client.evaluate(Some(b"Password:")) {
            SaslClientStep::Complete(r) => assert_eq!(r, b"s3cret"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn server_takes_a_password_that_looks_like_base64_literally() {
        for password in ["abcd", "YWxpY2U=", "Zm9v"] {
            let store: Arc<dyn CredentialStore> = Arc::new(PasswordStore::new().with_user("abcd", password));
            let mut server = LoginServer::new(store);
            assert!(matches!(step(&mut server, None), SaslServerStep::Challenge(_)));
            assert!(matches!(step(&mut server, Some(b"abcd")), SaslServerStep::Challenge(_)));
            match step(&mut server, Some(password.as_bytes())) {
                SaslServerStep::Complete { username, .. } => assert_eq!(username, "abcd"),
                other => panic!("password {password:?}: {other:?}"),
            }
        }
    }
}
