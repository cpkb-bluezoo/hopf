// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! `SmtpVerify`: an auto-pilot that opens a session, learns the server's
//! capabilities and, when given credentials, proves them — then `QUIT`s
//! without sending anything.
//!
//! This is what a mail client runs when the user saves an outgoing
//! account ("are these settings right?") and what it runs first to find
//! out which `AUTH` mechanisms a server offers before it asks for a
//! password at all. The sequence is greeting → EHLO → (STARTTLS → EHLO)
//! → (AUTH) → QUIT, with the same TLS policy knobs as [`SmtpSend`].
//!
//! [`SmtpSend`]: super::SmtpSend

use std::io;
use std::sync::{Arc, Mutex};

use hopf_auth::{create_client, SaslClient, SaslClientStep};
use hopf_core::{Endpoint, Runtime};

use super::handlers::{SmtpClientDriver, SmtpClientHandlerFactory};
use super::pipeline::{choose_sasl_mechanism, ehlo_argument, no_mechanism_message};
use super::state::{
    SmtpCapabilities, SmtpClientAuthExchange, SmtpClientEnvelope, SmtpClientHello,
    SmtpClientMessageData, SmtpClientPostTls, SmtpClientSession,
};

/// How a [`SmtpVerify`] session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpVerifyOutcome {
    /// The session reached the point it was asked to: EHLO (after
    /// STARTTLS when that was required or offered), and AUTH when
    /// credentials were given. Carries the capabilities of the final
    /// EHLO — post-STARTTLS when TLS was negotiated, so `auth_methods`
    /// is what the server really offers an encrypted client.
    Verified(SmtpCapabilities),
    /// The server refused the credentials (`535` or another `5xx` to
    /// AUTH). The connection was closed cleanly.
    AuthFailed {
        /// The SMTP reply code.
        code: u16,
    },
    /// Anything else: no connection, no greeting, STARTTLS required but
    /// not offered or failed, no usable mechanism, a timeout.
    Failed(String),
}

impl SmtpVerifyOutcome {
    /// `true` for [`Verified`](Self::Verified).
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }
}

struct SmtpVerifyState {
    hostname: String,
    require_starttls: bool,
    opportunistic_starttls: bool,
    auth: Option<(String, String)>,
    auth_bearer: bool,
    sasl_client: Option<Box<dyn SaslClient>>,
    /// Capabilities of the last EHLO, reported on success.
    caps: Option<SmtpCapabilities>,
    on_result: Option<Box<dyn FnOnce(SmtpVerifyOutcome) + Send>>,
}

/// Builder and [`SmtpClientHandlerFactory`] for a verify-only session.
///
/// ```rust,ignore
/// let verify = SmtpVerify::new("")                 // EHLO with our address literal
///     .opportunistic_starttls(true)
///     .credentials_password("alice", "s3cret")
///     .on_result(Box::new(|outcome| println!("{outcome:?}")));
/// SmtpClient::new("smtp.example", 587)
///     .starttls(connector, "smtp.example")
///     .connect(&rt, Arc::new(verify))?;
/// ```
pub struct SmtpVerify(Arc<Mutex<SmtpVerifyState>>);

impl SmtpVerify {
    /// `hostname` is the EHLO argument; empty means this connection's own
    /// address literal (see [`SmtpSend::new`](super::SmtpSend::new)).
    pub fn new(hostname: impl Into<String>) -> Self {
        Self(Arc::new(Mutex::new(SmtpVerifyState {
            hostname: hostname.into(),
            require_starttls: false,
            opportunistic_starttls: false,
            auth: None,
            auth_bearer: false,
            sasl_client: None,
            caps: None,
            on_result: None,
        })))
    }

    /// Insist on STARTTLS: a server that does not offer it is a failure.
    pub fn require_starttls(self, require: bool) -> Self {
        self.0.lock().unwrap().require_starttls = require;
        self
    }

    /// Upgrade with STARTTLS when offered, carry on in the clear otherwise.
    pub fn opportunistic_starttls(self, enable: bool) -> Self {
        self.0.lock().unwrap().opportunistic_starttls = enable;
        self
    }

    /// Prove a username/password (SCRAM-SHA-256, CRAM-MD5, PLAIN or LOGIN,
    /// whichever strongest the server offers).
    pub fn credentials_password(self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        let mut st = self.0.lock().unwrap();
        st.auth = Some((user.into(), pass.into()));
        st.auth_bearer = false;
        drop(st);
        self
    }

    /// Prove an OAuth 2.0 bearer token (XOAUTH2, else OAUTHBEARER).
    pub fn credentials_bearer(self, user: impl Into<String>, token: impl Into<String>) -> Self {
        let mut st = self.0.lock().unwrap();
        st.auth = Some((user.into(), token.into()));
        st.auth_bearer = true;
        drop(st);
        self
    }

    /// Called exactly once with how the session ended.
    pub fn on_result(self, cb: Box<dyn FnOnce(SmtpVerifyOutcome) + Send>) -> Self {
        self.0.lock().unwrap().on_result = Some(cb);
        self
    }
}

impl SmtpClientHandlerFactory for SmtpVerify {
    fn create(&self, _runtime: &Arc<Runtime>) -> Box<dyn SmtpClientDriver> {
        Box::new(SmtpVerifyDriver { state: Arc::clone(&self.0) })
    }

    fn connect_failed(&self, host: &str, error: &io::Error) {
        let cb = self.0.lock().unwrap().on_result.take();
        if let Some(cb) = cb {
            cb(SmtpVerifyOutcome::Failed(format!("connect to {host} failed: {error}")));
        }
    }
}

struct SmtpVerifyDriver {
    state: Arc<Mutex<SmtpVerifyState>>,
}

impl SmtpVerifyDriver {
    fn finish(&self, outcome: SmtpVerifyOutcome) {
        let cb = self.state.lock().unwrap().on_result.take();
        if let Some(cb) = cb {
            cb(outcome);
        }
    }

    fn fail(&self, msg: impl Into<String>) {
        self.finish(SmtpVerifyOutcome::Failed(msg.into()));
    }

    /// Done with what was asked: report the final EHLO's capabilities.
    fn succeed(&self, session: &mut dyn SmtpClientSession) {
        let caps = self.state.lock().unwrap().caps.clone().unwrap_or_default();
        self.finish(SmtpVerifyOutcome::Verified(caps));
        session.quit();
    }
}

impl SmtpClientDriver for SmtpVerifyDriver {
    fn on_greeting(&mut self, hello: &mut dyn SmtpClientHello, ep: &mut dyn Endpoint, esmtp: bool) {
        let hostname = ehlo_argument(&self.state.lock().unwrap().hostname, ep);
        if esmtp {
            hello.ehlo(&hostname);
        } else {
            hello.helo(&hostname);
        }
    }

    fn on_service_unavailable(&mut self, ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("service unavailable: {message}"));
        ep.close();
    }

    fn on_ehlo(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint, caps: &SmtpCapabilities) {
        let mut st = self.state.lock().unwrap();
        st.caps = Some(caps.clone());

        if !ep.is_secure() {
            if st.require_starttls {
                drop(st);
                if caps.starttls {
                    session.starttls();
                } else {
                    self.fail("STARTTLS required but the server does not offer it");
                    session.quit();
                }
                return;
            } else if st.opportunistic_starttls && caps.starttls {
                drop(st);
                session.starttls();
                return;
            }
        }

        let Some((user, secret)) = st.auth.clone() else {
            drop(st);
            self.succeed(session);
            return;
        };
        let bearer = st.auth_bearer;
        let Some(mech) = choose_sasl_mechanism(&caps.auth_methods, bearer) else {
            drop(st);
            self.fail(no_mechanism_message(&caps.auth_methods, bearer));
            session.quit();
            return;
        };
        let mut client = create_client(mech, &user, &secret, "", "smtp", None);
        if client.has_initial_response() {
            if let SaslClientStep::Response(initial) = client.evaluate(None) {
                st.sasl_client = Some(client);
                drop(st);
                session.auth(mech.name(), Some(&initial));
                return;
            }
        }
        st.sasl_client = Some(client);
        drop(st);
        session.auth(mech.name(), None);
    }

    fn on_ehlo_not_supported(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        // Plain HELO server: nothing to verify beyond reachability unless
        // credentials were given, which it cannot take.
        let has_auth = self.state.lock().unwrap().auth.is_some();
        if has_auth {
            self.fail("server does not support ESMTP, so it offers no AUTH");
        } else {
            self.finish(SmtpVerifyOutcome::Verified(SmtpCapabilities::default()));
        }
        session.quit();
    }

    fn on_ehlo_error(&mut self, ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("EHLO rejected: {message}"));
        ep.close();
    }

    fn on_helo(&mut self, session: &mut dyn SmtpClientSession, ep: &mut dyn Endpoint) {
        self.on_ehlo_not_supported(session, ep);
    }

    fn on_helo_error(&mut self, ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("HELO rejected: {message}"));
        ep.close();
    }

    fn on_tls_established(&mut self, post_tls: &mut dyn SmtpClientPostTls, ep: &mut dyn Endpoint) {
        let hostname = ehlo_argument(&self.state.lock().unwrap().hostname, ep);
        post_tls.ehlo(&hostname);
    }

    fn on_tls_unavailable(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        self.fail("STARTTLS refused by the server");
        session.quit();
    }

    fn on_tls_error(&mut self, ep: &mut dyn Endpoint, message: &str) {
        self.fail(format!("TLS handshake failed: {message}"));
        ep.close();
    }

    fn on_auth_ok(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        self.succeed(session);
    }

    fn on_auth_challenge(&mut self, exchange: &mut dyn SmtpClientAuthExchange, _ep: &mut dyn Endpoint, challenge: &[u8]) {
        let mut st = self.state.lock().unwrap();
        let Some(mut client) = st.sasl_client.take() else {
            drop(st);
            exchange.abort();
            return;
        };
        match client.evaluate(Some(challenge)) {
            SaslClientStep::Response(r) => {
                st.sasl_client = Some(client);
                drop(st);
                exchange.respond(&r);
            }
            SaslClientStep::Complete(r) => {
                st.sasl_client = Some(client);
                drop(st);
                if !r.is_empty() {
                    exchange.respond(&r);
                }
            }
            SaslClientStep::Failure => {
                drop(st);
                exchange.abort();
            }
        }
    }

    fn on_auth_failed(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, code: u16) {
        self.finish(SmtpVerifyOutcome::AuthFailed { code });
        session.quit();
    }

    fn on_auth_aborted(&mut self, session: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {
        self.fail("AUTH exchange aborted");
        session.quit();
    }

    // Nothing below the session stage is ever reached: this pipeline never
    // issues MAIL FROM.
    fn on_mail_ok(&mut self, _e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint) {}
    fn on_mail_rejected(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _code: u16, _message: &str) {}
    fn on_rcpt_ok(&mut self, _e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint, _recipient: &str) {}
    fn on_rcpt_rejected(&mut self, _e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint, _recipient: &str, _code: u16, _message: &str) {}
    fn on_ready_for_data(&mut self, _d: &mut dyn SmtpClientMessageData, _ep: &mut dyn Endpoint) {}
    fn on_bdat_chunk_ok(&mut self, _d: &mut dyn SmtpClientMessageData, _ep: &mut dyn Endpoint) {}
    fn on_data_rejected(&mut self, _e: &mut dyn SmtpClientEnvelope, _ep: &mut dyn Endpoint, _code: u16, _message: &str) {}
    fn on_message_accepted(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _queue_id: Option<&str>) {}
    fn on_message_rejected(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _code: u16, _message: &str) {}
    fn on_rset_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint) {}
    fn on_vrfy_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _code: u16, _text: &str) {}
    fn on_vrfy_failed(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _code: u16, _message: &str) {}
    fn on_expn_ok(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _members: &[String]) {}
    fn on_expn_failed(&mut self, _s: &mut dyn SmtpClientSession, _ep: &mut dyn Endpoint, _code: u16, _message: &str) {}

    fn on_error(&mut self, ep: &mut dyn Endpoint, err: &io::Error) {
        self.fail(format!("connection error: {err}"));
        ep.close();
    }

    fn on_timeout(&mut self, ep: &mut dyn Endpoint) {
        self.fail("timed out waiting for the server");
        ep.close();
    }

    fn on_disconnected(&mut self, _ep: &mut dyn Endpoint) {
        // Normally already reported before QUIT; a drop before that is a
        // failure the callback has not heard about yet.
        self.fail("connection closed before the session completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_predicates() {
        assert!(SmtpVerifyOutcome::Verified(SmtpCapabilities::default()).is_verified());
        assert!(!SmtpVerifyOutcome::AuthFailed { code: 535 }.is_verified());
        assert!(!SmtpVerifyOutcome::Failed("x".into()).is_verified());
    }

    #[test]
    fn result_fires_once_and_connect_failure_reaches_it() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = Arc::clone(&seen);
        let v = SmtpVerify::new("").on_result(Box::new(move |o| s2.lock().unwrap().push(o)));
        v.connect_failed("smtp.example", &io::Error::new(io::ErrorKind::NotFound, "no such host"));
        v.connect_failed("smtp.example", &io::Error::other("again"));
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(matches!(&seen[0], SmtpVerifyOutcome::Failed(m) if m.contains("no such host")), "{seen:?}");
    }
}
