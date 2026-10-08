// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! Application-facing callbacks.

use std::io;
use std::sync::Mutex;

use super::session::NntpSession;

/// What the server said when the session became usable.
#[derive(Debug, Clone)]
pub struct NntpGreeting {
    /// `200` (posting allowed) or `201` (no posting).
    pub code: u16,
    pub text: String,
    pub posting_allowed: bool,
    /// `CAPABILITIES` lines, upper-cased, from after TLS and before auth.
    pub capabilities: Vec<String>,
    pub secure: bool,
    pub authenticated: bool,
}

/// Lifecycle of one client connection. Everything runs on the
/// connection's reactor thread; keep the callbacks short.
pub trait NntpClientHandler: Send {
    /// Greeting read, capabilities fetched, TLS and `AUTHINFO` done as
    /// configured: the session accepts commands.
    fn on_connected(&mut self, session: &NntpSession, greeting: &NntpGreeting);

    /// The connection failed: a refused or timed-out dial, a TLS failure,
    /// a `STARTTLS` the server did not offer, rejected credentials, a
    /// command timeout, or the transport going away with commands in
    /// flight. Those commands have already heard about it through their
    /// own completion callbacks.
    fn on_error(&mut self, error: &io::Error);

    /// The connection closed (after `QUIT`, or by the server).
    fn on_disconnected(&mut self) {}
}

/// Creates the handler for each connection a [`super::NntpClient`] makes.
pub trait NntpClientHandlerFactory: Send + Sync {
    fn create(&self) -> Box<dyn NntpClientHandler>;

    /// The dial never produced a connection: DNS failed or returned no
    /// addresses for `host`, or the connect could not be started at all.
    /// Default: a line on stderr.
    fn connect_failed(&self, host: &str, error: &io::Error) {
        eprintln!("hopf-nntp: connect to {host} failed: {error}");
    }
}

/// A factory for exactly one connection: hands out the handler it was
/// given and reports a dial failure to it.
pub(crate) struct SingleHandler(pub Mutex<Option<Box<dyn NntpClientHandler>>>);

impl NntpClientHandlerFactory for SingleHandler {
    fn create(&self) -> Box<dyn NntpClientHandler> {
        self.0.lock().unwrap().take().unwrap_or_else(|| Box::new(Spent))
    }

    fn connect_failed(&self, host: &str, error: &io::Error) {
        if let Some(mut h) = self.0.lock().unwrap().take() {
            h.on_error(&io::Error::new(error.kind(), format!("connect to {host}: {error}")));
        }
    }
}

/// Stands in once the single handler has been handed out.
struct Spent;

impl NntpClientHandler for Spent {
    fn on_connected(&mut self, session: &NntpSession, _greeting: &NntpGreeting) {
        session.quit();
    }
    fn on_error(&mut self, _error: &io::Error) {}
}
