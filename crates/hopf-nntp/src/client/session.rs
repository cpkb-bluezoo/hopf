// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The command queue shared between the application and the reactor.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;

use super::error::NntpClientError;
use super::reply::{
    dot_stuff, parse_group_response, parse_newsgroup_line, parse_overview_line, GroupResult,
    NewsgroupEntry, NntpStatus, OverviewEntry,
};

/// Receives each line of a multi-line block, dot-unstuffed, without CRLF.
pub type LineCallback = Box<dyn FnMut(&[u8]) + Send>;
/// Receives a command's final status, or the error that ended the session.
pub type CompletionCallback = Box<dyn FnOnce(Result<NntpStatus, NntpClientError>) + Send>;

/// One queued command.
pub(crate) struct Command {
    /// Without CRLF.
    pub line: String,
    /// Whether a multi-line block follows a 2xx reply that announces one.
    pub multiline: bool,
    pub on_line: LineCallback,
    pub on_complete: CompletionCallback,
    /// When the first reply carries this code, write the payload (already
    /// framed) and wait for a second status line.
    pub continuation: Option<(u16, Vec<u8>)>,
}

#[derive(Default)]
pub(crate) struct Queue {
    pub pending: VecDeque<Command>,
    /// Set once the session can take no more commands, with the reason.
    pub closed: Option<String>,
}

/// The live session: cloneable, usable from any thread. Commands go out
/// in the order queued, one at a time.
#[derive(Clone)]
pub struct NntpSession {
    pub(crate) queue: Arc<Mutex<Queue>>,
    conn: ConnHandle,
    posting_allowed: bool,
    capabilities: Arc<Vec<String>>,
}

impl NntpSession {
    pub(crate) fn new(queue: Arc<Mutex<Queue>>, conn: ConnHandle, posting_allowed: bool, capabilities: Vec<String>) -> Self {
        Self { queue, conn, posting_allowed, capabilities: Arc::new(capabilities) }
    }

    /// Whether the greeting was `200` (posting allowed).
    pub fn posting_allowed(&self) -> bool {
        self.posting_allowed
    }

    /// `CAPABILITIES` as seen after TLS and before authentication.
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// A handle to the connection's reactor.
    pub fn conn_handle(&self) -> &ConnHandle {
        &self.conn
    }

    /// False once the connection is gone or `QUIT` was sent.
    pub fn is_alive(&self) -> bool {
        self.queue.lock().unwrap().closed.is_none() && self.conn.is_probably_open()
    }

    fn enqueue(&self, cmd: Command) {
        let closed = self.queue.lock().unwrap().closed.clone();
        if let Some(reason) = closed {
            (cmd.on_complete)(Err(NntpClientError::transport(reason)));
            return;
        }
        self.queue.lock().unwrap().pending.push_back(cmd);
        self.conn.poke();
    }

    /// Any command. `on_line` receives each line of a multi-line block
    /// (dot-unstuffed, without CRLF) when `multiline` is set and the reply
    /// code announces one; `on_complete` gets the final status, or the
    /// transport error that ended the session.
    pub fn command(
        &self,
        line: impl Into<String>,
        multiline: bool,
        on_line: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<NntpStatus, NntpClientError>) + Send + 'static,
    ) {
        self.enqueue(Command {
            line: line.into(),
            multiline,
            on_line: Box::new(on_line),
            on_complete: Box::new(on_complete),
            continuation: None,
        });
    }

    /// `LIST ACTIVE [wildmat]`.
    pub fn list_active(
        &self,
        wildmat: &str,
        mut on_entry: impl FnMut(NewsgroupEntry) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        let wm = wildmat.trim();
        let line = if wm.is_empty() { "LIST ACTIVE".to_string() } else { format!("LIST ACTIVE {wm}") };
        self.command(
            line,
            true,
            move |l| {
                if let Some(e) = parse_newsgroup_line(&String::from_utf8_lossy(l)) {
                    on_entry(e);
                }
            },
            move |r| on_complete(expect(r, "LIST ACTIVE", 215).map(|_| ())),
        );
    }

    /// `GROUP name`.
    pub fn group(&self, name: &str, on_complete: impl FnOnce(Result<GroupResult, NntpClientError>) + Send + 'static) {
        self.command(format!("GROUP {name}"), false, |_| {}, move |r| {
            on_complete(expect(r, "GROUP", 211).and_then(|s| {
                parse_group_response(&s.text).ok_or_else(|| NntpClientError::new(211, format!("bad GROUP response: {}", s.text)))
            }))
        });
    }

    /// `OVER first-last` in the selected group.
    pub fn over(
        &self,
        first: u64,
        last: u64,
        mut on_entry: impl FnMut(OverviewEntry) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.command(
            format!("OVER {first}-{last}"),
            true,
            move |l| {
                if let Some(e) = parse_overview_line(&String::from_utf8_lossy(l)) {
                    on_entry(e);
                }
            },
            move |r| on_complete(expect(r, "OVER", 224).map(|_| ())),
        );
    }

    /// `ARTICLE number` in the selected group; `on_line` gets headers,
    /// the empty separator line and the body, line by line.
    pub fn article(
        &self,
        number: u64,
        on_line: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.command(format!("ARTICLE {number}"), true, on_line, move |r| {
            on_complete(expect(r, "ARTICLE", 220).map(|_| ()))
        });
    }

    /// `HEAD number` in the selected group.
    pub fn head(
        &self,
        number: u64,
        on_line: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.command(format!("HEAD {number}"), true, on_line, move |r| {
            on_complete(expect(r, "HEAD", 221).map(|_| ()))
        });
    }

    /// `POST` an article (headers, blank line, body; any line endings).
    /// Dot-stuffing and the terminator are added here.
    pub fn post(&self, article: &[u8], on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static) {
        self.enqueue(Command {
            line: "POST".to_string(),
            multiline: false,
            on_line: Box::new(|_| {}),
            on_complete: Box::new(move |r| on_complete(expect(r, "POST", 240).map(|_| ()))),
            continuation: Some((340, dot_stuff(article))),
        });
    }

    /// `QUIT`; the session takes no commands after this.
    pub fn quit(&self) {
        let conn = self.conn.clone();
        self.enqueue(Command {
            line: "QUIT".to_string(),
            multiline: false,
            on_line: Box::new(|_| {}),
            on_complete: Box::new(move |_| conn.close()),
            continuation: None,
        });
        self.queue.lock().unwrap().closed = Some("QUIT sent".to_string());
    }
}

/// Map a completion to `Ok(status)` only when the code is `expected`.
fn expect(r: Result<NntpStatus, NntpClientError>, command: &str, expected: u16) -> Result<NntpStatus, NntpClientError> {
    match r {
        Ok(s) if s.code == expected => Ok(s),
        Ok(s) => Err(NntpClientError::rejected(command, s.code, &s.text)),
        Err(e) => Err(e),
    }
}
