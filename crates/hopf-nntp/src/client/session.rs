// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The command queue shared between the application and the reactor.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use hopf_core::ConnHandle;

use super::error::NntpClientError;
use super::reply::{dot_stuff, ArticleRef, Block, GroupResult, NewsgroupEntry, NntpStatus, OverviewEntry};

/// Receives the text of a multi-line block as it arrives: dot-unstuffed, line
/// ends kept, in as many pieces as the connection delivers it in. No line
/// is held back to be handed over whole.
pub type ContentCallback = Box<dyn FnMut(&[u8]) + Send>;
/// Receives a command's final status, or the error that ended the session.
pub type CompletionCallback = Box<dyn FnOnce(Result<NntpStatus, NntpClientError>) + Send>;

/// Where the block that follows a command's reply goes, and so how it is read.
pub(crate) enum Sink {
    Content(ContentCallback),
    Newsgroups(Box<dyn FnMut(NewsgroupEntry) + Send>),
    Overview(Box<dyn FnMut(OverviewEntry) + Send>),
}

impl Sink {
    pub fn block(&self) -> Block {
        match self {
            Sink::Content(_) => Block::Raw,
            Sink::Newsgroups(_) => Block::Newsgroups,
            Sink::Overview(_) => Block::Overview,
        }
    }
}

/// What a status line carried, read into its fields as it arrived.
pub(crate) enum Detail {
    Group(GroupResult),
    Article(ArticleRef),
}

/// One queued command.
pub(crate) struct Command {
    /// Without CRLF.
    pub line: String,
    /// Where a multi-line block goes, when a 2xx reply announces one.
    pub sink: Option<Sink>,
    /// Receives the fields of a `GROUP` or article status.
    pub on_detail: Option<Box<dyn FnMut(Detail) + Send>>,
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

    fn queue(&self, line: String, sink: Option<Sink>, on_detail: Option<Box<dyn FnMut(Detail) + Send>>, on_complete: CompletionCallback) {
        self.enqueue(Command { line, sink, on_detail, on_complete, continuation: None });
    }

    /// Any command. `on_content` receives the multi-line block (dot-unstuffed,
    /// line ends kept, in pieces) when `multiline` is set and the reply code
    /// announces one; `on_complete` gets the final status, or the
    /// transport error that ended the session.
    pub fn command(
        &self,
        line: impl Into<String>,
        multiline: bool,
        on_content: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<NntpStatus, NntpClientError>) + Send + 'static,
    ) {
        let sink = multiline.then(|| Sink::Content(Box::new(on_content)));
        self.queue(line.into(), sink, None, Box::new(on_complete));
    }

    /// `LIST ACTIVE [wildmat]`: one call per newsgroup, as its line is read.
    pub fn list_active(
        &self,
        wildmat: &str,
        on_entry: impl FnMut(NewsgroupEntry) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        let wm = wildmat.trim();
        let line = if wm.is_empty() { "LIST ACTIVE".to_string() } else { format!("LIST ACTIVE {wm}") };
        self.queue(
            line,
            Some(Sink::Newsgroups(Box::new(on_entry))),
            None,
            Box::new(move |r| on_complete(expect(r, "LIST ACTIVE", 215).map(|_| ()))),
        );
    }

    /// `GROUP name`.
    pub fn group(&self, name: &str, on_complete: impl FnOnce(Result<GroupResult, NntpClientError>) + Send + 'static) {
        let slot: Arc<Mutex<Option<GroupResult>>> = Arc::default();
        let fill = Arc::clone(&slot);
        self.queue(
            format!("GROUP {name}"),
            None,
            Some(Box::new(move |d| {
                if let Detail::Group(g) = d {
                    *fill.lock().unwrap() = Some(g);
                }
            })),
            Box::new(move |r| {
                on_complete(expect(r, "GROUP", 211).and_then(|s| {
                    slot.lock().unwrap().take().ok_or_else(|| NntpClientError::new(211, format!("bad GROUP response: {}", s.text)))
                }))
            }),
        );
    }

    /// `STAT number`: whether the article exists, and what it is called.
    pub fn stat(&self, number: u64, on_complete: impl FnOnce(Result<ArticleRef, NntpClientError>) + Send + 'static) {
        let slot: Arc<Mutex<Option<ArticleRef>>> = Arc::default();
        let fill = Arc::clone(&slot);
        self.queue(
            format!("STAT {number}"),
            None,
            Some(Box::new(move |d| {
                if let Detail::Article(a) = d {
                    *fill.lock().unwrap() = Some(a);
                }
            })),
            Box::new(move |r| {
                on_complete(expect(r, "STAT", 223).and_then(|s| {
                    slot.lock().unwrap().take().ok_or_else(|| NntpClientError::new(223, format!("bad STAT response: {}", s.text)))
                }))
            }),
        );
    }

    /// `OVER first-last` in the selected group: one call per article, as its
    /// line is read.
    pub fn over(
        &self,
        first: u64,
        last: u64,
        on_entry: impl FnMut(OverviewEntry) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.queue(
            format!("OVER {first}-{last}"),
            Some(Sink::Overview(Box::new(on_entry))),
            None,
            Box::new(move |r| on_complete(expect(r, "OVER", 224).map(|_| ()))),
        );
    }

    /// `ARTICLE number` in the selected group; `on_content` gets the headers,
    /// the empty separator line and the body, as they arrive.
    pub fn article(
        &self,
        number: u64,
        on_content: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.command(format!("ARTICLE {number}"), true, on_content, move |r| {
            on_complete(expect(r, "ARTICLE", 220).map(|_| ()))
        });
    }

    /// `HEAD number` in the selected group.
    pub fn head(
        &self,
        number: u64,
        on_content: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.command(format!("HEAD {number}"), true, on_content, move |r| {
            on_complete(expect(r, "HEAD", 221).map(|_| ()))
        });
    }

    /// `BODY number` in the selected group.
    pub fn body(
        &self,
        number: u64,
        on_content: impl FnMut(&[u8]) + Send + 'static,
        on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static,
    ) {
        self.command(format!("BODY {number}"), true, on_content, move |r| {
            on_complete(expect(r, "BODY", 222).map(|_| ()))
        });
    }

    /// `POST` an article (headers, blank line, body; any line endings).
    /// Dot-stuffing and the terminator are added here.
    pub fn post(&self, article: &[u8], on_complete: impl FnOnce(Result<(), NntpClientError>) + Send + 'static) {
        self.enqueue(Command {
            line: "POST".to_string(),
            sink: None,
            on_detail: None,
            on_complete: Box::new(move |r| on_complete(expect(r, "POST", 240).map(|_| ()))),
            continuation: Some((340, dot_stuff(article))),
        });
    }

    /// `QUIT`; the session takes no commands after this.
    pub fn quit(&self) {
        let conn = self.conn.clone();
        self.enqueue(Command {
            line: "QUIT".to_string(),
            sink: None,
            on_detail: None,
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
