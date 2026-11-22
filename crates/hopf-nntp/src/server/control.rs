// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The NNTP connection handler: reads commands, runs them against the
//! connection's [`ReaderHandler`], and sends the answers.
//!
//! Commands are read one at a time from the connection's ring, and the bytes
//! after a command stay there until it has been answered, so a client may
//! pipeline and the answers come in order. A command that needs the news runs
//! on the storage pool and writes its answer into a bounded pipe, which the
//! reactor empties as the connection drains (see [`crate::server::pipe`]).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, StorageError};

use crate::server::codec::{NntpCommand, NntpServerLexer, MAX_COMMAND_LINE};
use crate::server::commands::{self, civil_from_days, JobEnd, SessionState};
use crate::server::ingress::NntpDotUnstuffer;
use crate::server::handler::{
    ClientConnected, ConnectedState, NntpConnectionMetadata, ReaderHandler,
};
use crate::server::metrics::NntpServerMetrics;
use crate::server::pipe::{Pipe, Poll};
use crate::server::reply;
use crate::server::service::NntpConfig;

#[cfg(test)]
mod tests;

/// The most a batch handed to the connection holds, so that what is queued
/// in the connection's own buffer stays small.
const BATCH: usize = 64 * 1024;

/// What the connection's jobs share.
struct Shared {
    reader: Mutex<Option<Box<dyn ReaderHandler>>>,
    session: Mutex<SessionState>,
    post: commands::PostSlot,
}

/// How much of a posted article is taken from the ring and given to the sink
/// at a time.
const POST_PIECE: usize = 64 * 1024;

/// An article being received.
struct PostData {
    unstuffer: NntpDotUnstuffer,
    /// Octets of the article so far.
    bytes: u64,
    /// The article is being thrown away (too large, or already refused).
    discarding: bool,
    /// The whole article has been read; what is left is to accept it.
    finished: bool,
}

/// What a job on the storage pool does.
enum JobKind {
    Command(NntpCommand),
    PostWrite(Vec<u8>),
    PostTooLarge,
    PostCommit,
}

/// A command running on the storage pool.
struct Job {
    pipe: Pipe,
    /// How the command ended, set by the job itself before it finishes.
    end: Arc<Mutex<Option<JobEnd>>>,
    /// The storage pool refused the job or it panicked.
    failed: Arc<AtomicBool>,
    /// Has any of the answer been given to the connection?
    sent_any: bool,
}

enum Admission {
    Pending,
    Accepted {
        greeting: String,
        posting_allowed: bool,
        handler: Box<dyn ReaderHandler>,
    },
    Rejected(String),
}

struct ConnectedView<'a> {
    admission: &'a mut Admission,
}

impl ConnectedState for ConnectedView<'_> {
    fn accept_connection(&mut self, greeting: &str, posting_allowed: bool, handler: Box<dyn ReaderHandler>) {
        *self.admission = Admission::Accepted {
            greeting: greeting.to_string(),
            posting_allowed,
            handler,
        };
    }

    fn reject_connection(&mut self, message: &str) {
        *self.admission = Admission::Rejected(message.to_string());
    }
}

/// The protocol handler for one NNTP connection.
pub struct NntpControlHandler {
    client: Option<Box<dyn ClientConnected>>,
    shared: Arc<Shared>,
    config: NntpConfig,
    metrics: Arc<NntpServerMetrics>,
    runtime: Arc<Runtime>,
    lexer: NntpServerLexer,
    meta: NntpConnectionMetadata,
    handle: Option<ConnHandle>,
    expect_implicit_tls: bool,
    greeted: bool,
    posting_allowed: bool,
    /// The connection is going away: nothing more is read or sent.
    closed: bool,
    job: Option<Job>,
    /// Output has been handed to the connection and has not drained yet.
    write_pending: Arc<AtomicBool>,
    /// An article is being received.
    post: Option<PostData>,
}

impl NntpControlHandler {
    /// A handler for one accepted connection.
    pub fn new(
        client: Box<dyn ClientConnected>,
        metrics: Arc<NntpServerMetrics>,
        config: NntpConfig,
        runtime: Arc<Runtime>,
    ) -> Self {
        let expect_implicit_tls = config.implicit_tls && config.tls_acceptor.is_some();
        let unknown = SocketAddr::from(([0, 0, 0, 0], 0));
        Self {
            client: Some(client),
            shared: Arc::new(Shared {
                reader: Mutex::new(None),
                session: Mutex::new(SessionState::default()),
                post: commands::PostSlot::new(),
            }),
            config,
            metrics,
            runtime,
            lexer: NntpServerLexer::new(MAX_COMMAND_LINE),
            meta: NntpConnectionMetadata { peer: unknown, local: unknown, tls: false },
            handle: None,
            expect_implicit_tls,
            greeted: false,
            posting_allowed: false,
            closed: false,
            job: None,
            write_pending: Arc::new(AtomicBool::new(false)),
            post: None,
        }
    }

    /// Is the handler waiting for something that will happen on its own?
    #[cfg(test)]
    fn busy(&self) -> bool {
        self.job.is_some() && !self.write_pending.load(Ordering::Relaxed)
    }

    fn send(&self, ep: &mut dyn Endpoint, bytes: &[u8]) {
        ep.send(bytes);
    }

    fn say(&self, ep: &mut dyn Endpoint, code: u16, text: &str) {
        self.send(ep, &reply::status(code, text));
    }

    fn close(&mut self, ep: &mut dyn Endpoint) {
        self.closed = true;
        ep.close();
    }

    // ---- connecting ----

    fn greet(&mut self, ep: &mut dyn Endpoint) {
        if self.greeted {
            return;
        }
        self.greeted = true;
        NntpServerMetrics::add(&self.metrics.connections, 1);
        let mut admission = Admission::Pending;
        if let Some(mut client) = self.client.take() {
            client.connected(&mut ConnectedView { admission: &mut admission }, &self.meta);
            self.client = Some(client);
        }
        match admission {
            Admission::Accepted { greeting, posting_allowed, handler } => {
                self.posting_allowed = posting_allowed && self.config.posting_allowed;
                *self.shared.reader.lock().unwrap() = Some(handler);
                let code = if self.posting_allowed { 200 } else { 201 };
                self.say(ep, code, &greeting);
            }
            Admission::Rejected(message) => {
                self.say(ep, 400, &message);
                self.close(ep);
            }
            Admission::Pending => {
                self.say(ep, 400, "Service temporarily unavailable");
                self.close(ep);
            }
        }
    }

    // ---- commands ----

    fn dispatch(&mut self, ep: &mut dyn Endpoint, command: NntpCommand) {
        NntpServerMetrics::add(&self.metrics.commands, 1);
        if command == NntpCommand::Post && !self.posting_allowed {
            self.say(ep, 440, "Posting not permitted");
            return;
        }
        if commands::needs_handler(&command) {
            self.start_job(ep, JobKind::Command(command));
            return;
        }
        match command {
            NntpCommand::Capabilities => self.capabilities(ep),
            NntpCommand::ModeReader => {
                let code = if self.posting_allowed { 200 } else { 201 };
                let text = if self.posting_allowed { "Reader mode, posting permitted" } else { "Reader mode, posting prohibited" };
                self.say(ep, code, text);
            }
            NntpCommand::Quit => {
                self.say(ep, 205, "Connection closing");
                self.close(ep);
            }
            NntpCommand::Help => self.help(ep),
            NntpCommand::Date => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                self.say(ep, 111, &format_date(now));
            }
            NntpCommand::Malformed(_) => self.say(ep, 501, "Syntax error in command"),
            NntpCommand::TooLong => self.say(ep, 501, "Command line too long"),
            _ => self.say(ep, 500, "Unknown command"),
        }
    }

    fn capabilities(&self, ep: &mut dyn Endpoint) {
        let mut body = Vec::new();
        reply::data_line("VERSION 2", &mut body);
        reply::data_line(&format!("IMPLEMENTATION hopf {}", hopf_core::VERSION), &mut body);
        reply::data_line("READER", &mut body);
        if self.posting_allowed {
            reply::data_line("POST", &mut body);
        }
        reply::data_line("LIST ACTIVE NEWSGROUPS OVERVIEW.FMT", &mut body);
        reply::data_line("OVER", &mut body);
        reply::data_line("HDR", &mut body);
        body.extend_from_slice(reply::END);
        let mut out = reply::status(101, "Capability list follows");
        out.extend_from_slice(&body);
        self.send(ep, &out);
    }

    fn help(&self, ep: &mut dyn Endpoint) {
        let mut out = reply::status(100, "Help text follows");
        for line in [
            "ARTICLE [number|<message-id>]",
            "BODY [number|<message-id>]",
            "CAPABILITIES",
            "DATE",
            "GROUP newsgroup",
            "HDR field [range|<message-id>]",
            "HEAD [number|<message-id>]",
            "HELP",
            "LAST",
            "LIST [ACTIVE|NEWSGROUPS [wildmat]|OVERVIEW.FMT]",
            "LISTGROUP [newsgroup [range]]",
            "MODE READER",
            "NEWGROUPS date time [GMT]",
            "NEXT",
            "OVER [range|<message-id>]",
            "QUIT",
            "STAT [number|<message-id>]",
        ] {
            reply::data_line(line, &mut out);
        }
        out.extend_from_slice(reply::END);
        self.send(ep, &out);
    }

    // ---- jobs ----

    fn start_job(&mut self, ep: &mut dyn Endpoint, kind: JobKind) {
        let handle = ep.handle();
        let pipe = Pipe::new();
        let wake: Arc<dyn Fn() + Send + Sync> = {
            let handle = handle.clone();
            Arc::new(move || handle.with_endpoint(|ep| ep.poke_handler()))
        };
        let out = pipe.output(self.config.write_stall_timeout, Arc::clone(&wake));
        let end = Arc::new(Mutex::new(None));
        let failed = Arc::new(AtomicBool::new(false));
        let shared = Arc::clone(&self.shared);
        let metrics = Arc::clone(&self.metrics);
        let job_end = Arc::clone(&end);
        let job_failed = Arc::clone(&failed);
        let job_pipe = pipe.clone();
        ep.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut out = out;
                let result = match kind {
                    JobKind::PostWrite(piece) => commands::post_write(&shared.post, &piece),
                    JobKind::PostTooLarge => commands::post_too_large(&shared.post),
                    JobKind::PostCommit => commands::post_commit(&shared.post, &mut out, &metrics),
                    JobKind::Command(command) => {
                        let mut reader = shared.reader.lock().unwrap_or_else(|e| e.into_inner());
                        let mut session = shared.session.lock().unwrap_or_else(|e| e.into_inner());
                        match (reader.as_mut(), command) {
                            (Some(r), NntpCommand::Post) => commands::post_begin(r.as_mut(), &shared.post, &mut out),
                            (Some(r), command) => commands::run(&command, r.as_mut(), &mut session, &mut out, &metrics),
                            (None, _) => JobEnd::Fatal,
                        }
                    }
                };
                *job_end.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
                out.finish();
                Ok(())
            },
            move |result: Result<(), StorageError>| {
                if result.is_err() {
                    job_failed.store(true, Ordering::Relaxed);
                    job_pipe.mark_done();
                }
                handle.with_endpoint(|ep| ep.poke_handler());
            },
        );
        self.job = Some(Job { pipe, end, failed, sent_any: false });
    }

    /// Hands the connection what the running job has produced, as the
    /// connection can take it, and finishes the job when it is all sent.
    fn pump(&mut self, ep: &mut dyn Endpoint) {
        loop {
            let Some(job) = self.job.as_mut() else { return };
            if job.pipe.stalled() {
                hopf_core::subsystem_log(
                    hopf_core::LogLevel::Warn,
                    "hopf-nntp",
                    "nntp.write.stalled",
                    "closing a connection that stopped reading a response".to_string(),
                );
                self.job = None;
                self.close(ep);
                return;
            }
            if self.write_pending.load(Ordering::Relaxed) {
                return;
            }
            match job.pipe.poll(BATCH) {
                Poll::Data(chunks) => {
                    job.sent_any = true;
                    for chunk in &chunks {
                        ep.send(chunk);
                    }
                    self.write_pending.store(true, Ordering::Relaxed);
                    let flag = Arc::clone(&self.write_pending);
                    ep.on_write_ready(Some(Box::new(move |ep| {
                        flag.store(false, Ordering::Relaxed);
                        ep.poke_handler();
                    })));
                    return;
                }
                Poll::Empty { done: false } => return,
                Poll::Empty { done: true } => {
                    self.finish_job(ep);
                    return;
                }
            }
        }
    }

    fn finish_job(&mut self, ep: &mut dyn Endpoint) {
        let Some(job) = self.job.take() else { return };
        let end = *job.end.lock().unwrap_or_else(|e| e.into_inner());
        if job.failed.load(Ordering::Relaxed) || end.is_none() {
            hopf_core::subsystem_log(
                hopf_core::LogLevel::Error,
                "hopf-nntp",
                "nntp.job.failed",
                "a command could not be run".to_string(),
            );
            if job.sent_any {
                self.close(ep);
            } else {
                self.say(ep, 403, "Internal fault or problem preventing action being taken");
                ep.resume_read();
            }
            return;
        }
        if end == Some(JobEnd::Fatal) {
            self.close(ep);
            return;
        }
        if end == Some(JobEnd::PostData) {
            self.post = Some(PostData {
                unstuffer: NntpDotUnstuffer::new(),
                bytes: 0,
                discarding: false,
                finished: false,
            });
        }
        ep.resume_read();
    }

    /// Takes the next piece of the article being posted from `data`. Returns
    /// false when there is nothing more to do until more bytes arrive.
    fn receive_article(&mut self, ep: &mut dyn Endpoint, data: &mut &[u8]) -> bool {
        let max = self.config.max_post_size;
        let post = self.post.as_mut().expect("an article is being received");
        if post.finished {
            self.post = None;
            self.start_job(ep, JobKind::PostCommit);
            return true;
        }
        if data.is_empty() {
            return false;
        }
        let take = data.len().min(POST_PIECE);
        let mut piece = Vec::with_capacity(take);
        let used = post.unstuffer.feed(&data[..take], &mut piece);
        *data = &data[used..];
        post.finished = post.unstuffer.is_done();
        post.bytes += piece.len() as u64;
        let refused = self.shared.post.error.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        if post.discarding || refused {
            return true;
        }
        if max.is_some_and(|m| post.bytes > m) {
            post.discarding = true;
            self.start_job(ep, JobKind::PostTooLarge);
        } else if !piece.is_empty() {
            self.start_job(ep, JobKind::PostWrite(piece));
        }
        true
    }

    fn close_reader(&self) {
        let Some(handle) = self.handle.clone() else { return };
        let shared = Arc::clone(&self.shared);
        self.runtime.storage().submit_on(
            handle,
            move || {
                shared.post.abandon();
                let reader = shared.reader.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(mut reader) = reader {
                    reader.close();
                }
                Ok(())
            },
            |_: Result<(), StorageError>| {},
        );
    }
}

/// `yyyymmddhhmmss` for a time given in seconds since the epoch.
fn format_date(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!("{y:04}{m:02}{d:02}{:02}{:02}{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
}

impl ProtocolHandler for NntpControlHandler {
    fn connected(&mut self, ep: &mut dyn Endpoint) {
        if let Some(peer) = ep.remote_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.meta.peer = peer;
        }
        if let Some(local) = ep.local_addr().ok().and_then(|a| a.as_socket_addr()) {
            self.meta.local = local;
        }
        if ep.is_secure() {
            self.meta.tls = true;
        }
        self.handle = Some(ep.handle());
        if !self.expect_implicit_tls || self.meta.tls {
            self.greet(ep);
        }
    }

    fn receive(&mut self, ep: &mut dyn Endpoint, buf: &mut hopf_core::LoopBuf) {
        hopf_core::with_slice(buf, |data| {
            loop {
                if self.job.is_some() {
                    self.pump(ep);
                    if self.job.is_some() {
                        // Whatever else has arrived waits in the ring until
                        // this command has been answered.
                        return;
                    }
                }
                if self.closed {
                    *data = &[];
                    return;
                }
                if !self.greeted {
                    return;
                }
                if self.post.is_some() {
                    if !self.receive_article(ep, data) {
                        return;
                    }
                    continue;
                }
                match self.lexer.next_command(data) {
                    Some(command) => self.dispatch(ep, command),
                    None => return,
                }
            }
        });
    }

    fn disconnected(&mut self, _ep: &mut dyn Endpoint) {
        self.closed = true;
        if let Some(job) = &self.job {
            job.pipe.close_consumer();
        }
        if let Some(mut client) = self.client.take() {
            client.disconnected();
        }
        self.close_reader();
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, _info: &hopf_core::SecurityInfo) {
        self.meta.tls = true;
        if self.expect_implicit_tls && !self.greeted {
            self.greet(ep);
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, _err: &std::io::Error) {
        self.close(ep);
    }
}
