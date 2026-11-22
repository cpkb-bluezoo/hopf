// Copyright (C) 2026 Chris Burdess <dog@gnu.org>

//! The NNTP connection handler: reads commands, runs them against the
//! connection's [`ReaderHandler`], and sends the answers.
//!
//! Commands are read one at a time from the connection's ring, and the bytes
//! after a command stay there until it has been answered, so a client may
//! pipeline and the answers come in order. A command that needs the news runs
//! on the storage pool and writes its answer into a bounded pipe, which the
//! reactor empties as the connection drains (see [`crate::server::pipe`]).

use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hopf_core::{ConnHandle, Endpoint, ProtocolHandler, Runtime, StorageError};
use hopf_otel::{ExportHandle, NntpServerMetrics as OtelNntpMetrics, RequestTimer, Span, SpanKind, Trace};

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
    auth: Mutex<commands::AuthState>,
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
    AuthPassword { user: String, password: String },
    AuthSasl(commands::SaslStep),
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
    /// What is being measured, for the commands that move an article.
    article: Option<ArticleTelemetry>,
}

/// Timing and a span for the retrieval or posting of one article.
struct ArticleTelemetry {
    timer: RequestTimer,
    span: Option<Span>,
    /// `retrieved` or `posted`.
    kind: &'static str,
    /// The count of such articles when the command began, to tell whether it
    /// added one.
    before: u64,
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
    /// The name given by `AUTHINFO USER`, awaiting its `PASS`.
    pending_user: Option<String>,
    /// The fingerprint of the certificate the client presented, for EXTERNAL.
    peer_certificate: Option<String>,
    /// Credentials this connection has had refused.
    auth_failures: u32,
    /// `STARTTLS` has been answered and the handshake has not finished:
    /// nothing is read until it has.
    tls_pending: bool,
    /// How the client is authenticating: `USER`, or the SASL mechanism.
    auth_attempt: Option<String>,
    otel_metrics: Option<Arc<OtelNntpMetrics>>,
    export: Option<ExportHandle>,
    traces_enabled: bool,
    conn_trace: Option<Trace>,
    opened_at: Instant,
    /// Octets handed to the connection.
    bytes_sent: Cell<u64>,
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
                auth: Mutex::new(commands::AuthState::default()),
            }),
            config,
            metrics,
            runtime,
            lexer: NntpServerLexer::new(MAX_COMMAND_LINE),
            meta: NntpConnectionMetadata { peer: unknown, local: unknown, tls: false, traceparent: None },
            handle: None,
            expect_implicit_tls,
            greeted: false,
            posting_allowed: false,
            closed: false,
            job: None,
            write_pending: Arc::new(AtomicBool::new(false)),
            post: None,
            pending_user: None,
            peer_certificate: None,
            auth_failures: 0,
            tls_pending: false,
            auth_attempt: None,
            otel_metrics: None,
            export: None,
            traces_enabled: false,
            conn_trace: None,
            opened_at: Instant::now(),
            bytes_sent: Cell::new(0),
        }
    }

    /// Attaches OTel metrics and traces from a telemetry pipeline.
    pub fn with_telemetry(
        mut self,
        otel_metrics: Option<Arc<OtelNntpMetrics>>,
        export: Option<ExportHandle>,
        traces_enabled: bool,
    ) -> Self {
        self.otel_metrics = otel_metrics;
        self.export = export;
        self.traces_enabled = traces_enabled;
        self
    }

    fn begin_connection_telemetry(&mut self) {
        self.opened_at = Instant::now();
        if let Some(m) = &self.otel_metrics {
            m.connection_opened();
        }
        if self.traces_enabled {
            if let Some(export) = self.export.clone() {
                let t = Trace::new("NNTP connection", SpanKind::Server);
                t.set_exporter(export);
                self.meta.traceparent = Some(t.traceparent());
                self.conn_trace = Some(t);
            }
        }
    }

    fn end_connection_telemetry(&mut self) {
        if let Some(trace) = self.conn_trace.take() {
            let root = trace.root_span();
            root.set_status_ok();
            root.end();
            trace.end();
        }
        self.meta.traceparent = None;
        if let Some(m) = &self.otel_metrics {
            m.connection_closed(self.opened_at.elapsed(), self.bytes_sent.get());
        }
    }

    /// Starts timing a command that moves an article, if telemetry is on.
    fn begin_article_telemetry(&self, kind: &'static str) -> Option<ArticleTelemetry> {
        if self.otel_metrics.is_none() && self.conn_trace.is_none() {
            return None;
        }
        let span = self.conn_trace.as_ref().map(|t| {
            t.start_span(if kind == "posted" { "NNTP post" } else { "NNTP retrieve" }, SpanKind::Server)
        });
        let counter = if kind == "posted" { &self.metrics.articles_posted } else { &self.metrics.articles_retrieved };
        Some(ArticleTelemetry { timer: RequestTimer::start(), span, kind, before: counter.load(Ordering::Relaxed) })
    }

    fn finish_article_telemetry(&self, telemetry: ArticleTelemetry, failed: bool) {
        let counter = if telemetry.kind == "posted" { &self.metrics.articles_posted } else { &self.metrics.articles_retrieved };
        // A command that did not move an article (no such article, a refused
        // post) is not an article event.
        if counter.load(Ordering::Relaxed) == telemetry.before && !failed {
            if let Some(span) = telemetry.span {
                span.end();
            }
            return;
        }
        let outcome = if failed { "fail" } else { "ok" };
        if let Some(span) = telemetry.span {
            span.set_attribute("nntp.article", telemetry.kind);
            span.set_attribute("outcome", outcome);
            if failed {
                span.set_status_error(outcome);
            } else {
                span.set_status_ok();
            }
            span.end();
        }
        if let Some(m) = &self.otel_metrics {
            m.article(telemetry.kind, outcome, telemetry.timer.elapsed());
        }
    }

    /// Is the handler waiting for something that will happen on its own?
    #[cfg(test)]
    fn busy(&self) -> bool {
        self.job.is_some() && !self.write_pending.load(Ordering::Relaxed)
    }

    fn send(&self, ep: &mut dyn Endpoint, bytes: &[u8]) {
        self.bytes_sent.set(self.bytes_sent.get() + bytes.len() as u64);
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
        if let Some(m) = &self.otel_metrics {
            m.command(command.name());
        }
        if command == NntpCommand::Post && !self.posting_allowed {
            self.say(ep, 440, "Posting not permitted");
            return;
        }
        if commands::needs_handler(&command) {
            if self.config.authentication_required && !self.authenticated() {
                self.say(ep, 480, "Authentication required");
                return;
            }
            self.start_job(ep, JobKind::Command(command));
            return;
        }
        match command {
            NntpCommand::StartTls => self.starttls(ep),
            NntpCommand::AuthinfoUser(user) => self.authinfo_user(ep, user),
            NntpCommand::AuthinfoPass(password) => self.authinfo_pass(ep, password),
            NntpCommand::AuthinfoSasl { mechanism, initial_response } => self.authinfo_sasl(ep, &mechanism, initial_response),
            NntpCommand::SaslResponse(response) => {
                self.start_job(ep, JobKind::AuthSasl(commands::SaslStep::Respond(response)));
            }
            NntpCommand::SaslAbort => {
                self.shared.auth.lock().unwrap_or_else(|e| e.into_inner()).sasl = None;
                self.say(ep, 481, "Authentication failed/rejected");
            }
            NntpCommand::SaslInvalid => {
                self.shared.auth.lock().unwrap_or_else(|e| e.into_inner()).sasl = None;
                self.say(ep, 504, "Base64 encoding was incorrect");
            }
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

    fn authenticated(&self) -> bool {
        self.shared.auth.lock().unwrap_or_else(|e| e.into_inner()).user.is_some()
    }

    /// May a password be sent on this connection?
    fn cleartext_ok(&self) -> bool {
        self.meta.tls || self.config.allow_cleartext_auth
    }

    /// The SASL mechanisms offered on this connection.
    fn mechanisms(&self) -> Vec<hopf_auth::SaslMechanism> {
        let Some(store) = &self.config.credentials else { return Vec::new() };
        store
            .supported_mechanisms()
            .into_iter()
            .filter(|m| self.cleartext_ok() || !m.requires_tls())
            .filter(|m| *m != hopf_auth::SaslMechanism::External || self.peer_certificate.is_some())
            .collect()
    }

    fn starttls(&mut self, ep: &mut dyn Endpoint) {
        if self.meta.tls || self.authenticated() {
            self.say(ep, 502, "Command unavailable");
            return;
        }
        if self.config.tls_acceptor.is_none() || self.config.implicit_tls {
            self.say(ep, 580, "Can not initiate TLS negotiation");
            return;
        }
        self.say(ep, 382, "Continue with TLS negotiation");
        self.tls_pending = true;
        if ep.start_tls().is_err() {
            self.close(ep);
        }
    }

    fn authinfo_user(&mut self, ep: &mut dyn Endpoint, user: String) {
        if self.config.credentials.is_none() || self.authenticated() {
            self.say(ep, 502, "Command unavailable");
        } else if !self.cleartext_ok() {
            self.say(ep, 483, "Encryption or stronger authentication required");
        } else {
            self.pending_user = Some(user);
            self.say(ep, 381, "Password required");
        }
    }

    fn authinfo_pass(&mut self, ep: &mut dyn Endpoint, password: String) {
        if self.config.credentials.is_none() || self.authenticated() {
            self.say(ep, 502, "Command unavailable");
        } else if !self.cleartext_ok() {
            self.say(ep, 483, "Encryption or stronger authentication required");
        } else if let Some(user) = self.pending_user.take() {
            self.start_job(ep, JobKind::AuthPassword { user, password });
        } else {
            self.say(ep, 482, "Authentication commands issued out of sequence");
        }
    }

    fn authinfo_sasl(&mut self, ep: &mut dyn Endpoint, mechanism: &str, initial_response: Option<Vec<u8>>) {
        if self.config.credentials.is_none() || self.authenticated() {
            self.say(ep, 502, "Command unavailable");
            return;
        }
        let Some(mech) = hopf_auth::SaslMechanism::from_name(mechanism) else {
            self.say(ep, 503, "Mechanism not recognized");
            return;
        };
        let supported = self.config.credentials.as_ref().is_some_and(|s| s.supported_mechanisms().contains(&mech));
        if !supported {
            self.say(ep, 503, "Mechanism not recognized");
        } else if mech.requires_tls() && !self.cleartext_ok() {
            self.say(ep, 483, "Encryption or stronger authentication required");
        } else {
            self.pending_user = None;
            self.start_job(
                ep,
                JobKind::AuthSasl(commands::SaslStep::Begin {
                    mechanism: mech,
                    initial_response,
                    peer_certificate: self.peer_certificate.clone(),
                }),
            );
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
        if !self.authenticated() {
            if !self.meta.tls && self.config.tls_acceptor.is_some() && !self.config.implicit_tls {
                reply::data_line("STARTTLS", &mut body);
            }
            if self.config.credentials.is_some() {
                if self.cleartext_ok() {
                    reply::data_line("AUTHINFO USER", &mut body);
                }
                let mechanisms = self.mechanisms();
                if !mechanisms.is_empty() {
                    let names: Vec<&str> = mechanisms.iter().map(|m| m.name()).collect();
                    reply::data_line(&format!("SASL {}", names.join(" ")), &mut body);
                }
            }
        }
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
        let credentials = self.config.credentials.clone();
        let job_end = Arc::clone(&end);
        let job_failed = Arc::clone(&failed);
        let job_pipe = pipe.clone();
        let article = match &kind {
            JobKind::Command(NntpCommand::Article(_) | NntpCommand::Head(_) | NntpCommand::Body(_)) => {
                self.begin_article_telemetry("retrieved")
            }
            JobKind::PostCommit => self.begin_article_telemetry("posted"),
            _ => None,
        };
        match &kind {
            JobKind::AuthPassword { .. } => self.auth_attempt = Some("USER".to_string()),
            JobKind::AuthSasl(commands::SaslStep::Begin { mechanism, .. }) => {
                self.auth_attempt = Some(mechanism.name().to_string());
            }
            _ => {}
        }
        ep.pause_read();
        self.runtime.storage().submit_on(
            handle.clone(),
            move || {
                let mut out = out;
                let result = match kind {
                    JobKind::PostWrite(piece) => commands::post_write(&shared.post, &piece),
                    JobKind::PostTooLarge => commands::post_too_large(&shared.post),
                    JobKind::PostCommit => commands::post_commit(&shared.post, &mut out, &metrics),
                    JobKind::AuthPassword { user, password } => match (credentials.as_ref(), shared.reader.lock().unwrap_or_else(|e| e.into_inner()).as_mut()) {
                        (Some(store), Some(r)) => commands::auth_password(r.as_mut(), store, &shared.auth, &user, &password, &mut out),
                        _ => JobEnd::Fatal,
                    },
                    JobKind::AuthSasl(step) => match (credentials.as_ref(), shared.reader.lock().unwrap_or_else(|e| e.into_inner()).as_mut()) {
                        (Some(store), Some(r)) => commands::auth_sasl(r.as_mut(), store, &shared.auth, step, &mut out),
                        _ => JobEnd::Fatal,
                    },
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
        self.job = Some(Job { pipe, end, failed, sent_any: false, article });
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
                        self.bytes_sent.set(self.bytes_sent.get() + chunk.len() as u64);
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
        let Some(mut job) = self.job.take() else { return };
        let end = *job.end.lock().unwrap_or_else(|e| e.into_inner());
        let broken = job.failed.load(Ordering::Relaxed) || end.is_none() || end == Some(JobEnd::Fatal);
        if let Some(telemetry) = job.article.take() {
            self.finish_article_telemetry(telemetry, broken);
        }
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
        match end {
            Some(JobEnd::AuthOk) => {
                NntpServerMetrics::add(&self.metrics.auth_ok, 1);
                if let (Some(m), Some(mech)) = (&self.otel_metrics, self.auth_attempt.take()) {
                    m.auth(&mech, true);
                }
            }
            Some(JobEnd::AuthFailed) => {
                NntpServerMetrics::add(&self.metrics.auth_fail, 1);
                if let (Some(m), Some(mech)) = (&self.otel_metrics, self.auth_attempt.take()) {
                    m.auth(&mech, false);
                }
                self.auth_failures += 1;
                let limit = self.config.max_auth_failures;
                if limit > 0 && self.auth_failures >= limit {
                    self.say(ep, 400, "Too many authentication failures");
                    self.close(ep);
                    return;
                }
            }
            Some(JobEnd::SaslContinue) => self.lexer.expect_sasl_response(),
            _ => {}
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
        self.begin_connection_telemetry();
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
                if self.tls_pending {
                    // The client must wait for the answer to STARTTLS before it
                    // sends more; what it sent ahead of the handshake is not to
                    // be taken as if it had been sent after it.
                    if !data.is_empty() {
                        *data = &[];
                        self.close(ep);
                    }
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
        self.end_connection_telemetry();
    }

    fn security_established(&mut self, ep: &mut dyn Endpoint, info: &hopf_core::SecurityInfo) {
        self.meta.tls = true;
        self.peer_certificate = info.peer_certificate_fingerprint().map(str::to_string);
        if self.expect_implicit_tls && !self.greeted {
            self.greet(ep);
            return;
        }
        if self.tls_pending {
            // The protocol starts again, as after the greeting: nothing the
            // client said before the handshake is remembered (RFC 4642
            // section 2.2.2).
            self.tls_pending = false;
            self.pending_user = None;
            *self.shared.session.lock().unwrap_or_else(|e| e.into_inner()) = SessionState::default();
            NntpServerMetrics::add(&self.metrics.starttls, 1);
            if let Some(m) = &self.otel_metrics {
                m.starttls();
            }
            ep.poke_handler();
        }
    }

    fn error(&mut self, ep: &mut dyn Endpoint, _err: &std::io::Error) {
        self.close(ep);
    }
}
